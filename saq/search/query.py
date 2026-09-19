"""The read path: parse the query, run the lanes, fuse them, page the fused ranking.

The query is parsed first (saq.search.syntax). What it yields decides which lanes run at all:

  field terms   tag:/uuid:/<observable type>: -> the lexical lane; queue:/alert_date:/... ->
                pre-filters, and the rest of the alert-management filter vocabulary -> a SQL
                post-filter
  free text     the dense and sparse lanes -- and ONLY when there is some. An embedding of ""
                still has a nearest neighbour, so running them on "tag:phish" alone would
                return unrelated alerts above the floor.
  nothing       filters but no query at all is a LISTING: plain newest-first SQL, no ranking,
                no tiers. This is what answers "every alert carrying this signature uuid".

lexical lane   mysql: exact observable / tag / uuid matches (saq.search.lexical)
dense lane     qdrant: cosine over the embedding, with an absolute floor (search.score_threshold)
sparse lane    qdrant: IDF-weighted term overlap (saq.search.sparse)

The dense lane always has a nearest neighbour, so it is floored; the sparse lane only returns
documents that share a term with the query. The three lanes are fused with weighted reciprocal
rank fusion, exact matches are moved to the front (newest first), and the fused list is what
gets paginated. Tiers come from the evidence behind each alert (an exact match, its best dense
score, whether a term matched), never from its position in the result set.

Callers supply a post_filter that applies whatever SQL-only scoping they need (node visibility,
GUI filters the payload cannot express); it runs on the capped fused list before pagination so
`total` is honest.
"""

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Optional

import pytz
from qdrant_client import QdrantClient, models
from sqlalchemy import distinct, func

from saq.configuration.config import get_config
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.database.util.index import tag_key
from saq.gui.filter_query import build_alert_query, filter_alert_uuids
from saq.qdrant_client import get_qdrant_client
from saq.search import index
from saq.search.lexical import apply_sql_filters, candidates_from_terms, lexical_search
from saq.search.model import encode_query, load_model
from saq.search.sparse import sparse_vector
from saq.search.syntax import ParsedQuery, parse_search_query
from saq.util.relative_time import RelativeTimeError, parse_date_range
from saq.search.types import (
    KIND_ALERT,
    KIND_ANALYSIS,
    KIND_COMMENT,
    KIND_CONTEXT,
    KIND_DETECTION,
    LANE_LEXICAL,
    LANE_SEMANTIC,
    TIER_EXACT,
    TIER_GOOD,
    TIER_STRONG,
    TIER_WEAK,
    AlertSearchResult,
    SearchFilters,
    SearchHit,
    SearchRequest,
    SearchResponse,
)

# document kinds an alert's own vectors are drawn from for "similar alerts"
SIMILARITY_KINDS = (KIND_ALERT, KIND_ANALYSIS, KIND_DETECTION, KIND_COMMENT, KIND_CONTEXT)

# internal lane names for fusion (both qdrant lanes are reported to callers as "semantic")
LANE_DENSE = "dense"
LANE_SPARSE = "sparse"

PostFilter = Callable[[list[str]], list[str]]
LaneResult = list[tuple[str, list[SearchHit]]]


@dataclass
class SemanticLane:
    """What qdrant returned for a query: each sub-lane grouped by alert, plus the best score per alert."""

    dense: LaneResult = field(default_factory=list)
    sparse: LaneResult = field(default_factory=list)
    dense_scores: dict[str, float] = field(default_factory=dict)
    sparse_scores: dict[str, float] = field(default_factory=dict)


def _iso(value) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_payload_filter(filters: SearchFilters, *, exclude_alert_uuids: Iterable[str] = ()) -> Optional[models.Filter]:
    """Translates SearchFilters into a qdrant payload filter (None when there is nothing to filter)."""
    must: list = []
    must_not: list = []

    if filters.insert_date_ranges:
        ranges = models.Filter(should=[
            models.FieldCondition(key=index.FIELD_INSERT_DATE, range=models.DatetimeRange(gte=_iso(start), lte=_iso(end)))
            for start, end in filters.insert_date_ranges
        ])
        (must_not if filters.insert_date_inverted else must).append(ranges)

    for values, inverted, field_name in (
        (filters.alert_types, filters.alert_types_inverted, index.FIELD_ALERT_TYPE),
        (filters.dispositions, filters.dispositions_inverted, index.FIELD_DISPOSITION),
        (filters.queues, filters.queues_inverted, index.FIELD_QUEUE),
        (filters.tags, filters.tags_inverted, index.FIELD_TAGS),
    ):
        if values:
            condition = models.FieldCondition(key=field_name, match=models.MatchAny(any=list(values)))
            (must_not if inverted else must).append(condition)

    if filters.locations is not None:
        must.append(models.FieldCondition(key=index.FIELD_LOCATION, match=models.MatchAny(any=list(filters.locations))))

    excluded = list(filters.exclude_alert_uuids) + list(exclude_alert_uuids)
    if excluded:
        must_not.append(models.FieldCondition(key=index.FIELD_ROOT_UUID, match=models.MatchAny(any=excluded)))

    if not must and not must_not:
        return None

    return models.Filter(must=must or None, must_not=must_not or None)


def _groups_to_lane(groups) -> tuple[LaneResult, dict[str, float]]:
    result: LaneResult = []
    scores: dict[str, float] = {}
    for group in groups:
        alert_uuid = str(group.id)
        hits = []
        for point in group.hits:
            payload = point.payload or {}
            hits.append(SearchHit(
                lane=LANE_SEMANTIC,
                kind=payload.get(index.FIELD_KIND, ""),
                key=f"{payload.get(index.FIELD_KIND, '')}:{payload.get(index.FIELD_KEY, '')}:{payload.get(index.FIELD_CHUNK, 0)}",
                title=payload.get(index.FIELD_TITLE),
                text=payload.get(index.FIELD_TEXT, ""),
                score=float(point.score),
                analysis_uuid=payload.get(index.FIELD_ANALYSIS_UUID),
                observable_uuid=payload.get(index.FIELD_OBSERVABLE_UUID),
            ))
        if hits:
            scores[alert_uuid] = max(hit.score for hit in hits)
        result.append((alert_uuid, hits))

    return result, scores


def _grouped_query(client: QdrantClient, name: str, *, query, using: str, payload_filter, limit: int, group_size: int, score_threshold: Optional[float] = None):
    return client.query_points_groups(
        collection_name=name,
        query=query,
        using=using,
        query_filter=payload_filter,
        group_by=index.FIELD_ROOT_UUID,
        group_size=group_size,
        limit=limit,
        score_threshold=score_threshold,
        with_payload=True,
        timeout=get_config().qdrant.search_timeout,
    ).groups


def semantic_search(
    query: str,
    filters: SearchFilters,
    *,
    limit: int,
    group_size: int,
    client: Optional[QdrantClient] = None,
    model=None,
) -> SemanticLane:
    """Dense (floored) and sparse retrieval, each grouped by alert."""
    config = get_config()
    client = client or get_qdrant_client(timeout=config.qdrant.search_timeout)
    name = index.collection_name()
    if not client.collection_exists(collection_name=name):
        logging.debug(f"search collection {name} does not exist yet")
        return SemanticLane()

    model = model or load_model()
    payload_filter = build_payload_filter(filters)
    lane = SemanticLane()

    dense_groups = _grouped_query(client, name, query=encode_query(model, query), using=index.DENSE, payload_filter=payload_filter,
                                  limit=limit, group_size=group_size, score_threshold=config.search.score_threshold)
    lane.dense, lane.dense_scores = _groups_to_lane(dense_groups)

    sparse = sparse_vector(query)
    if sparse.indices:
        sparse_groups = _grouped_query(client, name, query=sparse, using=index.SPARSE, payload_filter=payload_filter, limit=limit, group_size=group_size)
        lane.sparse, lane.sparse_scores = _groups_to_lane(sparse_groups)

    return lane


def similar_search(
    alert_uuid: str,
    filters: SearchFilters,
    *,
    limit: int,
    group_size: int,
    client: Optional[QdrantClient] = None,
) -> SemanticLane:
    """Alerts whose documents are nearest to the alert's own dense vectors."""
    config = get_config()
    client = client or get_qdrant_client(timeout=config.qdrant.search_timeout)
    ids = index.alert_point_ids(alert_uuid, client=client, kinds=SIMILARITY_KINDS)
    if not ids:
        return SemanticLane()

    groups = _grouped_query(
        client, index.collection_name(),
        query=models.RecommendQuery(recommend=models.RecommendInput(positive=ids)),
        using=index.DENSE,
        payload_filter=build_payload_filter(filters, exclude_alert_uuids=[alert_uuid]),
        limit=limit, group_size=group_size, score_threshold=config.search.score_threshold,
    )
    lane = SemanticLane()
    lane.dense, lane.dense_scores = _groups_to_lane(groups)
    return lane


def fuse(lanes: dict[str, list[str]], weights: dict[str, float], k: int) -> list[tuple[str, float]]:
    """Weighted reciprocal rank fusion: score(u) = sum over lanes of weight / (k + rank)."""
    scores: dict[str, float] = {}
    for lane, ranked in lanes.items():
        weight = weights.get(lane, 1.0)
        for rank, alert_uuid in enumerate(ranked, start=1):
            scores[alert_uuid] = scores.get(alert_uuid, 0.0) + weight / (k + rank)

    # ties broken by first appearance (dict order) so the result is deterministic
    return sorted(scores.items(), key=lambda item: -item[1])


def exact_first(fused: list[tuple[str, float]], lexical_order: list[str]) -> list[tuple[str, float]]:
    """Moves every exact (lexical) match to the front, in the lexical lane's own newest-first order.

    Reciprocal rank fusion alone would let a weak semantic co-hit reorder exact matches, and
    "every alert with this indicator, newest first" is precisely what an analyst typing an
    indicator expects. Semantic-only matches follow in fused order.
    """
    if not lexical_order:
        return fused

    scores = dict(fused)
    exact = [(alert_uuid, scores[alert_uuid]) for alert_uuid in lexical_order if alert_uuid in scores]
    exact_set = set(lexical_order)
    return exact + [(alert_uuid, score) for alert_uuid, score in fused if alert_uuid not in exact_set]


def assign_tier(result: AlertSearchResult) -> str:
    """The tier is the evidence: exact > strong (clearly similar, or similar and sharing terms)
    > good (similar above the floor) > weak (only a term in common)."""
    config = get_config().search
    if LANE_LEXICAL in result.lanes:
        return TIER_EXACT

    dense = result.dense_score
    sparse = result.sparse_score
    if dense is not None and (dense >= config.strong_threshold or (sparse is not None and dense >= config.score_threshold)):
        return TIER_STRONG

    if dense is not None:
        return TIER_GOOD

    return TIER_WEAK


def _merge_hits(*hit_lists: list[SearchHit]) -> list[SearchHit]:
    """Exact hits first, then semantic hits by score; the same chunk reached by both qdrant lanes appears once."""
    best: dict[str, SearchHit] = {}
    for hit in (hit for hits in hit_lists for hit in hits):
        current = best.get(hit.key)
        if current is None or (hit.lane == current.lane and hit.score > current.score):
            best[hit.key] = hit

    return sorted(best.values(), key=lambda hit: (hit.lane != LANE_LEXICAL, -hit.score))


def _assemble(
    query: str,
    *,
    lexical: Optional[LaneResult],
    semantic: Optional[SemanticLane],
    limit: int,
    offset: int,
    include_hits: bool,
    post_filter: Optional[PostFilter],
    timings: dict[str, int],
) -> SearchResponse:
    config = get_config().search
    lanes_used: set[str] = set()
    ranked: dict[str, list[str]] = {}
    hits_by_alert: dict[str, list[list[SearchHit]]] = {}
    lanes_by_alert: dict[str, set[str]] = {}

    def take(name: str, external: str, results: LaneResult):
        ranked[name] = [alert_uuid for alert_uuid, _ in results]
        for alert_uuid, hits in results:
            lanes_by_alert.setdefault(alert_uuid, set()).add(external)
            hits_by_alert.setdefault(alert_uuid, []).append(hits)

    if lexical is not None:
        lanes_used.add(LANE_LEXICAL)
        take(LANE_LEXICAL, LANE_LEXICAL, lexical)

    if semantic is not None:
        lanes_used.add(LANE_SEMANTIC)
        take(LANE_DENSE, LANE_SEMANTIC, semantic.dense)
        take(LANE_SPARSE, LANE_SEMANTIC, semantic.sparse)

    weights = {LANE_LEXICAL: config.lexical_weight, LANE_DENSE: config.semantic_weight, LANE_SPARSE: config.semantic_weight}
    fused = fuse(ranked, weights, config.rrf_k)
    fused = exact_first(fused, ranked.get(LANE_LEXICAL, []))
    fused = fused[:config.max_results]

    if post_filter is not None and fused:
        start = time.time()
        kept = set(post_filter([alert_uuid for alert_uuid, _ in fused]))
        fused = [(alert_uuid, score) for alert_uuid, score in fused if alert_uuid in kept]
        timings["post_filter"] = int((time.time() - start) * 1000)

    results = []
    for rank, (alert_uuid, score) in enumerate(fused, start=1):
        result = AlertSearchResult(
            alert_uuid=alert_uuid,
            rank=rank,
            fused_score=score,
            tier=TIER_WEAK,
            lanes=frozenset(lanes_by_alert.get(alert_uuid, ())),
            dense_score=semantic.dense_scores.get(alert_uuid) if semantic else None,
            sparse_score=semantic.sparse_scores.get(alert_uuid) if semantic else None,
        )
        result.tier = assign_tier(result)
        results.append(result)

    page = results[offset:offset + limit]
    if include_hits:
        for result in page:
            result.hits = _merge_hits(*hits_by_alert.get(result.alert_uuid, []))

    return SearchResponse(
        query=query,
        total=len(results),
        offset=offset,
        limit=limit,
        results=page,
        lanes_used=frozenset(lanes_used),
        timings_ms=timings,
    )


# parsed filter terms that have a qdrant payload field: {filter name: (values, inverted)}
_PAYLOAD_FIELDS = {
    "Alert Type": ("alert_types", "alert_types_inverted"),
    "Disposition": ("dispositions", "dispositions_inverted"),
    "Queue": ("queues", "queues_inverted"),
}


def _fold_date_range(entry: dict, tz) -> tuple:
    """An Alert Date entry as (start, end) pairs, or () if it cannot be resolved."""
    now = datetime.now(pytz.utc)
    try:
        return tuple(parse_date_range(value, now=now, tz=tz) for value in entry["values"])
    except RelativeTimeError:
        # the parser already validated these; a value that fails here would have to be
        # timezone-dependent, and silently widening the search is worse than SQL-only
        return ()


def merge_parsed_filters(filters: SearchFilters, parsed: ParsedQuery) -> SearchFilters:
    """Folds the parsed query's filter terms into the request's own filters.

    They are ANDed, which is what an analyst means by typing `queue:default` on top of a filter
    chip that already says `Disposition = OPEN`: a typed term narrows, it does not widen. The
    parser has already merged repeats of the same field within the query, so what arrives here
    cannot ask one alert to be in two queues.

    A term that has a qdrant payload field becomes a real pre-filter rather than a SQL
    post-filter. That is not just an optimization: the semantic lane retrieves
    `search.semantic_limit` alerts and post-filtering throws away whatever is left, so typing
    `queue:default` would otherwise return a fraction of what it should. It can only be folded
    when the caller has not already set that field -- SearchFilters holds one value set per
    field, and two different ones ANDed are not expressible there. Anything left over goes to
    the filter list, which ANDs correctly in SQL.
    """
    if not parsed.filters:
        return filters

    changes: dict = {}
    remaining: list = []
    tz = filters.timezone or pytz.utc

    for entry in parsed.filters:
        name = entry["name"]
        values, inverted = entry["values"], entry["inverted"]

        if name in _PAYLOAD_FIELDS:
            field, inverted_field = _PAYLOAD_FIELDS[name]
            if not getattr(filters, field) and field not in changes:
                changes[field] = tuple(values)
                changes[inverted_field] = inverted
                continue

        elif name == "Tag" and not any("*" in value for value in values):
            # a wildcard has no payload equivalent; an exact tag does
            if not filters.tags and "tags" not in changes:
                changes["tags"] = tuple(tag_key(value) for value in values)
                changes["tags_inverted"] = inverted
                continue

        elif name == "Alert Date":
            if not filters.insert_date_ranges and "insert_date_ranges" not in changes:
                ranges = _fold_date_range(entry, tz)
                if ranges:
                    changes["insert_date_ranges"] = ranges
                    changes["insert_date_inverted"] = inverted
                    continue

        remaining.append(entry)

    if remaining:
        changes["filter_list"] = tuple(filters.filter_list) + tuple(remaining)

    return replace(filters, **changes) if changes else filters


def _sql_post_filter(filters: SearchFilters, caller: Optional[PostFilter]) -> Optional[PostFilter]:
    """Composes the filter-list narrowing with whatever the caller already asked for.

    The filter list is applied here rather than inside the lanes because none of its filters
    has a qdrant payload equivalent. It runs on the capped fused list BEFORE pagination, so
    `total` stays honest.
    """
    if not filters.filter_list:
        return caller

    def post_filter(uuids: list[str]) -> list[str]:
        # locations=None: node scoping is already in SearchFilters (and in the caller's own
        # post_filter); asking for it again here would just repeat the same condition
        kept = filter_alert_uuids(
            list(filters.filter_list), uuids,
            entity=Alert, tz=filters.timezone or pytz.utc, locations=None)
        return caller(kept) if caller is not None else kept

    return post_filter


def filter_listing(
    filters: SearchFilters,
    *,
    limit: int,
    offset: int,
    post_filter: Optional[PostFilter] = None,
    timings: Optional[dict] = None,
) -> SearchResponse:
    """Alerts matching the filters, newest first. No query, no ranking, no tiers.

    This is the answer to "every alert carrying this observable", and it is a listing rather
    than a search on purpose: there is no evidence of relevance to report, `total` is a real
    SQL count rather than the size of a capped fused list, and the page is a LIMIT/OFFSET
    instead of a slice of at most `search.max_results`.
    """
    timings = timings if timings is not None else {}
    start = time.time()

    # locations are applied by apply_sql_filters below, from SearchFilters
    query = build_alert_query(
        list(filters.filter_list), entity=Alert, tz=filters.timezone or pytz.utc, locations=None)
    query = apply_sql_filters(query, filters)

    total = get_db().execute(
        query.statement.with_only_columns(func.count(distinct(Alert.id)))).scalar() or 0

    # GROUP BY rather than DISTINCT: the observable and tag joins fan out, and under
    # ONLY_FULL_GROUP_BY mysql refuses to order a DISTINCT by a column that is not selected
    rows = query.with_entities(Alert.uuid) \
        .group_by(Alert.id) \
        .order_by(Alert.insert_date.desc(), Alert.id.desc()) \
        .limit(limit).offset(offset)
    uuids = [row[0] for row in rows]

    if post_filter is not None and uuids:
        kept = set(post_filter(uuids))
        uuids = [alert_uuid for alert_uuid in uuids if alert_uuid in kept]

    timings["listing"] = int((time.time() - start) * 1000)
    return SearchResponse(
        query="",
        total=total,
        offset=offset,
        limit=limit,
        results=[
            AlertSearchResult(alert_uuid=alert_uuid, rank=offset + index, fused_score=0.0, tier=None)
            for index, alert_uuid in enumerate(uuids, start=1)
        ],
        lanes_used=frozenset(),
        timings_ms=timings,
    )


def search_alerts(request: SearchRequest, *, post_filter: Optional[PostFilter] = None, client: Optional[QdrantClient] = None, model=None) -> SearchResponse:
    """Parses request.query, runs the lanes it calls for, and returns one page of results."""
    config = get_config().search
    timings: dict[str, int] = {}
    query = (request.query or "").strip()

    parsed = parse_search_query(query)
    if parsed.errors:
        # A query that cannot be honored returns nothing and says why. Searching the part we
        # understood would quietly answer a different question than the one that was asked.
        return SearchResponse(query=query, total=0, offset=request.offset, limit=request.limit,
                              errors=parsed.errors)

    filters = merge_parsed_filters(request.filters, parsed)
    effective_post_filter = _sql_post_filter(filters, post_filter)

    if parsed.is_empty() and filters.is_empty():
        return SearchResponse(query=query, total=0, offset=request.offset, limit=request.limit)

    if not parsed.text and not parsed.exact:
        # filters only -- a listing, not a search
        return filter_listing(filters, limit=request.limit, offset=request.offset,
                              post_filter=post_filter, timings=timings)

    lexical: Optional[LaneResult] = None
    semantic: Optional[SemanticLane] = None

    if LANE_LEXICAL in request.lanes and parsed.exact:
        start = time.time()
        try:
            lexical = lexical_search(candidates_from_terms(parsed.exact), filters, limit=config.lexical_limit)
        except Exception as e:
            logging.error(f"lexical search failed for {query!r}: {e}")
            lexical = []
        timings[LANE_LEXICAL] = int((time.time() - start) * 1000)

    # No free text means no query to embed. encode_query("") is a valid vector with a nearest
    # neighbour, so running the lane anyway would attach unrelated alerts to `tag:phish`.
    if LANE_SEMANTIC in request.lanes and parsed.text:
        start = time.time()
        try:
            semantic = semantic_search(parsed.text, filters, limit=config.semantic_limit, group_size=config.semantic_group_size, client=client, model=model)
        except Exception as e:
            logging.error(f"semantic search failed for {query!r}: {e}")
            semantic = SemanticLane()
        timings[LANE_SEMANTIC] = int((time.time() - start) * 1000)

    return _assemble(query, lexical=lexical, semantic=semantic, limit=request.limit, offset=request.offset,
                     include_hits=request.include_hits, post_filter=effective_post_filter, timings=timings)


def similar_alerts(
    alert_uuid: str,
    filters: SearchFilters = SearchFilters(),
    *,
    limit: int = 10,
    offset: int = 0,
    include_hits: bool = True,
    post_filter: Optional[PostFilter] = None,
    client: Optional[QdrantClient] = None,
) -> SearchResponse:
    """Alerts most similar to alert_uuid (the alert itself is excluded)."""
    config = get_config().search
    timings: dict[str, int] = {}
    start = time.time()
    try:
        semantic = similar_search(alert_uuid, filters, limit=config.semantic_limit, group_size=config.semantic_group_size, client=client)
    except Exception as e:
        logging.error(f"similar search failed for {alert_uuid}: {e}")
        semantic = SemanticLane()
    timings[LANE_SEMANTIC] = int((time.time() - start) * 1000)

    return _assemble(f"similar:{alert_uuid}", lexical=None, semantic=semantic, limit=limit, offset=offset,
                     include_hits=include_hits, post_filter=_sql_post_filter(filters, post_filter), timings=timings)
