"""The read path: run the lanes, fuse them, page the fused ranking.

lexical lane   mysql: exact observable / hash / tag / uuid matches (saq.search.lexical)
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
from dataclasses import dataclass, field
from datetime import timezone
from typing import Optional

from qdrant_client import QdrantClient, models

from saq.configuration.config import get_config
from saq.qdrant_client import get_qdrant_client
from saq.search import index
from saq.search.lexical import lexical_search, parse_query
from saq.search.model import encode_query, load_model
from saq.search.sparse import sparse_vector
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


def search_alerts(request: SearchRequest, *, post_filter: Optional[PostFilter] = None, client: Optional[QdrantClient] = None, model=None) -> SearchResponse:
    """Runs the requested lanes for request.query and returns one page of the fused ranking."""
    config = get_config().search
    timings: dict[str, int] = {}
    query = (request.query or "").strip()
    if not query:
        return SearchResponse(query=query, total=0, offset=request.offset, limit=request.limit)

    lexical: Optional[LaneResult] = None
    semantic: Optional[SemanticLane] = None

    if LANE_LEXICAL in request.lanes:
        start = time.time()
        try:
            lexical = lexical_search(parse_query(query), request.filters, limit=config.lexical_limit)
        except Exception as e:
            logging.error(f"lexical search failed for {query!r}: {e}")
            lexical = []
        timings[LANE_LEXICAL] = int((time.time() - start) * 1000)

    if LANE_SEMANTIC in request.lanes:
        start = time.time()
        try:
            semantic = semantic_search(query, request.filters, limit=config.semantic_limit, group_size=config.semantic_group_size, client=client, model=model)
        except Exception as e:
            logging.error(f"semantic search failed for {query!r}: {e}")
            semantic = SemanticLane()
        timings[LANE_SEMANTIC] = int((time.time() - start) * 1000)

    return _assemble(query, lexical=lexical, semantic=semantic, limit=request.limit, offset=request.offset,
                     include_hits=request.include_hits, post_filter=post_filter, timings=timings)


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
                     include_hits=include_hits, post_filter=post_filter, timings=timings)
