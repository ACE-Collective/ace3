"""Search service: adapts the wire schemas to saq.search and loads the alert rows for a page.

The functions are synchronous (saq.search uses the sync ORM session and qdrant client) and are
run through run_db_in_thread() by the routers.
"""

from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import selectinload

from aceapi_v2.search.schemas import (
    AlertSearchRequest,
    AlertSearchResponse,
    AlertSearchResultOut,
    AlertSummaryOut,
    SearchFiltersBody,
    SearchHitOut,
    SimilarAlertsRequest,
)
from saq.database.model import Alert, Tag, TagMapping
from saq.database.pool import get_db
from saq.database.util.alert import node_scope_locations
from saq.database.util.index import tag_key
from saq.search.query import search_alerts, similar_alerts
from saq.search.types import SearchFilters, SearchRequest, SearchResponse
from saq.util.uuid import is_uuid


def to_search_filters(body: SearchFiltersBody) -> SearchFilters:
    """Wire filters -> search filters, with this deployment's node scoping applied."""
    ranges = ()
    if body.insert_date_start or body.insert_date_end:
        start = body.insert_date_start or datetime(1970, 1, 1, tzinfo=timezone.utc)
        end = body.insert_date_end or datetime(9999, 12, 31, tzinfo=timezone.utc)
        ranges = ((start, end),)

    locations = node_scope_locations()
    return SearchFilters(
        insert_date_ranges=ranges,
        alert_types=tuple(body.alert_types),
        dispositions=tuple(body.dispositions),
        queues=tuple(body.queues),
        tags=tuple(tag_key(tag) for tag in body.tags),
        locations=tuple(locations) if locations is not None else None,
        exclude_alert_uuids=tuple(body.exclude_alert_uuids),
    )


def node_scope_post_filter(uuids: list[str]) -> list[str]:
    """Keeps only the alerts that exist and are visible on this node, preserving order."""
    if not uuids:
        return []

    query = get_db().query(Alert.uuid).filter(Alert.uuid.in_(uuids))
    locations = node_scope_locations()
    if locations is not None:
        query = query.filter(Alert.location.in_(locations))

    visible = {row[0] for row in query}
    return [alert_uuid for alert_uuid in uuids if alert_uuid in visible]


def load_alert_summaries(uuids: list[str]) -> dict[str, AlertSummaryOut]:
    if not uuids:
        return {}

    db = get_db()
    tags: dict[str, list[str]] = {}
    for alert_uuid, name in db.query(Alert.uuid, Tag.name).join(TagMapping, TagMapping.alert_id == Alert.id).join(Tag, Tag.id == TagMapping.tag_id).filter(Alert.uuid.in_(uuids)):
        tags.setdefault(alert_uuid, []).append(name)

    summaries = {}
    for alert in db.query(Alert).options(selectinload(Alert.owner)).filter(Alert.uuid.in_(uuids)):
        summaries[alert.uuid] = AlertSummaryOut(
            uuid=alert.uuid,
            description=alert.description or "",
            alert_type=alert.alert_type,
            tool=alert.tool,
            tool_instance=alert.tool_instance,
            queue=alert.queue,
            disposition=alert.disposition,
            disposition_time=alert.disposition_time,
            insert_date=alert.insert_date,
            owner=alert.owner.gui_display if alert.owner is not None else None,
            location=alert.location,
            tags=sorted(tags.get(alert.uuid, [])),
        )

    return summaries


def to_response(response: SearchResponse) -> AlertSearchResponse:
    summaries = load_alert_summaries(response.alert_uuids)
    results = []
    for result in response.results:
        summary = summaries.get(result.alert_uuid)
        if summary is None:
            continue

        results.append(AlertSearchResultOut(
            alert=summary,
            rank=result.rank,
            tier=result.tier,
            score=result.fused_score,
            lanes=sorted(result.lanes),
            hits=[SearchHitOut(lane=hit.lane, kind=hit.kind, title=hit.title, text=hit.text, score=hit.score) for hit in result.hits],
        ))

    return AlertSearchResponse(
        query=response.query,
        total=response.total,
        offset=response.offset,
        limit=response.limit,
        results=results,
        lanes_used=sorted(response.lanes_used),
        timings_ms=response.timings_ms,
    )


def search_alerts_sync(body: AlertSearchRequest) -> AlertSearchResponse:
    request = SearchRequest(
        query=body.query,
        filters=to_search_filters(body.filters),
        limit=body.limit,
        offset=body.offset,
        include_hits=body.include_hits,
        lanes=frozenset(body.lanes),
    )
    return to_response(search_alerts(request, post_filter=node_scope_post_filter))


def similar_alerts_sync(body: SimilarAlertsRequest) -> AlertSearchResponse:
    if not is_uuid(body.alert_uuid):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid alert uuid")

    if not node_scope_post_filter([body.alert_uuid]):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")

    response = similar_alerts(
        body.alert_uuid,
        to_search_filters(body.filters),
        limit=body.limit,
        offset=body.offset,
        include_hits=body.include_hits,
        post_filter=node_scope_post_filter,
    )
    return to_response(response)
