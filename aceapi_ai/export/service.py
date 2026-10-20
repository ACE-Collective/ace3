"""Bulk export of alerts and observables for the AI API: what an offline analysis of ACE's alert
history needs, read straight from the database.

An alert's observables come from `observable_mapping`, not from its storage directory, so an
archived alert (every FALSE_POSITIVE older than fp_days) exports in full: archiving prunes the
analysis details and files but keeps the observables and their mapping rows.

The alert pages are the GET /api/v2/alerts keyset listing (aceapi_v2/alerts/service.py), unfiltered:
by id, or by (updated_at, id) after changed_since, at-least-once. An alert's index rows
(observable_mapping, detection_points) are written in their own transaction just after the
alert row commits, and that write does not bump updated_at, so a page read in between carries
the alert with the mappings it had before. A client that resumes with changed_since a few
minutes before the newest updated_at it saw picks those up on its next pull.
"""

import logging
from datetime import datetime

import pytz
from fastapi import HTTPException, Request
from sqlalchemy import select

from aceapi_ai.audit import audit_event
from aceapi_ai.export.schemas import (
    AlertExportPage,
    ExportAlert,
    ExportDetection,
    ExportObservable,
    ObservableExportPage,
    ObservableExportRequest,
)
from aceapi_ai.limited import run_limited
from aceapi_v2.alerts import service as alerts_service
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import InvalidCursor
from saq.configuration.config import get_config
from saq.database.model import Alert, DetectionPoint, EventMapping, Observable, ObservableMapping
from saq.database.pool import get_db
from saq.disposition import get_disposition_class

logger = logging.getLogger(__name__)

# the limiter keys its counters by backend name; export is its own bucket
EXPORT_LIMIT_NAME = "export"


def load_export_alerts(alert_ids: list[int]) -> list[ExportAlert]:
    """The export rows for these alert ids, in the order given; an alert deleted meanwhile is absent."""
    if not alert_ids:
        return []

    db = get_db()
    rows = {row.uuid: row for row in alerts_service.load_alert_rows(alert_ids)}

    reviews = {
        alert_id: (alert_uuid, review, incorrect)
        for alert_id, alert_uuid, review, incorrect in db.execute(
            select(Alert.id, Alert.uuid, Alert.disposition_review, Alert.incorrect_disposition)
            .where(Alert.id.in_(alert_ids)))
    }

    observable_ids: dict[int, list[int]] = {}
    for alert_id, observable_id in db.execute(
        select(ObservableMapping.alert_id, ObservableMapping.observable_id)
        .where(ObservableMapping.alert_id.in_(alert_ids))
        .order_by(ObservableMapping.alert_id, ObservableMapping.observable_id)
    ):
        observable_ids.setdefault(alert_id, []).append(observable_id)

    detections: dict[int, list[ExportDetection]] = {}
    for alert_id, signature_uuid, signature_version, signature_family, node_kind, node_type, node_value_sha256 in db.execute(
        select(DetectionPoint.alert_id, DetectionPoint.signature_uuid, DetectionPoint.signature_version,
               DetectionPoint.signature_family, DetectionPoint.node_kind, DetectionPoint.node_type,
               DetectionPoint.node_value_sha256)
        .where(DetectionPoint.alert_id.in_(alert_ids))
        .order_by(DetectionPoint.alert_id, DetectionPoint.id)
    ):
        detections.setdefault(alert_id, []).append(ExportDetection(
            signature_uuid=signature_uuid,
            signature_version=signature_version,
            signature_family=signature_family,
            node_kind=node_kind,
            node_type=node_type,
            node_value_sha256=node_value_sha256,
        ))

    event_ids: dict[int, list[int]] = {}
    for alert_id, event_id in db.execute(
        select(EventMapping.alert_id, EventMapping.event_id)
        .where(EventMapping.alert_id.in_(alert_ids))
        .order_by(EventMapping.alert_id, EventMapping.event_id)
    ):
        event_ids.setdefault(alert_id, []).append(event_id)

    result = []
    for alert_id in alert_ids:
        if alert_id not in reviews:
            continue

        alert_uuid, review, incorrect = reviews[alert_id]
        row = rows.get(alert_uuid)
        if row is None:
            continue

        result.append(ExportAlert(
            **row.model_dump(),
            disposition_class=get_disposition_class(row.disposition),
            disposition_review=review,
            incorrect_disposition=incorrect,
            observable_ids=observable_ids.get(alert_id, []),
            detections=detections.get(alert_id, []),
            event_ids=event_ids.get(alert_id, []),
        ))

    return result


def export_alert_page(changed_since: datetime | None, cursor: str | None, limit: int) -> tuple[list[ExportAlert], str | None]:
    """One page of every alert this node shows. Raises InvalidCursor."""
    listing = alerts_service.prepare_alert_listing(
        [], changed_since=changed_since, tz=pytz.utc, viewer_user_id=None)
    alert_ids, next_cursor = alerts_service.fetch_alert_page_ids(listing, cursor, limit)
    return load_export_alerts(alert_ids), next_cursor


def load_export_observables(ids: list[int]) -> list[ExportObservable]:
    """The observables with these ids, in id order; an unknown id is absent."""
    return [
        ExportObservable(id=observable_id, type=observable_type, sha256=sha256.hex(),
                         value=value.decode("utf8", errors="ignore"))
        for observable_id, observable_type, sha256, value in get_db().execute(
            select(Observable.id, Observable.type, Observable.sha256, Observable.value)
            .where(Observable.id.in_(set(ids)))
            .order_by(Observable.id))
    ]


async def export_alerts(
    changed_since: datetime | None, cursor: str | None, limit: int, auth: ApiAuthResult, request: Request
) -> AlertExportPage:
    # the page itself is not recorded: (changed_since, cursor, limit) reproduces it
    fields = dict(changed_since=changed_since, cursor=cursor, limit=limit)
    limits = get_config().ai_api.export_limits
    try:
        rows, next_cursor = await run_limited(
            EXPORT_LIMIT_NAME, limits, "export", "export_alerts", auth, request,
            lambda: export_alert_page(changed_since, cursor, limit), **fields)
    except InvalidCursor as e:
        audit_event("export_alerts_error", auth, request, **fields, status=400, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))

    audit_event("export_alerts", auth, request, **fields, result_count=len(rows),
                next_cursor=next_cursor, status=200)
    return AlertExportPage(data=rows, next_cursor=next_cursor)


async def export_observables(body: ObservableExportRequest, auth: ApiAuthResult, request: Request) -> ObservableExportPage:
    # the ids are not recorded: an audit line per 5000 ids would dwarf the rest of the trail
    fields = dict(id_count=len(body.ids), first_id=min(body.ids), last_id=max(body.ids))
    limits = get_config().ai_api.export_limits
    rows = await run_limited(
        EXPORT_LIMIT_NAME, limits, "export", "export_observables", auth, request,
        lambda: load_export_observables(body.ids), **fields)

    audit_event("export_observables", auth, request, **fields, result_count=len(rows), status=200)
    return ObservableExportPage(data=rows)
