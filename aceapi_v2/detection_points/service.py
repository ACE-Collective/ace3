"""Detection point service for ACE API v2: an alert's detections and their verdicts.

Synchronous; the router runs each function through run_db_in_thread.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, exists, or_, select

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import InvalidListingRequest, decode_cursor, encode_cursor, rows_to_csv
from aceapi_v2.detection_points.schemas import (
    DETECTION_POINT_ROW_CSV_FIELDS,
    ConfirmResult,
    DetectionPointRow,
)
from saq.database.model import Alert, DetectionPoint, DetectionPointVerdictHistory
from saq.database.pool import get_db
from saq.database.util.alert import node_scope_locations
from saq.detection_verdicts.filters import detection_point_filter_conditions
from saq.detection_verdicts.query import (
    detection_points_select,
    get_alert_detection_point,
    list_alert_detection_points,
)
from saq.detection_verdicts.store import (
    DetectionNotFound,
    VerdictNotAllowed,
    clear_verdict,
    confirm_alert,
    set_verdict,
)
from saq.gui.filter_screens import DETECTION_POINTS_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.util.uuid import is_uuid


def _resolve_alert_id(alert_uuid: str) -> int:
    if not is_uuid(alert_uuid):
        raise HTTPException(status_code=400, detail="invalid alert UUID")

    alert_id = get_db().query(Alert.id).filter(Alert.uuid == alert_uuid).scalar()
    if alert_id is None:
        raise HTTPException(status_code=404, detail="alert not found")

    return alert_id


def _parse_details(details: str | None) -> Any:
    if details is None:
        return None
    try:
        return json.loads(details)
    except ValueError:
        return details


def _to_row(record: dict[str, Any]) -> DetectionPointRow:
    return DetectionPointRow(**{**record, "details": _parse_details(record["details"])})


def list_detection_points(alert_uuid: str) -> list[DetectionPointRow]:
    return [_to_row(record) for record in list_alert_detection_points(_resolve_alert_id(alert_uuid))]


def _detection_point(alert_id: int, content_hash: str) -> DetectionPointRow:
    record = get_alert_detection_point(alert_id, content_hash)
    if record is None:
        raise HTTPException(status_code=404, detail="detection not found")

    return _to_row(record)


def _require_user(user_id: int | None) -> int:
    # a verdict records who set it; a config API key belongs to nobody
    if user_id is None:
        raise HTTPException(status_code=422, detail="setting a verdict requires a user's API key or session")

    return user_id


def set_detection_verdict(alert_uuid: str, content_hash: str, verdict: str, auth: ApiAuthResult) -> DetectionPointRow:
    user_id = _require_user(auth.auth_user_id)
    alert_id = _resolve_alert_id(alert_uuid)
    try:
        set_verdict(alert_id, content_hash, verdict, user_id, auth=auth)
    except DetectionNotFound:
        raise HTTPException(status_code=404, detail="detection not found")
    except VerdictNotAllowed as e:
        raise HTTPException(status_code=409, detail=str(e))

    return _detection_point(alert_id, content_hash)


def clear_detection_verdict(alert_uuid: str, content_hash: str, auth: ApiAuthResult) -> DetectionPointRow:
    user_id = _require_user(auth.auth_user_id)
    alert_id = _resolve_alert_id(alert_uuid)
    try:
        clear_verdict(alert_id, content_hash, user_id, auth=auth)
    except DetectionNotFound:
        raise HTTPException(status_code=404, detail="detection not found")
    except VerdictNotAllowed as e:
        raise HTTPException(status_code=409, detail=str(e))

    return _detection_point(alert_id, content_hash)


def confirm_detection_verdicts(alert_uuid: str, auth: ApiAuthResult) -> ConfirmResult:
    user_id = _require_user(auth.auth_user_id)
    alert_id = _resolve_alert_id(alert_uuid)
    try:
        return ConfirmResult(confirmed=confirm_alert(alert_id, user_id, auth=auth))
    except VerdictNotAllowed as e:
        raise HTTPException(status_code=409, detail=str(e))


#
# GET /api/v2/detection-points: every detection, for export and reporting (docs/SVS_API.md)
#
# Paged by keyset on detection_points.id, never by offset, so a report builder pulling every row
# does not skip or repeat one while new detections arrive. The statement is built once per request
# (relative dates resolve then) and each page runs in its own thread.
#

@dataclass(frozen=True)
class DetectionPointListing:
    """A prepared listing: the filtered, scoped statement, with no order or limit."""

    statement: Select


def _to_utc_naive(value: datetime) -> datetime:
    # TIMESTAMP columns are compared in the session time zone, which ACE runs as UTC
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _changed_since(value: datetime):
    """A detection whose data may have changed since `value`: its alert's row changed (a
    disposition, which re-derives every verdict), the row was (re)inserted, or its stored verdict
    was set or cleared. A cleared verdict leaves no row of its own, which is why the history is
    the signal."""
    value = _to_utc_naive(value)
    return or_(
        Alert.updated_at >= value,
        DetectionPoint.insert_date >= value,
        exists(select(DetectionPointVerdictHistory.id)
               .where(DetectionPointVerdictHistory.alert_id == DetectionPoint.alert_id)
               .where(DetectionPointVerdictHistory.content_hash == DetectionPoint.content_hash)
               .where(DetectionPointVerdictHistory.changed_at >= value)))


def prepare_detection_point_listing(
    filter_params: list[str], *, changed_since: datetime | None, tz
) -> DetectionPointListing:
    """Builds the listing statement from share-link filters (`f=`) of the detection points
    screen, scoped to the alerts this node shows, as the alert listing is. Raises
    InvalidListingRequest."""
    try:
        entries, _ = decode_filter_query(filter_params, screen=DETECTION_POINTS_SCREEN, strict=True)
    except FilterQueryError as e:
        raise InvalidListingRequest(str(e))

    try:
        entries = [entry.model_dump() for entry in DETECTION_POINTS_SCREEN.validate_entries(entries)]
    except ValidationError as e:
        raise InvalidListingRequest(e.errors(include_url=False, include_context=False))

    statement = detection_points_select()
    for condition in detection_point_filter_conditions(entries, tz):
        statement = statement.where(condition)

    locations = node_scope_locations()
    if locations is not None:
        statement = statement.where(Alert.location.in_(locations))

    if changed_since is not None:
        statement = statement.where(_changed_since(changed_since))

    return DetectionPointListing(statement=statement)


def encode_listing_cursor(detection_point_id: int) -> str:
    return encode_cursor(k=detection_point_id)


def decode_listing_cursor(cursor: str) -> int:
    """The detection_points.id a cursor carries. Raises InvalidCursor."""
    return decode_cursor(cursor, lambda payload: int(payload["k"]))


def fetch_detection_point_page(
    listing: DetectionPointListing, cursor: str | None, limit: int
) -> tuple[list[DetectionPointRow], str | None]:
    """One page of the listing after `cursor` (the first page when None), and the cursor of the
    next page (None on the last). Raises InvalidCursor."""
    statement = listing.statement
    if cursor is not None:
        statement = statement.where(DetectionPoint.id > decode_listing_cursor(cursor))

    records = [dict(row) for row in get_db().execute(
        statement.order_by(DetectionPoint.id).limit(limit + 1)).mappings()]
    next_cursor = None
    if len(records) > limit:
        records = records[:limit]
        next_cursor = encode_listing_cursor(records[-1]["id"])

    return [_to_row(record) for record in records], next_cursor


def detection_point_rows_to_csv(rows: list[DetectionPointRow], *, header: bool) -> str:
    """CSV text for rows of the export, with the header line when asked."""
    def flatten(values: dict) -> None:
        if values["details"] is not None:
            values["details"] = json.dumps(values["details"], sort_keys=True)

    return rows_to_csv(rows, DETECTION_POINT_ROW_CSV_FIELDS, header=header, flatten=flatten)
