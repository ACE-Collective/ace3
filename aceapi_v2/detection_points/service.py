"""Detection point service for ACE API v2: an alert's detections and their verdicts.

Synchronous; the router runs each function through run_db_in_thread.
"""

import json
from typing import Any

from fastapi import HTTPException

from aceapi_v2.detection_points.schemas import ConfirmResult, DetectionPointRow
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.detection_verdicts.query import get_alert_detection_point, list_alert_detection_points
from saq.detection_verdicts.store import (
    DetectionNotFound,
    VerdictNotAllowed,
    clear_verdict,
    confirm_alert,
    set_verdict,
)
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


def set_detection_verdict(alert_uuid: str, content_hash: str, verdict: str, user_id: int | None) -> DetectionPointRow:
    user_id = _require_user(user_id)
    alert_id = _resolve_alert_id(alert_uuid)
    try:
        set_verdict(alert_id, content_hash, verdict, user_id)
    except DetectionNotFound:
        raise HTTPException(status_code=404, detail="detection not found")
    except VerdictNotAllowed as e:
        raise HTTPException(status_code=409, detail=str(e))

    return _detection_point(alert_id, content_hash)


def clear_detection_verdict(alert_uuid: str, content_hash: str, user_id: int | None) -> DetectionPointRow:
    user_id = _require_user(user_id)
    alert_id = _resolve_alert_id(alert_uuid)
    try:
        clear_verdict(alert_id, content_hash, user_id)
    except DetectionNotFound:
        raise HTTPException(status_code=404, detail="detection not found")
    except VerdictNotAllowed as e:
        raise HTTPException(status_code=409, detail=str(e))

    return _detection_point(alert_id, content_hash)


def confirm_detection_verdicts(alert_uuid: str, user_id: int | None) -> ConfirmResult:
    user_id = _require_user(user_id)
    alert_id = _resolve_alert_id(alert_uuid)
    try:
        return ConfirmResult(confirmed=confirm_alert(alert_id, user_id))
    except VerdictNotAllowed as e:
        raise HTTPException(status_code=409, detail=str(e))
