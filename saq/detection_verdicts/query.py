"""Selecting detections together with their effective verdict (saq.detection_verdicts.effective)."""

from typing import Any

from sqlalchemy import Select, select

from saq.database.model import Alert, DetectionPoint, DetectionPointVerdict, User
from saq.database.pool import get_db
from saq.detection_verdicts.effective import (
    effective_verdict_expr,
    verdict_join_condition,
    verdict_source_expr,
)


def detection_points_select() -> Select:
    """Every detection with its alert's uuid, its node, its effective verdict and source, and the
    stored override behind them (if any), one row per detection_points row. Callers add their own
    WHERE and ORDER BY; the joins are on the plain model classes, so filters can name them."""
    return (
        select(
            DetectionPoint.id,
            DetectionPoint.alert_id,
            Alert.uuid.label("alert_uuid"),
            DetectionPoint.content_hash,
            DetectionPoint.description,
            DetectionPoint.details,
            DetectionPoint.queue,
            DetectionPoint.signature_uuid,
            DetectionPoint.signature_version,
            DetectionPoint.signature_family,
            DetectionPoint.node_kind,
            DetectionPoint.node_type,
            DetectionPoint.node_value_sha256,
            DetectionPoint.node_module_path,
            DetectionPoint.insert_date,
            effective_verdict_expr(Alert, DetectionPoint, DetectionPointVerdict).label("verdict"),
            verdict_source_expr(Alert, DetectionPoint, DetectionPointVerdict).label("verdict_source"),
            DetectionPointVerdict.verdict.label("override"),
            User.username.label("override_user"),
            DetectionPointVerdict.set_at.label("override_set_at"),
        )
        .select_from(DetectionPoint)
        .join(Alert, Alert.id == DetectionPoint.alert_id)
        .outerjoin(DetectionPointVerdict, verdict_join_condition(DetectionPoint, DetectionPointVerdict))
        .outerjoin(User, User.id == DetectionPointVerdict.user_id))


def list_alert_detection_points(alert_id: int) -> list[dict[str, Any]]:
    """The detections of one alert, in the order they were first synced."""
    statement = (detection_points_select()
                 .where(DetectionPoint.alert_id == alert_id)
                 .order_by(DetectionPoint.id))
    return [dict(row) for row in get_db().execute(statement).mappings()]


def get_alert_detection_point(alert_id: int, content_hash: str) -> dict[str, Any] | None:
    """One detection of an alert, or None."""
    statement = (detection_points_select()
                 .where(DetectionPoint.alert_id == alert_id)
                 .where(DetectionPoint.content_hash == content_hash))
    row = get_db().execute(statement).mappings().one_or_none()
    return dict(row) if row is not None else None
