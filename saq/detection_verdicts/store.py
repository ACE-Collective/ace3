"""Writing and clearing analyst verdicts on detections (docs/SVS.md, Part 1).

An analyst can only refine a TP alert: mark a detection that was noise as FP, or confirm an
inherited TP. On an FP alert every detection is FP, and an alert dispositioned wrongly is fixed by
correcting its disposition, not by overriding its detections (DP-3). Each change is recorded in
detection_point_verdict_history in the same transaction (RPT-4).
"""

import logging
from typing import Optional

from sqlalchemy import select

from saq.database.model import Alert, DetectionPoint, DetectionPointVerdict, DetectionPointVerdictHistory
from saq.database.pool import get_db
from saq.detection_verdicts.effective import (
    SOURCE_INHERITED_MULTI,
    VERDICT_TP,
    VERDICTS,
    verdict_join_condition,
    verdict_source_expr,
)
from saq.disposition import DISPOSITION_CLASS_FP, DISPOSITION_CLASS_TP, get_disposition_class, is_selectable_disposition


class DetectionNotFound(Exception):
    """The alert has no detection with that content hash."""


class VerdictNotAllowed(Exception):
    """A verdict cannot be written on this detection. The message says why."""


def _check_alert(disposition: Optional[str], analyst: bool):
    disposition_class = get_disposition_class(disposition)
    if disposition_class == DISPOSITION_CLASS_FP:
        raise VerdictNotAllowed(
            "every detection on a false positive alert is FP; if the alert was wrong, correct its disposition")

    if disposition_class != DISPOSITION_CLASS_TP:
        raise VerdictNotAllowed(
            f"the alert's disposition {disposition} is unclassified, so its detections have no verdict")

    # a disposition only ACE sets (SIMULATED) belongs to the test run review, not to analysts
    if analyst and not is_selectable_disposition(disposition):
        raise VerdictNotAllowed(
            f"the verdicts of an alert with the disposition {disposition} are set by ACE, not by analysts")


def _check_detection(detection: DetectionPoint):
    # the identity of a row synced before the node was part of it is not the one verdicts are
    # keyed on (saq.analysis.detection_identity); the alert's next sync replaces the row
    if detection.node_kind is None:
        raise VerdictNotAllowed("the detection predates detection identity; re-sync the alert first")


def _lock_detection(session, alert_id: int, content_hash: str) -> DetectionPoint:
    # locking the detection row serializes writers of its verdict, including the first insert,
    # which has no verdict row to lock yet
    detection = session.execute(
        select(DetectionPoint)
        .where(DetectionPoint.alert_id == alert_id)
        .where(DetectionPoint.content_hash == content_hash)
        .with_for_update()).scalar_one_or_none()
    if detection is None:
        raise DetectionNotFound(f"alert {alert_id} has no detection {content_hash}")

    return detection


def _alert_disposition(session, alert_id: int) -> Optional[str]:
    return session.execute(select(Alert.disposition).where(Alert.id == alert_id)).scalar_one()


def _write(session, detection: DetectionPoint, new_verdict: Optional[str], user_id: int) -> bool:
    """Stores new_verdict (None clears it) and records the change. False if nothing changed."""
    current = session.execute(
        select(DetectionPointVerdict)
        .where(DetectionPointVerdict.alert_id == detection.alert_id)
        .where(DetectionPointVerdict.content_hash == detection.content_hash)).scalar_one_or_none()
    old_verdict = current.verdict if current is not None else None
    if old_verdict == new_verdict:
        return False

    if new_verdict is None:
        session.delete(current)
    elif current is None:
        session.add(DetectionPointVerdict(
            alert_id=detection.alert_id,
            content_hash=detection.content_hash,
            signature_uuid=detection.signature_uuid,
            verdict=new_verdict,
            user_id=user_id))
    else:
        current.verdict = new_verdict
        current.user_id = user_id

    session.add(DetectionPointVerdictHistory(
        alert_id=detection.alert_id,
        content_hash=detection.content_hash,
        signature_uuid=detection.signature_uuid,
        old_verdict=old_verdict,
        new_verdict=new_verdict,
        user_id=user_id))

    logging.info("AUDIT: detection verdict changed", extra={
        "alert_id": detection.alert_id, "content_hash": detection.content_hash,
        "signature_uuid": detection.signature_uuid, "old_verdict": old_verdict,
        "new_verdict": new_verdict, "actor_user_id": user_id})
    return True


def _change(alert_id: int, content_hash: str, new_verdict: Optional[str], user_id: int, analyst: bool) -> bool:
    session = get_db()
    try:
        detection = _lock_detection(session, alert_id, content_hash)
        _check_alert(_alert_disposition(session, alert_id), analyst)
        _check_detection(detection)
        changed = _write(session, detection, new_verdict, user_id)
        session.commit()
        return changed
    except Exception:
        session.rollback()
        raise


def set_verdict(alert_id: int, content_hash: str, verdict: str, user_id: int, *, analyst: bool = True) -> bool:
    """Stores an explicit verdict ('tp' or 'fp') on one detection. Returns False if it was already
    stored. analyst=False is for ACE itself (the test run review), which may write verdicts on
    alerts whose disposition analysts cannot set."""
    if verdict not in VERDICTS:
        raise ValueError(f"invalid verdict {verdict!r}")

    return _change(alert_id, content_hash, verdict, user_id, analyst)


def clear_verdict(alert_id: int, content_hash: str, user_id: int, *, analyst: bool = True) -> bool:
    """Removes the explicit verdict on one detection, so it inherits from the alert again. Returns
    False if there was none."""
    return _change(alert_id, content_hash, None, user_id, analyst)


def confirm_alert(alert_id: int, user_id: int, *, analyst: bool = True) -> int:
    """Confirms every unconfirmed (inherited_multi) TP on the alert: stores an explicit TP on each,
    which does not change the verdict but upgrades its source. Returns how many were confirmed."""
    session = get_db()
    try:
        disposition = _alert_disposition(session, alert_id)
        _check_alert(disposition, analyst)

        hashes = session.execute(
            select(DetectionPoint.content_hash)
            .select_from(DetectionPoint)
            .join(Alert, Alert.id == DetectionPoint.alert_id)
            .outerjoin(DetectionPointVerdict, verdict_join_condition(DetectionPoint, DetectionPointVerdict))
            .where(DetectionPoint.alert_id == alert_id)
            .where(verdict_source_expr(Alert, DetectionPoint, DetectionPointVerdict) == SOURCE_INHERITED_MULTI)
            .order_by(DetectionPoint.id)).scalars().all()

        confirmed = 0
        for content_hash in hashes:
            detection = _lock_detection(session, alert_id, content_hash)
            _check_detection(detection)
            if _write(session, detection, VERDICT_TP, user_id):
                confirmed += 1

        session.commit()
        return confirmed
    except Exception:
        session.rollback()
        raise
