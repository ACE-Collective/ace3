"""Writing and clearing analyst verdicts on detections (docs/SVS.md, Part 1).

An analyst can only refine a TP alert: mark a detection that was noise as FP, or confirm an
inherited TP. On an FP alert every detection is FP, and an alert dispositioned wrongly is fixed by
correcting its disposition, not by overriding its detections (DP-3). Each change is recorded in
detection_point_verdict_history in the same transaction (RPT-4).
"""

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Optional

from sqlalchemy import select

from saq.database.model import Alert, DetectionPoint, DetectionPointVerdict, DetectionPointVerdictHistory
from saq.database.pool import get_db
from saq.detection_verdicts.constants import SOURCE_INHERITED_MULTI, VERDICT_TP, VERDICTS
from saq.detection_verdicts.effective import verdict_join_condition, verdict_source_expr
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


class SkipCause(StrEnum):
    ALERT = "alert"            # the alert's disposition does not take analyst verdicts
    DETECTION = "detection"    # the detection predates detection identity
    GONE = "gone"              # the detection left its alert's tree
    SOURCE = "source"          # its verdict source is not the one asked for (only_source)


@dataclass(frozen=True)
class SkippedDetection:
    alert_id: int
    content_hash: str
    cause: SkipCause
    reason: str


@dataclass
class VerdictBatch:
    """What set_verdicts() did: how many detections changed, how many already had the verdict,
    and the ones it could not write, each with why."""
    changed: int = 0
    unchanged: int = 0
    skipped: list[SkippedDetection] = field(default_factory=list)


_GONE = "the detection is gone from its alert"


def _source_of(session, detection: DetectionPoint) -> Optional[str]:
    return session.execute(
        select(verdict_source_expr(Alert, DetectionPoint, DetectionPointVerdict))
        .select_from(DetectionPoint)
        .join(Alert, Alert.id == DetectionPoint.alert_id)
        .outerjoin(DetectionPointVerdict, verdict_join_condition(DetectionPoint, DetectionPointVerdict))
        .where(DetectionPoint.id == detection.id)).scalar_one()


def set_verdicts(targets: list[tuple[int, str]], verdict: Optional[str], user_id: int, *, analyst: bool = True,
                 only_source: Optional[str] = None, refuse: frozenset[SkipCause] = frozenset()) -> VerdictBatch:
    """Stores verdict ('tp' or 'fp'; None clears) on every (alert_id, content_hash) detection of
    targets, in one transaction: any error rolls back the whole batch. A detection that cannot take
    the verdict (its alert is not a tp alert analysts can grade, it predates detection identity,
    or it is gone) is skipped with the reason, not an error. With only_source, a detection whose
    verdict source is not that one once it is locked is skipped too, so a Confirm (only_source
    inherited_multi) never overwrites a verdict someone set in the meantime. A skip whose cause is
    in refuse raises VerdictNotAllowed instead, and nothing is written."""
    if verdict is not None and verdict not in VERDICTS:
        raise ValueError(f"invalid verdict {verdict!r}")

    batch = VerdictBatch()
    if not targets:
        return batch

    session = get_db()
    try:
        # the detections are locked in (alert id, detection id) order, the order confirm_alert has
        # always locked one alert's in, so two batches never wait on each other in a cycle
        wanted = set(targets)
        rows = session.execute(
            select(DetectionPoint.alert_id, DetectionPoint.content_hash, DetectionPoint.id)
            .where(DetectionPoint.alert_id.in_({alert_id for alert_id, _ in wanted}))
            .order_by(DetectionPoint.alert_id, DetectionPoint.id)).all()
        ordered = [(row.alert_id, row.content_hash) for row in rows if (row.alert_id, row.content_hash) in wanted]
        for alert_id, content_hash in sorted(wanted - set(ordered)):
            batch.skipped.append(SkippedDetection(alert_id, content_hash, SkipCause.GONE, _GONE))

        alert_refusals: dict[int, Optional[str]] = {}
        for alert_id, content_hash in ordered:
            try:
                detection = _lock_detection(session, alert_id, content_hash)
            except DetectionNotFound:
                batch.skipped.append(SkippedDetection(alert_id, content_hash, SkipCause.GONE, _GONE))
                continue

            if alert_id not in alert_refusals:
                try:
                    _check_alert(_alert_disposition(session, alert_id), analyst)
                    alert_refusals[alert_id] = None
                except VerdictNotAllowed as e:
                    alert_refusals[alert_id] = str(e)

            skip: Optional[tuple[SkipCause, str]] = None
            if alert_refusals[alert_id] is not None:
                skip = (SkipCause.ALERT, alert_refusals[alert_id])
            else:
                try:
                    _check_detection(detection)
                except VerdictNotAllowed as e:
                    skip = (SkipCause.DETECTION, str(e))

            if skip is None and only_source is not None:
                source = _source_of(session, detection)
                if source != only_source:
                    skip = (SkipCause.SOURCE, f"its verdict source is {source}, not {only_source}")

            if skip is not None and skip[0] in refuse:
                raise VerdictNotAllowed(skip[1])
            if skip is not None:
                batch.skipped.append(SkippedDetection(alert_id, content_hash, *skip))
            elif _write(session, detection, verdict, user_id):
                batch.changed += 1
            else:
                batch.unchanged += 1

        session.commit()
        return batch
    except Exception:
        session.rollback()
        raise


def confirm_alert(alert_id: int, user_id: int, *, analyst: bool = True) -> int:
    """Confirms every unconfirmed (inherited_multi) TP on the alert: stores an explicit TP on each,
    which does not change the verdict but upgrades its source. Returns how many were confirmed."""
    session = get_db()
    try:
        _check_alert(_alert_disposition(session, alert_id), analyst)

        hashes = session.execute(
            select(DetectionPoint.content_hash)
            .select_from(DetectionPoint)
            .join(Alert, Alert.id == DetectionPoint.alert_id)
            .outerjoin(DetectionPointVerdict, verdict_join_condition(DetectionPoint, DetectionPointVerdict))
            .where(DetectionPoint.alert_id == alert_id)
            .where(verdict_source_expr(Alert, DetectionPoint, DetectionPointVerdict) == SOURCE_INHERITED_MULTI)
            ).scalars().all()
        if not hashes:
            session.commit()
            return 0
    except Exception:
        session.rollback()
        raise

    # a detection that is gone, or no longer unconfirmed (someone set it meanwhile), has nothing
    # to confirm; anything else refuses the whole confirm, as it always has
    batch = set_verdicts([(alert_id, content_hash) for content_hash in hashes], VERDICT_TP, user_id,
                         analyst=analyst, only_source=SOURCE_INHERITED_MULTI,
                         refuse=frozenset({SkipCause.ALERT, SkipCause.DETECTION}))
    return batch.changed
