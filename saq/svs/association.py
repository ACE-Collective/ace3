"""A person's changes to which alerts belong to a test run (docs/SVS_RUNS.md, *Associating alerts by
hand*; docs/SVS.md, Part 3, *Manual (re)association*).

- **Associate** an alert with a run: every detection of the alert is attributed to the run, as
  certain as a marker that agrees (its status is TEST), and the alert moves to the test queue.
- **Disassociate** it: its attributions to the run are removed by the person, and the router never
  attributes the alert to that run again. An alert no longer fully attributed goes back to the queue
  it came from, and one already SIMULATED is given back to analysts as OPEN.
- **Not a test** is a disassociation of a TEST? alert, whose attributions are by context only.
- From the alert's side, an analyst disassociates the alert from every run that holds it, or marks
  a TEST? alert not a test (disassociate_alert, alert:write in the API).
- **Keep** a context attribution: the person confirms a TEST? alert is the run's (run review asks
  for it).

Every change is reversible (associating again revives the rows), appends to the run's event log,
marks the run's result stale and a reviewed run changed since review, and is logged as an AUDIT
record. A queue move a person makes here is recorded with the router name svs_manual, and the marker
router never overrides it (saq/svs/routing.py). Like the engine, a move is made only while the alert
is OPEN and nobody else has taken it.

Each operation locks the alert row first, then writes the attribution rows, the events and the run
flags in the order the router writes them, in one transaction; the moves and the reopen come after
its commit.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_OPEN, DISPOSITION_SIMULATED
from saq.database.model import Alert, AlertQueueChange, DetectionPoint, SVSAttribution, SVSRun
from saq.database.pool import get_db
from saq.database.util.alert import move_alert_to_queue, set_dispositions
from saq.svs.alert_status import alert_svs_statuses
from saq.svs.attribution import alert_event_time, flag_changed_since_review
from saq.svs.constants import (
    SVS_MANUAL_ROUTER,
    AttributionConfidence,
    AttributionSource,
    RunEventKind,
    RunState,
    SVSStatus,
)
from saq.svs.result_state import mark_runs_stale
from saq.svs.run_events import new_run_event, run_log_fields
from saq.svs.runs import get_run

# the name of the marker router's alert_routers entry (etc/saq.default.yaml): a move into the test
# queue it made, or one a person made here, is what disassociating undoes
MARKER_ROUTER_NAME = "svs_marker"

REASON_ASSOCIATED = "associated with SVS test run {run} by hand"
REASON_DISASSOCIATED = "disassociated from SVS test run {run}"
REASON_NOT_A_TEST = "not a test"


class UnknownAlert(LookupError):
    pass


class AssociationConflict(Exception):
    """The change doesn't apply to the alert or the run as they are; the message says why."""


class InvalidAssociation(ValueError):
    """The alert can't be associated; the message says why."""


@dataclass(frozen=True)
class AssociationResult:
    alert_uuid: str
    # the alert's SVS status after the change (saq.svs.alert_status), None when it has none
    svs_status: Optional[str]
    queue: str
    # the alert moved to another queue
    moved: bool = False
    # the alert was SIMULATED and is OPEN again
    reopened: bool = False


@dataclass(frozen=True)
class AlertDisassociationResult:
    alert_uuid: str
    # the runs the alert was disassociated from, oldest first
    runs: tuple[str, ...]
    svs_status: Optional[str]
    queue: str
    moved: bool = False
    reopened: bool = False


@dataclass(frozen=True)
class _Alert:
    id: int
    uuid: str
    queue: str
    disposition: str
    owner_id: Optional[int]
    insert_date: datetime
    storage_dir: str


def _lock_alert(alert_uuid: str) -> _Alert:
    row = get_db().execute(
        select(Alert.id, Alert.uuid, Alert.queue, Alert.disposition, Alert.owner_id, Alert.insert_date,
               Alert.storage_dir)
        .where(Alert.uuid == alert_uuid)
        .with_for_update()).first()
    if row is None:
        raise UnknownAlert(f"alert {alert_uuid} not found")
    return _Alert(*row)


def _read_alert(alert_id: int) -> _Alert:
    db = get_db()
    db.expire_all()
    return _Alert(*db.execute(
        select(Alert.id, Alert.uuid, Alert.queue, Alert.disposition, Alert.owner_id, Alert.insert_date,
               Alert.storage_dir)
        .where(Alert.id == alert_id)).one())


def _status(alert: _Alert) -> Optional[SVSStatus]:
    status = alert_svs_statuses({alert.id: alert.uuid}).get(alert.id)
    return status.status if status is not None else None


def _movable(alert: _Alert, user_id: int) -> bool:
    """The engine's rule for moving an existing alert: OPEN, and nobody else has taken it."""
    return alert.disposition == DISPOSITION_OPEN and alert.owner_id in (
        None, get_config().global_settings.automation_user_id, user_id)


def _move(alert: _Alert, queue: str, reason: str, user_id: int) -> bool:
    """Moves the alert while _movable still holds for it when the row is written: an analyst may
    have taken it since it was read."""
    db = get_db()
    row = db.get(Alert, alert.id)
    return move_alert_to_queue(row, queue, reason, actor_user_id=user_id, router=SVS_MANUAL_ROUTER,
                               open_unless_owned_by_others={get_config().global_settings.automation_user_id, user_id})


def _changed(run: SVSRun, session) -> None:
    """What every change to the run's attributions does to the run, in the router's lock order."""
    flag_changed_since_review(session, {run.id})
    mark_runs_stale(session, run_ids=[run.id])


def _audit(message: str, run: SVSRun, alert_uuid: str, actor: str, user_id: int, **fields) -> None:
    logging.info(f"AUDIT: {message}", extra={**run_log_fields(run), "alert_uuid": alert_uuid, "actor": actor,
                                             "actor_user_id": user_id, **fields})


def _late(alert: _Alert, run: SVSRun) -> bool:
    """The alert's event came after the run's observation window, judged as the router judges it."""
    if run.observation_ends_at is None:
        return False
    try:
        event_time = alert_event_time(load_root(alert.storage_dir), alert.insert_date)
    except Exception as e:
        logging.warning("unable to load alert %s for its event time; using its insert time: %s", alert.uuid, e)
        event_time = alert.insert_date
    return event_time > run.observation_ends_at


#
# associating
#

def associate(run_uuid: str, alert_uuid: str, user_id: int, actor: str, reason: Optional[str] = None,
              now: Optional[datetime] = None) -> AssociationResult:
    """Attributes every detection of the alert to the run, by hand, and moves the alert to the test
    queue when it is now fully attributed. Raises UnknownRun, UnknownAlert, AssociationConflict (a
    run that never started), InvalidAssociation (an alert without detections)."""
    now = now or datetime.now()
    run = get_run(run_uuid)
    if run.state == RunState.CREATED:
        raise AssociationConflict(f"run {run.uuid} never started, so no alert can be its")

    db = get_db()
    alert = _lock_alert(alert_uuid)
    detections = db.execute(
        select(DetectionPoint.content_hash, DetectionPoint.signature_uuid, DetectionPoint.signature_family)
        .where(DetectionPoint.alert_id == alert.id)
        .order_by(DetectionPoint.id)).all()
    if not detections:
        db.rollback()
        raise InvalidAssociation(f"alert {alert.uuid} has no detections to attribute")

    late = _late(alert, run)
    manual = {"source": AttributionSource.MANUAL.value, "confidence": AttributionConfidence.MARKER.value,
              "scan_point": None, "late": late, "actor": actor[:256], "actor_user_id": user_id,
              "removed_at": None, "removed_by": None, "removed_by_user_id": None, "removal_reason": None}
    for content_hash, signature_uuid, signature_family in detections:
        db.execute(mysql_insert(SVSAttribution)
                   .values(run_id=run.id, alert_uuid=alert.uuid, content_hash=content_hash,
                           signature_uuid=signature_uuid, signature_family=signature_family, created_at=now, **manual)
                   .on_duplicate_key_update(**manual))

    hashes = [content_hash for content_hash, _, _ in detections]
    db.add(new_run_event(run.id, RunEventKind.ASSOCIATED, actor, actor_user_id=user_id, now=now,
                         details={"alert_uuid": alert.uuid, "detections": hashes, "late": late, "reason": reason}))
    _changed(run, db)
    db.commit()
    _audit("svs alert associated with a run", run, alert.uuid, actor, user_id, reason=reason, late=late)

    alert = _read_alert(alert.id)
    status = _status(alert)
    moved = False
    queue = get_config().svs.queue
    if status in (SVSStatus.TEST, SVSStatus.TEST_CONTEXT) and alert.queue != queue and _movable(alert, user_id):
        moved = _move(alert, queue, REASON_ASSOCIATED.format(run=run.uuid), user_id)
        alert = _read_alert(alert.id)
    return AssociationResult(alert.uuid, status.value if status else None, alert.queue, moved=moved)


#
# disassociating
#

def _previous_queue(alert: _Alert) -> Optional[str]:
    """The queue the alert came from when SVS put it in the test queue: the alert's latest move,
    when that move was into the test queue by the marker router or a person through SVS."""
    change = get_db().execute(
        select(AlertQueueChange.router, AlertQueueChange.from_queue, AlertQueueChange.to_queue)
        .where(AlertQueueChange.alert_id == alert.id)
        .order_by(AlertQueueChange.id.desc()).limit(1)).first()
    if change is None:
        return None
    router, from_queue, to_queue = change
    if to_queue != get_config().svs.queue or router not in (MARKER_ROUTER_NAME, SVS_MANUAL_ROUTER):
        return None
    return from_queue


def disassociate(run_uuid: str, alert_uuid: str, user_id: int, actor: str, reason: Optional[str] = None, *,
                 not_a_test: bool = False, now: Optional[datetime] = None) -> AssociationResult:
    """Removes the alert's attributions to the run, by hand: the router never attributes the alert
    to the run again. An alert that is no longer fully attributed is given back: OPEN if it was
    SIMULATED, and back in the queue SVS took it from. not_a_test applies only to an alert the run
    holds by context alone. Raises UnknownRun, UnknownAlert, AssociationConflict."""
    now = now or datetime.now()
    run = get_run(run_uuid)
    db = get_db()
    alert = _lock_alert(alert_uuid)
    rows = db.execute(
        select(SVSAttribution.id, SVSAttribution.content_hash, SVSAttribution.confidence)
        .where(SVSAttribution.run_id == run.id, SVSAttribution.alert_uuid == alert.uuid,
               SVSAttribution.removed_at.is_(None))).all()
    if not rows:
        db.rollback()
        raise AssociationConflict(f"alert {alert.uuid} is not attributed to run {run.uuid}")
    if not_a_test and any(confidence != AttributionConfidence.CONTEXT for _, _, confidence in rows):
        db.rollback()
        raise AssociationConflict(f"alert {alert.uuid} is attributed to run {run.uuid} by more than context: "
                                  "disassociate it instead")

    removal_reason = REASON_NOT_A_TEST if not_a_test else reason
    db.execute(update(SVSAttribution)
               .where(SVSAttribution.id.in_([row_id for row_id, _, _ in rows]))
               .values(removed_at=now, removed_by=actor[:256], removed_by_user_id=user_id,
                       removal_reason=removal_reason)
               .execution_options(synchronize_session=False))
    db.add(new_run_event(run.id, RunEventKind.DISASSOCIATED, actor, actor_user_id=user_id, now=now, details={
        "alert_uuid": alert.uuid, "detections": [content_hash for _, content_hash, _ in rows], "reason": reason,
        "not_a_test": not_a_test}))
    _changed(run, db)
    db.commit()
    _audit("svs alert disassociated from a run", run, alert.uuid, actor, user_id, reason=reason, not_a_test=not_a_test)

    alert = _read_alert(alert.id)
    status = _status(alert)
    if status in (SVSStatus.TEST, SVSStatus.TEST_CONTEXT):
        # still fully attributed, to another run: it stays a test alert
        return AssociationResult(alert.uuid, status.value, alert.queue)

    reopened = False
    if alert.disposition == DISPOSITION_SIMULATED:
        # the automation user set SIMULATED and owns the alert, so it is the writer; the comment
        # names the person
        result = set_dispositions(
            [alert.uuid], DISPOSITION_OPEN, get_config().global_settings.automation_user_id,
            user_comment=f"disassociated from SVS test run {run.uuid} by {actor}", system=True,
            expected_dispositions={DISPOSITION_SIMULATED})
        reopened = alert.uuid in result.permitted
        alert = _read_alert(alert.id)

    moved = False
    previous = _previous_queue(alert)
    if previous is not None and previous != alert.queue and _movable(alert, user_id):
        moved = _move(alert, previous, REASON_DISASSOCIATED.format(run=run.uuid), user_id)
        alert = _read_alert(alert.id)
    return AssociationResult(alert.uuid, status.value if status else None, alert.queue, moved=moved,
                             reopened=reopened)


#
# keeping a context attribution
#

def keep(run_uuid: str, alert_uuid: str, user_id: int, actor: str, now: Optional[datetime] = None) -> AssociationResult:
    """Confirms the alert's context attributions to the run: it is the run's. Raises UnknownRun,
    UnknownAlert, AssociationConflict (no context attribution to keep)."""
    now = now or datetime.now()
    run = get_run(run_uuid)
    db = get_db()
    alert = _lock_alert(alert_uuid)
    kept = db.execute(
        update(SVSAttribution)
        .where(SVSAttribution.run_id == run.id, SVSAttribution.alert_uuid == alert.uuid,
               SVSAttribution.removed_at.is_(None),
               SVSAttribution.confidence == AttributionConfidence.CONTEXT.value)
        .values(kept_at=now, kept_by_user_id=user_id)
        .execution_options(synchronize_session=False))
    if kept.rowcount == 0:
        db.rollback()
        raise AssociationConflict(f"alert {alert.uuid} has no context attribution to run {run.uuid} to keep")

    db.add(new_run_event(run.id, RunEventKind.CONTEXT_KEPT, actor, actor_user_id=user_id, now=now,
                         details={"alert_uuid": alert.uuid}))
    db.commit()
    _audit("svs context attribution kept", run, alert.uuid, actor, user_id)

    alert = _read_alert(alert.id)
    status = _status(alert)
    return AssociationResult(alert.uuid, status.value if status else None, alert.queue)


#
# from the alert's side
#

def disassociate_alert(alert_uuid: str, user_id: int, actor: str, reason: Optional[str] = None, *,
                       not_a_test: bool = False, now: Optional[datetime] = None) -> AlertDisassociationResult:
    """Disassociates the alert from every run that holds it, oldest run first, so it is given back
    to analysts (docs/SVS_RUNS.md, *Associating alerts by hand*). not_a_test applies only to a TEST?
    alert, which its runs hold by context alone. Raises UnknownAlert, AssociationConflict (nothing
    holds it, or not_a_test on an alert that a marker or a person attributed)."""
    db = get_db()
    alert_id = db.execute(select(Alert.id).where(Alert.uuid == alert_uuid)).scalar()
    if alert_id is None:
        raise UnknownAlert(f"alert {alert_uuid} not found")

    # the runs that hold it, oldest first
    run_uuids = list(dict.fromkeys(db.execute(
        select(SVSRun.uuid)
        .join(SVSAttribution, SVSAttribution.run_id == SVSRun.id)
        .where(SVSAttribution.alert_uuid == alert_uuid, SVSAttribution.removed_at.is_(None))
        .order_by(SVSRun.id)).scalars()))
    if not run_uuids:
        raise AssociationConflict(f"alert {alert_uuid} is not attributed to any test run")
    if not_a_test and _status(_read_alert(alert_id)) != SVSStatus.TEST_CONTEXT:
        raise AssociationConflict(f"alert {alert_uuid} is not TEST? (attributed by context only): "
                                  "disassociate it instead")

    done, moved, reopened = [], False, False
    for run_uuid in run_uuids:
        try:
            result = disassociate(run_uuid, alert_uuid, user_id, actor, reason, not_a_test=not_a_test, now=now)
        except AssociationConflict as e:
            # a concurrent change released the alert from this run first
            logging.info(f"svs alert {alert_uuid} was no longer held by run {run_uuid}: {e}",
                         extra={"svs_run": run_uuid, "alert_uuid": alert_uuid})
            continue
        done.append(run_uuid)
        moved = moved or result.moved
        reopened = reopened or result.reopened

    if not done:
        raise AssociationConflict(f"alert {alert_uuid} is not attributed to any test run")
    alert = _read_alert(alert_id)
    status = _status(alert)
    return AlertDisassociationResult(alert.uuid, tuple(done), status.value if status else None, alert.queue,
                                     moved=moved, reopened=reopened)
