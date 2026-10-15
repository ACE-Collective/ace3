"""What a person does to a test run (docs/SVS_RUNS.md, *Reviewing runs*; docs/SVS.md, Part 3 and
Part 5): take it, cancel it, close it, and review it.

- **Ownership** works as it does for alerts (saq.database.util.alert.check_alert_ownership): a run
  someone else owns is changed only when the person confirmed taking it from them, and then becomes
  theirs; a run whose owner's account is disabled or gone counts as nobody's. Reviewing a run also
  takes it when nobody owns it.
- **Cancel** and **close** are the lifecycle's own (saq/svs/runs.py). Closing discards the run:
  its alerts become SIMULATED and nothing is learned from it.
- **Review** signs the run's result off: an Ended run becomes Reviewed, and a Reviewed run can be
  reviewed again, which replaces what was signed off (a late alert or a manual association after
  the review marks it changed since review). It needs the result to be current, every candidate
  decided (saq/svs/expectations.py) and every context-only attribution kept or marked not a test
  (saq/svs/association.py). In this order, because capture skips the alerts of a run that is not
  reviewed:
  1. the run is committed as Reviewed, with its reviewer, and its live result is copied to the
     reviewed columns of svs_run_results;
  2. its fully attributed open alerts nobody has taken become SIMULATED, which requeues them so
     their YARA hits are captured as TP samples;
  3. the detections of signatures ignored for the test get an FP verdict from the reviewer, unless
     someone already set one, so launcher noise is not learned as a true positive.

svs_runs, svs_run_events and the reviewed columns of svs_run_results are written here for these
actions.
"""

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from sqlalchemy import and_, delete, select, update

from saq.database.model import (
    Alert,
    DetectionPointVerdict,
    SVSAttribution,
    SVSRun,
    SVSRunResult,
    SVSRunResultState,
    User,
)
from saq.database.pool import get_db
from saq.database.util.alert import AlertOwner, check_alert_ownership
from saq.detection_verdicts.constants import VERDICT_FP
from saq.detection_verdicts.store import set_verdicts
from saq.error.reporting import report_exception
from saq.svs import runs
from saq.svs.constants import AttributionConfidence, ResultStatus, RunEventKind, RunState
from saq.svs.result_state import mark_runs_stale
from saq.svs.results import test_decisions
from saq.svs.run_events import new_run_event, run_log_fields

# the states a run can be reviewed in: once when it ended, and again after that
REVIEWABLE_STATES = (RunState.ENDED.value, RunState.REVIEWED.value)


class RunOwned(Exception):
    """Someone else owns the run, and taking it from them was not confirmed."""

    def __init__(self, run_uuid: str, owner: str, owner_id: int):
        super().__init__(f"run {run_uuid} is owned by {owner}: confirm taking it from them")
        self.run_uuid = run_uuid
        self.owner = owner
        self.owner_id = owner_id


class ReviewBlocked(Exception):
    """The run can't be reviewed yet; what stands in the way is in blockers."""

    def __init__(self, run_uuid: str, blockers: dict):
        reasons = []
        if blockers.get("stale"):
            reasons.append("its result is being recomputed")
        if blockers.get("candidates"):
            reasons.append(f"{len(blockers['candidates'])} candidate signature(s) are undecided")
        if blockers.get("context_alerts"):
            reasons.append(f"{len(blockers['context_alerts'])} context-only alert(s) are neither kept nor marked "
                           "not a test")
        super().__init__(f"run {run_uuid} can't be reviewed: {'; '.join(reasons)}")
        self.run_uuid = run_uuid
        self.blockers = blockers


#
# ownership
#

def _owners(run_uuids: list[str]) -> dict[str, AlertOwner]:
    """The owner of each run that exists, locking the run rows until the transaction ends. The owner
    is named by username, as on a run row, because that is what a confirmation to take a run names."""
    rows = get_db().execute(
        select(SVSRun.uuid, SVSRun.owner_id, User.username, User.enabled)
        .outerjoin(User, User.id == SVSRun.owner_id)
        .where(SVSRun.uuid.in_(run_uuids))
        .with_for_update(of=SVSRun)).all()
    # an owner whose users row is gone has nobody left to protect, the same as a disabled one
    return {run_uuid: AlertOwner(user_id=owner_id, name=username, enabled=bool(enabled))
            for run_uuid, owner_id, username, enabled in rows}


def _take(run_uuid: str, owner: AlertOwner, user_id: int, actor: str, now: datetime) -> None:
    """Makes the person the run's owner, in the caller's transaction, and records it."""
    run = get_db().execute(select(SVSRun).where(SVSRun.uuid == run_uuid)).scalar_one()
    run.owner_id = user_id
    get_db().add(new_run_event(run.id, RunEventKind.OWNERSHIP_TAKEN, actor, actor_user_id=user_id, now=now,
                               details={"from": owner.name if owner.user_id is not None else None}))
    logging.info("AUDIT: svs run ownership taken", extra={
        **run_log_fields(run), "actor": actor, "actor_user_id": user_id,
        "previous_owner": owner.name if owner.user_id is not None else None})


@dataclass
class BulkResult:
    """What a bulk action did to each run it was given."""
    done: list[str] = field(default_factory=list)
    # run uuid -> the username of the person who owns it, for the runs left alone
    left_alone: dict[str, str] = field(default_factory=dict)
    # run uuid -> why the action doesn't apply to it
    conflicts: dict[str, str] = field(default_factory=dict)
    unknown: list[str] = field(default_factory=list)


def take_ownership(run_uuids: list[str], user_id: int, actor: str,
                   confirmed_takes: Optional[dict[str, int]] = None, now: Optional[datetime] = None) -> BulkResult:
    """Makes the person the owner of the runs, those owned by someone else only when the person
    confirmed taking them (run uuid -> the owner's user id they agreed to take it from)."""
    now = now or datetime.now()
    result = BulkResult()
    owners = _owners(run_uuids)
    result.unknown = [run_uuid for run_uuid in run_uuids if run_uuid not in owners]
    check = check_alert_ownership(run_uuids, owners, user_id, confirmed_takes)
    result.left_alone = dict(check.skipped)
    for run_uuid in check.permitted:
        if owners[run_uuid].user_id != user_id:
            _take(run_uuid, owners[run_uuid], user_id, actor, now)
        result.done.append(run_uuid)
    get_db().commit()
    return result


def _claim(run_uuid: str, user_id: int, actor: str, confirmed_from: Optional[int], now: datetime) -> None:
    """Checks that the person may act on the run, taking it from its owner when they confirmed it.
    Commits. Raises UnknownRun, RunOwned."""
    owners = _owners([run_uuid])
    if run_uuid not in owners:
        get_db().rollback()
        raise runs.UnknownRun(f"run {run_uuid} not found")
    owner = owners[run_uuid]
    check = check_alert_ownership([run_uuid], owners, user_id,
                                  {run_uuid: confirmed_from} if confirmed_from is not None else None)
    if run_uuid in check.skipped:
        get_db().rollback()
        raise RunOwned(run_uuid, check.skipped[run_uuid], owner.user_id)
    if run_uuid in check.reassigned:
        _take(run_uuid, owner, user_id, actor, now)
    get_db().commit()


def _bulk(run_uuids: list[str], user_id: int, actor: str, confirmed_takes: Optional[dict[str, int]],
          act: Callable[[str], object], now: datetime) -> BulkResult:
    result = BulkResult()
    for run_uuid in dict.fromkeys(run_uuids):
        try:
            _claim(run_uuid, user_id, actor, (confirmed_takes or {}).get(run_uuid), now)
            act(run_uuid)
            result.done.append(run_uuid)
        except runs.UnknownRun:
            result.unknown.append(run_uuid)
        except RunOwned as e:
            result.left_alone[run_uuid] = e.owner
        except (runs.RunStateConflict, runs.ReasonRequired) as e:
            get_db().rollback()
            result.conflicts[run_uuid] = str(e)
    return result


def cancel_runs(run_uuids: list[str], user_id: int, actor: str, confirmed_takes: Optional[dict[str, int]] = None,
                now: Optional[datetime] = None) -> BulkResult:
    """Cancels the runs (Created or Started), as the launcher would."""
    now = now or datetime.now()
    return _bulk(run_uuids, user_id, actor, confirmed_takes,
                 lambda run_uuid: runs.cancel_by_person(run_uuid, actor, user_id, now), now)


def close_runs(run_uuids: list[str], user_id: int, actor: str, reason: Optional[str] = None,
               confirmed_takes: Optional[dict[str, int]] = None, now: Optional[datetime] = None) -> BulkResult:
    """Closes the runs (Ended, Canceled or Error): nothing is learned from them, and their alerts
    become SIMULATED. An Ended run needs the reason."""
    now = now or datetime.now()
    return _bulk(run_uuids, user_id, actor, confirmed_takes,
                 lambda run_uuid: runs.close_by_person(run_uuid, actor, user_id, reason, now), now)


#
# review
#

@dataclass(frozen=True)
class ReviewResult:
    run: SVSRun
    re_review: bool
    # signatures per status, as signed off
    counts: dict[str, int]
    alerts_closed: int = 0
    fp_verdicts: int = 0


def review_blockers(session, run: SVSRun, *, lock: bool = True) -> dict:
    """What keeps the run from being reviewed: its result is stale (or was never computed),
    candidate signatures are undecided, or context-only alerts are neither kept nor marked not a
    test. Empty when nothing does. A review locks the run's result state (lock); the run page only
    reads it."""
    blockers: dict = {}
    statement = select(SVSRunResultState.stale).where(SVSRunResultState.run_id == run.id)
    state = session.execute(statement.with_for_update() if lock else statement).first()
    if state is None or state[0]:
        blockers["stale"] = True
    if state is None:
        # computed by nothing yet (it ended before results existed): the caller marks it stale
        blockers["never_computed"] = True
    candidates = list(session.execute(
        select(SVSRunResult.signature_uuid)
        .where(SVSRunResult.run_id == run.id, SVSRunResult.status == ResultStatus.CANDIDATE.value)
        .order_by(SVSRunResult.signature_uuid)).scalars())
    if candidates:
        blockers["candidates"] = candidates
    unkept = list(session.execute(
        select(SVSAttribution.alert_uuid).distinct()
        .where(SVSAttribution.run_id == run.id, SVSAttribution.removed_at.is_(None),
               SVSAttribution.confidence == AttributionConfidence.CONTEXT.value, SVSAttribution.kept_at.is_(None))
        .order_by(SVSAttribution.alert_uuid)).scalars())
    if unkept:
        blockers["context_alerts"] = unkept
    return blockers


def _sign_off(run: SVSRun, user_id: int, actor: str, now: datetime) -> tuple[bool, dict[str, int]]:
    """Commits the run as reviewed and copies its live result to the reviewed columns. Raises
    RunStateConflict, ReviewBlocked."""
    db = get_db()
    from_state = run.state
    if from_state not in REVIEWABLE_STATES:
        db.rollback()
        raise runs.RunStateConflict(run.uuid, from_state, "review")
    blockers = review_blockers(db, run)
    if blockers:
        if blockers.pop("never_computed", False):
            # so the timers compute it, and a review after that goes through
            mark_runs_stale(db, run_ids=[run.id])
            db.commit()
        else:
            db.rollback()
        raise ReviewBlocked(run.uuid, blockers)

    unowned = run.owner_id is None
    reviewed = db.execute(
        update(SVSRun)
        .where(SVSRun.id == run.id, SVSRun.state == from_state)
        .values(state=RunState.REVIEWED.value, reviewer_id=user_id, reviewed_at=now, changed_since_review=False,
                **({"owner_id": user_id} if unowned else {}))
        .execution_options(synchronize_session=False))
    if reviewed.rowcount != 1:
        db.rollback()
        raise runs.RunStateConflict(run.uuid, run.state, "review")
    if unowned:
        # reviewing a run takes it when nobody owns it
        db.add(new_run_event(run.id, RunEventKind.OWNERSHIP_TAKEN, actor, actor_user_id=user_id, now=now,
                             details={"from": None}))

    # what left the live result held only the earlier sign-off, which this one replaces
    db.execute(delete(SVSRunResult).where(SVSRunResult.run_id == run.id, SVSRunResult.status.is_(None)))
    db.execute(update(SVSRunResult)
               .where(SVSRunResult.run_id == run.id)
               .values(reviewed_status=SVSRunResult.status, reviewed_alert_count=SVSRunResult.alert_count,
                       reviewed_late_only=SVSRunResult.late_only, reviewed_content_hash=SVSRunResult.content_hash)
               .execution_options(synchronize_session=False))
    counts = dict(sorted(Counter(db.execute(
        select(SVSRunResult.status).where(SVSRunResult.run_id == run.id)).scalars()).items()))

    re_review = from_state == RunState.REVIEWED
    db.add(new_run_event(run.id, RunEventKind.REVIEWED, actor, actor_user_id=user_id, from_state=from_state,
                         to_state=RunState.REVIEWED.value, now=now, details={"counts": counts, "re_review": re_review}))
    db.commit()
    db.refresh(run)
    runs.log_transition(run, from_state, RunState.REVIEWED.value, actor, "re-review" if re_review else None)
    return re_review, counts


def ignored_detections(session, run: SVSRun) -> list[tuple[int, str]]:
    """(alert id, content hash) of the run's attributed detections of signatures ignored for its
    test, that nobody has given a verdict yet."""
    ignored = test_decisions(session, run.test_guid).ignored
    if not ignored:
        return []
    return [(alert_id, content_hash) for alert_id, content_hash in session.execute(
        select(Alert.id, SVSAttribution.content_hash)
        .join(Alert, Alert.uuid == SVSAttribution.alert_uuid)
        .outerjoin(DetectionPointVerdict, and_(DetectionPointVerdict.alert_id == Alert.id,
                                               DetectionPointVerdict.content_hash == SVSAttribution.content_hash))
        .where(SVSAttribution.run_id == run.id, SVSAttribution.removed_at.is_(None),
               SVSAttribution.signature_uuid.in_(ignored), DetectionPointVerdict.id.is_(None))
        .order_by(Alert.id, SVSAttribution.content_hash))]


def review(run_uuid: str, user_id: int, actor: str, confirmed_from: Optional[int] = None,
           now: Optional[datetime] = None) -> ReviewResult:
    """Signs the run's result off (Ended -> Reviewed, or Reviewed again), then closes its alerts
    as SIMULATED and gives its ignored detections an FP verdict. A failure after the sign-off never
    undoes it: the alerts stay open and keep the run in Needs attention, and reviewing it again
    finishes the job. Raises UnknownRun, RunOwned, RunStateConflict, ReviewBlocked."""
    now = now or datetime.now()
    # taking an unowned run happens with the sign-off, so a review that can't go through takes nothing
    _claim(run_uuid, user_id, actor, confirmed_from, now)
    db = get_db()
    run = db.execute(select(SVSRun).where(SVSRun.uuid == run_uuid).with_for_update()).scalar_one()
    re_review, counts = _sign_off(run, user_id, actor, now)

    alerts_closed = fp_verdicts = 0
    try:
        alerts_closed = runs.close_reviewed_run_alerts(run, actor)
        targets = ignored_detections(db, run)
        if targets:
            fp_verdicts = set_verdicts(targets, VERDICT_FP, user_id, analyst=False).changed
    except Exception as e:
        db.rollback()
        logging.error("unable to close the alerts of reviewed svs run %s: %s", run.uuid, e, extra=run_log_fields(run))
        report_exception()

    logging.info("svs run %s reviewed by %s: %d alerts closed, %d ignored detections FP", run.uuid, actor,
                 alerts_closed, fp_verdicts,
                 extra={**run_log_fields(run), "actor": actor, "counts": counts, "re_review": re_review,
                        "alerts_closed": alerts_closed, "fp_verdicts": fp_verdicts})
    return ReviewResult(run, re_review, counts, alerts_closed, fp_verdicts)
