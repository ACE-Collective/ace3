"""A run's result (docs/SVS_RUNS.md, *Results*): what fired during the run against what its test is
expected to fire, one row of svs_run_results per signature.

What fired is the run's attributions that hold, by the signature of each attributed detection.
Each signature that fired is, in this order of precedence:
- ignored: globally or for the test (launcher noise);
- hit: expected for the test on the run's platform;
- rejected: decided, for the run's platform, not to be what the test is about;
- candidate: nobody has decided about it yet.

Each expected signature that did not fire (and is not ignored) is missing, or possibly suppressed
when it is a hunt with a suppression period and [ART-8]:
- it has group_by, and the hunter recorded that it dropped a match for its suppression during the
  run, on one of the run's test hosts (svs_suppressed_matches);
- otherwise, the hunt alerted within that period before the run's window closed, on an alert not
  attributed to the run. For a hunt that deduplicates its alerts that can't be told for certain,
  and the row says so.

The result is computed when the run ends, and again by the timers whenever it is stale
(saq/svs/result_state.py). Each computation runs in a transaction of its own and clears the stale
flag only if nothing marked the run stale since it began.
"""

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import Integer, case, cast, func, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.database.model import (
    Alert,
    DetectionPoint,
    SVSAttribution,
    SVSExpectation,
    SVSIgnore,
    SVSRun,
    SVSRunResult,
    SVSRunResultState,
    SVSSuppressedMatch,
)
from saq.database.private_session import private_transaction
from saq.error.reporting import log_loop_exception
from saq.signatures.builtin import (
    GENERIC,
    LEGACY,
    OBSERVABLE_FLAGGED,
    YARA_RULE_MATCH,
)
from saq.svs.constants import (
    GLOBAL_SCOPE_KEY,
    RUN_SIGNATURES,
    AttributionConfidence,
    ExpectationState,
    ResultStatus,
    RunEventKind,
    RunState,
)
from saq.svs.run_events import new_run_event, run_log_fields
from saq.svs.signatures import describe_signatures
from saq.svs import windows
from saq.svs.windows import HuntInfo

# signatures a result never counts. GENERIC, LEGACY and YARA_RULE_MATCH stand for many unrelated
# detections (no specific signature, a pre-attribution detection, a YARA rule without a uuid);
# OBSERVABLE_FLAGGED fires on whatever analysts flagged, so flagging a value would change results;
# the SVS built-ins are about runs and are never attributed to one
UNTRACKED_SIGNATURES = frozenset({
    GENERIC.uuid, LEGACY.uuid, YARA_RULE_MATCH.uuid, OBSERVABLE_FLAGGED.uuid}) | RUN_SIGNATURES

# the runs whose result the timers recompute; a started run is computed when it ends
COMPUTED_STATES = (RunState.ENDED.value, RunState.REVIEWED.value)

# the actor of a computed result's event
RESULT_ACTOR = "svs"

# how many stale results one timer pass recomputes at most; the next pass does the rest
RECOMPUTE_BATCH = 200

MISSING_STATUSES = (ResultStatus.MISSING, ResultStatus.POSSIBLY_SUPPRESSED)


@dataclass(frozen=True)
class Fired:
    """A signature attributed detections of the run carry."""
    signature_uuid: str
    family: Optional[str]
    alert_count: int
    late_only: bool
    context_only: bool


@dataclass(frozen=True)
class Decisions:
    """What has been decided about the test's signatures."""
    expected: dict[str, SVSExpectation] = field(default_factory=dict)
    rejected: dict[str, SVSExpectation] = field(default_factory=dict)
    ignored: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ResultRow:
    """One signature of a computed result: the live columns of its svs_run_results row."""
    signature_uuid: str
    status: ResultStatus
    family: Optional[str] = None
    name: Optional[str] = None
    alert_count: int = 0
    late_only: bool = False
    context_only: bool = False
    content_hash: Optional[str] = None
    suppressing_alert_uuid: Optional[str] = None
    suppression_imprecise: bool = False

    def values(self) -> dict:
        return {"status": self.status.value, "signature_family": self.family, "signature_name": self.name,
                "alert_count": self.alert_count, "late_only": self.late_only, "context_only": self.context_only,
                "content_hash": self.content_hash, "suppressing_alert_uuid": self.suppressing_alert_uuid,
                "suppression_imprecise": self.suppression_imprecise}


@dataclass
class ComputedResult:
    run_id: int
    rows: list[ResultRow]
    counts: dict[str, int]
    previous_counts: dict[str, int]
    # (signature uuid, previous status or None) of the rows whose status changed
    changed: list[tuple[ResultRow, Optional[str]]]
    # the computation was current when it finished: nothing marked the run stale meanwhile
    current: bool


#
# reading
#

def fired_signatures(session, run_id: int) -> dict[str, Fired]:
    """The signatures the run's attributions that hold carry, but those a result never counts."""
    statement = (
        select(SVSAttribution.signature_uuid,
               func.max(SVSAttribution.signature_family),
               func.count(SVSAttribution.alert_uuid.distinct()),
               func.min(cast(SVSAttribution.late, Integer)),
               func.min(case((SVSAttribution.confidence == AttributionConfidence.CONTEXT.value, 1), else_=0)))
        .where(SVSAttribution.run_id == run_id, SVSAttribution.removed_at.is_(None),
               SVSAttribution.signature_uuid != "", SVSAttribution.signature_uuid.not_in(UNTRACKED_SIGNATURES))
        .group_by(SVSAttribution.signature_uuid))
    return {uuid: Fired(uuid, family, int(alerts), bool(late_only), bool(context_only))
            for uuid, family, alerts, late_only, context_only in session.execute(statement)}


def test_decisions(session, test_guid: str, platform: str) -> Decisions:
    """The test's expectations on the platform, and the ignores that apply to its runs (on every
    platform)."""
    decisions = Decisions()
    for expectation in session.execute(
            select(SVSExpectation).where(SVSExpectation.test_guid == test_guid,
                                         SVSExpectation.platform == platform)).scalars():
        if expectation.state == ExpectationState.EXPECTED:
            decisions.expected[expectation.signature_uuid] = expectation
        else:
            decisions.rejected[expectation.signature_uuid] = expectation
    decisions.ignored.update(session.execute(
        select(SVSIgnore.signature_uuid).where(SVSIgnore.scope_key.in_([GLOBAL_SCOPE_KEY, test_guid]))).scalars())
    return decisions


def suppressing_alert(session, run: SVSRun, hunt: HuntInfo, now: datetime) -> Optional[str]:
    """The latest alert of the hunt (one carrying a detection of it) inserted within its suppression
    period before the run's window closed, and not attributed to the run; None if there is none.
    A hunt checks its suppression each time it runs, and the run that would have caught the test
    comes up to its latency after the start, so the period reaches back from the run's end."""
    if hunt.suppression is None or run.started_at is None:
        return None

    attributed = select(SVSAttribution.alert_uuid).where(SVSAttribution.run_id == run.id)
    return session.execute(
        select(Alert.uuid)
        .join(DetectionPoint, DetectionPoint.alert_id == Alert.id)
        .where(DetectionPoint.signature_uuid == hunt.uuid,
               Alert.insert_date >= run.started_at - hunt.suppression,
               Alert.insert_date < (run.ended_at or now),
               Alert.uuid.not_in(attributed))
        .order_by(Alert.insert_date.desc(), Alert.id.desc())
        .limit(1)).scalar()


def suppressed_hunts(session, run_id: int) -> set[str]:
    """The hunts with group_by that dropped a match for their suppression during the run, on one
    of its test hosts (saq.svs.attribution.record_suppressed_matches)."""
    return set(session.execute(
        select(SVSSuppressedMatch.hunt_uuid).where(SVSSuppressedMatch.run_id == run_id)).scalars())


#
# computing
#

def _rows(session, run: SVSRun, fired: dict[str, Fired], decisions: Decisions,
          known: dict[str, SVSRunResult], now: datetime) -> list[ResultRow]:
    missing = [uuid for uuid in decisions.expected if uuid not in fired and uuid not in decisions.ignored]
    info = describe_signatures(set(fired) | set(missing))
    hunts = windows.hunt_info() if missing else {}

    def described(uuid: str, family: Optional[str] = None) -> dict:
        signature = info.get(uuid)
        decision = decisions.expected.get(uuid) or decisions.rejected.get(uuid)
        row = known.get(uuid)
        return {
            "family": (signature.family if signature else None) or family
                      or (decision.signature_family if decision else None) or (row.signature_family if row else None),
            "name": (signature.name if signature else None)
                    or (decision.signature_name if decision else None) or (row.signature_name if row else None),
            "content_hash": signature.content_hash if signature else None,
        }

    rows = []
    for uuid, signature in sorted(fired.items()):
        if uuid in decisions.ignored:
            status = ResultStatus.IGNORED
        elif uuid in decisions.expected:
            status = ResultStatus.HIT
        elif uuid in decisions.rejected:
            status = ResultStatus.REJECTED
        else:
            status = ResultStatus.CANDIDATE
        rows.append(ResultRow(uuid, status, alert_count=signature.alert_count, late_only=signature.late_only,
                              context_only=signature.context_only, **described(uuid, signature.family)))

    suppressed = suppressed_hunts(session, run.id) if any(
        uuid in hunts and hunts[uuid].per_group for uuid in missing) else set()
    for uuid in sorted(missing):
        hunt = hunts.get(uuid)
        if hunt is not None and hunt.per_group and hunt.suppression is not None:
            # the hunter's record says it was suppressed but not by which alert, and the hunt's latest
            # alert may be another group's, so none is named
            if uuid in suppressed:
                rows.append(ResultRow(uuid, ResultStatus.POSSIBLY_SUPPRESSED, **described(uuid)))
            else:
                rows.append(ResultRow(uuid, ResultStatus.MISSING, **described(uuid)))
            continue

        alert_uuid = suppressing_alert(session, run, hunt, now) if hunt is not None else None
        if alert_uuid is not None:
            rows.append(ResultRow(uuid, ResultStatus.POSSIBLY_SUPPRESSED, suppressing_alert_uuid=alert_uuid,
                                  suppression_imprecise=hunt.grouped, **described(uuid)))
        else:
            rows.append(ResultRow(uuid, ResultStatus.MISSING, **described(uuid)))

    return rows


def _finish(session, run_id: int, generation: Optional[int], now: datetime) -> bool:
    """Clears the run's stale flag if its generation is still the one the computation read."""
    if generation is None:
        # nothing ever marked it; a writer that marks it meanwhile keeps its row stale
        session.execute(
            mysql_insert(SVSRunResultState)
            .values(run_id=run_id, generation=0, stale=False, computed_generation=0, computed_at=now)
            .on_duplicate_key_update(run_id=SVSRunResultState.run_id))
        state = session.get(SVSRunResultState, run_id, populate_existing=True)
        return state is not None and not state.stale

    finished = session.execute(
        update(SVSRunResultState)
        .where(SVSRunResultState.run_id == run_id, SVSRunResultState.generation == generation)
        .values(stale=False, computed_generation=generation, computed_at=now)
        .execution_options(synchronize_session=False))
    return finished.rowcount == 1


def compute_result(run_id: int, now: Optional[datetime] = None) -> Optional[ComputedResult]:
    """Computes the run's live result and writes it, in a transaction of its own. Returns None for
    a run that doesn't exist."""
    now = now or datetime.now()
    with private_transaction() as session:
        # the generation is read first: everything after it is read in the same snapshot, so a
        # change committed later bumps the generation past it and the run stays stale
        generation = session.execute(
            select(SVSRunResultState.generation).where(SVSRunResultState.run_id == run_id)).scalar()
        run = session.get(SVSRun, run_id)
        if run is None:
            return None

        known = {row.signature_uuid: row for row in session.execute(
            select(SVSRunResult).where(SVSRunResult.run_id == run_id)).scalars()}
        rows = _rows(session, run, fired_signatures(session, run_id), test_decisions(session, run.test_guid, run.platform),
                     known, now)

        previous_counts = Counter(row.status for row in known.values() if row.status is not None)
        changed = []
        for row in rows:
            existing = known.pop(row.signature_uuid, None)
            if existing is None:
                session.add(SVSRunResult(run_id=run_id, signature_uuid=row.signature_uuid, **row.values()))
                changed.append((row, None))
                continue
            previous = existing.status
            for key, value in row.values().items():
                if getattr(existing, key) != value:
                    setattr(existing, key, value)
            if previous != row.status.value:
                changed.append((row, previous))

        # what left the live result: kept, without a live status, only for the reviewed result
        for existing in known.values():
            if existing.reviewed_status is None:
                session.delete(existing)
            elif existing.status is not None:
                existing.status = None

        counts = Counter(row.status.value for row in rows)
        if counts != previous_counts:
            session.add(new_run_event(run_id, RunEventKind.RESULT_COMPUTED, RESULT_ACTOR, now=now, details={
                "counts": dict(sorted(counts.items())), "previous": dict(sorted(previous_counts.items()))}))

        current = _finish(session, run_id, generation, now)
        fields = run_log_fields(run)

    result = ComputedResult(run_id, rows, dict(counts), dict(previous_counts), changed, current)
    _log(fields, result)
    return result


def _log(fields: dict, result: ComputedResult) -> None:
    logging.info("svs run %s result computed: %s", fields["svs_run"],
                 ", ".join(f"{count} {status}" for status, count in sorted(result.counts.items())) or "nothing",
                 extra={**fields, "counts": result.counts})
    for row in result.rows:
        logging.debug("svs run %s result: signature %s %s", fields["svs_run"], row.signature_uuid, row.status.value,
                      extra={**fields, "signature_uuid": row.signature_uuid, "signature_family": row.family,
                             "status": row.status.value, "alert_count": row.alert_count})
    for row, previous in result.changed:
        if row.status in MISSING_STATUSES and previous not in MISSING_STATUSES:
            logging.info("svs run %s is missing expected signature %s (%s)%s", fields["svs_run"], row.signature_uuid,
                         row.name or "unknown",
                         ", possibly suppressed" if row.status == ResultStatus.POSSIBLY_SUPPRESSED else "",
                         extra={**fields, "signature_uuid": row.signature_uuid, "signature_family": row.family,
                                "possibly_suppressed": row.status == ResultStatus.POSSIBLY_SUPPRESSED,
                                "suppressing_alert_uuid": row.suppressing_alert_uuid,
                                "suppression_imprecise": row.suppression_imprecise})


def recompute_stale_results(now: Optional[datetime] = None, limit: int = RECOMPUTE_BATCH) -> int:
    """Recomputes the stale results of ended and reviewed runs, each in its own transaction; a run
    that fails is logged and stays stale. Returns how many were computed."""
    with private_transaction() as session:
        run_ids = list(session.execute(
            select(SVSRunResultState.run_id)
            .join(SVSRun, SVSRun.id == SVSRunResultState.run_id)
            .where(SVSRunResultState.stale.is_(True), SVSRun.state.in_(COMPUTED_STATES))
            .order_by(SVSRunResultState.run_id)
            .limit(limit)).scalars())

    count = 0
    for run_id in run_ids:
        try:
            if compute_result(run_id, now) is not None:
                count += 1
        except Exception as e:
            log_loop_exception(e, f"unable to compute the result of svs run id {run_id}")
    return count
