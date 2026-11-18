"""What the runs screen shows of a run's result and alerts (docs/SVS.md, Part 5, *Runs*): the number of
signatures per result status, live and as signed off, and the run's alerts by confidence and lateness. Read per page, for
any number of runs in a fixed number of queries; nothing here is stored."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy import Integer, case, cast, func, select

from saq.database.model import SVSAttribution, SVSRun, SVSRunEvent, SVSRunResult, SVSRunResultState
from saq.svs.constants import AttributionConfidence, ResultStatus, RunEventKind


@dataclass(frozen=True)
class RunSummary:
    # signatures per live result status (docs/SVS_RUNS.md, *Results*)
    hit: int = 0
    missing: int = 0
    possibly_suppressed: int = 0
    candidate: int = 0
    rejected: int = 0
    ignored: int = 0
    cleanup: int = 0
    # something changed since the result was computed; the timers recompute it shortly
    result_stale: bool = False
    # the expected signatures per status as signed off at the run's latest review (reviewed_status)
    reviewed_hit: int = 0
    reviewed_missing: int = 0
    reviewed_possibly_suppressed: int = 0
    # the alerts attributed to the run (attributions that hold): by a marker (at least one of its
    # attributions is), by context alone, and late (at least one of its attributions is)
    alerts: int = 0
    marker_alerts: int = 0
    context_alerts: int = 0
    late_alerts: int = 0

    @property
    def expected(self) -> int:
        """The expected signatures the result judged: hit, missing or possibly suppressed."""
        return self.hit + self.missing + self.possibly_suppressed

    @property
    def reviewed_expected(self) -> int:
        """expected, as signed off."""
        return self.reviewed_hit + self.reviewed_missing + self.reviewed_possibly_suppressed


def run_summaries(session, run_ids: Iterable[int]) -> dict[int, RunSummary]:
    """The summary of each run, by run id; a run with no result and no alerts gets the empty one."""
    run_ids = sorted(set(run_ids))
    if not run_ids:
        return {}

    values: dict[int, dict] = {run_id: {} for run_id in run_ids}
    for run_id, status, count in session.execute(
            select(SVSRunResult.run_id, SVSRunResult.status, func.count())
            .where(SVSRunResult.run_id.in_(run_ids), SVSRunResult.status.is_not(None))
            .group_by(SVSRunResult.run_id, SVSRunResult.status)):
        values[run_id][status] = count

    signed_off = (ResultStatus.HIT.value, ResultStatus.MISSING.value, ResultStatus.POSSIBLY_SUPPRESSED.value)
    for run_id, status, count in session.execute(
            select(SVSRunResult.run_id, SVSRunResult.reviewed_status, func.count())
            .where(SVSRunResult.run_id.in_(run_ids), SVSRunResult.reviewed_status.in_(signed_off))
            .group_by(SVSRunResult.run_id, SVSRunResult.reviewed_status)):
        values[run_id][f"reviewed_{status}"] = count

    for run_id in session.execute(
            select(SVSRunResultState.run_id)
            .where(SVSRunResultState.run_id.in_(run_ids), SVSRunResultState.stale.is_(True))).scalars():
        values[run_id]["result_stale"] = True

    alerts = (
        select(SVSAttribution.run_id,
               func.max(case((SVSAttribution.confidence == AttributionConfidence.MARKER.value, 1), else_=0))
               .label("marker"),
               func.max(cast(SVSAttribution.late, Integer)).label("late"))
        .where(SVSAttribution.run_id.in_(run_ids), SVSAttribution.removed_at.is_(None))
        .group_by(SVSAttribution.run_id, SVSAttribution.alert_uuid)
        .subquery())
    for run_id, count, marker, late in session.execute(
            select(alerts.c.run_id, func.count(), func.sum(alerts.c.marker), func.sum(alerts.c.late))
            .group_by(alerts.c.run_id)):
        values[run_id].update(alerts=count, marker_alerts=int(marker or 0), context_alerts=count - int(marker or 0),
                              late_alerts=int(late or 0))

    return {run_id: RunSummary(**fields) for run_id, fields in values.items()}


def batch_result_summaries(session, batch_ids: Iterable[str], conditions: Iterable = ()) -> dict[str, RunSummary]:
    """The live results of each batch's runs that match the conditions, summed, keyed by the batch id
    in lower case (a batch id compares without case, as the batch filter does). Only the result
    counts are filled in."""
    batch_ids = sorted(set(batch_ids))
    if not batch_ids:
        return {}

    values: dict[str, dict] = {}
    for batch_id, status, count in session.execute(
            select(SVSRun.batch_id, SVSRunResult.status, func.count())
            .join(SVSRunResult, SVSRunResult.run_id == SVSRun.id)
            .where(SVSRun.batch_id.in_(batch_ids), SVSRunResult.status.is_not(None), *conditions)
            .group_by(SVSRun.batch_id, SVSRunResult.status)):
        counts = values.setdefault(batch_id.lower(), {})
        counts[status] = counts.get(status, 0) + count

    return {batch_id: RunSummary(**counts) for batch_id, counts in values.items()}


#
# the possibly-suppressed share: when to revisit keeping the hunter from suppressing test targets
# (docs/SVS.md, Part 3, *Hunt suppression*) [ART-8]
#

# the revisit trigger: this many reviewed runs, or this long since the first review
SUPPRESSION_REVIEW_RUNS = 50
SUPPRESSION_REVIEW_PERIOD = timedelta(days=90)
# above this share of missing results that are possibly suppressed, suppression is worth preventing
SUPPRESSION_SHARE_THRESHOLD = 0.10


@dataclass(frozen=True)
class SuppressionShare:
    # the expected signatures missing from the signed-off results of the reviewed runs, possibly
    # suppressed ones included, and of those the possibly suppressed
    missing: int
    possibly_suppressed: int
    # the runs with a signed-off result, and when the first one was signed off
    reviewed_runs: int
    first_reviewed_at: Optional[datetime]
    trigger_reached: bool

    @property
    def share(self) -> Optional[float]:
        """possibly_suppressed / missing; None while nothing is missing."""
        return self.possibly_suppressed / self.missing if self.missing else None

    @property
    def reconsider(self) -> bool:
        """The trigger is reached and the share is above the threshold."""
        return self.trigger_reached and self.share is not None and self.share > SUPPRESSION_SHARE_THRESHOLD


def suppression_share(session, now: Optional[datetime] = None) -> SuppressionShare:
    """The share of missing expected signatures that were possibly suppressed, over every run's
    result as signed off."""
    now = now or datetime.now()
    missing, possibly_suppressed = session.execute(
        select(func.count(),
               func.coalesce(func.sum(case(
                   (SVSRunResult.reviewed_status == ResultStatus.POSSIBLY_SUPPRESSED.value, 1), else_=0)), 0))
        .where(SVSRunResult.reviewed_status.in_(
            [ResultStatus.MISSING.value, ResultStatus.POSSIBLY_SUPPRESSED.value]))).one()
    reviewed_runs = session.execute(
        select(func.count()).select_from(SVSRun).where(SVSRun.reviewed_at.is_not(None))).scalar_one()
    # a review again moves reviewed_at, so the first sign-off is the event log's
    first_reviewed_at = session.execute(
        select(func.min(SVSRunEvent.created_at)).where(SVSRunEvent.kind == RunEventKind.REVIEWED.value)).scalar()

    trigger_reached = reviewed_runs >= SUPPRESSION_REVIEW_RUNS or (
        first_reviewed_at is not None and now - first_reviewed_at >= SUPPRESSION_REVIEW_PERIOD)
    return SuppressionShare(missing=int(missing), possibly_suppressed=int(possibly_suppressed),
                            reviewed_runs=reviewed_runs, first_reviewed_at=first_reviewed_at,
                            trigger_reached=trigger_reached)
