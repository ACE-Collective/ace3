"""SVS test runs service for ACE API v2 (docs/SVS_RUNS.md, *Registering a run*; docs/SVS_API.md).

Synchronous; the router runs each function through run_db_in_thread. saq.svs.runs owns the runs
and their lifecycle; this maps its errors to HTTP, and reads the runs and their event logs.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.orm import aliased, selectinload, undefer

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import (
    CHANGED_SINCE_SETTLE_SECONDS,
    InvalidCursor,
    InvalidListingRequest,
    decode_cursor,
    encode_cursor,
    rows_to_csv,
    settled,
)
from aceapi_v2.alerts.service import load_alert_rows
from aceapi_v2.svs.runs.schemas import (
    ATTRIBUTION_CSV_FIELDS,
    RUN_BATCH_CSV_FIELDS,
    RUN_EVENT_CSV_FIELDS,
    RUN_RESULT_CSV_FIELDS,
    RUN_ROW_CSV_FIELDS,
    AssociationRequest,
    AssociationResult,
    Attribution,
    HostHolder,
    BulkRunRequest,
    BulkRunResult,
    HistoryRun,
    ReviewBlockers,
    ReviewRequest,
    ReviewResult,
    RunAlert,
    RunAlertDetection,
    RunBatch,
    RunComment,
    RunCommentRequest,
    RunCount,
    RunDetail,
    RunEvent,
    RunExecutedRequest,
    RunHistory,
    RunLifecycle,
    RunRegistrationRequest,
    RunResult,
    RunRow,
    RunTarget,
    RunValidation,
    RunValidationTarget,
    SignatureHistory,
    SuppressionShare,
)
from saq.database.model import (
    Alert,
    DetectionPoint,
    SVSAttribution,
    SVSCatalogTest,
    SVSRun,
    SVSRunEvent,
    SVSRunResult,
    SVSRunResultState,
    User,
)
from saq.database.pool import get_db
from saq.gui.filter_screens import SVS_RUNS_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.svs import association, review, run_comments, runs
from saq.svs.constants import FALLBACK_EVENT_TIME_SOURCES, RUN_STATES, AttributionConfidence, RunState
from saq.svs.log_search import log_search_url
from saq.svs.refusals import Caller
from saq.svs.results import cleanup_condition
from saq.svs.run_filters import needs_attention_condition, run_filter_conditions
from saq.svs.run_summary import RunSummary, batch_result_summaries, run_summaries, suppression_share
from saq.svs.samples import to_utc_naive
from saq.util.uuid import UUID_REGEX

logger = logging.getLogger(__name__)


def _target(target) -> RunTarget:
    return RunTarget(hostname=target.hostname, username=target.username, host=target.host, fqdn=target.fqdn,
                     user=target.user)


def _lifecycle(run: SVSRun) -> RunLifecycle:
    return RunLifecycle(
        run_id=run.uuid, marker=run.marker, state=run.state, test_guid=run.test_guid, platform=run.platform,
        targets=[_target(t) for t in run.targets],
        observation_seconds=run.observation_seconds, attribution_seconds=run.attribution_seconds,
        holds_host=run.holds_host, created_at=run.created_at, started_at=run.started_at,
        cleanup_at=run.cleanup_at, observation_ends_at=run.observation_ends_at,
        attribution_ends_at=run.attribution_ends_at, error_reason=run.error_reason, close_reason=run.close_reason)


def _holder(holder: runs.HostHolder) -> HostHolder:
    return HostHolder(host=holder.host, run_id=holder.run_uuid, state=holder.state, until=holder.until,
                      maintenance_id=holder.maintenance_uuid)


def host_busy_error(e: runs.HostBusy) -> HTTPException:
    return HTTPException(status_code=409, detail={
        "message": str(e), "holders": [_holder(holder).model_dump(mode="json") for holder in e.holders]})


def _call(fn, *args, **kwargs) -> RunLifecycle:
    try:
        return _lifecycle(fn(*args, **kwargs))
    except runs.UnknownRun as e:
        raise HTTPException(status_code=404, detail=str(e))
    except runs.RunStateConflict as e:
        raise HTTPException(status_code=409, detail={"message": str(e), "state": e.state})
    except runs.HostBusy as e:
        raise host_busy_error(e)


def _registration(body: RunRegistrationRequest) -> runs.Registration:
    return runs.Registration(
        test_guid=body.test_guid,
        targets=[runs.TargetSpec(hostname=t.hostname, username=t.username) for t in body.targets],
        launcher=body.launcher, batch_id=body.batch_id, extra=body.extra)


def register(body: RunRegistrationRequest, caller: Caller) -> RunLifecycle:
    try:
        return _lifecycle(runs.register(_registration(body), caller))
    except runs.InvalidRegistration as e:
        raise HTTPException(status_code=422, detail=str(e))
    except runs.RegistrationRefused as e:
        raise HTTPException(status_code=403, detail={"message": "registration refused", "reasons": e.reasons})
    except runs.HostBusy as e:
        raise host_busy_error(e)


def validate(body: RunRegistrationRequest, caller: Caller) -> RunValidation:
    decision = runs.validate(_registration(body), caller)
    targets = [
        RunValidationTarget(hostname=target.hostname, username=target.username, accepted=match.matched,
                            reason=match.reason,
                            test_host=match.host.hostname if match.host is not None else None,
                            platform=match.host.platform if match.host is not None else None,
                            held_by=[_holder(holder) for holder in decision.busy
                                     if match.host is not None and holder.host == match.host.hostname])
        for target, match in decision.matches]
    if decision.invalid:
        return RunValidation(decision="invalid", status_code=422, message=decision.invalid, targets=targets)
    if decision.refused:
        return RunValidation(decision="refused", status_code=403, targets=targets)
    if decision.busy:
        return RunValidation(decision="host_busy", status_code=409, targets=targets, platform=decision.platform)
    return RunValidation(
        decision="accepted", status_code=201, targets=targets, platform=decision.platform,
        observation_seconds=int(decision.observation.total_seconds()),
        observation_source=decision.observation_source,
        attribution_seconds=int(decision.attribution.total_seconds()), holds_host=decision.holds_host)


def start(run_id: str, caller: Caller) -> RunLifecycle:
    return _call(runs.start, run_id, caller)


def executed(run_id: str, body: RunExecutedRequest, caller: Caller) -> RunLifecycle:
    return _call(runs.executed, run_id, caller, body.exit_code, body.error, output=body.output)


def cleanup(run_id: str, caller: Caller) -> RunLifecycle:
    return _call(runs.cleanup, run_id, caller)


def cancel(run_id: str, caller: Caller) -> RunLifecycle:
    return _call(runs.cancel, run_id, caller)


#
# reading
#

def _json(value: Optional[str]) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except ValueError:
        logger.warning("unreadable JSON in an svs run: %.80r", value)
        return None


def _filter_conditions(filter_params: list[str], tz) -> list:
    try:
        entries, _ = decode_filter_query(filter_params, screen=SVS_RUNS_SCREEN, strict=True)
    except FilterQueryError as e:
        raise InvalidListingRequest(str(e))

    try:
        entries = [entry.model_dump() for entry in SVS_RUNS_SCREEN.validate_entries(entries)]
    except ValidationError as e:
        raise InvalidListingRequest(e.errors(include_url=False, include_context=False))

    return run_filter_conditions(entries, tz)


def _validate_run_id(run_id: str) -> str:
    run_id = run_id.lower()
    if not UUID_REGEX.fullmatch(run_id):
        raise HTTPException(status_code=400, detail="invalid run id")
    return run_id


def _runs_statement() -> Select:
    """The runs with what a row shows besides the run itself: the catalog test, the owner's and the
    reviewer's names, and whether the run needs attention. The targets are loaded per page."""
    owner, reviewer = aliased(User), aliased(User)
    return (select(SVSRun, SVSCatalogTest.name, SVSCatalogTest.technique, SVSCatalogTest.technique_name,
                   owner.username, reviewer.username, needs_attention_condition().label("needs_attention"))
            .outerjoin(SVSCatalogTest, SVSCatalogTest.guid == SVSRun.test_guid)
            .outerjoin(owner, owner.id == SVSRun.owner_id)
            .outerjoin(reviewer, reviewer.id == SVSRun.reviewer_id)
            .options(selectinload(SVSRun.targets)))


def _row_values(row) -> dict:
    run, test_name, technique, technique_name, owner, reviewer, needs_attention = row
    return dict(
        run_id=run.uuid, state=run.state, test_guid=run.test_guid, test_name=test_name, technique=technique,
        technique_name=technique_name, platform=run.platform, marker=run.marker, targets=[_target(t) for t in run.targets],
        launcher=run.launcher, batch_id=run.batch_id, created_at=run.created_at, started_at=run.started_at,
        executed_at=run.executed_at, exit_code=run.exit_code, cleanup_at=run.cleanup_at, ended_at=run.ended_at,
        canceled_at=run.canceled_at,
        closed_at=run.closed_at, observation_ends_at=run.observation_ends_at,
        attribution_ends_at=run.attribution_ends_at, error_reason=run.error_reason, close_reason=run.close_reason,
        owner=owner, reviewer=reviewer, reviewed_at=run.reviewed_at, changed_since_review=run.changed_since_review,
        needs_attention=bool(needs_attention), updated_at=run.updated_at)


def _summary_values(summary: RunSummary) -> dict:
    return dict(
        result_hit=summary.hit, result_expected=summary.expected,
        result_missing=summary.missing + summary.possibly_suppressed,
        result_possibly_suppressed=summary.possibly_suppressed, result_candidate=summary.candidate,
        result_rejected=summary.rejected, result_ignored=summary.ignored, result_cleanup=summary.cleanup,
        result_stale=summary.result_stale,
        reviewed_hit=summary.reviewed_hit, reviewed_expected=summary.reviewed_expected,
        reviewed_missing=summary.reviewed_missing + summary.reviewed_possibly_suppressed,
        reviewed_possibly_suppressed=summary.reviewed_possibly_suppressed,
        alerts=summary.alerts, marker_alerts=summary.marker_alerts, context_alerts=summary.context_alerts,
        late_alerts=summary.late_alerts)


def _rows(rows) -> list[RunRow]:
    """The page's rows with their result and alert summaries, read for the whole page at once."""
    summaries = run_summaries(get_db(), [row[0].id for row in rows])
    return [RunRow(**_row_values(row), **_summary_values(summaries[row[0].id])) for row in rows]


#
# the listing: newest first, or (updated_at, id) for a changed_since pull
#

LISTING_ORDER_CREATED = "created"
LISTING_ORDER_UPDATED = "updated_at"


@dataclass(frozen=True)
class RunListing:
    statement: Select
    order: str


def prepare_listing(filter_params: list[str], *, changed_since: datetime | None, tz) -> RunListing:
    """Builds the listing statement from share-link filters (`f=`) of the runs screen. Raises
    InvalidListingRequest."""
    statement = _runs_statement()
    for condition in _filter_conditions(filter_params, tz):
        statement = statement.where(condition)

    if changed_since is None:
        return RunListing(statement=statement, order=LISTING_ORDER_CREATED)

    statement = statement.where(SVSRun.updated_at >= to_utc_naive(changed_since))
    return RunListing(statement=statement, order=LISTING_ORDER_UPDATED)


def _parse_key(order: str):
    def parse(payload: dict) -> tuple[datetime, int]:
        if payload["o"] != order:
            raise InvalidCursor(
                f"this cursor pages a listing ordered by {payload['o']}, not {order}: "
                "pass the same changed_since (or none) as the request that returned it")
        at, row_id = payload["k"]
        return datetime.fromisoformat(at), int(row_id)

    return parse


def fetch_page(listing: RunListing, cursor: str | None, limit: int) -> tuple[list[RunRow], str | None]:
    """One page of the listing after `cursor`, and the next page's cursor (None on the last).
    Raises InvalidCursor."""
    statement = listing.statement
    after = decode_cursor(cursor, _parse_key(listing.order)) if cursor is not None else None
    if listing.order == LISTING_ORDER_CREATED:
        if after is not None:
            created_at, row_id = after
            statement = statement.where(or_(
                SVSRun.created_at < created_at, and_(SVSRun.created_at == created_at, SVSRun.id < row_id)))
        statement = statement.order_by(SVSRun.created_at.desc(), SVSRun.id.desc())
    else:
        statement = statement.where(settled(SVSRun.updated_at, CHANGED_SINCE_SETTLE_SECONDS))
        if after is not None:
            updated_at, row_id = after
            statement = statement.where(or_(
                SVSRun.updated_at > updated_at, and_(SVSRun.updated_at == updated_at, SVSRun.id > row_id)))
        statement = statement.order_by(SVSRun.updated_at, SVSRun.id)

    rows = get_db().execute(statement.limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1][0]
        at = last.created_at if listing.order == LISTING_ORDER_CREATED else last.updated_at
        next_cursor = encode_cursor(o=listing.order, k=[at.isoformat(), last.id])

    return _rows(rows), next_cursor


def _flatten_run(values: dict) -> None:
    values["targets"] = ",".join(
        f"{t['hostname']}/{t['username']}" if t["username"] else t["hostname"] for t in values["targets"])


def run_rows_to_csv(rows: list[RunRow], *, header: bool) -> str:
    return rows_to_csv(rows, RUN_ROW_CSV_FIELDS, header=header, flatten=_flatten_run)


#
# the count, and the batches: one row per batch_id over the runs the filters match
#

def get_suppression_share() -> SuppressionShare:
    share = suppression_share(get_db())
    return SuppressionShare(
        missing=share.missing, possibly_suppressed=share.possibly_suppressed, share=share.share,
        reviewed_runs=share.reviewed_runs, first_reviewed_at=share.first_reviewed_at,
        trigger_reached=share.trigger_reached, reconsider=share.reconsider)


def count_runs(filter_params: list[str], tz) -> RunCount:
    """How many runs the share-link filters match. Raises InvalidListingRequest."""
    statement = select(func.count()).select_from(SVSRun).where(*_filter_conditions(filter_params, tz))
    return RunCount(count=get_db().execute(statement).scalar_one())


LISTING_ORDER_BATCH = "batch"


@dataclass(frozen=True)
class BatchListing:
    conditions: tuple


def prepare_batch_listing(filter_params: list[str], *, tz) -> BatchListing:
    """The runs a batch row counts: those the share-link filters match. Raises InvalidListingRequest."""
    return BatchListing(conditions=tuple(_filter_conditions(filter_params, tz)))


def _parse_batch_key(payload: dict) -> tuple[datetime, str]:
    if payload["o"] != LISTING_ORDER_BATCH:
        raise InvalidCursor(f"this cursor pages a listing ordered by {payload['o']}, not by batch")
    at, batch_id = payload["k"]
    return datetime.fromisoformat(at), str(batch_id)


def fetch_batch_page(listing: BatchListing, cursor: str | None, limit: int) -> tuple[list[RunBatch], str | None]:
    """One page of batches after `cursor`, the one with the latest run first, and the next page's
    cursor (None on the last). Raises InvalidCursor."""
    last_created_at = func.max(SVSRun.created_at)
    states = [func.sum(case((SVSRun.state == state, 1), else_=0)) for state in RUN_STATES]
    statement = (select(SVSRun.batch_id, func.count(), func.min(SVSRun.created_at), last_created_at,
                        func.sum(case((needs_attention_condition(), 1), else_=0)), *states)
                 .where(SVSRun.batch_id.is_not(None), *listing.conditions)
                 .group_by(SVSRun.batch_id))
    if cursor is not None:
        at, batch_id = decode_cursor(cursor, _parse_batch_key)
        statement = statement.having(or_(
            last_created_at < at, and_(last_created_at == at, SVSRun.batch_id < batch_id)))
    statement = statement.order_by(last_created_at.desc(), SVSRun.batch_id.desc())

    rows = get_db().execute(statement.limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(o=LISTING_ORDER_BATCH, k=[rows[-1][3].isoformat(), rows[-1][0]])

    summaries = batch_result_summaries(get_db(), [row[0] for row in rows], listing.conditions)
    batches = []
    for batch_id, runs_count, first_created_at, last_at, needs_attention, *state_counts in rows:
        summary = _summary_values(summaries.get(batch_id.lower(), RunSummary()))
        batches.append(RunBatch(
            batch_id=batch_id, runs=runs_count, states=dict(zip(RUN_STATES, (int(n) for n in state_counts))),
            needs_attention=int(needs_attention), first_created_at=first_created_at, last_created_at=last_at,
            result_hit=summary["result_hit"], result_expected=summary["result_expected"],
            result_missing=summary["result_missing"], result_candidate=summary["result_candidate"]))

    return batches, next_cursor


def _flatten_batch(values: dict) -> None:
    for state, count in values.pop("states").items():
        values[f"state_{state}"] = count


def run_batches_to_csv(rows: list[RunBatch], *, header: bool) -> str:
    return rows_to_csv(rows, RUN_BATCH_CSV_FIELDS, header=header, flatten=_flatten_batch)


#
# one run
#

def get_detail(run_id: str) -> RunDetail:
    row = get_db().execute(_runs_statement().where(SVSRun.uuid == _validate_run_id(run_id))
                           .options(undefer(SVSRun.launcher_output))).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")

    run = row[0]
    registrar = get_db().get(User, run.registered_by) if run.registered_by is not None else None
    summary = run_summaries(get_db(), [run.id])[run.id]
    blockers = None
    if run.state in review.REVIEWABLE_STATES:
        found = review.review_blockers(get_db(), run, lock=False)
        blockers = ReviewBlockers(stale=bool(found.get("stale")), candidates=found.get("candidates", []),
                                  context_alerts=found.get("context_alerts", []))
    return RunDetail(
        **_row_values(row), **_summary_values(summary), extra=_json(run.extra), launcher_error=run.launcher_error,
        launcher_output=run.launcher_output,
        test_content_hash=run.test_content_hash, catalog_commit=run.catalog_commit,
        observation_seconds=run.observation_seconds, attribution_seconds=run.attribution_seconds,
        holds_host=run.holds_host, registered_by=registrar.username if registrar is not None else None, review_blockers=blockers,
        log_search_url=log_search_url(run))


#
# event logs: one run's in id order, and the feed over every run's in (updated_at, id) order
#

def _events_statement() -> Select:
    return (select(SVSRunEvent, SVSRun.uuid, User.username)
            .join(SVSRun, SVSRun.id == SVSRunEvent.run_id)
            .outerjoin(User, User.id == SVSRunEvent.actor_user_id))


def _event(row) -> RunEvent:
    event, run_uuid, username = row
    return RunEvent(
        id=event.id, run_id=run_uuid, kind=event.kind, from_state=event.from_state, to_state=event.to_state,
        actor=event.actor, actor_user=username, details=_json(event.details), created_at=event.created_at,
        updated_at=event.updated_at)


def _flatten_event(values: dict) -> None:
    if values["details"] is not None:
        values["details"] = json.dumps(values["details"], sort_keys=True)


def run_events_to_csv(rows: list[RunEvent], *, header: bool) -> str:
    return rows_to_csv(rows, RUN_EVENT_CSV_FIELDS, header=header, flatten=_flatten_event)


@dataclass(frozen=True)
class RunEventSelection:
    run_db_id: int
    run_uuid: str


def select_run_events(run_id: str) -> RunEventSelection:
    """The event log of one run; 400 for a malformed run id, 404 for an unknown run."""
    run_uuid = _validate_run_id(run_id)
    run_db_id = get_db().execute(select(SVSRun.id).where(SVSRun.uuid == run_uuid)).scalar_one_or_none()
    if run_db_id is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")

    return RunEventSelection(run_db_id=run_db_id, run_uuid=run_uuid)


def _parse_event_id(payload: dict) -> int:
    (event_id,) = payload["k"]
    return int(event_id)


def fetch_run_events_page(selection: RunEventSelection, cursor: str | None,
                          limit: int) -> tuple[list[RunEvent], str | None]:
    """One page of a run's event log, oldest first. Raises InvalidCursor."""
    statement = _events_statement().where(SVSRunEvent.run_id == selection.run_db_id)
    if cursor is not None:
        statement = statement.where(SVSRunEvent.id > decode_cursor(cursor, _parse_event_id))

    rows = get_db().execute(statement.order_by(SVSRunEvent.id).limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(k=[rows[-1][0].id])

    return [_event(row) for row in rows], next_cursor


@dataclass(frozen=True)
class EventFeed:
    statement: Select


def prepare_event_feed(filter_params: list[str], *, changed_since: datetime | None, tz) -> EventFeed:
    """The events of every run the runs screen's filters (`f=`) match. Raises InvalidListingRequest."""
    statement = _events_statement()
    for condition in _filter_conditions(filter_params, tz):
        statement = statement.where(condition)

    if changed_since is not None:
        statement = statement.where(SVSRunEvent.updated_at >= to_utc_naive(changed_since))

    return EventFeed(statement=statement)


def _parse_feed_key(payload: dict) -> tuple[datetime, int]:
    updated_at, event_id = payload["k"]
    return datetime.fromisoformat(updated_at), int(event_id)


def fetch_event_feed_page(feed: EventFeed, cursor: str | None, limit: int) -> tuple[list[RunEvent], str | None]:
    """One page of the feed in (updated_at, id) order, settled rows only. Raises InvalidCursor."""
    statement = feed.statement.where(settled(SVSRunEvent.updated_at, CHANGED_SINCE_SETTLE_SECONDS))
    if cursor is not None:
        updated_at, event_id = decode_cursor(cursor, _parse_feed_key)
        statement = statement.where(or_(
            SVSRunEvent.updated_at > updated_at,
            and_(SVSRunEvent.updated_at == updated_at, SVSRunEvent.id > event_id)))

    rows = get_db().execute(statement.order_by(SVSRunEvent.updated_at, SVSRunEvent.id).limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1][0]
        next_cursor = encode_cursor(k=[last.updated_at.isoformat(), last.id])

    return [_event(row) for row in rows], next_cursor


#
# results: one run's in id order, and the feed over every run's in (updated_at, id) order
#

def _results_statement() -> Select:
    return select(SVSRunResult, SVSRun.uuid).join(SVSRun, SVSRun.id == SVSRunResult.run_id)


def _result(row) -> RunResult:
    result, run_uuid = row
    return RunResult(
        id=result.id, run_id=run_uuid, signature_uuid=result.signature_uuid,
        signature_family=result.signature_family, signature_name=result.signature_name, status=result.status,
        alert_count=result.alert_count, late_only=result.late_only, context_only=result.context_only,
        fallback_time=result.fallback_time,
        content_hash=result.content_hash, suppressing_alert_uuid=result.suppressing_alert_uuid,
        reviewed_status=result.reviewed_status,
        reviewed_alert_count=result.reviewed_alert_count, reviewed_late_only=result.reviewed_late_only,
        reviewed_content_hash=result.reviewed_content_hash, updated_at=result.updated_at)


def run_results_to_csv(rows: list[RunResult], *, header: bool) -> str:
    return rows_to_csv(rows, RUN_RESULT_CSV_FIELDS, header=header)


@dataclass(frozen=True)
class RunResultSelection:
    run_db_id: int
    run_uuid: str
    stale: bool
    computed_at: Optional[datetime]


def select_run_results(run_id: str) -> RunResultSelection:
    """The result of one run; 400 for a malformed run id, 404 for an unknown run. A run whose
    result was never computed or marked is not stale (it has none yet)."""
    run_uuid = _validate_run_id(run_id)
    row = get_db().execute(
        select(SVSRun.id, SVSRunResultState.stale, SVSRunResultState.computed_at)
        .outerjoin(SVSRunResultState, SVSRunResultState.run_id == SVSRun.id)
        .where(SVSRun.uuid == run_uuid)).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")

    run_db_id, stale, computed_at = row
    return RunResultSelection(run_db_id=run_db_id, run_uuid=run_uuid, stale=bool(stale), computed_at=computed_at)


def _parse_result_id(payload: dict) -> int:
    (result_id,) = payload["k"]
    return int(result_id)


def fetch_run_results_page(selection: RunResultSelection, cursor: str | None,
                           limit: int) -> tuple[list[RunResult], str | None]:
    """One page of a run's result rows in id order. Raises InvalidCursor."""
    statement = _results_statement().where(SVSRunResult.run_id == selection.run_db_id)
    if cursor is not None:
        statement = statement.where(SVSRunResult.id > decode_cursor(cursor, _parse_result_id))

    rows = get_db().execute(statement.order_by(SVSRunResult.id).limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(k=[rows[-1][0].id])

    return [_result(row) for row in rows], next_cursor


@dataclass(frozen=True)
class ResultFeed:
    statement: Select


def prepare_result_feed(filter_params: list[str], *, changed_since: datetime | None, tz) -> ResultFeed:
    """The result rows of every run the runs screen's filters (`f=`) match. Raises
    InvalidListingRequest."""
    statement = _results_statement()
    for condition in _filter_conditions(filter_params, tz):
        statement = statement.where(condition)

    if changed_since is not None:
        statement = statement.where(SVSRunResult.updated_at >= to_utc_naive(changed_since))

    return ResultFeed(statement=statement)


def fetch_result_feed_page(feed: ResultFeed, cursor: str | None, limit: int) -> tuple[list[RunResult], str | None]:
    """One page of the feed in (updated_at, id) order, settled rows only. Raises InvalidCursor."""
    statement = feed.statement.where(settled(SVSRunResult.updated_at, CHANGED_SINCE_SETTLE_SECONDS))
    if cursor is not None:
        updated_at, result_id = decode_cursor(cursor, _parse_feed_key)
        statement = statement.where(or_(
            SVSRunResult.updated_at > updated_at,
            and_(SVSRunResult.updated_at == updated_at, SVSRunResult.id > result_id)))

    rows = get_db().execute(statement.order_by(SVSRunResult.updated_at, SVSRunResult.id).limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1][0]
        next_cursor = encode_cursor(k=[last.updated_at.isoformat(), last.id])

    return [_result(row) for row in rows], next_cursor


#
# attributions: one run's in id order, and the feed over every run's in (updated_at, id) order
#

def _attributions_statement() -> Select:
    actor, remover, keeper = aliased(User), aliased(User), aliased(User)
    return (select(SVSAttribution, SVSRun.uuid, actor.username, remover.username, keeper.username,
                   cleanup_condition().label("cleanup"))
            .join(SVSRun, SVSRun.id == SVSAttribution.run_id)
            .outerjoin(actor, actor.id == SVSAttribution.actor_user_id)
            .outerjoin(remover, remover.id == SVSAttribution.removed_by_user_id)
            .outerjoin(keeper, keeper.id == SVSAttribution.kept_by_user_id))


def _attribution(row) -> Attribution:
    attribution, run_uuid, actor_user, removed_by_user, kept_by_user, cleanup = row
    return Attribution(
        id=attribution.id, run_id=run_uuid, alert_uuid=attribution.alert_uuid, detection=attribution.content_hash,
        signature_uuid=attribution.signature_uuid, signature_family=attribution.signature_family,
        confidence=attribution.confidence, late=attribution.late, event_time=attribution.event_time,
        cleanup=bool(cleanup), event_time_source=attribution.event_time_source,
        fallback_time=attribution.event_time_source in FALLBACK_EVENT_TIME_SOURCES, source=attribution.source,
        scan_point=attribution.scan_point, actor=attribution.actor, actor_user=actor_user,
        created_at=attribution.created_at, removed_at=attribution.removed_at, removed_by=attribution.removed_by,
        removed_by_user=removed_by_user, removal_reason=attribution.removal_reason, kept_at=attribution.kept_at,
        kept_by_user=kept_by_user, updated_at=attribution.updated_at)


def attributions_to_csv(rows: list[Attribution], *, header: bool) -> str:
    return rows_to_csv(rows, ATTRIBUTION_CSV_FIELDS, header=header)


def select_run_attributions(run_id: str) -> RunEventSelection:
    """The attributions of one run; 400 for a malformed run id, 404 for an unknown run."""
    return select_run_events(run_id)


def fetch_run_attributions_page(selection: RunEventSelection, cursor: str | None,
                                limit: int) -> tuple[list[Attribution], str | None]:
    """One page of a run's attributions in id order, removed ones included. Raises InvalidCursor."""
    statement = _attributions_statement().where(SVSAttribution.run_id == selection.run_db_id)
    if cursor is not None:
        statement = statement.where(SVSAttribution.id > decode_cursor(cursor, _parse_result_id))

    rows = get_db().execute(statement.order_by(SVSAttribution.id).limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(k=[rows[-1][0].id])

    return [_attribution(row) for row in rows], next_cursor


#
# the run page: the run's alerts, and how its signatures did in the test's earlier runs
#

def _run_alert(alert_uuid: str, alert, attributions: list[Attribution], detections: list) -> RunAlert:
    holding = [a for a in attributions if a.removed_at is None]
    context = [a for a in holding if a.confidence == AttributionConfidence.CONTEXT.value]
    confidence = None
    if holding:
        confidence = (AttributionConfidence.CONTEXT.value if len(context) == len(holding)
                      else AttributionConfidence.MARKER.value)

    by_hash = {a.detection: a for a in attributions}
    rows = [RunAlertDetection(detection=content_hash, description=description, signature_uuid=signature_uuid,
                              signature_family=signature_family, attribution=by_hash.pop(content_hash, None))
            for content_hash, description, signature_uuid, signature_family in detections]
    # attributed detections the alert no longer has
    rows.extend(RunAlertDetection(detection=a.detection, signature_uuid=a.signature_uuid,
                                  signature_family=a.signature_family, attribution=a) for a in by_hash.values())
    return RunAlert(
        alert_uuid=alert_uuid, alert=alert, holds=bool(holding), confidence=confidence,
        late=any(a.late for a in holding), cleanup=bool(holding) and all(a.cleanup for a in holding),
        fallback_time=any(a.fallback_time for a in holding),
        manual=any(a.source == "manual" for a in holding),
        kept=any(a.kept_at is not None for a in context),
        undecided_context=any(a.kept_at is None for a in context), detections=rows)


def fetch_run_alerts_page(selection: RunEventSelection, cursor: str | None,
                          limit: int) -> tuple[list[RunAlert], str | None]:
    """One page of the alerts the run holds or held, in the order they were first attributed to
    it. Raises InvalidCursor."""
    db = get_db()
    first_id = func.min(SVSAttribution.id)
    statement = (select(SVSAttribution.alert_uuid, first_id)
                 .where(SVSAttribution.run_id == selection.run_db_id)
                 .group_by(SVSAttribution.alert_uuid))
    if cursor is not None:
        statement = statement.having(first_id > decode_cursor(cursor, _parse_result_id))

    keys = db.execute(statement.order_by(first_id).limit(limit + 1)).all()
    next_cursor = None
    if len(keys) > limit:
        keys = keys[:limit]
        next_cursor = encode_cursor(k=[keys[-1][1]])
    alert_uuids = [alert_uuid for alert_uuid, _ in keys]
    if not alert_uuids:
        return [], next_cursor

    attributions: dict[str, list[Attribution]] = {}
    for row in db.execute(_attributions_statement()
                          .where(SVSAttribution.run_id == selection.run_db_id,
                                 SVSAttribution.alert_uuid.in_(alert_uuids))
                          .order_by(SVSAttribution.id)):
        attribution = _attribution(row)
        attributions.setdefault(attribution.alert_uuid, []).append(attribution)

    alert_ids = dict(db.execute(select(Alert.id, Alert.uuid).where(Alert.uuid.in_(alert_uuids))).all())
    alerts = {row.uuid: row for row in load_alert_rows(list(alert_ids))}
    detections: dict[str, list] = {}
    for alert_id, *detection in db.execute(
            select(DetectionPoint.alert_id, DetectionPoint.content_hash, DetectionPoint.description,
                   DetectionPoint.signature_uuid, DetectionPoint.signature_family)
            .where(DetectionPoint.alert_id.in_(list(alert_ids)))
            .order_by(DetectionPoint.id)):
        detections.setdefault(alert_ids[alert_id], []).append(detection)

    return [_run_alert(alert_uuid, alerts.get(alert_uuid), attributions.get(alert_uuid, []),
                       detections.get(alert_uuid, []))
            for alert_uuid in alert_uuids], next_cursor


RUN_HISTORY_MAX_RUNS = 50
HISTORY_STATES = (RunState.ENDED.value, RunState.REVIEWED.value)


def run_history(run_id: str, max_runs: int) -> RunHistory:
    """How each signature of the run's result did in the test's ended and reviewed runs on the
    run's platform (the only runs it is compared with) registered before it, the latest max_runs of
    them; 400 for a malformed run id, 404 for an unknown run."""
    run_uuid = _validate_run_id(run_id)
    db = get_db()
    run = db.execute(select(SVSRun.id, SVSRun.test_guid, SVSRun.platform, SVSRun.created_at)
                     .where(SVSRun.uuid == run_uuid)).first()
    if run is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")

    signatures = list(db.execute(select(SVSRunResult.signature_uuid)
                                 .where(SVSRunResult.run_id == run.id)
                                 .order_by(SVSRunResult.id)).scalars())
    earlier = db.execute(
        select(SVSRun.id, SVSRun.uuid, SVSRun.state, SVSRun.created_at, SVSRun.reviewed_at)
        .where(SVSRun.test_guid == run.test_guid, SVSRun.platform == run.platform, SVSRun.state.in_(HISTORY_STATES),
               or_(SVSRun.created_at < run.created_at,
                   and_(SVSRun.created_at == run.created_at, SVSRun.id < run.id)))
        .order_by(SVSRun.created_at.desc(), SVSRun.id.desc())
        .limit(max_runs)).all()

    statuses: dict[tuple[int, str], Optional[str]] = {}
    if earlier and signatures:
        reviewed = {row.id for row in earlier if row.state == RunState.REVIEWED.value}
        for run_db_id, signature_uuid, status, reviewed_status in db.execute(
                select(SVSRunResult.run_id, SVSRunResult.signature_uuid, SVSRunResult.status,
                       SVSRunResult.reviewed_status)
                .where(SVSRunResult.run_id.in_([row.id for row in earlier]),
                       SVSRunResult.signature_uuid.in_(signatures))):
            statuses[(run_db_id, signature_uuid)] = reviewed_status if run_db_id in reviewed else status

    return RunHistory(
        runs=[HistoryRun(run_id=row.uuid, state=row.state, created_at=row.created_at, reviewed_at=row.reviewed_at)
              for row in earlier],
        signatures=[SignatureHistory(signature_uuid=signature_uuid,
                                     statuses=[statuses.get((row.id, signature_uuid)) for row in earlier])
                    for signature_uuid in signatures])


@dataclass(frozen=True)
class AttributionFeed:
    statement: Select


def prepare_attribution_feed(filter_params: list[str], *, changed_since: datetime | None, tz) -> AttributionFeed:
    """The attributions of every run the runs screen's filters (`f=`) match. Raises
    InvalidListingRequest."""
    statement = _attributions_statement()
    for condition in _filter_conditions(filter_params, tz):
        statement = statement.where(condition)

    if changed_since is not None:
        statement = statement.where(SVSAttribution.updated_at >= to_utc_naive(changed_since))

    return AttributionFeed(statement=statement)


def fetch_attribution_feed_page(feed: AttributionFeed, cursor: str | None,
                                limit: int) -> tuple[list[Attribution], str | None]:
    """One page of the feed in (updated_at, id) order, settled rows only. Raises InvalidCursor."""
    statement = feed.statement.where(settled(SVSAttribution.updated_at, CHANGED_SINCE_SETTLE_SECONDS))
    if cursor is not None:
        updated_at, row_id = decode_cursor(cursor, _parse_feed_key)
        statement = statement.where(or_(
            SVSAttribution.updated_at > updated_at,
            and_(SVSAttribution.updated_at == updated_at, SVSAttribution.id > row_id)))

    rows = get_db().execute(statement.order_by(SVSAttribution.updated_at, SVSAttribution.id).limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1][0]
        next_cursor = encode_cursor(k=[last.updated_at.isoformat(), last.id])

    return [_attribution(row) for row in rows], next_cursor


#
# a person's association changes (svs:run_manage)
#

def change_association(action: str, run_id: str, alert_uuid: str, body: AssociationRequest | None,
                       auth: ApiAuthResult) -> AssociationResult:
    """associate, disassociate, not-a-test or keep on (run, alert). 422 for a config key (a change records who made
    it), 400 for a malformed id, 404 for an unknown run or alert, 409 when it doesn't apply."""
    _require_user(auth.auth_user_id)
    run_uuid = _validate_run_id(run_id)
    if not UUID_REGEX.fullmatch(alert_uuid.lower()):
        raise HTTPException(status_code=400, detail="invalid alert uuid")
    reason = body.reason if body is not None else None

    try:
        if action == "associate":
            result = association.associate(run_uuid, alert_uuid.lower(), auth, reason)
        elif action == "disassociate":
            result = association.disassociate(run_uuid, alert_uuid.lower(), auth, reason)
        elif action == "not-a-test":
            result = association.disassociate(run_uuid, alert_uuid.lower(), auth, reason, not_a_test=True)
        else:
            result = association.keep(run_uuid, alert_uuid.lower(), auth)
    except (runs.UnknownRun, association.UnknownAlert) as e:
        raise HTTPException(status_code=404, detail=str(e))
    except association.AssociationConflict as e:
        raise HTTPException(status_code=409, detail=str(e))
    except association.InvalidAssociation as e:
        raise HTTPException(status_code=422, detail=str(e))

    return AssociationResult(alert_uuid=result.alert_uuid, svs_status=result.svs_status, queue=result.queue,
                             moved=result.moved, reopened=result.reopened)


#
# a person's actions on runs (svs:run_manage): ownership, cancel, close, review, comments
#

def _require_user(user_id: int | None) -> int:
    # every action records who took it; a config API key belongs to nobody
    if user_id is None:
        raise HTTPException(status_code=422, detail="this action records who took it: it requires a user's API key or session")
    return user_id


def _user_ids(usernames) -> dict[str, int]:
    usernames = {name for name in usernames if name}
    if not usernames:
        return {}
    return dict(get_db().execute(select(User.username, User.id).where(User.username.in_(usernames))).all())


def _confirmed_takes(body: BulkRunRequest) -> dict[str, int]:
    """run uuid -> the owner's user id, from the usernames the caller agreed to take runs from."""
    ids = _user_ids(body.confirmed_takes.values())
    return {run_id.lower(): ids[name] for run_id, name in body.confirmed_takes.items() if name in ids}


def _bulk_result(result) -> BulkRunResult:
    return BulkRunResult(done=result.done, left_alone=result.left_alone, conflicts=result.conflicts,
                         unknown=result.unknown)


def _run_ids(body: BulkRunRequest) -> list[str]:
    run_ids = [run_id.lower() for run_id in body.run_ids]
    for run_id in run_ids:
        if not UUID_REGEX.fullmatch(run_id):
            raise HTTPException(status_code=400, detail=f"invalid run id {run_id!r}")
    return run_ids


def take_runs(body: BulkRunRequest, user_id: int | None, actor: str) -> BulkRunResult:
    user_id = _require_user(user_id)
    return _bulk_result(review.take_ownership(_run_ids(body), user_id, actor, _confirmed_takes(body)))


def cancel_runs(body: BulkRunRequest, user_id: int | None, actor: str) -> BulkRunResult:
    user_id = _require_user(user_id)
    return _bulk_result(review.cancel_runs(_run_ids(body), user_id, actor, _confirmed_takes(body)))


def close_runs(body: BulkRunRequest, user_id: int | None, actor: str) -> BulkRunResult:
    user_id = _require_user(user_id)
    return _bulk_result(review.close_runs(_run_ids(body), user_id, actor, body.reason, _confirmed_takes(body)))


def review_run(run_id: str, body: ReviewRequest | None, user_id: int | None, actor: str) -> ReviewResult:
    """404 for an unknown run; 409 with what stands in the way: another person's ownership, the
    run's state, a stale result, undecided candidates or context-only alerts."""
    user_id = _require_user(user_id)
    run_uuid = _validate_run_id(run_id)
    confirmed_from = None
    if body is not None and body.confirmed_take_from:
        confirmed_from = _user_ids([body.confirmed_take_from]).get(body.confirmed_take_from)

    try:
        result = review.review(run_uuid, user_id, actor, confirmed_from)
    except runs.UnknownRun as e:
        raise HTTPException(status_code=404, detail=str(e))
    except review.RunOwned as e:
        raise HTTPException(status_code=409, detail={"message": str(e), "owner": e.owner})
    except runs.RunStateConflict as e:
        raise HTTPException(status_code=409, detail={"message": str(e), "state": e.state})
    except review.ReviewBlocked as e:
        raise HTTPException(status_code=409, detail={"message": str(e), **e.blockers})

    return ReviewResult(run=get_detail(run_uuid), re_review=result.re_review, counts=result.counts,
                        alerts_closed=result.alerts_closed, fp_verdicts=result.fp_verdicts)


def _comment(row, run_uuid: str) -> RunComment:
    username = None
    if row.user_id is not None:
        username = get_db().execute(select(User.username).where(User.id == row.user_id)).scalar()
    return RunComment(id=row.id, run_id=run_uuid, user=username, comment=row.comment, created_at=row.created_at,
                      updated_at=row.updated_at)


def _comment_errors(e: Exception) -> HTTPException:
    if isinstance(e, (runs.UnknownRun, run_comments.UnknownComment)):
        return HTTPException(status_code=404, detail=str(e))
    if isinstance(e, run_comments.NotTheAuthor):
        return HTTPException(status_code=403, detail=str(e))
    return HTTPException(status_code=422, detail=str(e))


COMMENT_ERRORS = (runs.UnknownRun, run_comments.UnknownComment, run_comments.NotTheAuthor, run_comments.InvalidComment)


def list_run_comments(run_id: str) -> list[RunComment]:
    run_uuid = _validate_run_id(run_id)
    try:
        return [_comment(row, run_uuid) for row in run_comments.list_comments(run_uuid)]
    except COMMENT_ERRORS as e:
        raise _comment_errors(e)


def add_run_comment(run_id: str, body: RunCommentRequest, user_id: int | None, actor: str) -> RunComment:
    user_id = _require_user(user_id)
    run_uuid = _validate_run_id(run_id)
    try:
        return _comment(run_comments.add_comment(run_uuid, user_id, actor, body.comment), run_uuid)
    except COMMENT_ERRORS as e:
        raise _comment_errors(e)


def update_run_comment(run_id: str, comment_id: int, body: RunCommentRequest, user_id: int | None,
                       actor: str) -> RunComment:
    user_id = _require_user(user_id)
    run_uuid = _validate_run_id(run_id)
    try:
        return _comment(run_comments.update_comment(run_uuid, comment_id, user_id, actor, body.comment), run_uuid)
    except COMMENT_ERRORS as e:
        raise _comment_errors(e)


def delete_run_comment(run_id: str, comment_id: int, user_id: int | None, actor: str) -> None:
    user_id = _require_user(user_id)
    run_uuid = _validate_run_id(run_id)
    try:
        run_comments.delete_comment(run_uuid, comment_id, user_id, actor)
    except COMMENT_ERRORS as e:
        raise _comment_errors(e)
