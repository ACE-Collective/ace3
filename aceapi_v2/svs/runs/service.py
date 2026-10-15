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
from sqlalchemy import Select, and_, or_, select
from sqlalchemy.orm import aliased, selectinload

from aceapi_v2.common.listing import (
    CHANGED_SINCE_SETTLE_SECONDS,
    InvalidCursor,
    InvalidListingRequest,
    decode_cursor,
    encode_cursor,
    rows_to_csv,
    settled,
)
from aceapi_v2.svs.runs.schemas import (
    RUN_EVENT_CSV_FIELDS,
    RUN_RESULT_CSV_FIELDS,
    RUN_ROW_CSV_FIELDS,
    RunDetail,
    RunEvent,
    RunExecutedRequest,
    RunLifecycle,
    RunRegistrationRequest,
    RunResult,
    RunRow,
    RunTarget,
)
from saq.database.model import SVSCatalogTest, SVSRun, SVSRunEvent, SVSRunResult, SVSRunResultState, User
from saq.database.pool import get_db
from saq.gui.filter_screens import SVS_RUNS_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.svs import runs
from saq.svs.refusals import Caller
from saq.svs.run_filters import needs_attention_condition, run_filter_conditions
from saq.svs.samples import to_utc_naive
from saq.util.uuid import UUID_REGEX

logger = logging.getLogger(__name__)


def _target(target) -> RunTarget:
    return RunTarget(hostname=target.hostname, username=target.username, host=target.host, fqdn=target.fqdn,
                     user=target.user)


def _lifecycle(run: SVSRun) -> RunLifecycle:
    return RunLifecycle(
        run_id=run.uuid, marker=run.marker, state=run.state, test_guid=run.test_guid,
        targets=[_target(t) for t in run.targets],
        observation_seconds=run.observation_seconds, attribution_seconds=run.attribution_seconds,
        created_at=run.created_at, started_at=run.started_at, observation_ends_at=run.observation_ends_at,
        attribution_ends_at=run.attribution_ends_at, error_reason=run.error_reason, close_reason=run.close_reason)


def _call(fn, *args, **kwargs) -> RunLifecycle:
    try:
        return _lifecycle(fn(*args, **kwargs))
    except runs.UnknownRun as e:
        raise HTTPException(status_code=404, detail=str(e))
    except runs.RunStateConflict as e:
        raise HTTPException(status_code=409, detail={"message": str(e), "state": e.state})


def register(body: RunRegistrationRequest, caller: Caller) -> RunLifecycle:
    registration = runs.Registration(
        test_guid=body.test_guid,
        targets=[runs.TargetSpec(hostname=t.hostname, username=t.username) for t in body.targets],
        launcher=body.launcher, batch_id=body.batch_id, extra=body.extra)
    try:
        return _lifecycle(runs.register(registration, caller))
    except runs.InvalidRegistration as e:
        raise HTTPException(status_code=422, detail=str(e))
    except runs.RegistrationRefused as e:
        raise HTTPException(status_code=403, detail={"message": "registration refused", "reasons": e.reasons})


def start(run_id: str, caller: Caller) -> RunLifecycle:
    return _call(runs.start, run_id, caller)


def executed(run_id: str, body: RunExecutedRequest, caller: Caller) -> RunLifecycle:
    return _call(runs.executed, run_id, caller, body.exit_code, body.error)


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
        technique_name=technique_name, marker=run.marker, targets=[_target(t) for t in run.targets],
        launcher=run.launcher, batch_id=run.batch_id, created_at=run.created_at, started_at=run.started_at,
        executed_at=run.executed_at, exit_code=run.exit_code, ended_at=run.ended_at, canceled_at=run.canceled_at,
        closed_at=run.closed_at, observation_ends_at=run.observation_ends_at,
        attribution_ends_at=run.attribution_ends_at, error_reason=run.error_reason, close_reason=run.close_reason,
        owner=owner, reviewer=reviewer, reviewed_at=run.reviewed_at, changed_since_review=run.changed_since_review,
        needs_attention=bool(needs_attention), updated_at=run.updated_at)


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

    return [RunRow(**_row_values(row)) for row in rows], next_cursor


def _flatten_run(values: dict) -> None:
    values["targets"] = ",".join(
        f"{t['hostname']}/{t['username']}" if t["username"] else t["hostname"] for t in values["targets"])


def run_rows_to_csv(rows: list[RunRow], *, header: bool) -> str:
    return rows_to_csv(rows, RUN_ROW_CSV_FIELDS, header=header, flatten=_flatten_run)


#
# one run
#

def get_detail(run_id: str) -> RunDetail:
    row = get_db().execute(_runs_statement().where(SVSRun.uuid == _validate_run_id(run_id))).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")

    run = row[0]
    registrar = get_db().get(User, run.registered_by) if run.registered_by is not None else None
    return RunDetail(
        **_row_values(row), extra=_json(run.extra), launcher_error=run.launcher_error,
        test_content_hash=run.test_content_hash, catalog_commit=run.catalog_commit,
        observation_seconds=run.observation_seconds, attribution_seconds=run.attribution_seconds,
        registered_by=registrar.username if registrar is not None else None)


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
        content_hash=result.content_hash, suppressing_alert_uuid=result.suppressing_alert_uuid,
        suppression_imprecise=result.suppression_imprecise, reviewed_status=result.reviewed_status,
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
