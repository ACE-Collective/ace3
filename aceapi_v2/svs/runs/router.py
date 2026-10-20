"""SVS test runs router for ACE API v2 (docs/SVS_RUNS.md, *Registering a run*; docs/SVS_API.md).

The launcher's lifecycle calls: register a run, start it, report how the test executed, cancel it.
Every call needs svs:run_register [ART-2]. A registration against a host that is not a test host is
refused with 403 and alerts (docs/SVS_RUNS.md, *Refused registrations*).

Reading runs, each run's event log, result, attributions and alerts, how its signatures did in the
test's earlier runs, and the feeds of those over every run needs svs:run_read; the runs screen's filters (`f=`) apply to the runs and to the feeds, and pick
the runs that the count and the batches (one row per batch_id) are over. A person's
actions need svs:run_manage: associating an alert with a run by hand, disassociating it, marking it
not a test and keeping a context attribution (docs/SVS_RUNS.md, *Associating alerts by hand*), and
taking, canceling, closing and reviewing runs and commenting on them (*Reviewing runs*).
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import (
    LISTING_MAX_PAGE_SIZE,
    csv_response,
    ndjson_response,
    parse_timezone,
    run_listing,
    start_export,
)
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.svs.runs import service
from aceapi_v2.svs.runs.schemas import (
    AssociationRequest,
    AssociationResult,
    AttributionPage,
    BulkRunRequest,
    BulkRunResult,
    ReviewRequest,
    ReviewResult,
    RunAlertPage,
    RunComment,
    RunCommentRequest,
    RunDetail,
    RunEventPage,
    RunExecutedRequest,
    RunHistory,
    RunLifecycle,
    RunBatchPage,
    RunCount,
    RunPage,
    RunRegistrationRequest,
    RunResultPage,
    SuppressionShare,
)
from aceapi_v2.sync import run_db_in_thread
from saq.svs.refusals import Caller

router = APIRouter(dependencies=[Security(get_current_auth)])

RegisterAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_register"))]
ReadAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))]
ManageAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_manage"))]

FilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the runs screen's slugs: "
                "needs_attention, state, test, test_name, technique (T1059 also finds its sub-techniques), target, "
                "platform, launcher, batch, created, started, ended, reviewed, owner, reviewer, reason, "
                "changed_since_review, "
                "has_open_alerts, has_missing, has_possibly_suppressed, has_candidates, has_late, has_context_only "
                "(see docs/SVS_API.md); repeat for more. Filters are ANDed, the values of one ORed.")]
TimezoneParam = Annotated[str, Query(description="the timezone relative date filters (`-7d`, `@d`) resolve in")]
CursorParam = Annotated[str | None, Query(description="the next_cursor of the previous page")]
LimitParam = Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)]
RunsChangedSinceParam = Annotated[datetime | None, Query(
    description="only runs registered or changed at or after this time (UTC if no offset is given); the pages "
                "are then in (updated_at, id) order")]
EventsChangedSinceParam = Annotated[datetime | None, Query(
    description="only events written at or after this time (UTC if no offset is given)")]
ResultsChangedSinceParam = Annotated[datetime | None, Query(
    description="only result rows written or changed at or after this time (UTC if no offset is given)")]
AttributionsChangedSinceParam = Annotated[datetime | None, Query(
    description="only attributions written, removed or kept at or after this time (UTC if no offset is given)")]


def _caller(auth: ApiAuthResult, request: Request) -> Caller:
    return Caller(name=auth.auth_name, user_id=auth.auth_user_id, key_id=auth.key_id,
                  address=request.client.host if request.client is not None else None)


#
# a person's bulk actions (svs:run_manage); declared before /{run_id}/cancel, which would take
# "bulk" for a run id
#

@router.post("/bulk/take-ownership", response_model=BulkRunResult)
async def take_ownership(body: BulkRunRequest, auth: ManageAuth) -> BulkRunResult:
    """Take the runs. One someone else owns is left alone unless confirmed_takes names that owner;
    one whose owner's account is disabled is taken without asking."""
    return await run_db_in_thread(service.take_runs, body, auth.auth_user_id, auth.auth_name)


@router.post("/bulk/cancel", response_model=BulkRunResult)
async def cancel_runs(body: BulkRunRequest, auth: ManageAuth) -> BulkRunResult:
    """Cancel the runs (created or started), as the launcher would. A run someone else owns is left
    alone unless confirmed_takes names that owner, and then becomes the caller's."""
    return await run_db_in_thread(service.cancel_runs, body, auth.auth_user_id, auth.auth_name)


@router.post("/bulk/close", response_model=BulkRunResult)
async def close_runs(body: BulkRunRequest, auth: ManageAuth) -> BulkRunResult:
    """Close the runs (ended, canceled or error): nothing is learned from them and their alerts
    become SIMULATED. An ended run needs a reason. Ownership as for cancel."""
    return await run_db_in_thread(service.close_runs, body, auth.auth_user_id, auth.auth_name)


#
# the count, the batches and the suppression share; declared before /{run_id}, which would take
# "count", "batches" and "suppression-share" for a run id
#

@router.get("/count", response_model=RunCount)
async def count_runs(auth: ReadAuth, f: FilterParam, tz: TimezoneParam = "UTC") -> RunCount:
    """How many runs the filters match: f=needs_attention:true is the count on the GUI's SVS entry."""
    return await run_listing(service.count_runs, f, parse_timezone(tz))


@router.get("/suppression-share", response_model=SuppressionShare)
async def get_suppression_share(auth: ReadAuth) -> SuppressionShare:
    """How many of the expected signatures missing from reviewed runs were possibly suppressed, and
    whether the revisit trigger is reached (docs/SVS_API.md, *Suppression share*)."""
    return await run_db_in_thread(service.get_suppression_share)


async def _prepare_batches(f: list[str], tz: str) -> service.BatchListing:
    return await run_listing(service.prepare_batch_listing, f, tz=parse_timezone(tz))


@router.get("/batches", response_model=RunBatchPage)
async def list_batches(
    auth: ReadAuth,
    f: FilterParam,
    cursor: CursorParam = None,
    limit: LimitParam = 100,
    tz: TimezoneParam = "UTC",
) -> RunBatchPage:
    """One row per batch_id over the runs the filters match, summing only those runs: their states,
    how many need attention, and their results. The batch with the latest run comes first; runs
    without a batch_id are left out. Follow next_cursor, with the same filters, until it is null."""
    listing = await _prepare_batches(f, tz)
    rows, next_cursor = await run_listing(service.fetch_batch_page, listing, cursor, limit)
    return RunBatchPage(data=rows, next_cursor=next_cursor)


# the GUI's list pages request {api}/
router.add_api_route("/batches/", list_batches, methods=["GET"], response_model=RunBatchPage,
                     include_in_schema=False)


@router.get("/batches/export/ndjson", response_class=NdjsonStreamResponse)
async def export_batches_ndjson(auth: ReadAuth, f: FilterParam, tz: TimezoneParam = "UTC") -> NdjsonStreamResponse:
    """Stream every batch as NDJSON, one RunBatch per line."""
    listing = await _prepare_batches(f, tz)
    export = await start_export(service.fetch_batch_page, listing, what="svs run batch")
    return ndjson_response(export, "svs-run-batches.ndjson")


@router.get("/batches/export/csv", response_class=CsvStreamResponse)
async def export_batches_csv(auth: ReadAuth, f: FilterParam, tz: TimezoneParam = "UTC") -> CsvStreamResponse:
    """Stream every batch as CSV, with one state_<state> column per state."""
    listing = await _prepare_batches(f, tz)
    export = await start_export(service.fetch_batch_page, listing, what="svs run batch")
    return csv_response(export, service.run_batches_to_csv, "svs-run-batches.csv")


#
# the launcher's calls
#

@router.post("/", response_model=RunLifecycle, status_code=201)
async def register_run(body: RunRegistrationRequest, auth: RegisterAuth, request: Request) -> RunLifecycle:
    """Register a run in state created and get its marker. 422 for a test that is not in the
    catalog, a target whose platform the test doesn't support, or an extra that is too large; 403
    when a target is not a test host or not a user the host lists, which also alerts."""
    return await run_db_in_thread(service.register, body, _caller(auth, request))


@router.post("/{run_id}/start", response_model=RunLifecycle)
async def start_run(run_id: str, auth: RegisterAuth, request: Request) -> RunLifecycle:
    """created -> started: the windows start now. 409 in any other state."""
    return await run_db_in_thread(service.start, run_id, _caller(auth, request))


@router.post("/{run_id}/executed", response_model=RunLifecycle)
async def run_executed(run_id: str, body: RunExecutedRequest, auth: RegisterAuth, request: Request) -> RunLifecycle:
    """Report how the test executed on a started run. A non-zero exit code or an error moves it to
    error. 409 in any other state."""
    return await run_db_in_thread(service.executed, run_id, body, _caller(auth, request))


@router.post("/{run_id}/cancel", response_model=RunLifecycle)
async def cancel_run(run_id: str, auth: RegisterAuth, request: Request) -> RunLifecycle:
    """created or started -> canceled. A canceled run keeps attributing until its attribution window
    ends; one canceled before it started is closed at once. 409 in any other state."""
    return await run_db_in_thread(service.cancel, run_id, _caller(auth, request))


#
# the listing and its exports
#

async def _prepare_listing(f: list[str], changed_since: datetime | None, tz: str) -> service.RunListing:
    return await run_listing(service.prepare_listing, f, changed_since=changed_since, tz=parse_timezone(tz))


@router.get("/", response_model=RunPage)
async def list_runs(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: RunsChangedSinceParam = None,
    cursor: CursorParam = None,
    limit: LimitParam = 100,
    tz: TimezoneParam = "UTC",
) -> RunPage:
    """List runs, newest first (by updated_at with changed_since). Follow next_cursor, with the same
    filters and changed_since, until it is null."""
    listing = await _prepare_listing(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_page, listing, cursor, limit)
    return RunPage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_runs_ndjson(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: RunsChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream every run the listing matches as NDJSON, one RunRow per line; a failure part-way ends
    the stream with an {"error": ...} line."""
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_page, listing, what="svs run")
    return ndjson_response(export, "svs-runs.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_runs_csv(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: RunsChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream every run the listing matches as CSV (targets joined as host or host/user with ","); a
    failure part-way truncates it."""
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_page, listing, what="svs run")
    return csv_response(export, service.run_rows_to_csv, "svs-runs.csv")


#
# the event feed over every run
#

async def _prepare_feed(f: list[str], changed_since: datetime | None, tz: str) -> service.EventFeed:
    return await run_listing(service.prepare_event_feed, f, changed_since=changed_since, tz=parse_timezone(tz))


@router.get("/events", response_model=RunEventPage)
async def list_events(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: EventsChangedSinceParam = None,
    cursor: CursorParam = None,
    limit: LimitParam = 100,
    tz: TimezoneParam = "UTC",
) -> RunEventPage:
    """The events of every run the filters match, in (updated_at, id) order: the runs' change feed.
    An event shows up a few seconds after it is written, so a pull resumed from its last
    updated_at never misses one (and may repeat one)."""
    feed = await _prepare_feed(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_event_feed_page, feed, cursor, limit)
    return RunEventPage(data=rows, next_cursor=next_cursor)


@router.get("/events/export/ndjson", response_class=NdjsonStreamResponse)
async def export_events_ndjson(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: EventsChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream the feed as NDJSON, one RunEvent per line."""
    feed = await _prepare_feed(f, changed_since, tz)
    export = await start_export(service.fetch_event_feed_page, feed, what="svs run event")
    return ndjson_response(export, "svs-run-events.ndjson")


@router.get("/events/export/csv", response_class=CsvStreamResponse)
async def export_events_csv(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: EventsChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream the feed as CSV (details as a JSON string)."""
    feed = await _prepare_feed(f, changed_since, tz)
    export = await start_export(service.fetch_event_feed_page, feed, what="svs run event")
    return csv_response(export, service.run_events_to_csv, "svs-run-events.csv")


#
# the result feed over every run
#

async def _prepare_result_feed(f: list[str], changed_since: datetime | None, tz: str) -> service.ResultFeed:
    return await run_listing(service.prepare_result_feed, f, changed_since=changed_since, tz=parse_timezone(tz))


@router.get("/results", response_model=RunResultPage)
async def list_results(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: ResultsChangedSinceParam = None,
    cursor: CursorParam = None,
    limit: LimitParam = 100,
    tz: TimezoneParam = "UTC",
) -> RunResultPage:
    """The result rows of every run the filters match, in (updated_at, id) order: what reports pull.
    A row shows up a few seconds after it is written, so a pull resumed from its last updated_at
    never misses one (and may repeat one)."""
    feed = await _prepare_result_feed(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_result_feed_page, feed, cursor, limit)
    return RunResultPage(data=rows, next_cursor=next_cursor)


@router.get("/results/export/ndjson", response_class=NdjsonStreamResponse)
async def export_results_ndjson(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: ResultsChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream the result feed as NDJSON, one RunResult per line."""
    feed = await _prepare_result_feed(f, changed_since, tz)
    export = await start_export(service.fetch_result_feed_page, feed, what="svs run result")
    return ndjson_response(export, "svs-run-results.ndjson")


@router.get("/results/export/csv", response_class=CsvStreamResponse)
async def export_results_csv(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: ResultsChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream the result feed as CSV."""
    feed = await _prepare_result_feed(f, changed_since, tz)
    export = await start_export(service.fetch_result_feed_page, feed, what="svs run result")
    return csv_response(export, service.run_results_to_csv, "svs-run-results.csv")


#
# the attribution feed over every run
#

async def _prepare_attribution_feed(f: list[str], changed_since: datetime | None,
                                    tz: str) -> service.AttributionFeed:
    return await run_listing(service.prepare_attribution_feed, f, changed_since=changed_since,
                             tz=parse_timezone(tz))


@router.get("/attributions", response_model=AttributionPage)
async def list_attributions(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: AttributionsChangedSinceParam = None,
    cursor: CursorParam = None,
    limit: LimitParam = 100,
    tz: TimezoneParam = "UTC",
) -> AttributionPage:
    """The attributions of every run the filters match, removed ones included, in (updated_at, id)
    order: where reports see what was associated and disassociated."""
    feed = await _prepare_attribution_feed(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_attribution_feed_page, feed, cursor, limit)
    return AttributionPage(data=rows, next_cursor=next_cursor)


@router.get("/attributions/export/ndjson", response_class=NdjsonStreamResponse)
async def export_attributions_ndjson(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: AttributionsChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream the attribution feed as NDJSON, one Attribution per line."""
    feed = await _prepare_attribution_feed(f, changed_since, tz)
    export = await start_export(service.fetch_attribution_feed_page, feed, what="svs attribution")
    return ndjson_response(export, "svs-attributions.ndjson")


@router.get("/attributions/export/csv", response_class=CsvStreamResponse)
async def export_attributions_csv(
    auth: ReadAuth,
    f: FilterParam,
    changed_since: AttributionsChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream the attribution feed as CSV."""
    feed = await _prepare_attribution_feed(f, changed_since, tz)
    export = await start_export(service.fetch_attribution_feed_page, feed, what="svs attribution")
    return csv_response(export, service.attributions_to_csv, "svs-attributions.csv")


#
# one run
#

@router.get("/{run_id}", response_model=RunDetail)
async def get_run(run_id: str, auth: ReadAuth) -> RunDetail:
    """One run with what the launcher sent; its history is GET /{run_id}/events."""
    return await run_db_in_thread(service.get_detail, run_id)


@router.get("/{run_id}/events", response_model=RunEventPage)
async def list_run_events(run_id: str, auth: ReadAuth, cursor: CursorParam = None,
                          limit: LimitParam = 100) -> RunEventPage:
    """The run's event log, oldest first."""
    selection = await run_db_in_thread(service.select_run_events, run_id)
    rows, next_cursor = await run_listing(service.fetch_run_events_page, selection, cursor, limit)
    return RunEventPage(data=rows, next_cursor=next_cursor)


@router.get("/{run_id}/events/export/ndjson", response_class=NdjsonStreamResponse)
async def export_run_events_ndjson(run_id: str, auth: ReadAuth) -> NdjsonStreamResponse:
    """Stream the run's event log as NDJSON."""
    selection = await run_db_in_thread(service.select_run_events, run_id)
    export = await start_export(service.fetch_run_events_page, selection, what="svs run event")
    return ndjson_response(export, f"svs-run-{selection.run_uuid}-events.ndjson")


@router.get("/{run_id}/events/export/csv", response_class=CsvStreamResponse)
async def export_run_events_csv(run_id: str, auth: ReadAuth) -> CsvStreamResponse:
    """Stream the run's event log as CSV (details as a JSON string)."""
    selection = await run_db_in_thread(service.select_run_events, run_id)
    export = await start_export(service.fetch_run_events_page, selection, what="svs run event")
    return csv_response(export, service.run_events_to_csv, f"svs-run-{selection.run_uuid}-events.csv")


@router.get("/{run_id}/results", response_model=RunResultPage)
async def list_run_results(run_id: str, auth: ReadAuth, cursor: CursorParam = None,
                           limit: LimitParam = 100) -> RunResultPage:
    """The run's result, one row per signature (docs/SVS_RUNS.md, *Results*). stale says it is
    about to be recomputed."""
    selection = await run_db_in_thread(service.select_run_results, run_id)
    rows, next_cursor = await run_listing(service.fetch_run_results_page, selection, cursor, limit)
    return RunResultPage(data=rows, next_cursor=next_cursor, stale=selection.stale, computed_at=selection.computed_at)


@router.get("/{run_id}/results/export/ndjson", response_class=NdjsonStreamResponse)
async def export_run_results_ndjson(run_id: str, auth: ReadAuth) -> NdjsonStreamResponse:
    """Stream the run's result as NDJSON."""
    selection = await run_db_in_thread(service.select_run_results, run_id)
    export = await start_export(service.fetch_run_results_page, selection, what="svs run result")
    return ndjson_response(export, f"svs-run-{selection.run_uuid}-results.ndjson")


@router.get("/{run_id}/results/export/csv", response_class=CsvStreamResponse)
async def export_run_results_csv(run_id: str, auth: ReadAuth) -> CsvStreamResponse:
    """Stream the run's result as CSV."""
    selection = await run_db_in_thread(service.select_run_results, run_id)
    export = await start_export(service.fetch_run_results_page, selection, what="svs run result")
    return csv_response(export, service.run_results_to_csv, f"svs-run-{selection.run_uuid}-results.csv")


@router.get("/{run_id}/attributions", response_model=AttributionPage)
async def list_run_attributions(run_id: str, auth: ReadAuth, cursor: CursorParam = None,
                                limit: LimitParam = 100) -> AttributionPage:
    """The run's attributions, one row per (alert, detection), removed ones included."""
    selection = await run_db_in_thread(service.select_run_attributions, run_id)
    rows, next_cursor = await run_listing(service.fetch_run_attributions_page, selection, cursor, limit)
    return AttributionPage(data=rows, next_cursor=next_cursor)


@router.get("/{run_id}/attributions/export/ndjson", response_class=NdjsonStreamResponse)
async def export_run_attributions_ndjson(run_id: str, auth: ReadAuth) -> NdjsonStreamResponse:
    """Stream the run's attributions as NDJSON."""
    selection = await run_db_in_thread(service.select_run_attributions, run_id)
    export = await start_export(service.fetch_run_attributions_page, selection, what="svs attribution")
    return ndjson_response(export, f"svs-run-{selection.run_uuid}-attributions.ndjson")


@router.get("/{run_id}/attributions/export/csv", response_class=CsvStreamResponse)
async def export_run_attributions_csv(run_id: str, auth: ReadAuth) -> CsvStreamResponse:
    """Stream the run's attributions as CSV."""
    selection = await run_db_in_thread(service.select_run_attributions, run_id)
    export = await start_export(service.fetch_run_attributions_page, selection, what="svs attribution")
    return csv_response(export, service.attributions_to_csv, f"svs-run-{selection.run_uuid}-attributions.csv")


@router.get("/{run_id}/alerts", response_model=RunAlertPage)
async def list_run_alerts(run_id: str, auth: ReadAuth, cursor: CursorParam = None,
                          limit: LimitParam = 100) -> RunAlertPage:
    """The alerts the run holds or held, in the order they were first attributed to it: each with
    its row as GET /api/v2/alerts lists it, what its attributions to the run say, and every
    detection with its attribution (docs/SVS_API.md, *Run alerts*)."""
    selection = await run_db_in_thread(service.select_run_events, run_id)
    rows, next_cursor = await run_listing(service.fetch_run_alerts_page, selection, cursor, limit)
    return RunAlertPage(data=rows, next_cursor=next_cursor)


@router.get("/{run_id}/alerts/export/ndjson", response_class=NdjsonStreamResponse)
async def export_run_alerts_ndjson(run_id: str, auth: ReadAuth) -> NdjsonStreamResponse:
    """Stream the run's alerts as NDJSON (they nest, so there is no CSV: GET
    /{run_id}/attributions/export/csv is the flat form)."""
    selection = await run_db_in_thread(service.select_run_events, run_id)
    export = await start_export(service.fetch_run_alerts_page, selection, what="svs run alert")
    return ndjson_response(export, f"svs-run-{selection.run_uuid}-alerts.ndjson")


@router.get("/{run_id}/history", response_model=RunHistory)
async def get_run_history(run_id: str, auth: ReadAuth,
                          runs: Annotated[int, Query(ge=1, le=service.RUN_HISTORY_MAX_RUNS,
                                                     description="how many earlier runs")] = 10) -> RunHistory:
    """How each signature of the run's result did in the test's ended and reviewed runs on the
    run's platform registered before it, latest first (docs/SVS_API.md, *Run history*)."""
    return await run_db_in_thread(service.run_history, run_id, runs)


#
# a person's association changes
#

@router.post("/{run_id}/alerts/{alert_uuid}/associate", response_model=AssociationResult)
async def associate_alert(run_id: str, alert_uuid: str, auth: ManageAuth,
                          body: AssociationRequest | None = None) -> AssociationResult:
    """Attribute every detection of the alert to the run, by hand; the alert moves to the test queue
    when it is OPEN and nobody else has taken it. 409 for a run that never started, 422 for an alert
    without detections."""
    return await run_db_in_thread(service.change_association, "associate", run_id, alert_uuid, body,
                                  auth.auth_user_id, auth.auth_name)


@router.post("/{run_id}/alerts/{alert_uuid}/disassociate", response_model=AssociationResult)
async def disassociate_alert(run_id: str, alert_uuid: str, auth: ManageAuth,
                             body: AssociationRequest | None = None) -> AssociationResult:
    """Remove the alert's attributions to the run, by hand; the router never attributes it to the run
    again. An alert no longer fully attributed is given back: OPEN if it was SIMULATED, and back in
    the queue SVS took it from. 409 when it isn't attributed to the run."""
    return await run_db_in_thread(service.change_association, "disassociate", run_id, alert_uuid, body,
                                  auth.auth_user_id, auth.auth_name)


@router.post("/{run_id}/alerts/{alert_uuid}/not-a-test", response_model=AssociationResult)
async def mark_not_a_test(run_id: str, alert_uuid: str, auth: ManageAuth,
                          body: AssociationRequest | None = None) -> AssociationResult:
    """Disassociate a TEST? alert: one the run holds by context alone (409 otherwise)."""
    return await run_db_in_thread(service.change_association, "not-a-test", run_id, alert_uuid, body,
                                  auth.auth_user_id, auth.auth_name)


@router.post("/{run_id}/alerts/{alert_uuid}/keep", response_model=AssociationResult)
async def keep_context(run_id: str, alert_uuid: str, auth: ManageAuth) -> AssociationResult:
    """Confirm the alert's context attributions to the run (409 when it has none)."""
    return await run_db_in_thread(service.change_association, "keep", run_id, alert_uuid, None,
                                  auth.auth_user_id, auth.auth_name)



#
# review and comments (svs:run_manage; comments are read with svs:run_read)
#

@router.post("/{run_id}/review", response_model=ReviewResult)
async def review_run(run_id: str, auth: ManageAuth, body: ReviewRequest | None = None) -> ReviewResult:
    """Sign the run's result off: an ended run becomes reviewed, a reviewed one is reviewed again.
    Its fully attributed open alerts become SIMULATED and its ignored detections get an FP verdict.
    Reviewing takes the run when nobody owns it. 409 with what stands in the way: another person's
    ownership (owner), the state, a stale result (stale), undecided candidates (candidates), or
    context-only alerts neither kept nor marked not a test (context_alerts)."""
    return await run_db_in_thread(service.review_run, run_id, body, auth.auth_user_id, auth.auth_name)


@router.get("/{run_id}/comments", response_model=list[RunComment])
async def list_run_comments(run_id: str, auth: ReadAuth) -> list[RunComment]:
    """The run's comments, oldest first."""
    return await run_db_in_thread(service.list_run_comments, run_id)


@router.post("/{run_id}/comments", response_model=RunComment, status_code=201)
async def add_run_comment(run_id: str, body: RunCommentRequest, auth: ManageAuth) -> RunComment:
    return await run_db_in_thread(service.add_run_comment, run_id, body, auth.auth_user_id, auth.auth_name)


@router.patch("/{run_id}/comments/{comment_id}", response_model=RunComment)
async def update_run_comment(run_id: str, comment_id: int, body: RunCommentRequest, auth: ManageAuth) -> RunComment:
    """Change a comment; only its author can (403)."""
    return await run_db_in_thread(service.update_run_comment, run_id, comment_id, body, auth.auth_user_id,
                                  auth.auth_name)


@router.delete("/{run_id}/comments/{comment_id}", status_code=204)
async def delete_run_comment(run_id: str, comment_id: int, auth: ManageAuth) -> Response:
    """Delete a comment; only its author can (403)."""
    await run_db_in_thread(service.delete_run_comment, run_id, comment_id, auth.auth_user_id, auth.auth_name)
    return Response(status_code=204)
