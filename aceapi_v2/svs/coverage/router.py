"""ATT&CK coverage router for ACE API v2, at /svs/coverage (docs/SVS_COVERAGE.md, docs/SVS_API.md).

Coverage per technique and platform as service_svs last refreshed it, counted in a summary, one
technique's drill-down, and the daily snapshots with their counts per day or month. Read with
svs:run_read; nothing here writes.
"""

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security

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
from aceapi_v2.svs.coverage import service
from aceapi_v2.svs.coverage.schemas import (
    CoverageHistoryCounts,
    CoverageHistoryPage,
    CoveragePage,
    CoverageSummary,
    TechniqueCoverage,
)
from aceapi_v2.sync import run_db_in_thread

router = APIRouter(dependencies=[Security(get_current_auth)])

ReadAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))]

FilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the coverage screen's slugs: technique "
                "(T1059 also finds its sub-techniques), name, tactic (an id or a shortname), platform, state, "
                "own_state, level, attack_platform, catalog_status, has_manual, state_changed, retired (see "
                "docs/SVS_API.md); repeat for more. Filters are ANDed, the values of one ORed.")]
HistoryFilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the coverage history's slugs: date, "
                "technique (T1059 also finds its sub-techniques), platform, state, own_state, level (see "
                "docs/SVS_API.md); repeat for more.")]
TimezoneParam = Annotated[str, Query(description="the timezone relative date filters (`-7d`, `@d`) resolve in")]
CursorParam = Annotated[str | None, Query(description="the next_cursor of the previous page")]
LimitParam = Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only rows written or changed at or after this time (UTC if no offset is given); the pages are "
                "then in (updated_at, id) order")]


class Group(StrEnum):
    DAY = service.GROUP_DAY
    MONTH = service.GROUP_MONTH


async def _prepare_listing(f: list[str], changed_since: datetime | None, tz: str) -> service.CoverageListing:
    return await run_listing(service.prepare_listing, f, changed_since=changed_since, tz=parse_timezone(tz))


async def _prepare_history(f: list[str], changed_since: datetime | None, tz: str) -> service.HistoryListing:
    return await run_listing(service.prepare_history, f, changed_since=changed_since, tz=parse_timezone(tz))


@router.get("/", response_model=CoveragePage)
async def list_coverage(auth: ReadAuth, f: FilterParam, changed_since: ChangedSinceParam = None,
                        tz: TimezoneParam = "UTC", cursor: CursorParam = None, limit: LimitParam = 100) -> CoveragePage:
    """The coverage rows by technique, then platform. Follow next_cursor, with the same filters, until
    it is null."""
    listing = await _prepare_listing(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_page, listing, cursor, limit)
    return CoveragePage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_coverage_ndjson(auth: ReadAuth, f: FilterParam, changed_since: ChangedSinceParam = None,
                                 tz: TimezoneParam = "UTC") -> NdjsonStreamResponse:
    """Stream every row the listing matches as NDJSON, one CoverageRow per line."""
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_page, listing, what="svs coverage")
    return ndjson_response(export, "svs-coverage.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_coverage_csv(auth: ReadAuth, f: FilterParam, changed_since: ChangedSinceParam = None,
                              tz: TimezoneParam = "UTC") -> CsvStreamResponse:
    """Stream every row the listing matches as CSV (tactics joined with ",")."""
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_page, listing, what="svs coverage")
    return csv_response(export, service.coverage_rows_to_csv, "svs-coverage.csv")


@router.get("/summary", response_model=CoverageSummary)
async def get_summary(auth: ReadAuth, f: FilterParam, tz: TimezoneParam = "UTC") -> CoverageSummary:
    """The rows the filters match, counted per state and per own state, overall and per platform, with
    what the last refresh did."""
    return await run_listing(service.get_summary, f, parse_timezone(tz))


#
# the snapshots; declared before /{technique}, which would take "history" for a technique
#

@router.get("/history", response_model=CoverageHistoryPage)
async def list_history(auth: ReadAuth, f: HistoryFilterParam, changed_since: ChangedSinceParam = None,
                       tz: TimezoneParam = "UTC", cursor: CursorParam = None,
                       limit: LimitParam = 100) -> CoverageHistoryPage:
    """The daily snapshot rows by day, technique and platform, oldest first."""
    listing = await _prepare_history(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_history_page, listing, cursor, limit)
    return CoverageHistoryPage(data=rows, next_cursor=next_cursor)


@router.get("/history/export/ndjson", response_class=NdjsonStreamResponse)
async def export_history_ndjson(auth: ReadAuth, f: HistoryFilterParam, changed_since: ChangedSinceParam = None,
                                tz: TimezoneParam = "UTC") -> NdjsonStreamResponse:
    """Stream every snapshot row the filters match as NDJSON, one CoverageSnapshotRow per line."""
    listing = await _prepare_history(f, changed_since, tz)
    export = await start_export(service.fetch_history_page, listing, what="svs coverage history")
    return ndjson_response(export, "svs-coverage-history.ndjson")


@router.get("/history/export/csv", response_class=CsvStreamResponse)
async def export_history_csv(auth: ReadAuth, f: HistoryFilterParam, changed_since: ChangedSinceParam = None,
                             tz: TimezoneParam = "UTC") -> CsvStreamResponse:
    """Stream every snapshot row the filters match as CSV."""
    listing = await _prepare_history(f, changed_since, tz)
    export = await start_export(service.fetch_history_page, listing, what="svs coverage history")
    return csv_response(export, service.history_rows_to_csv, "svs-coverage-history.csv")


@router.get("/history/counts", response_model=CoverageHistoryCounts)
async def get_history_counts(auth: ReadAuth, f: HistoryFilterParam, group: Group = Group.DAY,
                             tz: TimezoneParam = "UTC") -> CoverageHistoryCounts:
    """The snapshot rows the filters match counted per state and own state, per day, or per month
    from each month's last snapshot."""
    return await run_listing(service.get_history_counts, f, group.value, parse_timezone(tz))


@router.get("/{technique}", response_model=TechniqueCoverage)
async def get_technique(technique: str, auth: ReadAuth) -> TechniqueCoverage:
    """A technique's coverage: its rows and its sub-techniques' as of the last refresh, and the tests
    and signatures that count toward them now. A revoked id answers for its successor; 400 for
    something that isn't a technique id, 404 for a technique with no rows that the release doesn't
    have."""
    return await run_db_in_thread(service.get_technique, technique)
