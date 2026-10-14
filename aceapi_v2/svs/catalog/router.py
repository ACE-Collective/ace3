"""Atomic Red Team test catalog router for ACE API v2, at /svs/tests (docs/SVS_RUNS.md,
docs/SVS_API.md).

The tests runs may be registered for, as service_svs reads them from the catalog repositories.
Read with svs:run_read. The test state and run history columns of the Tests screen come with the
runs, later in phase 4.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import LISTING_MAX_PAGE_SIZE, csv_response, ndjson_response, run_listing, start_export
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.svs.catalog import service
from aceapi_v2.svs.catalog.schemas import CatalogTestDetail, CatalogTestPage
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

FilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the tests screen's slugs: technique "
                "(T1059 also finds its sub-techniques), name, platform, executor, repository, removed (see "
                "docs/SVS_API.md); repeat for more. Filters are ANDed, the values of one ORed.")]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only tests added, changed or removed at or after this time (UTC if no offset is given)")]


async def _prepare_listing(f: list[str], changed_since: datetime | None) -> service.CatalogListing:
    return await run_listing(service.prepare_listing, f, changed_since=changed_since)


@router.get("/", response_model=CatalogTestPage)
async def list_tests(
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
) -> CatalogTestPage:
    """The catalog's tests by technique, then name. Follow next_cursor, with the same filters,
    until it is null."""
    listing = await _prepare_listing(f, changed_since)
    rows, next_cursor = await run_listing(service.fetch_page, listing, cursor, limit)
    return CatalogTestPage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_tests_ndjson(
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
) -> NdjsonStreamResponse:
    """Stream every test the listing matches as NDJSON, one CatalogTest per line."""
    listing = await _prepare_listing(f, changed_since)
    export = await start_export(service.fetch_page, listing, what="svs catalog test")
    return ndjson_response(export, "svs-tests.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_tests_csv(
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
) -> CsvStreamResponse:
    """Stream every test the listing matches as CSV (platforms joined with ",")."""
    listing = await _prepare_listing(f, changed_since)
    export = await start_export(service.fetch_page, listing, what="svs catalog test")
    return csv_response(export, service.catalog_tests_to_csv, "svs-tests.csv")


@router.get("/{guid}", response_model=CatalogTestDetail)
async def get_test(
    guid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
) -> CatalogTestDetail:
    """One test with its description and its atomic entry: commands, input arguments, dependencies."""
    return await run_db_in_thread(service.get_catalog_test, guid)
