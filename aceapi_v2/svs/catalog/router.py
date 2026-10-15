"""Atomic Red Team test catalog router for ACE API v2, at /svs/tests (docs/SVS_RUNS.md,
docs/SVS_API.md).

The tests runs may be registered for, as service_svs reads them from the catalog repositories.
Read with svs:run_read. The test state and run history columns of the Tests screen come with the
runs, later in phase 4.

What is decided about a test's signatures (docs/SVS_RUNS.md, *Expectations and ignores*) and its
settings (*Windows*) are changed here, with svs:run_manage: each change marks the results of the
test's runs stale, and the timers recompute them.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import LISTING_MAX_PAGE_SIZE, csv_response, ndjson_response, run_listing, start_export
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.svs.catalog import service
from aceapi_v2.svs.catalog.schemas import CatalogTestDetail, CatalogTestPage
from aceapi_v2.svs.expectations import service as expectations_service
from aceapi_v2.svs.expectations.schemas import Expectation, ExpectationRequest, TestSettings, TestSettingsRequest
from aceapi_v2.svs.ignores import service as ignores_service
from aceapi_v2.svs.ignores.schemas import Ignore, IgnoreRequest
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

ManageAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_manage"))]

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


#
# a test's decisions and settings (svs:run_manage)
#

@router.put("/{guid}/expectations/{signature_uuid}", response_model=Expectation)
async def set_expectation(guid: str, signature_uuid: str, body: ExpectationRequest, auth: ManageAuth) -> Expectation:
    """Decide a signature for the test: expected or rejected. 404 for an unknown test; 422 for a
    run_id that isn't one of the test's runs, or a config key (a decision records who made it)."""
    return await run_db_in_thread(expectations_service.set_expectation, guid, signature_uuid, body,
                                  auth.auth_user_id, auth.auth_name)


@router.delete("/{guid}/expectations/{signature_uuid}", status_code=204)
async def remove_expectation(guid: str, signature_uuid: str, auth: ManageAuth) -> Response:
    """Remove a decision: the signature is a candidate again the next time a run fires it."""
    await run_db_in_thread(expectations_service.remove_expectation, guid, signature_uuid, auth.auth_user_id,
                           auth.auth_name)
    return Response(status_code=204)


@router.put("/{guid}/ignores/{signature_uuid}", response_model=Ignore)
async def set_test_ignore(guid: str, signature_uuid: str, body: IgnoreRequest, auth: ManageAuth) -> Ignore:
    """Ignore a signature during the test's runs; setting it again replaces its reason."""
    return await run_db_in_thread(ignores_service.set_ignore, signature_uuid, body, auth.auth_user_id,
                                  auth.auth_name, guid)


@router.delete("/{guid}/ignores/{signature_uuid}", status_code=204)
async def remove_test_ignore(guid: str, signature_uuid: str, auth: ManageAuth) -> Response:
    """Stop ignoring a signature during the test's runs; 404 when it isn't."""
    await run_db_in_thread(ignores_service.remove_ignore, signature_uuid, auth.auth_user_id, auth.auth_name, guid)
    return Response(status_code=204)


@router.get("/{guid}/settings", response_model=TestSettings)
async def get_test_settings(
    guid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
) -> TestSettings:
    """The test's settings; 404 when it has none (its runs get the computed window)."""
    return await run_db_in_thread(expectations_service.get_test_settings, guid)


@router.put("/{guid}/settings", response_model=TestSettings)
async def set_test_settings(guid: str, body: TestSettingsRequest, auth: ManageAuth) -> TestSettings:
    """Set the observation window of the test's runs registered from now on; 422 outside 1 minute to
    the configured ceiling."""
    return await run_db_in_thread(expectations_service.set_test_settings, guid, body, auth.auth_user_id,
                                  auth.auth_name)


@router.delete("/{guid}/settings", status_code=204)
async def remove_test_settings(guid: str, auth: ManageAuth) -> Response:
    """Back to the computed window; 404 when the test has no settings."""
    await run_db_in_thread(expectations_service.remove_test_settings, guid, auth.auth_user_id, auth.auth_name)
    return Response(status_code=204)
