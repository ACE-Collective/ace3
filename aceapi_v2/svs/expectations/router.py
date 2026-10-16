"""SVS expectations router for ACE API v2, at /svs/expectations (docs/SVS_RUNS.md, *Expectations and
ignores*; docs/SVS_API.md).

Every test's decided signatures, per platform, read with svs:run_read. A test's decisions are made at
/svs/tests/{guid}/expectations/{platform}/{signature_uuid} with svs:run_manage.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import LISTING_MAX_PAGE_SIZE, csv_response, ndjson_response, run_listing, start_export
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.svs.expectations import service
from aceapi_v2.svs.expectations.schemas import ExpectationPage

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

ReadAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))]
TestParam = Annotated[str | None, Query(description="only this test's (its guid)")]
PlatformParam = Annotated[str | None, Query(description="only those about this platform (windows, linux, macos, ...)")]
SignatureParam = Annotated[str | None, Query(description="only this signature's (its uuid)")]
StateParam = Annotated[str | None, Query(description="only expected or only rejected")]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only decisions made or changed at or after this time (UTC if no offset is given); the rows then "
                "come in (updated_at, id) order")]


async def _prepare(test, platform, signature, state, changed_since) -> service.ExpectationListing:
    return await run_listing(service.prepare_listing, test, platform, signature, state, changed_since)


@router.get("/", response_model=ExpectationPage)
async def list_expectations(
    auth: ReadAuth,
    test: TestParam = None,
    platform: PlatformParam = None,
    signature: SignatureParam = None,
    state: StateParam = None,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
) -> ExpectationPage:
    """Every test's decided signatures, per platform. Follow next_cursor, with the same filters, until it is null."""
    listing = await _prepare(test, platform, signature, state, changed_since)
    rows, next_cursor = await run_listing(service.fetch_page, listing, cursor, limit)
    return ExpectationPage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_expectations_ndjson(
    auth: ReadAuth,
    test: TestParam = None,
    platform: PlatformParam = None,
    signature: SignatureParam = None,
    state: StateParam = None,
    changed_since: ChangedSinceParam = None,
) -> NdjsonStreamResponse:
    """Stream the expectations as NDJSON, one Expectation per line."""
    listing = await _prepare(test, platform, signature, state, changed_since)
    export = await start_export(service.fetch_page, listing, what="svs expectation")
    return ndjson_response(export, "svs-expectations.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_expectations_csv(
    auth: ReadAuth,
    test: TestParam = None,
    platform: PlatformParam = None,
    signature: SignatureParam = None,
    state: StateParam = None,
    changed_since: ChangedSinceParam = None,
) -> CsvStreamResponse:
    """Stream the expectations as CSV."""
    listing = await _prepare(test, platform, signature, state, changed_since)
    export = await start_export(service.fetch_page, listing, what="svs expectation")
    return csv_response(export, service.expectations_to_csv, "svs-expectations.csv")
