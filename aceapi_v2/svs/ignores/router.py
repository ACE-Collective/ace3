"""SVS ignores router for ACE API v2, at /svs/ignores (docs/SVS_RUNS.md, *Expectations and ignores*;
docs/SVS_API.md).

Reading them needs svs:run_read. A global ignore changes every test's results, so adding or
removing one needs svs:admin; a test's own ignores are at /svs/tests/{guid}/ignores/{signature_uuid}
with svs:run_manage.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import LISTING_MAX_PAGE_SIZE, csv_response, ndjson_response, run_listing, start_export
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.svs.ignores import service
from aceapi_v2.svs.ignores.schemas import Ignore, IgnorePage, IgnoreRequest
from aceapi_v2.svs.preconditions import WritePrecondition
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

ReadAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))]
AdminAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "admin"))]
ScopeParam = Annotated[str | None, Query(description="only global or only test ignores")]
TestParam = Annotated[str | None, Query(description="the ignores that apply to this test (its guid): its own and the global ones")]
SignatureParam = Annotated[str | None, Query(description="only this signature's (its uuid)")]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only ignores added or changed at or after this time (UTC if no offset is given); the rows then "
                "come in (updated_at, id) order. A removed ignore is gone, not listed")]


async def _prepare(scope, test, signature, changed_since) -> service.IgnoreListing:
    return await run_listing(service.prepare_listing, scope, test, signature, changed_since)


@router.get("/", response_model=IgnorePage)
async def list_ignores(
    auth: ReadAuth,
    scope: ScopeParam = None,
    test: TestParam = None,
    signature: SignatureParam = None,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
) -> IgnorePage:
    """The ignores. Follow next_cursor, with the same filters, until it is null."""
    listing = await _prepare(scope, test, signature, changed_since)
    rows, next_cursor = await run_listing(service.fetch_page, listing, cursor, limit)
    return IgnorePage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_ignores_ndjson(
    auth: ReadAuth,
    scope: ScopeParam = None,
    test: TestParam = None,
    signature: SignatureParam = None,
    changed_since: ChangedSinceParam = None,
) -> NdjsonStreamResponse:
    """Stream the ignores as NDJSON, one Ignore per line."""
    listing = await _prepare(scope, test, signature, changed_since)
    export = await start_export(service.fetch_page, listing, what="svs ignore")
    return ndjson_response(export, "svs-ignores.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_ignores_csv(
    auth: ReadAuth,
    scope: ScopeParam = None,
    test: TestParam = None,
    signature: SignatureParam = None,
    changed_since: ChangedSinceParam = None,
) -> CsvStreamResponse:
    """Stream the ignores as CSV."""
    listing = await _prepare(scope, test, signature, changed_since)
    export = await start_export(service.fetch_page, listing, what="svs ignore")
    return csv_response(export, service.ignores_to_csv, "svs-ignores.csv")


@router.put("/global/{signature_uuid}", response_model=Ignore)
async def set_global_ignore(signature_uuid: str, body: IgnoreRequest, auth: AdminAuth,
                            precondition: WritePrecondition) -> Ignore:
    """Ignore a signature during every test's runs; setting it again replaces its reason. 422 for a
    config key (an ignore records who added it); 412 when an If-Match or If-None-Match precondition no longer holds (docs/SVS_API.md, *Conflicting writes*)."""
    return await run_db_in_thread(service.set_ignore, signature_uuid, body, auth.auth_user_id, auth.auth_name,
                                  None, precondition)


@router.delete("/global/{signature_uuid}", status_code=204)
async def remove_global_ignore(signature_uuid: str, auth: AdminAuth) -> Response:
    """Stop ignoring a signature globally; 404 when it isn't."""
    await run_db_in_thread(service.remove_ignore, signature_uuid, auth.auth_user_id, auth.auth_name)
    return Response(status_code=204)
