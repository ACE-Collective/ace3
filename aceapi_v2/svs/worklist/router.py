"""The declared-vs-measured worklist router for ACE API v2, at /svs/worklist (docs/SVS_COVERAGE.md,
*The worklist*; docs/SVS_API.md).

One row per (signature, ATT&CK technique) for each measured signature: its mitre: tags, confirmed
or not by the tests it is expected of, and the techniques it is measured on that no tag names.
Read with svs:run_read; a tag measurement doesn't confirm is resolved keep or remove with
svs:run_manage.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, Security

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
from aceapi_v2.svs.worklist import service
from aceapi_v2.svs.worklist.schemas import (
    BulkResolutionRequest,
    BulkResolutionResult,
    ResolutionRequest,
    SignatureWorklist,
    WorklistPage,
    WorklistRow,
)
from aceapi_v2.sync import run_db_in_thread

router = APIRouter(dependencies=[Security(get_current_auth)])

ReadAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))]
ManageAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_manage"))]

FilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the worklist screen's slugs: signature "
                "(a uuid, or text in the name), family, technique (T1059 also finds its sub-techniques), status, kind, "
                "resolution (keep, remove, none), resolved_by, resolved (see docs/SVS_API.md); repeat for more. "
                "Filters are ANDed, the values of one ORed.")]
TimezoneParam = Annotated[str, Query(description="the timezone relative date filters (`-7d`, `@d`) resolve in")]
CursorParam = Annotated[str | None, Query(description="the next_cursor of the previous page")]
LimitParam = Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only rows written or changed at or after this time (UTC if no offset is given); the pages are "
                "then in (updated_at, id) order")]


async def _prepare_listing(f: list[str], changed_since: datetime | None, tz: str) -> service.WorklistListing:
    return await run_listing(service.prepare_listing, f, changed_since=changed_since, tz=parse_timezone(tz))


@router.get("/", response_model=WorklistPage)
async def list_worklist(auth: ReadAuth, f: FilterParam, changed_since: ChangedSinceParam = None,
                        tz: TimezoneParam = "UTC", cursor: CursorParam = None, limit: LimitParam = 100) -> WorklistPage:
    """The worklist rows by signature, then technique. Follow next_cursor, with the same filters,
    until it is null."""
    listing = await _prepare_listing(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_page, listing, cursor, limit)
    return WorklistPage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_worklist_ndjson(auth: ReadAuth, f: FilterParam, changed_since: ChangedSinceParam = None,
                                 tz: TimezoneParam = "UTC") -> NdjsonStreamResponse:
    """Stream every row the listing matches as NDJSON, one WorklistRow per line."""
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_page, listing, what="svs worklist")
    return ndjson_response(export, "svs-worklist.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_worklist_csv(auth: ReadAuth, f: FilterParam, changed_since: ChangedSinceParam = None,
                              tz: TimezoneParam = "UTC") -> CsvStreamResponse:
    """Stream every row the listing matches as CSV (declared_as and measured_techniques joined with ",")."""
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_page, listing, what="svs worklist")
    return csv_response(export, service.worklist_rows_to_csv, "svs-worklist.csv")


# declared before /{signature_uuid}, which would take "bulk" for a signature
@router.post("/bulk/resolve", response_model=BulkResolutionResult)
async def bulk_resolve(body: BulkResolutionRequest, auth: ManageAuth) -> BulkResolutionResult:
    """Resolve many rows alike, in one transaction; rows that don't exist or can't be resolved are
    reported and left alone. 422 for a resolution, reason or reference that isn't valid."""
    return await run_db_in_thread(service.bulk_resolve, body, auth.auth_user_id, auth.auth_name)


@router.get("/{signature_uuid}", response_model=SignatureWorklist)
async def get_signature(signature_uuid: str, auth: ReadAuth) -> SignatureWorklist:
    """A signature's rows, retired ones included, and what it is measured on now; 404 when it has
    none."""
    return await run_db_in_thread(service.get_signature, signature_uuid)


@router.put("/{signature_uuid}/{technique}/resolution", response_model=WorklistRow)
async def set_resolution(signature_uuid: str, technique: str, body: ResolutionRequest,
                         auth: ManageAuth) -> WorklistRow:
    """Resolve a tag measurement doesn't confirm: keep it, or remove it (it stops counting toward
    coverage from the next refresh). 404 for an unknown row; 409 for a row that is confirmed,
    informational, retired or removed; 422 for an invalid body or a config key (a resolution records
    who made it)."""
    return await run_db_in_thread(service.set_resolution, signature_uuid, technique, body, auth.auth_user_id,
                                  auth.auth_name)


@router.delete("/{signature_uuid}/{technique}/resolution", status_code=204)
async def clear_resolution(signature_uuid: str, technique: str, auth: ManageAuth) -> Response:
    """Clear a row's resolution; 404 when the row doesn't exist or has none."""
    await run_db_in_thread(service.clear_resolution, signature_uuid, technique, auth.auth_user_id, auth.auth_name)
    return Response(status_code=204)
