"""SVS YARA validations router for ACE API v2 (docs/SVS_VALIDATION.md, docs/SVS_API.md).

A validation replays every SVS sample under two commits of a rule repository and reports what the
change does to the graded corpus. The signature repository's CI requests one and polls its status
with an svs:validate key, which reads counts and rule names and uuids only. The reports and the
samples they name are read with signature:read; the files need signature:download.
"""

import shutil
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, Security
from starlette.background import BackgroundTask

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
from aceapi_v2.responses import ZIP_DOWNLOAD_RESPONSES, CsvStreamResponse, NdjsonStreamResponse, ZipFileResponse
from aceapi_v2.svs.samples import service as samples_service
from aceapi_v2.svs.yara.validations import service
from aceapi_v2.svs.yara.validations.schemas import (
    ValidationDetail,
    ValidationListPage,
    ValidationRequest,
    ValidationResultPage,
    ValidationStatus,
)
from aceapi_v2.sync import run_db_in_thread
from saq.logging import log_audit

router = APIRouter(dependencies=[Security(get_current_auth)])

FilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the validations screen's slugs: "
                "repository, branch, head, state, has_regressions, has_new_fp, compile_errors, created (see "
                "docs/SVS_API.md); repeat for more. Filters are ANDed, the values of one ORed.")]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only validations created or changed (queued, run, completed) at or after this time (UTC if no "
                "offset is given)")]
TimezoneParam = Annotated[str, Query(description="the timezone relative date filters (`-7d`, `@d`) resolve in")]
CategoryParam = Annotated[list[str], Query(
    default_factory=list, description="only rows of these categories (repeat for more)")]
RuleParam = Annotated[list[str], Query(default_factory=list, description="only rows of these rule uuids (repeat for more)")]


#
# CI
#

@router.post("/", response_model=ValidationStatus, status_code=202)
async def request_validation(
    body: ValidationRequest,
    response: Response,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "validate"))],
) -> ValidationStatus:
    """Request a validation of head_sha against base_sha: 202 with a new queued validation, or 200
    with the one that already answers it (queued or running for the same commits, or completed with
    the samples, their labels and the engine unchanged since). Poll GET /{uuid}/status."""
    status, created = await run_db_in_thread(service.request, body, auth.auth_user_id)
    if not created:
        response.status_code = 200

    log_audit("%s requested svs validation %s of %s %s..%s (%s): %s",
              auth.auth_name, status.uuid, body.repository, body.base_sha, body.head_sha, body.branch,
              "queued" if created else f"answered by an existing {status.state} validation",
              auth=auth, validation_uuid=status.uuid, repository=body.repository)
    return status


@router.get("/{validation_uuid}/status", response_model=ValidationStatus)
async def get_validation_status(
    validation_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "validate"))],
) -> ValidationStatus:
    """A validation's state and, once completed, its counts per category, the rules with samples
    in each listed category, and the head's compile errors. Names no sample."""
    return await run_db_in_thread(service.get_status, validation_uuid)


#
# the listing and its exports
#

async def _prepare_listing(f: list[str], changed_since: datetime | None, tz: str) -> service.ValidationListing:
    return await run_listing(service.prepare_listing, f, changed_since=changed_since, tz=parse_timezone(tz))


@router.get("/", response_model=ValidationListPage)
async def list_validations(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
    tz: TimezoneParam = "UTC",
) -> ValidationListPage:
    """List validations, newest first. Follow next_cursor, with the same filters, until it is null."""
    listing = await _prepare_listing(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_page, listing, cursor, limit)
    return ValidationListPage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_validations_ndjson(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream every validation the listing matches as NDJSON, one ValidationRow per line; a failure
    part-way ends the stream with an {"error": ...} line."""
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_page, listing, what="svs validation")
    return ndjson_response(export, "svs-validations.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_validations_csv(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream every validation the listing matches as CSV (without the per-category counts); a
    failure part-way truncates it."""
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_page, listing, what="svs validation")
    return csv_response(export, service.validation_rows_to_csv, "svs-validations.csv")


#
# one validation
#

@router.get("/{validation_uuid}", response_model=ValidationDetail)
async def get_validation(
    validation_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
) -> ValidationDetail:
    """One validation with its report; the pairs it lists are GET /{uuid}/results."""
    return await run_db_in_thread(service.get_detail, validation_uuid)


@router.get("/{validation_uuid}/results", response_model=ValidationResultPage)
async def list_results(
    validation_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    category: CategoryParam,
    rule_uuid: RuleParam,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
) -> ValidationResultPage:
    """The (sample, rule uuid) pairs the report lists, with each sample's label when the validation
    ran, in a stable order."""
    selection = await run_db_in_thread(service.select_results, validation_uuid, category, rule_uuid)
    rows, next_cursor = await run_listing(service.fetch_results_page, selection, cursor, limit)
    return ValidationResultPage(data=rows, next_cursor=next_cursor)


@router.get("/{validation_uuid}/results/export/ndjson", response_class=NdjsonStreamResponse)
async def export_results_ndjson(
    validation_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    category: CategoryParam,
    rule_uuid: RuleParam,
) -> NdjsonStreamResponse:
    """Stream the selected rows as NDJSON."""
    selection = await run_db_in_thread(service.select_results, validation_uuid, category, rule_uuid)
    export = await start_export(service.fetch_results_page, selection, what="svs validation result")
    return ndjson_response(export, f"svs-validation-{selection.validation_uuid}.ndjson")


@router.get("/{validation_uuid}/results/export/csv", response_class=CsvStreamResponse)
async def export_results_csv(
    validation_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    category: CategoryParam,
    rule_uuid: RuleParam,
) -> CsvStreamResponse:
    """Stream the selected rows as CSV."""
    selection = await run_db_in_thread(service.select_results, validation_uuid, category, rule_uuid)
    export = await start_export(service.fetch_results_page, selection, what="svs validation result")
    return csv_response(export, service.results_to_csv, f"svs-validation-{selection.validation_uuid}.csv")


@router.get("/{validation_uuid}/download", response_class=ZipFileResponse, responses=ZIP_DOWNLOAD_RESPONSES)
async def download_results(
    validation_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "download"))],
    category: CategoryParam,
    rule_uuid: RuleParam,
) -> ZipFileResponse:
    """Download the files of the selected rows, with the match records of their samples and a
    manifest, as one zip encrypted with password 'infected'. The samples download's limits apply,
    and files on another node's local pool are listed in the manifest as skipped."""
    selection = await run_db_in_thread(service.select_results, validation_uuid, category, rule_uuid)
    download = await run_db_in_thread(service.resolve_results_download, selection)
    log_audit("user %s downloading %s svs sample files of validation %s (categories %s, rules %s): %s",
              auth.auth_name, len(download.local), selection.validation_uuid, category, rule_uuid,
              download.sha256s, auth=auth, validation_uuid=selection.validation_uuid, sha256s=download.sha256s)
    label = f"svs-validation-{selection.validation_uuid}"
    zip_path, staging = await run_db_in_thread(samples_service.create_sample_zip, label, download, auth.auth_name)
    return ZipFileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"{label}.zip",
        background=BackgroundTask(shutil.rmtree, staging, ignore_errors=True),
    )
