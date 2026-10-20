"""SVS YARA validations router for ACE API v2 (docs/SVS_VALIDATION.md, docs/SVS_API.md).

A validation replays every SVS sample under two commits of a rule repository and reports what the
change does to the graded corpus. The signature repository's CI requests one and polls its status
with an svs:validate key, which reads counts and rule names and uuids only. The reports and the
samples they name are read with signature:read; the files need signature:download.
"""

import json
import logging
import shutil
from datetime import datetime
from typing import Annotated

import pytz
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Security
from starlette.background import BackgroundTask

from aceapi_v2.auth.schemas import ApiAuthResult
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

logger = logging.getLogger(__name__)

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


def _timezone(name: str):
    try:
        return pytz.timezone(name)
    except pytz.UnknownTimeZoneError:
        raise HTTPException(status_code=422, detail=f"unknown timezone {name!r}")


def _attachment(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


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

    logger.info("AUDIT: %s requested svs validation %s of %s %s..%s (%s): %s",
                auth.auth_name, status.uuid, body.repository, body.base_sha, body.head_sha, body.branch,
                "queued" if created else f"answered by an existing {status.state} validation")
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
    try:
        return await run_db_in_thread(service.prepare_listing, f, changed_since=changed_since, tz=_timezone(tz))
    except samples_service.InvalidListingRequest as e:
        raise HTTPException(status_code=422, detail=e.detail)


async def _fetch(fetch, *args):
    try:
        return await run_db_in_thread(fetch, *args)
    except samples_service.InvalidCursor as e:
        raise HTTPException(status_code=400, detail=str(e))


class _ExportFailed(Exception):
    """A page after the first could not be fetched, after the response started."""


async def _export_pages(fetch, selection, first_page):
    """Yields the rows of every page in turn; raises _ExportFailed (after logging) when a later
    page fails."""
    rows, next_cursor = first_page
    yield rows
    while next_cursor is not None:
        try:
            rows, next_cursor = await run_db_in_thread(fetch, selection, next_cursor, service.LISTING_EXPORT_PAGE_SIZE)
        except Exception as e:
            logger.error("svs validation export failed part-way: %s", e, exc_info=True)
            raise _ExportFailed() from e
        yield rows


def _ndjson(pages, filename: str) -> NdjsonStreamResponse:
    async def _stream():
        try:
            async for rows in pages:
                yield "".join(row.model_dump_json() + "\n" for row in rows)
        except _ExportFailed:
            yield json.dumps({"error": "the export failed part-way; the lines above are incomplete"}) + "\n"

    return NdjsonStreamResponse(_stream(), headers=_attachment(filename))


def _csv(pages, to_csv, filename: str) -> CsvStreamResponse:
    async def _stream():
        header = True
        try:
            async for rows in pages:
                yield to_csv(rows, header=header)
                header = False
        except _ExportFailed:
            # CSV has no way to say so in-band; the truncation and the log are the signal
            return

    return CsvStreamResponse(_stream(), headers=_attachment(filename))


@router.get("/", response_model=ValidationListPage)
async def list_validations(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=service.LISTING_MAX_PAGE_SIZE)] = 100,
    tz: TimezoneParam = "UTC",
) -> ValidationListPage:
    """List validations, newest first. Follow next_cursor, with the same filters, until it is null."""
    listing = await _prepare_listing(f, changed_since, tz)
    rows, next_cursor = await _fetch(service.fetch_page, listing, cursor, limit)
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
    first_page = await _fetch(service.fetch_page, listing, None, service.LISTING_EXPORT_PAGE_SIZE)
    return _ndjson(_export_pages(service.fetch_page, listing, first_page), "svs-validations.ndjson")


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
    first_page = await _fetch(service.fetch_page, listing, None, service.LISTING_EXPORT_PAGE_SIZE)
    return _csv(_export_pages(service.fetch_page, listing, first_page), service.rows_to_csv, "svs-validations.csv")


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
    limit: Annotated[int, Query(ge=1, le=service.LISTING_MAX_PAGE_SIZE)] = 100,
) -> ValidationResultPage:
    """The (sample, rule uuid) pairs the report lists, with each sample's label when the validation
    ran, in a stable order."""
    selection = await run_db_in_thread(service.select_results, validation_uuid, category, rule_uuid)
    rows, next_cursor = await _fetch(service.fetch_results_page, selection, cursor, limit)
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
    first_page = await _fetch(service.fetch_results_page, selection, None, service.LISTING_EXPORT_PAGE_SIZE)
    return _ndjson(_export_pages(service.fetch_results_page, selection, first_page),
                   f"svs-validation-{selection.validation_uuid}.ndjson")


@router.get("/{validation_uuid}/results/export/csv", response_class=CsvStreamResponse)
async def export_results_csv(
    validation_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    category: CategoryParam,
    rule_uuid: RuleParam,
) -> CsvStreamResponse:
    """Stream the selected rows as CSV."""
    selection = await run_db_in_thread(service.select_results, validation_uuid, category, rule_uuid)
    first_page = await _fetch(service.fetch_results_page, selection, None, service.LISTING_EXPORT_PAGE_SIZE)
    return _csv(_export_pages(service.fetch_results_page, selection, first_page), service.results_to_csv,
                f"svs-validation-{selection.validation_uuid}.csv")


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
    logger.info("AUDIT: user %s downloading %s svs sample files of validation %s (categories %s, rules %s): %s",
                auth.auth_name, len(download.local), selection.validation_uuid, category, rule_uuid,
                download.sha256s)
    label = f"svs-validation-{selection.validation_uuid}"
    zip_path, staging = await run_db_in_thread(samples_service.create_sample_zip, label, download, auth.auth_name)
    return ZipFileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"{label}.zip",
        background=BackgroundTask(shutil.rmtree, staging, ignore_errors=True),
    )
