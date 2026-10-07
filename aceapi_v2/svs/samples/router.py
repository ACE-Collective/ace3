"""SVS samples router for ACE API v2 (docs/SVS_SAMPLES.md, docs/SVS_API.md).

A sample is a file a YARA rule matched on an alert an analyst graded tp or fp, kept with its match
so rule changes can be tested against it. It is one (sha256, rule uuid) pair over every alert it
was captured from, with a TP/FP label derived from the verdicts on those alerts' detections.

Reading samples, their labels and match records needs signature:read. Anything that returns the
files needs signature:download: they are live malware, and they are served only inside zips
encrypted with the password 'infected'.
"""

import json
import logging
import os
import shutil
from datetime import datetime
from typing import Annotated

import pytz
from fastapi import APIRouter, Depends, HTTPException, Query, Security
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import ZIP_DOWNLOAD_RESPONSES, CsvStreamResponse, NdjsonStreamResponse, ZipFileResponse
from aceapi_v2.svs.samples import service
from aceapi_v2.svs.samples.schemas import MissingCount, SampleDetail, SampleListPage, SampleRow
from aceapi_v2.sync import run_db_in_thread
from saq.svs.samples import SampleSort

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

# default_factory rather than a `= []` default, so no list is shared between calls
FilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the samples screen's slugs: "
                "signature, rule, sha256, alert, file_name, label, label_source, last_captured, stored, "
                "missing_data, unknown_version (see docs/SVS_API.md); repeat for more. Filters are ANDed, "
                "the values of one ORed.")]
SortParam = Annotated[SampleSort, Query(description="what the listing is ordered by")]
DescendingParam = Annotated[bool, Query(description="descending order")]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only samples that may have changed at or after this time (UTC if no offset is given): "
                "a capture was added or changed, a contributing alert's row changed, or a contributing "
                "detection's verdict was set or cleared. At-least-once: pass the time the previous pull "
                "started.")]
TimezoneParam = Annotated[str, Query(description="the timezone relative date filters (`-7d`, `@d`) resolve in")]


def _timezone(name: str):
    try:
        return pytz.timezone(name)
    except pytz.UnknownTimeZoneError:
        raise HTTPException(status_code=422, detail=f"unknown timezone {name!r}")


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError as e:
        logger.warning("failed to remove temp file %s: %s", path, e)


def _safe_rmtree(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def _attachment(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


async def _prepare_listing(f: list[str], sort: SampleSort, desc: bool, changed_since: datetime | None,
                           tz: str) -> service.SampleListing:
    try:
        return await run_db_in_thread(
            service.prepare_sample_listing, f, sort=sort, descending=desc, changed_since=changed_since,
            tz=_timezone(tz))
    except service.InvalidListingRequest as e:
        raise HTTPException(status_code=422, detail=e.detail)


async def _fetch_page(listing: service.SampleListing, cursor: str | None, limit: int):
    try:
        return await run_db_in_thread(service.fetch_sample_page, listing, cursor, limit)
    except service.InvalidCursor as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", response_model=SampleListPage)
async def list_samples(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    f: FilterParam,
    sort: SortParam = SampleSort.LAST_CAPTURED,
    desc: DescendingParam = True,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=service.LISTING_MAX_PAGE_SIZE)] = 100,
    tz: TimezoneParam = "UTC",
) -> SampleListPage:
    """List samples, one per (sha256, rule uuid), with their capture counts and label.

    Pages are keyset pages in the requested order: follow next_cursor, with the same filters and
    sort, until it is null.
    """
    listing = await _prepare_listing(f, sort, desc, changed_since, tz)
    rows, next_cursor = await _fetch_page(listing, cursor, limit)
    return SampleListPage(data=rows, next_cursor=next_cursor)


#
# exports: every sample the listing matches, streamed in one response with the same filters and
# order as GET /svs/samples and no paging. One route per format.
#


class _ExportFailed(Exception):
    """A page after the first could not be fetched, after the response started."""


async def _prepare_export(f: list[str], sort: SampleSort, desc: bool, changed_since: datetime | None, tz: str):
    """The listing and its first page. Everything that can be a 4xx happens here, before the
    response starts: once the first byte is sent the status code cannot change."""
    listing = await _prepare_listing(f, sort, desc, changed_since, tz)
    first_page = await _fetch_page(listing, None, service.LISTING_EXPORT_PAGE_SIZE)
    return listing, first_page


async def _export_pages(listing: service.SampleListing, first_page: tuple[list[SampleRow], str | None]):
    """Yields the rows of every page in turn. Raises _ExportFailed (after logging) when a later
    page fails, so each format can end its stream the way that format can say so."""
    rows, next_cursor = first_page
    yield rows
    while next_cursor is not None:
        try:
            rows, next_cursor = await run_db_in_thread(
                service.fetch_sample_page, listing, next_cursor, service.LISTING_EXPORT_PAGE_SIZE)
        except Exception as e:
            logger.error("svs sample export failed part-way: %s", e, exc_info=True)
            raise _ExportFailed() from e
        yield rows


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_samples_ndjson(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    f: FilterParam,
    sort: SortParam = SampleSort.LAST_CAPTURED,
    desc: DescendingParam = True,
    changed_since: ChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream every sample the listing matches as NDJSON, one SampleRow per line.

    A failure part-way through cannot change the status code that was already sent: the stream
    then ends with an {"error": ...} line, and the failure is logged.
    """
    listing, first_page = await _prepare_export(f, sort, desc, changed_since, tz)

    async def _stream():
        try:
            async for rows in _export_pages(listing, first_page):
                yield "".join(row.model_dump_json() + "\n" for row in rows)
        except _ExportFailed:
            yield json.dumps({"error": "the export failed part-way; the lines above are incomplete"}) + "\n"

    return NdjsonStreamResponse(_stream(), headers=_attachment("svs-samples.ndjson"))


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_samples_csv(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    f: FilterParam,
    sort: SortParam = SampleSort.LAST_CAPTURED,
    desc: DescendingParam = True,
    changed_since: ChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream every sample the listing matches as CSV: a header line, then one row per sample,
    with the votes in their own columns.

    A failure part-way through cannot change the status code that was already sent: the CSV is
    then truncated, and the failure is logged.
    """
    listing, first_page = await _prepare_export(f, sort, desc, changed_since, tz)

    async def _stream():
        header = True
        try:
            async for rows in _export_pages(listing, first_page):
                yield service.sample_rows_to_csv(rows, header=header)
                header = False
        except _ExportFailed:
            # CSV has no way to say so in-band; the truncation and the log are the signal
            return

    return CsvStreamResponse(_stream(), headers=_attachment("svs-samples.csv"))


# the static routes come before the /{sha256}/{rule_uuid} ones, so "captures" or "download" is
# never read as a sha256

@router.get("/missing", response_model=list[MissingCount])
async def list_missing(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
) -> list[MissingCount]:
    """How many captures of each rule lack something, by reason: `file` (the file was gone before it
    could be kept), `storage` (the CAS refused it) or `match_record` (the file is kept, its match
    record was gone). Rules with the most first."""
    return await run_db_in_thread(service.missing_summary)


@router.get("/captures/{capture_id}/record")
async def get_capture_record(
    capture_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
) -> FileResponse:
    """The capture's full match record (application/json): the alert's YARA scan result for the
    rule, as the alert saved it.

    It is read from the CAS, so a capture stored on another node's local pool answers 409
    wrong_node.
    """
    row = await run_db_in_thread(service.resolve_record, capture_id)
    path = await run_in_threadpool(service.materialize_record, row)
    return FileResponse(
        path,
        media_type="application/json",
        filename=f"svs-capture-{row.id}.json",
        # shown in the browser rather than saved (the GUI opens it in a tab). the record holds bytes
        # from the analyzed file, so the browser must never sniff it into anything but JSON
        content_disposition_type="inline",
        headers={"X-Content-Type-Options": "nosniff"},
        background=BackgroundTask(_safe_unlink, path),
    )


def _zip_response(label: str, zip_path: str, staging: str) -> ZipFileResponse:
    return ZipFileResponse(
        zip_path,
        # FileResponse ignores the class attribute; without this it guesses from the filename
        media_type="application/zip",
        filename=f"{label}.zip",
        background=BackgroundTask(_safe_rmtree, staging),
    )


@router.get("/download", response_class=ZipFileResponse, responses=ZIP_DOWNLOAD_RESPONSES)
async def download_samples(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "download"))],
    f: FilterParam,
    tz: TimezoneParam = "UTC",
) -> ZipFileResponse:
    """Download the files of every sample the filters match, with their match records and a
    manifest, as one zip encrypted with password 'infected'.

    Each file is in the zip once, whatever the number of rules it matched. Limited to
    svs.samples.max_bulk_download_files files and svs.samples.max_bulk_download_bytes bytes (413
    past either). Files stored on another node's local pool are listed in the manifest under
    skipped.
    """
    try:
        download = await run_db_in_thread(service.resolve_bulk_download, f, tz=_timezone(tz))
    except service.InvalidListingRequest as e:
        raise HTTPException(status_code=422, detail=e.detail)

    logger.info("AUDIT: user %s downloading %s svs sample files (filters %s): %s",
                auth.auth_name, len(download.local), f, download.sha256s)
    label = "svs-samples"
    zip_path, staging = await run_in_threadpool(service.create_sample_zip, label, download, auth.auth_name)
    return _zip_response(label, zip_path, staging)


@router.get("/{sha256}/{rule_uuid}", response_model=SampleDetail)
async def get_sample(
    sha256: str,
    rule_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
) -> SampleDetail:
    """One sample, with every capture (newest first) and the verdicts of each capture's
    contributing detections."""
    return await run_db_in_thread(service.get_sample_detail, sha256, rule_uuid)


@router.get("/{sha256}/{rule_uuid}/download", response_class=ZipFileResponse, responses=ZIP_DOWNLOAD_RESPONSES)
async def download_sample(
    sha256: str,
    rule_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "download"))],
) -> ZipFileResponse:
    """Download one sample's file and the match records of its captures as a zip encrypted with
    password 'infected'."""
    download = await run_db_in_thread(service.resolve_sample_download, sha256, rule_uuid)
    logger.info("AUDIT: user %s downloading svs sample %s (rule %s)", auth.auth_name, download.sha256s[0], rule_uuid)
    label = f"svs-sample-{download.sha256s[0]}"
    zip_path, staging = await run_in_threadpool(service.create_sample_zip, label, download, auth.auth_name)
    return _zip_response(label, zip_path, staging)
