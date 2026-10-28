"""SVS samples router for ACE API v2 (docs/SVS_SAMPLES.md, docs/SVS_API.md).

A sample is a file a YARA rule matched on an alert an analyst graded tp or fp, kept with its match
so rule changes can be tested against it. It is one (sha256, rule uuid) pair over every alert it
was captured from, with a TP/FP label derived from the verdicts on those alerts' detections.

Reading samples, their labels and match records needs signature:read. Anything that returns the
files needs signature:download: they are live malware, and they are served only inside zips
encrypted with the password 'infected'.

The analyst actions (docs/SVS_SAMPLES.md, *Actions*): relabel, reset and confirm write verdicts on
the sample's detections, so they need alert:write as well as signature:read; retire and delete need
svs:admin. Each records who took it, so a config API key (no user) gets 422.
"""

import logging
import os
import shutil
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security
from fastapi.responses import FileResponse
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
from aceapi_v2.svs.samples import service
from aceapi_v2.svs.samples.schemas import (
    LabelActionResult,
    LabelRequest,
    MissingCount,
    ReasonRequest,
    Retirement,
    SampleDeletion,
    SampleDeletionPage,
    SampleDetail,
    SampleListPage,
)
from aceapi_v2.sync import run_db_in_thread
from saq.logging import log_audit
from saq.svs.samples import SampleSort

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

# default_factory rather than a `= []` default, so no list is shared between calls
FilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the samples screen's slugs: "
                "signature, rule, sha256, alert, file_name, label, label_source, last_captured, stored, "
                "missing_data, unknown_version, retired (see docs/SVS_API.md); repeat for more. Filters are ANDed, "
                "the values of one ORed.")]
SortParam = Annotated[SampleSort, Query(description="what the listing is ordered by")]
DescendingParam = Annotated[bool, Query(description="descending order")]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only samples that may have changed at or after this time (UTC if no offset is given): "
                "a capture was added or changed, a contributing alert's row changed, or a contributing "
                "detection's verdict was set or cleared. At-least-once: pass the time the previous pull "
                "started.")]
TimezoneParam = Annotated[str, Query(description="the timezone relative date filters (`-7d`, `@d`) resolve in")]


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError as e:
        logger.warning("failed to remove temp file %s: %s", path, e)


def _safe_rmtree(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


async def _prepare_listing(f: list[str], sort: SampleSort, desc: bool, changed_since: datetime | None,
                           tz: str, cursor: str | None = None) -> service.SampleListing:
    return await run_listing(
        service.prepare_sample_listing, f, sort=sort, descending=desc, changed_since=changed_since,
        tz=parse_timezone(tz), cursor=cursor)


@router.get("/", response_model=SampleListPage)
async def list_samples(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    f: FilterParam,
    sort: SortParam = SampleSort.LAST_CAPTURED,
    desc: DescendingParam = True,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
    tz: TimezoneParam = "UTC",
) -> SampleListPage:
    """List samples, one per (sha256, rule uuid), with their capture counts and label.

    Pages are keyset pages in the requested order: follow next_cursor, with the same filters and
    sort, until it is null.
    """
    listing = await _prepare_listing(f, sort, desc, changed_since, tz, cursor)
    rows, next_cursor = await run_listing(service.fetch_sample_page, listing, cursor, limit)
    return SampleListPage(data=rows, next_cursor=next_cursor)


#
# exports: every sample the listing matches, streamed in one response with the same filters and
# order as GET /svs/samples and no paging. One route per format.
#


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
    listing = await _prepare_listing(f, sort, desc, changed_since, tz)
    export = await start_export(service.fetch_sample_page, listing, what="svs sample")
    return ndjson_response(export, "svs-samples.ndjson")


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
    listing = await _prepare_listing(f, sort, desc, changed_since, tz)
    export = await start_export(service.fetch_sample_page, listing, what="svs sample")
    return csv_response(export, service.sample_rows_to_csv, "svs-samples.csv")


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
    path = await run_db_in_thread(service.materialize_record, row)
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


@router.get("/deletions", response_model=SampleDeletionPage)
async def list_deletions(
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    changed_since: Annotated[datetime | None, Query(
        description="only deletions recorded or changed (their purge finished) at or after this time (UTC if no "
                    "offset is given)")] = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
) -> SampleDeletionPage:
    """The audit of sample files deleted from SVS, oldest change first: who deleted each, why, which
    rules it had captures for, and whether its bytes are purged yet."""
    return await run_listing(service.list_deletions, changed_since, cursor, limit)


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
    download = await run_listing(service.resolve_bulk_download, f, tz=parse_timezone(tz))

    log_audit("user %s downloading %s svs sample files (filters %s): %s",
              auth.auth_name, len(download.local), f, download.sha256s, auth=auth, sha256s=download.sha256s)
    label = "svs-samples"
    zip_path, staging = await run_db_in_thread(service.create_sample_zip, label, download, auth.auth_name)
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
    log_audit("user %s downloading svs sample %s (rule %s)", auth.auth_name, download.sha256s[0], rule_uuid,
              auth=auth, sha256=download.sha256s[0], rule_uuid=rule_uuid)
    label = f"svs-sample-{download.sha256s[0]}"
    zip_path, staging = await run_db_in_thread(service.create_sample_zip, label, download, auth.auth_name)
    return _zip_response(label, zip_path, staging)


#
# actions
#

@router.put("/{sha256}/{rule_uuid}/label", response_model=LabelActionResult,
            dependencies=[Depends(require_permission("signature", "read"))])
async def relabel_sample(
    sha256: str,
    rule_uuid: str,
    body: LabelRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "write"))],
) -> LabelActionResult:
    """Relabel the sample: store the explicit verdict on every contributing detection that can take
    an analyst's verdict, in one transaction. Detections on false positive, unclassified or test
    alerts are skipped and listed with why; 409 when none can take it (correct the alert's
    disposition instead)."""
    return await run_db_in_thread(service.relabel_sample, sha256, rule_uuid, body.verdict, auth.auth_user_id)


@router.delete("/{sha256}/{rule_uuid}/label", response_model=LabelActionResult,
               dependencies=[Depends(require_permission("signature", "read"))])
async def reset_sample_label(
    sha256: str,
    rule_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "write"))],
) -> LabelActionResult:
    """Reset the sample's label to inherited: clear the explicit verdicts on its contributing
    detections, so they inherit from their alerts' dispositions again."""
    return await run_db_in_thread(service.reset_sample_label, sha256, rule_uuid, auth.auth_user_id)


@router.post("/{sha256}/{rule_uuid}/confirm", response_model=LabelActionResult,
             dependencies=[Depends(require_permission("signature", "read"))])
async def confirm_sample(
    sha256: str,
    rule_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "write"))],
) -> LabelActionResult:
    """Confirm the sample's unconfirmed TP detections (verdict source inherited_multi): an explicit
    TP on each, which makes them weigh as a person's verdict. Nothing to confirm is not an error."""
    return await run_db_in_thread(service.confirm_sample, sha256, rule_uuid, auth.auth_user_id)


@router.put("/{sha256}/{rule_uuid}/retirement", response_model=Retirement)
async def retire_sample(
    sha256: str,
    rule_uuid: str,
    body: ReasonRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "admin"))],
) -> Retirement:
    """Retire the sample for its rule: it is no longer expected to match, and YARA validation only
    counts it. Retiring a retired sample changes nothing."""
    return await run_db_in_thread(service.retire_sample, sha256, rule_uuid, body.reason, auth.auth_user_id)


@router.delete("/{sha256}/{rule_uuid}/retirement", response_model=Retirement)
async def unretire_sample(
    sha256: str,
    rule_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "admin"))],
) -> Retirement:
    """Unretire the sample: it is expected to match its rule again. 404 when it is not retired."""
    return await run_db_in_thread(service.unretire_sample, sha256, rule_uuid, auth.auth_user_id)


@router.delete("/{sha256}", response_model=SampleDeletion)
async def delete_sample(
    sha256: str,
    body: ReasonRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "admin"))],
) -> SampleDeletion:
    """Delete the file from SVS, for every rule: its captures and retirements are removed, its
    bytes purged from the pool, and an audit row is kept (GET /svs/samples/deletions) that also
    keeps the file from being captured again. Not reached: the alerts' own files and the YARA QA
    store.

    Deleting a deleted sample retries an unfinished purge. 409 wrong_node when the bytes are on
    another node's local pool, 409 legal_hold when the file is under legal hold."""
    log_audit("user %s deleting svs sample %s: %s", auth.auth_name, sha256, body.reason, auth=auth, sha256=sha256)
    return await run_db_in_thread(service.delete_sample_file, sha256, body.reason, auth.auth_user_id, auth.auth_name)
