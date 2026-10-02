"""Alert router for ACE API v2."""

import json
import logging
import os
from datetime import datetime
from typing import Annotated

import pytz
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, Security
from starlette.background import BackgroundTask

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import (
    ZIP_DOWNLOAD_RESPONSES,
    CsvStreamResponse,
    NdjsonStreamResponse,
    TextFileResponse,
    ZipFileResponse,
)
from aceapi_v2.sync import run_db_in_thread
from aceapi_v2.alerts import service
from aceapi_v2.alerts.schemas import (
    AlertListPage,
    AlertRow,
    BulkAddObservableRequest,
    BulkAddObservableResult,
)
from saq.database.util.observable_detection import InvalidDetectionValue, validate_observable_type

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError as e:
        logger.warning("failed to remove temp file %s: %s", path, e)


@router.post("/bulk-add-observable", response_model=BulkAddObservableResult)
async def bulk_add_observable(
    body: BulkAddObservableRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "write"))],
) -> BulkAddObservableResult:
    """Add an observable to multiple alerts at once."""
    if not body.alert_uuids:
        raise HTTPException(status_code=400, detail="No alert UUIDs provided")

    if not body.observable_value:
        raise HTTPException(status_code=400, detail="Missing observable value")

    # an unknown type can never succeed against any alert, so it is a request-level error rather
    # than a per-alert failure -- and rejecting it here means no alert is locked or loaded for it
    try:
        validate_observable_type(body.observable_type)
    except InvalidDetectionValue as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Parse time if provided
    o_time = None
    if body.observable_time:
        try:
            o_time = datetime.strptime(body.observable_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid time format. Expected YYYY-MM-DD HH:MM:SS",
            )

    return await service.bulk_add_observable(
        alert_uuids=body.alert_uuids,
        o_type=body.observable_type,
        o_value=body.observable_value,
        o_time=o_time,
        directives=body.directives,
        username=auth.auth_name or "unknown",
    )


# the listing's query parameters, shared by the page and the exports
FilterParam = Annotated[list[str], Query(
    description="a filter in the manage page's share-link encoding (`[!]slug:v1,v2`, see "
                "docs/ALERT_FILTER_URLS.md); repeat for more. Filters are ANDed.")]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only alerts whose row changed at or after this time (UTC if no offset is "
                "given), ordered by (updated_at, id) instead of id. At-least-once: resuming "
                "from the last updated_at seen may repeat a row, never skip one.")]
TimezoneParam = Annotated[str, Query(
    description="the timezone relative date filters (`-7d`, `@d`) resolve in")]


def _timezone(name: str):
    try:
        return pytz.timezone(name)
    except pytz.UnknownTimeZoneError:
        raise HTTPException(status_code=422, detail=f"unknown timezone {name!r}")


async def _prepare_listing(
    auth: ApiAuthResult, f: list[str], changed_since: datetime | None, tz: str
) -> service.AlertListing:
    try:
        return await run_db_in_thread(
            service.prepare_alert_listing, f, changed_since=changed_since, tz=_timezone(tz),
            viewer_user_id=auth.auth_user_id)
    except service.InvalidListingRequest as e:
        raise HTTPException(status_code=422, detail=e.detail)


async def _fetch_page(listing: service.AlertListing, cursor: str | None, limit: int):
    try:
        return await run_db_in_thread(service.fetch_alert_page, listing, cursor, limit)
    except service.InvalidCursor as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", response_model=AlertListPage)
async def list_alerts(
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    f: FilterParam = [],
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=service.LISTING_MAX_PAGE_SIZE)] = 100,
    tz: TimezoneParam = "UTC",
) -> AlertListPage:
    """List alerts as flat database rows, for export and reporting.

    Takes the manage page's filters and is scoped to the alerts this node shows, as the GUI
    is. Pages are keyset pages: follow next_cursor until it is null, and no alert is skipped
    or repeated while new ones arrive. Test alerts are not excluded; filter on the queue to
    leave them out.
    """
    listing = await _prepare_listing(auth, f, changed_since, tz)
    rows, next_cursor = await _fetch_page(listing, cursor, limit)
    return AlertListPage(data=rows, next_cursor=next_cursor)


#
# exports: every alert the listing matches, streamed in one response with the same filters,
# scoping and order as GET /alerts and no paging. One route per format.
#


class _ExportFailed(Exception):
    """A page after the first could not be fetched, after the response started."""


async def _prepare_export(
    auth: ApiAuthResult, f: list[str], changed_since: datetime | None, tz: str
) -> tuple[service.AlertListing, tuple[list[AlertRow], str | None]]:
    """The listing and its first page. Everything that can be a 4xx happens here, before the
    response starts: once the first byte is sent the status code cannot change."""
    listing = await _prepare_listing(auth, f, changed_since, tz)
    first_page = await _fetch_page(listing, None, service.LISTING_EXPORT_PAGE_SIZE)
    return listing, first_page


async def _export_pages(listing: service.AlertListing, first_page: tuple[list[AlertRow], str | None]):
    """Yields the rows of every page in turn. Raises _ExportFailed (after logging) when a later
    page fails, so each format can end its stream the way that format can say so."""
    rows, next_cursor = first_page
    yield rows
    while next_cursor is not None:
        try:
            rows, next_cursor = await run_db_in_thread(
                service.fetch_alert_page, listing, next_cursor, service.LISTING_EXPORT_PAGE_SIZE)
        except Exception as e:
            logger.error("alert export failed part-way: %s", e, exc_info=True)
            raise _ExportFailed() from e
        yield rows


def _attachment(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_alerts_ndjson(
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    f: FilterParam = [],
    changed_since: ChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream every alert the listing matches as NDJSON, one AlertRow per line.

    A failure part-way through cannot change the status code that was already sent: the
    stream then ends with an {"error": ...} line, and the failure is logged.
    """
    listing, first_page = await _prepare_export(auth, f, changed_since, tz)

    async def _stream():
        try:
            async for rows in _export_pages(listing, first_page):
                yield "".join(row.model_dump_json() + "\n" for row in rows)
        except _ExportFailed:
            yield json.dumps({"error": "the export failed part-way; the lines above are incomplete"}) + "\n"

    return NdjsonStreamResponse(_stream(), headers=_attachment("alerts.ndjson"))


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_alerts_csv(
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    f: FilterParam = [],
    changed_since: ChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream every alert the listing matches as CSV: a header line, then one row per alert
    (tags joined with ",").

    A failure part-way through cannot change the status code that was already sent: the CSV
    is then truncated, and the failure is logged.
    """
    listing, first_page = await _prepare_export(auth, f, changed_since, tz)

    async def _stream():
        header = True
        try:
            async for rows in _export_pages(listing, first_page):
                yield service.alert_rows_to_csv(rows, header=header)
                header = False
        except _ExportFailed:
            # CSV has no way to say so in-band; the truncation and the log are the signal
            return

    return CsvStreamResponse(_stream(), headers=_attachment("alerts.csv"))


@router.get(
    "/{alert_uuid}",
    responses={
        200: {"description": "The alert as {\"result\": {...}}; ETag header carries the version token."},
        304: {"description": "If-None-Match matched the current version; the alert has not changed."},
    },
)
async def get_alert(
    alert_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    if_none_match: Annotated[str | None, Header()] = None,
) -> Response:
    """Return the full alert: the analysis tree plus its database state.

    The alert's version token is returned both as the ETag header and as the
    `version` key of the result. It changes whenever anything about the alert
    changes (analysis, observables, comments, disposition, ownership, events), so a
    client can poll with If-None-Match and get a 304 without the alert being loaded.
    """
    version = await run_db_in_thread(service.get_alert_version, alert_uuid)
    if if_none_match and service.etag_matches(if_none_match, version):
        return Response(status_code=304, headers={"ETag": service.etag(version)})

    # the token comes from the loaded row, so the header always agrees with the body
    body, version = await run_db_in_thread(service.get_alert, alert_uuid)
    return Response(content=body, media_type="application/json", headers={"ETag": service.etag(version)})


@router.get(
    "/{alert_uuid}/download",
    response_class=ZipFileResponse,
    responses=ZIP_DOWNLOAD_RESPONSES,
)
async def download_alert(
    alert_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> ZipFileResponse:
    """Download the full alert storage directory as a zip encrypted with password 'infected'."""
    logger.info("AUDIT: user %s downloading alert %s", auth.auth_name, alert_uuid)
    zip_path = await run_db_in_thread(service.create_encrypted_alert_zip, alert_uuid)
    return ZipFileResponse(
        zip_path,
        # FileResponse ignores the class attribute; without this it guesses from the filename
        media_type="application/zip",
        filename=f"{alert_uuid}.zip",
        background=BackgroundTask(_safe_unlink, zip_path),
    )


@router.get("/{alert_uuid}/logs", response_class=TextFileResponse)
async def view_alert_logs(
    alert_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    download: bool = False,
) -> TextFileResponse:
    """Return the alert's raw saq.log file.

    Default: text/plain with inline disposition (renders in browser).
    With ?download=true, served as an attachment download.
    """
    log_path = await run_db_in_thread(service.resolve_alert_log_path, alert_uuid)
    # FileResponse ignores the class attribute; without media_type it would guess
    # application/octet-stream from the .log suffix
    if download:
        return TextFileResponse(
            log_path,
            media_type="text/plain",
            filename=f"{alert_uuid}-saq.log",
        )
    return TextFileResponse(
        log_path,
        media_type="text/plain; charset=utf-8",
        content_disposition_type="inline",
    )
