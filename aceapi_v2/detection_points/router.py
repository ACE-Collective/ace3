"""Detection points router for ACE API v2: every detection with its TP/FP verdict, for export and
reporting (docs/SVS_API.md). One alert's detections and the verdict writes live under
/alerts/{uuid}/detection-points."""

import json
import logging
from datetime import datetime
from typing import Annotated

import pytz
from fastapi import APIRouter, Depends, HTTPException, Query, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.detection_points import service
from aceapi_v2.detection_points.schemas import DetectionPointListPage, DetectionPointRow
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

# default_factory rather than a `= []` default, so no list is shared between calls
FilterParam = Annotated[list[str], Query(
    default_factory=list,
    description="a filter in the share-link encoding (`[!]slug:v1,v2`) with the detection points "
                "screen's slugs: signature, family, alert_date, queue, verdict, source, has_override "
                "(see docs/SVS_API.md); repeat for more. Filters are ANDed, the values of one ORed.")]
ChangedSinceParam = Annotated[datetime | None, Query(
    description="only detections that may have changed at or after this time (UTC if no offset is "
                "given): the alert's row changed, the detection was synced, or its verdict was set "
                "or cleared. At-least-once: pass the time the previous pull started.")]
TimezoneParam = Annotated[str, Query(
    description="the timezone relative date filters (`-7d`, `@d`) resolve in")]


def _timezone(name: str):
    try:
        return pytz.timezone(name)
    except pytz.UnknownTimeZoneError:
        raise HTTPException(status_code=422, detail=f"unknown timezone {name!r}")


async def _prepare_listing(f: list[str], changed_since: datetime | None, tz: str) -> service.DetectionPointListing:
    try:
        return await run_db_in_thread(
            service.prepare_detection_point_listing, f, changed_since=changed_since, tz=_timezone(tz))
    except service.InvalidListingRequest as e:
        raise HTTPException(status_code=422, detail=e.detail)


async def _fetch_page(listing: service.DetectionPointListing, cursor: str | None, limit: int):
    try:
        return await run_db_in_thread(service.fetch_detection_point_page, listing, cursor, limit)
    except service.InvalidCursor as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", response_model=DetectionPointListPage)
async def list_detection_points(
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=service.LISTING_MAX_PAGE_SIZE)] = 100,
    tz: TimezoneParam = "UTC",
) -> DetectionPointListPage:
    """List detections with their effective verdict, its source and any stored override.

    Scoped to the alerts this node shows, as the alert listing is. Pages are keyset pages in
    detection order: follow next_cursor until it is null.
    """
    listing = await _prepare_listing(f, changed_since, tz)
    rows, next_cursor = await _fetch_page(listing, cursor, limit)
    return DetectionPointListPage(data=rows, next_cursor=next_cursor)


#
# exports: every detection the listing matches, streamed in one response with the same filters,
# scoping and order as GET /detection-points and no paging. One route per format.
#


class _ExportFailed(Exception):
    """A page after the first could not be fetched, after the response started."""


async def _prepare_export(f: list[str], changed_since: datetime | None, tz: str):
    """The listing and its first page. Everything that can be a 4xx happens here, before the
    response starts: once the first byte is sent the status code cannot change."""
    listing = await _prepare_listing(f, changed_since, tz)
    first_page = await _fetch_page(listing, None, service.LISTING_EXPORT_PAGE_SIZE)
    return listing, first_page


async def _export_pages(listing: service.DetectionPointListing,
                        first_page: tuple[list[DetectionPointRow], str | None]):
    """Yields the rows of every page in turn. Raises _ExportFailed (after logging) when a later
    page fails, so each format can end its stream the way that format can say so."""
    rows, next_cursor = first_page
    yield rows
    while next_cursor is not None:
        try:
            rows, next_cursor = await run_db_in_thread(
                service.fetch_detection_point_page, listing, next_cursor, service.LISTING_EXPORT_PAGE_SIZE)
        except Exception as e:
            logger.error("detection point export failed part-way: %s", e, exc_info=True)
            raise _ExportFailed() from e
        yield rows


def _attachment(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_detection_points_ndjson(
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream every detection the listing matches as NDJSON, one DetectionPointRow per line.

    A failure part-way through cannot change the status code that was already sent: the stream
    then ends with an {"error": ...} line, and the failure is logged.
    """
    listing, first_page = await _prepare_export(f, changed_since, tz)

    async def _stream():
        try:
            async for rows in _export_pages(listing, first_page):
                yield "".join(row.model_dump_json() + "\n" for row in rows)
        except _ExportFailed:
            yield json.dumps({"error": "the export failed part-way; the lines above are incomplete"}) + "\n"

    return NdjsonStreamResponse(_stream(), headers=_attachment("detection-points.ndjson"))


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_detection_points_csv(
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    tz: TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream every detection the listing matches as CSV: a header line, then one row per
    detection (details written as JSON).

    A failure part-way through cannot change the status code that was already sent: the CSV is
    then truncated, and the failure is logged.
    """
    listing, first_page = await _prepare_export(f, changed_since, tz)

    async def _stream():
        header = True
        try:
            async for rows in _export_pages(listing, first_page):
                yield service.detection_point_rows_to_csv(rows, header=header)
                header = False
        except _ExportFailed:
            # CSV has no way to say so in-band; the truncation and the log are the signal
            return

    return CsvStreamResponse(_stream(), headers=_attachment("detection-points.csv"))
