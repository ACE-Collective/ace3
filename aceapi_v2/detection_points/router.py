"""Detection points router for ACE API v2: every detection with its TP/FP verdict, for export and
reporting (docs/SVS_API.md). One alert's detections and the verdict writes live under
/alerts/{uuid}/detection-points."""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security

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
from aceapi_v2.detection_points import service
from aceapi_v2.detection_points.schemas import DetectionPointListPage
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse

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


async def _prepare_listing(f: list[str], changed_since: datetime | None, tz: str) -> service.DetectionPointListing:
    return await run_listing(
        service.prepare_detection_point_listing, f, changed_since=changed_since, tz=parse_timezone(tz))


@router.get("/", response_model=DetectionPointListPage)
async def list_detection_points(
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    f: FilterParam,
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
    tz: TimezoneParam = "UTC",
) -> DetectionPointListPage:
    """List detections with their effective verdict, its source and any stored override.

    Scoped to the alerts this node shows, as the alert listing is. Pages are keyset pages in
    detection order: follow next_cursor until it is null.
    """
    listing = await _prepare_listing(f, changed_since, tz)
    rows, next_cursor = await run_listing(service.fetch_detection_point_page, listing, cursor, limit)
    return DetectionPointListPage(data=rows, next_cursor=next_cursor)


#
# exports: every detection the listing matches, streamed in one response with the same filters,
# scoping and order as GET /detection-points and no paging. One route per format.
#


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
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_detection_point_page, listing, what="detection point")
    return ndjson_response(export, "detection-points.ndjson")


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
    listing = await _prepare_listing(f, changed_since, tz)
    export = await start_export(service.fetch_detection_point_page, listing, what="detection point")
    return csv_response(export, service.detection_point_rows_to_csv, "detection-points.csv")
