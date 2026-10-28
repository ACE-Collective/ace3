"""File collection router (ACE API v2).

The File Collections page: the list of file collection requests with its filters (the
file_collections filter screen) and exports, a request's history, and stopping, retrying and
deleting one. Reading needs file_collection:read, changing a request file_collection:write.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security, status

from aceapi_v2 import listing
from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.file_collection import service
from aceapi_v2.file_collection.schemas import (
    FILE_COLLECTION_ROW_CSV_FIELDS,
    FileCollectionHistoryEntry,
    FileCollectionListPage,
    FileCollectionSummary,
)
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.schemas.base import ListResponse
from aceapi_v2.sync import run_db_in_thread
from saq.gui.filter_screens import FILE_COLLECTIONS_SCREEN
from saq.logging import log_audit

router = APIRouter(dependencies=[Security(get_current_auth)])

FilterParam = listing.filter_param(FILE_COLLECTIONS_SCREEN)


@router.get("/", response_model=FileCollectionListPage)
async def list_file_collections(
    _: Annotated[ApiAuthResult, Depends(require_permission("file_collection", "read"))],
    f: FilterParam,
    cursor: listing.CursorParam = None,
    limit: listing.LimitParam = 100,
    tz: listing.TimezoneParam = "UTC",
) -> FileCollectionListPage:
    """List file collection requests, newest first. Follow next_cursor, with the same filters,
    until it is null."""
    selection = service.prepare_listing(f, listing.timezone(tz))
    rows, next_cursor = await run_db_in_thread(listing.fetch_page, selection, cursor, limit)
    return FileCollectionListPage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_file_collections_ndjson(
    _: Annotated[ApiAuthResult, Depends(require_permission("file_collection", "read"))],
    f: FilterParam,
    tz: listing.TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream every request the filters match as NDJSON, one FileCollectionRow per line; a failure
    part-way ends the stream with an {"error": ...} line."""
    return await listing.export_ndjson(service.prepare_listing(f, listing.timezone(tz)), "file-collections.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_file_collections_csv(
    _: Annotated[ApiAuthResult, Depends(require_permission("file_collection", "read"))],
    f: FilterParam,
    tz: listing.TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream every request the filters match as CSV; a failure part-way truncates it."""
    return await listing.export_csv(
        service.prepare_listing(f, listing.timezone(tz)), FILE_COLLECTION_ROW_CSV_FIELDS, "file-collections.csv")


@router.get("/{collection_id}/history", response_model=ListResponse[FileCollectionHistoryEntry])
async def get_file_collection_history(
    collection_id: int,
    _: Annotated[ApiAuthResult, Depends(require_permission("file_collection", "read"))],
    limit: Annotated[int, Query(ge=1, le=1000, description="at most this many of the latest attempts")] = 100,
) -> ListResponse[FileCollectionHistoryEntry]:
    """What the file collector recorded of each attempt at a request, newest first."""
    return ListResponse(data=await run_db_in_thread(service.history, collection_id, limit))


@router.post("/{collection_id}/cancel", response_model=FileCollectionSummary)
async def cancel_file_collection(
    collection_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("file_collection", "write"))],
) -> FileCollectionSummary:
    """Stops a request that has not completed; it completes as CANCELLED. One that has completed
    is a 409: its result stands."""
    cancelled = await run_db_in_thread(service.cancel, collection_id)
    log_audit("user %s cancelled file collection %s", auth.auth_name, collection_id, auth=auth,
              file_collection_id=collection_id)
    return cancelled


@router.post("/{collection_id}/retry", response_model=FileCollectionSummary)
async def retry_file_collection(
    collection_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("file_collection", "write"))],
) -> FileCollectionSummary:
    """Starts a request over: queued again with no attempts counted, whatever its state."""
    retried = await run_db_in_thread(service.retry, collection_id)
    log_audit("user %s retried file collection %s", auth.auth_name, collection_id, auth=auth,
              file_collection_id=collection_id)
    return retried


@router.delete("/{collection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file_collection(
    collection_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("file_collection", "write"))],
) -> None:
    """Deletes a request and its history."""
    removed = await run_db_in_thread(service.delete, collection_id)
    log_audit("user %s deleted file collection %s (%s, %s)", auth.auth_name, collection_id,
              removed.status, removed.result, auth=auth, file_collection_id=collection_id)
