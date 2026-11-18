"""File collection service (ACE API v2).

Sync helpers over the file_collection tables, run through run_db_in_thread: saq.file_collection
reads and writes through the synchronous get_db() session.
"""

from datetime import tzinfo

from fastapi import HTTPException
from sqlalchemy import select

from aceapi_v2.file_collection.schemas import FileCollectionHistoryEntry, FileCollectionRow, FileCollectionSummary
from aceapi_v2.listing import Listing, filter_entries
from saq.database.model import FileCollection, FileCollectionHistory, User
from saq.database.pool import get_db
from saq.file_collection.database import cancel_file_collection, delete_file_collection, retry_file_collection
from saq.file_collection.filters import file_collection_filter_conditions
from saq.gui.filter_screens import FILE_COLLECTIONS_SCREEN


def file_collection_row(row) -> FileCollectionRow:
    """The API row of a (FileCollection, requester display name) result row."""
    collection, requested_by = row
    return FileCollectionRow(
        id=collection.id, collector=collection.name, observable_type=collection.type,
        observable_value=collection.key, status=collection.status, result=collection.result,
        result_message=collection.result_message, retry_count=collection.retry_count,
        max_retries=collection.max_retries, alert_uuid=collection.alert_uuid, requested_by=requested_by,
        collected_file_sha256=collection.collected_file_sha256, insert_date=collection.insert_date,
        update_time=collection.update_time)


def prepare_listing(f: list[str], tz: tzinfo) -> Listing:
    """The file collections the share-link filters (f=) of the file collections screen select."""
    statement = select(FileCollection, User.display_name).outerjoin(User, User.id == FileCollection.user_id)
    for condition in file_collection_filter_conditions(filter_entries(FILE_COLLECTIONS_SCREEN, f), tz):
        statement = statement.where(condition)

    return Listing(statement=statement, id_column=FileCollection.id, to_row=file_collection_row)


def _require(collection_id: int) -> FileCollection:
    collection = get_db().get(FileCollection, collection_id)
    if collection is None:
        raise HTTPException(status_code=404, detail=f"file collection {collection_id} not found")
    return collection


def _summary(collection_id: int) -> FileCollectionSummary:
    get_db().expire_all()
    collection = get_db().get(FileCollection, collection_id)
    return FileCollectionSummary(id=collection.id, status=collection.status, result=collection.result,
                                 retry_count=collection.retry_count)


def history(collection_id: int, limit: int) -> list[FileCollectionHistoryEntry]:
    """A request's latest attempts, newest first."""
    _require(collection_id)
    rows = (
        get_db().query(FileCollectionHistory)
        .filter(FileCollectionHistory.file_collection_id == collection_id)
        .order_by(FileCollectionHistory.insert_date.desc(), FileCollectionHistory.id.desc())
        .limit(limit)
        .all()
    )
    return [FileCollectionHistoryEntry(insert_date=row.insert_date, result=row.result, status=row.status,
                                       message=row.message) for row in rows]


def cancel(collection_id: int) -> FileCollectionSummary:
    """Stops a request that has not completed: it completes as CANCELLED."""
    _require(collection_id)
    if not cancel_file_collection(collection_id):
        raise HTTPException(status_code=409, detail=f"file collection {collection_id} has already completed")

    return _summary(collection_id)


def retry(collection_id: int) -> FileCollectionSummary:
    """Starts a request over: queued again with no attempts, whatever its state."""
    _require(collection_id)
    retry_file_collection(collection_id)
    return _summary(collection_id)


def delete(collection_id: int) -> FileCollectionSummary:
    """Deletes a request and its history. Returns it as it was."""
    removed = FileCollectionSummary(**{name: getattr(_require(collection_id), name)
                                       for name in ("id", "status", "result", "retry_count")})
    delete_file_collection(collection_id)
    return removed
