from typing import Optional

from sqlalchemy import func
from saq.database.model import FileCollection, FileCollectionHistory
from saq.database.pool import get_db
from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus


def queue_file_collection(
    collector_name: str,
    observable_type: str,
    observable_value: str,
    alert_uuid: Optional[str] = None,
    user_id: Optional[int] = None,
    max_retries: int = 10
) -> int:
    """Queues a file collection request.

    Args:
        collector_name: Name of the FileCollector to use (e.g., 'falcon_file_collection').
        observable_type: The observable type (e.g., 'file_location').
        observable_value: The observable value (e.g., 'hostname@/path/to/file').
        alert_uuid: UUID of the originating alert, or None for a collection no alert asked for
            (an API caller's). Its file is kept in the node's data directory instead of the
            alert's, and removed after service_file_collection.retention_days
            (saq.file_collection.storage).
        user_id: ID of the user who requested collection (optional for automated).
        max_retries: Maximum number of retry attempts.

    Returns:
        The database ID of the created file collection request.
    """
    file_collection = FileCollection(
        name=collector_name,
        type=observable_type,
        key=observable_value,
        alert_uuid=alert_uuid,
        user_id=user_id,
        max_retries=max_retries,
    )
    get_db().add(file_collection)
    get_db().flush()  # to get the id
    get_db().commit()
    return file_collection.id


def resolve_duplicate_pending_file_collection(collection_id: int) -> int:
    """Resolves a duplicate pending file collection created by a check-then-insert race.

    Call this immediately after queue_file_collection(). If an older pending
    (NEW or IN_PROGRESS) request exists for the same (name, type, key), the
    just-queued request is deleted and the older request's ID is returned so the
    caller attaches to it. Otherwise the given ID is returned unchanged. A request
    with an alert only attaches to another alert's, and one without only to another
    without, because the two keep their files in different places for different
    lengths of time (saq.file_collection.storage).

    The just-queued request is only deleted while it is still NEW and unlocked.
    If the collector loop already picked it up, it is kept (a brief duplicate is
    preferable to deleting a row the worker is about to record history against).
    """
    own = get_file_collection(collection_id)
    if own is None:
        return collection_id

    earlier = (
        get_db()
        .query(FileCollection)
        .filter(
            FileCollection.name == own.name,
            FileCollection.type == own.type,
            FileCollection.key == own.key,
            _has_alert(own.alert_uuid is not None),
            FileCollection.status.in_([
                FileCollectionStatus.NEW.value,
                FileCollectionStatus.IN_PROGRESS.value,
            ]),
            FileCollection.id < collection_id,
        )
        .order_by(FileCollection.id.asc())
        .first()
    )
    if earlier is None:
        return collection_id

    if own.status == FileCollectionStatus.NEW.value and own.lock is None:
        delete_file_collection(collection_id)
        return earlier.id

    return collection_id


def _has_alert(with_alert: bool):
    return FileCollection.alert_uuid.isnot(None) if with_alert else FileCollection.alert_uuid.is_(None)


def get_file_collection(collection_id: int) -> Optional[FileCollection]:
    """Returns the file collection request with the given ID."""
    return (
        get_db()
        .query(FileCollection)
        .filter(FileCollection.id == collection_id)
        .first()
    )


def get_file_collection_by_observable(
    collector_name: str,
    observable_type: str,
    observable_value: str,
    alert_uuid: str,
) -> Optional[FileCollection]:
    """Returns the most recent file collection request for the given observable.

    Args:
        collector_name: Name of the FileCollector.
        observable_type: The observable type.
        observable_value: The observable value.
        alert_uuid: The alert UUID to filter by.

    Returns:
        The most recent FileCollection matching the criteria, or None.
    """
    query = (
        get_db()
        .query(FileCollection)
        .filter(
            FileCollection.name == collector_name,
            FileCollection.type == observable_type,
            FileCollection.key == observable_value,
            FileCollection.alert_uuid == alert_uuid,
        )
    )

    return query.order_by(FileCollection.id.desc()).first()


def get_pending_file_collection_by_observable(
    collector_name: str,
    observable_type: str,
    observable_value: str,
    alert_uuid: Optional[str] = None,
    with_alert: bool = True,
) -> Optional[FileCollection]:
    """Returns any pending (NEW or IN_PROGRESS) file collection request for the observable.

    This is used to avoid creating duplicate requests when multiple users or alerts
    trigger collection for the same observable.

    Args:
        collector_name: Name of the FileCollector.
        observable_type: The observable type.
        observable_value: The observable value.
        alert_uuid: Optional alert UUID to filter by. When None, pending requests
            from any alert are considered.
        with_alert: False to consider only requests no alert asked for (an API
            caller's) instead. A request with an alert never converges on one without,
            or the other way round: their files are kept in different places for
            different lengths of time (saq.file_collection.storage).

    Returns:
        The matching pending FileCollection, or None.
    """
    query = (
        get_db()
        .query(FileCollection)
        .filter(
            FileCollection.name == collector_name,
            FileCollection.type == observable_type,
            FileCollection.key == observable_value,
            FileCollection.status.in_([
                FileCollectionStatus.NEW.value,
                FileCollectionStatus.IN_PROGRESS.value,
            ]),
        )
    )
    if alert_uuid is not None:
        query = query.filter(FileCollection.alert_uuid == alert_uuid)
        return query.order_by(FileCollection.id.desc()).first()

    # cross-alert lookup: return the oldest pending request so that all
    # concurrent callers converge on the same collection
    return query.filter(_has_alert(with_alert)).order_by(FileCollection.id.asc()).first()


def get_file_collection_history(collection_id: int) -> list[FileCollectionHistory]:
    """Returns the history of attempts for the given file collection request."""
    return (
        get_db()
        .query(FileCollectionHistory)
        .filter(FileCollectionHistory.file_collection_id == collection_id)
        .order_by(FileCollectionHistory.insert_date.desc())
        .all()
    )


def cancel_file_collection(collection_id: int) -> bool:
    """Cancels a file collection request.

    Args:
        collection_id: The ID of the file collection to cancel.

    Returns:
        True if the collection was cancelled, False if not found.
    """
    file_collection = get_file_collection(collection_id)
    if file_collection is None:
        return False

    # Can only cancel if not already completed
    if file_collection.status == FileCollectionStatus.COMPLETED.value:
        return False

    update = FileCollection.__table__.update()
    update = update.values(
        status=FileCollectionStatus.COMPLETED.value,
        result=FileCollectorStatus.CANCELLED.value,
        update_time=func.NOW(),
    )
    update = update.where(FileCollection.id == collection_id)
    get_db().execute(update)
    get_db().commit()
    return True


def retry_file_collection(collection_id: int) -> bool:
    """Resets a completed file collection request to try again.

    Args:
        collection_id: The ID of the file collection to retry.

    Returns:
        True if the collection was reset for retry, False if not found.
    """
    file_collection = get_file_collection(collection_id)
    if file_collection is None:
        return False

    update = FileCollection.__table__.update()
    update = update.values(
        status=FileCollectionStatus.NEW.value,
        result=None,
        result_message=None,
        lock=None,
        lock_time=None,
        update_time=func.NOW(),
        retry_count=0,
    )
    update = update.where(FileCollection.id == collection_id)
    get_db().execute(update)
    get_db().commit()
    return True


def delete_file_collection(collection_id: int) -> bool:
    """Deletes a file collection request.

    Args:
        collection_id: The ID of the file collection to delete.

    Returns:
        True if the collection was deleted, False if not found.
    """
    file_collection = get_file_collection(collection_id)
    if file_collection is None:
        return False

    # Delete history first
    delete_history = FileCollectionHistory.__table__.delete().where(
        FileCollectionHistory.file_collection_id == collection_id
    )
    get_db().execute(delete_history)

    # Delete the collection
    delete = FileCollection.__table__.delete().where(FileCollection.id == collection_id)
    get_db().execute(delete)
    get_db().commit()
    return True
