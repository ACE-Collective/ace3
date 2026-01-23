from typing import Optional

from sqlalchemy import func
from saq.database.model import FileCollection, FileCollectionHistory
from saq.database.pool import get_db
from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus


def queue_file_collection(
    collector_name: str,
    observable_type: str,
    observable_value: str,
    alert_uuid: str,
    user_id: Optional[int] = None,
    max_retries: int = 10
) -> int:
    """Queues a file collection request.

    Args:
        collector_name: Name of the FileCollector to use (e.g., 'falcon_file_collection').
        observable_type: The observable type (e.g., 'file_location').
        observable_value: The observable value (e.g., 'hostname@/path/to/file').
        alert_uuid: UUID of the originating alert.
        user_id: ID of the user who requested collection (optional for automated).
        max_retries: Maximum number of retry attempts.

    Returns:
        The database ID of the created file collection request.

    Raises:
        ValueError: If alert_uuid is not provided.
    """
    if not alert_uuid:
        raise ValueError("alert_uuid is required for file collection")
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
    alert_uuid: str,
) -> Optional[FileCollection]:
    """Returns any pending (NEW or IN_PROGRESS) file collection request for the observable.

    This is used to avoid creating duplicate requests when multiple users trigger
    collection for the same observable.

    Args:
        collector_name: Name of the FileCollector.
        observable_type: The observable type.
        observable_value: The observable value.
        alert_uuid: The alert UUID to filter by.

    Returns:
        The most recent pending FileCollection matching the criteria, or None.
    """
    query = (
        get_db()
        .query(FileCollection)
        .filter(
            FileCollection.name == collector_name,
            FileCollection.type == observable_type,
            FileCollection.key == observable_value,
            FileCollection.alert_uuid == alert_uuid,
            FileCollection.status != FileCollectionStatus.COMPLETED.value,
        )
    )
    return query.order_by(FileCollection.id.desc()).first()


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
