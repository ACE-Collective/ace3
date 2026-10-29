from datetime import UTC, datetime
import logging
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Query
from sqlalchemy.sql import func

from saq.database.model import Alert, FileCollection
from saq.database.pool import get_db
from saq.file_collection.interface import FileCollectionListener
from saq.file_collection.storage import unattached_storage_dir
from saq.file_collection.types import FileCollectionStatus, FileCollectionWorkItem, FileCollectorStatus
from saq.queue_service import QueueCollector
from saq.util.time import calculate_backoff_delay


def create_file_collection_work_item(file_collection: FileCollection) -> Optional[FileCollectionWorkItem]:
    """Creates a FileCollectionWorkItem from a FileCollection database object.

    The collected file goes in the alert's storage directory, or for a collection no alert asked
    for, in this node's directory for it (saq.file_collection.storage). Deleting an alert leaves
    its collections behind. A collection whose alert no longer exists has nowhere to put its file,
    so this marks it completed and failed, releases its lock and returns None.
    QueueCollector.collect_work_items commits that update.
    """
    if file_collection.alert_uuid is None:
        storage_dir = unattached_storage_dir(file_collection.id)
    else:
        alert = get_db().query(Alert).filter(Alert.uuid == file_collection.alert_uuid).first()
        if alert is None:
            message = f"alert {file_collection.alert_uuid} no longer exists"
            update = FileCollection.__table__.update()
            update = update.values(
                lock=None,
                status=FileCollectionStatus.COMPLETED.value,
                result=FileCollectorStatus.FAILED.value,
                result_message=message,
                update_time=func.NOW(),
            )
            update = update.where(FileCollection.id == file_collection.id, FileCollection.lock == file_collection.lock)
            get_db().execute(update)
            logging.warning(
                f"file collection {file_collection.id} for {file_collection.type} {file_collection.key} "
                f"failed: {message}",
                extra={"file_collection_id": file_collection.id, "alert_uuid": file_collection.alert_uuid},
            )
            return None
        storage_dir = alert.storage_dir

    return FileCollectionWorkItem(
        id=file_collection.id,
        name=file_collection.name,
        type=file_collection.type,
        key=file_collection.key,
        alert_uuid=file_collection.alert_uuid,
        storage_dir=storage_dir,
        retry_count=file_collection.retry_count,
        max_retries=file_collection.max_retries,
        lock=file_collection.lock,
    )


class FileCollectionCollector(QueueCollector[FileCollectionWorkItem]):
    """Responsible for collecting file collection jobs from the database and sending them to the appropriate workers.

    Uses exponential backoff for retry delays based on retry_count, and a time-based cutoff based
    on max_collection_time_seconds."""

    model = FileCollection
    label = "file collection"

    def __init__(
        self,
        lock_timeout_seconds: int = 300,
        initial_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
        max_collection_time_seconds: int = 604800,
    ):
        super().__init__(lock_timeout_seconds=lock_timeout_seconds)
        self.initial_retry_delay_seconds = initial_retry_delay_seconds
        self.max_retry_delay_seconds = max_retry_delay_seconds
        self.max_collection_time_seconds = max_collection_time_seconds
        self.listeners: dict[str, FileCollectionListener] = {}

    def pending_collection_ids(self) -> set[int]:
        """Returns the ids of every file collection currently held by a listener (queued or in progress)."""
        pending: set[int] = set()
        for listener in self.listeners.values():
            pending.update(listener.pending_collection_ids())
        return pending

    def filter_candidates(self, query: Query) -> Query:
        # only collections that have not exceeded max collection time (time-based cutoff)
        return query.filter(
            func.NOW() < func.DATE_ADD(
                FileCollection.insert_date, text(f"INTERVAL {self.max_collection_time_seconds} SECOND")
            )
        )

    def ready(self, rows: list[FileCollection]) -> list[FileCollection]:
        # Skip anything a listener already holds. A worker's queue can hold an item longer than
        # lock_timeout_seconds when collections are slow, and re-locking it here would push a
        # duplicate copy into that queue.
        pending_ids = self.pending_collection_ids()

        # Filter by per-record exponential backoff delay
        ready_for_retry = []
        now = datetime.now(UTC)
        for c in rows:
            if c.id in pending_ids:
                continue

            # Calculate the required delay for this record based on its retry_count
            required_delay = calculate_backoff_delay(
                c.retry_count,
                self.initial_retry_delay_seconds,
                self.max_retry_delay_seconds,
            )

            # Check if enough time has passed since last update
            if c.update_time is None:
                # Never been processed, ready immediately
                ready_for_retry.append(c)
            else:
                # Ensure update_time is timezone-aware for comparison
                update_time = c.update_time
                if update_time.tzinfo is None:
                    update_time = update_time.replace(tzinfo=UTC)

                elapsed = (now - update_time).total_seconds()
                if elapsed >= required_delay:
                    ready_for_retry.append(c)

        return ready_for_retry

    def build_work_item(self, row: FileCollection) -> Optional[FileCollectionWorkItem]:
        return create_file_collection_work_item(row)
