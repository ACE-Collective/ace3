from datetime import UTC, datetime
import logging
from threading import Lock
from typing import Optional

from sqlalchemy.sql import func

from saq.database.model import FileCollection, FileCollectionHistory
from saq.database.pool import get_db
from saq.file_collection.database import get_file_collection
from saq.file_collection.file_collector import FileCollector
from saq.file_collection.types import (
    FileCollectionStatus,
    FileCollectionWorkItem,
    FileCollectorResult,
    FileCollectorStatus,
)
from saq.queue_service import QueueWorker


class FileCollectionWorker(QueueWorker[FileCollectionWorkItem]):
    """Worker that executes file collection requests using a FileCollector implementation."""

    def __init__(self, file_collector: FileCollector):
        super().__init__()
        self.file_collector = file_collector
        # ids of the collections we have accepted but not yet finished (queued or in progress)
        self._pending_ids: set[int] = set()
        self._pending_ids_lock = Lock()

    @property
    def name(self) -> str:
        return self.file_collector.name

    @property
    def thread_count(self) -> int:
        return self.file_collector.config.thread_count

    def describe(self, work_item: FileCollectionWorkItem) -> str:
        return f"file collection {work_item.id} ({work_item.name} {work_item.type} {work_item.key})"

    def log_extra(self, work_item: FileCollectionWorkItem) -> dict:
        return {"alert_uuid": work_item.alert_uuid}

    def handle_request(self, work_item: FileCollectionWorkItem):
        # holding the lock while the item is queued keeps a worker thread from finishing it and
        # discarding its id before the id is added
        with self._pending_ids_lock:
            super().handle_request(work_item)
            self._pending_ids.add(work_item.id)

    def pending_collection_ids(self) -> set[int]:
        with self._pending_ids_lock:
            return set(self._pending_ids)

    def process_one(self, work_item: FileCollectionWorkItem):
        try:
            self.collect(work_item)
        finally:
            with self._pending_ids_lock:
                self._pending_ids.discard(work_item.id)

    def claim(self, target: FileCollectionWorkItem) -> bool:
        """Re-reads the database record for the work item and decides whether to collect it.

        A work item can sit in the queue long enough for its database lock to time out, and a
        service restart drops the queue entirely. Both can leave a work item that no longer
        reflects the record: the collection may have completed in the meantime or been locked
        again by a different collector. Returns False (and writes nothing) in those cases;
        otherwise refreshes the lock time so the timeout counts from when work actually starts."""
        file_collection = get_file_collection(target.id)
        if file_collection is None:
            logging.warning(f"file collection {target.id} for {target.type} {target.key} no longer exists")
            get_db().rollback()
            return False

        if file_collection.status == FileCollectionStatus.COMPLETED.value:
            logging.info(
                f"file collection {target.id} for {target.type} {target.key} already completed "
                f"({file_collection.result}), skipping"
            )
            get_db().rollback()
            return False

        if target.lock is not None and file_collection.lock != target.lock:
            logging.info(
                f"file collection {target.id} for {target.type} {target.key} is now locked by "
                f"{file_collection.lock}, skipping"
            )
            get_db().rollback()
            return False

        if target.lock is not None:
            update = FileCollection.__table__.update()
            update = update.values(lock_time=func.NOW())
            update = update.where(FileCollection.id == target.id, FileCollection.lock == target.lock)
            get_db().execute(update)

        get_db().commit()
        return True

    def collect(self, target: FileCollectionWorkItem) -> Optional[FileCollectorResult]:
        """Collects the target and records the result. Returns None if the work item was skipped
        because its database record was already completed or no longer locked by us."""
        if not self.claim(target):
            return None

        logging.info(
            f"STARTED collecting {target.type} {target.key} "
            f"(attempt {target.retry_count + 1}/{target.max_retries})"
        )

        try:
            # run the file collector on the target
            collector_result = self.file_collector.collect(target)
        except Exception as e:
            # set the result to error and log the error
            collector_result = FileCollectorResult(
                status=FileCollectorStatus.ERROR,
                message=f"{e.__class__.__name__}: {e}",
            )
            logging.error(
                f"{self.file_collector.name} failed to collect {target.type} {target.key}: {e}"
            )

        # determine if we should mark as completed or allow retry
        should_complete = collector_result.status.is_final or not self.file_collector.should_retry(
            collector_result, target.retry_count + 1, target.max_retries
        )

        # update the database record
        update = FileCollection.__table__.update()
        update = update.values(
            lock=None,  # release the lock
            status=collector_result.status.collection_status.value,
            result=collector_result.status.value,
            result_message=collector_result.message,
            collected_file_path=collector_result.collected_file_path,
            collected_file_sha256=collector_result.collected_file_sha256,
            update_time=datetime.now(UTC),
            retry_count=target.retry_count + 1,
        )
        # if we've exceeded retries or got a final status, mark as completed
        if should_complete:
            update = update.values(status="COMPLETED")

        update = update.where(FileCollection.id == target.id)
        get_db().execute(update)
        get_db().flush()

        # record history entry
        file_collection_history = FileCollectionHistory(
            file_collection_id=target.id,
            result=collector_result.status.value,
            message=collector_result.message or "",
            status=collector_result.status.collection_status.value,
        )
        get_db().add(file_collection_history)
        get_db().commit()

        # log result
        if collector_result.status == FileCollectorStatus.SUCCESS:
            logging.info(
                f"SUCCESS collecting {target.type} {target.key} -> {collector_result.collected_file_path}"
            )
        elif collector_result.status.is_retryable and not should_complete:
            logging.info(
                f"{collector_result.status.value} collecting {target.type} {target.key}, "
                f"will retry ({target.retry_count + 1}/{target.max_retries})"
            )
        else:
            logging.warning(
                f"{collector_result.status.value} collecting {target.type} {target.key}: "
                f"{collector_result.message}"
            )

        return collector_result
