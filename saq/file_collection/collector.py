from datetime import UTC, datetime
import logging
from threading import Event, Thread
from typing import Optional
from uuid import uuid4

from sqlalchemy import or_, text
from sqlalchemy.sql import func

from saq.database.model import Alert, FileCollection
from saq.database.pool import get_db
from saq.error.reporting import report_exception
from saq.file_collection.interface import FileCollectionListener
from saq.file_collection.types import FileCollectionStatus, FileCollectionWorkItem
from saq.util.time import calculate_backoff_delay


def create_file_collection_work_item(file_collection: FileCollection) -> Optional[FileCollectionWorkItem]:
    """Creates a FileCollectionWorkItem from a FileCollection database object.

    Returns None if the associated alert cannot be found.
    """
    # Look up the alert to get its storage_dir
    alert = get_db().query(Alert).filter(Alert.uuid == file_collection.alert_uuid).first()
    if alert is None:
        logging.error(f"Alert {file_collection.alert_uuid} not found for file collection {file_collection.id}")
        return None

    return FileCollectionWorkItem(
        id=file_collection.id,
        name=file_collection.name,
        type=file_collection.type,
        key=file_collection.key,
        alert_uuid=file_collection.alert_uuid,
        storage_dir=alert.storage_dir,
        retry_count=file_collection.retry_count,
        max_retries=file_collection.max_retries,
    )


class FileCollectionCollector:
    """Responsible for collecting file collection jobs from the database and sending them to the appropriate workers."""

    collector_thread: Thread

    def __init__(
        self,
        lock_timeout_seconds: int = 300,
        initial_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
        max_collection_time_seconds: int = 604800,
    ):
        self.lock_timeout_seconds = lock_timeout_seconds
        self.initial_retry_delay_seconds = initial_retry_delay_seconds
        self.max_retry_delay_seconds = max_retry_delay_seconds
        self.max_collection_time_seconds = max_collection_time_seconds
        self.collector_startup_event = Event()
        self.shutdown_event = Event()

        # maps a collector name to a FileCollectionListener instance
        self.listeners: dict[str, FileCollectionListener] = {}

    def start(self):
        self.collector_thread = Thread(target=self.collection_loop, name="File Collection Collector")
        self.collector_thread.start()

    def start_single_threaded(self):
        # execute the loop once and exit
        self.shutdown_event.set()
        self.collection_loop()

    def wait_for_start(self, timeout: float) -> bool:
        if not self.collector_startup_event.wait(timeout):
            logging.error("file collection collector thread did not start")
            return False

        return True

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        self.collector_thread.join()

    def register_file_collection_listener(self, name: str, listener: FileCollectionListener):
        """Called to associate a file collector name with a listener.
        Any jobs collected for this collector will be sent to this listener."""
        if name in self.listeners:
            raise ValueError(f"file collection listener {name} already registered")

        self.listeners[name] = listener

    def notify_file_collection_listeners(self, work_item: FileCollectionWorkItem):
        """Called to queue a file collection for processing."""
        if work_item.name not in self.listeners:
            raise ValueError(f"file collector name {work_item.name} not registered")

        self.listeners[work_item.name].handle_file_collection_request(work_item)

    def collect_work_items(self) -> list[FileCollectionWorkItem]:
        """Collects the file collection targets to process from the database.

        Uses exponential backoff for retry delays based on retry_count,
        and time-based cutoff based on max_collection_time_seconds.
        """
        lock_uuid = str(uuid4())

        # First, get all potential candidates (not completed, not expired by time)
        query = get_db().query(FileCollection)
        # only get collections that are ...
        # ...for the collectors we are interested in
        query = query.filter(FileCollection.name.in_(self.listeners.keys()))
        # ... not locked or that are locked but have timed out
        query = query.filter(
            or_(
                FileCollection.lock == None,  # noqa: E711
                func.NOW() >= func.DATE_ADD(
                    FileCollection.lock_time, text(f"INTERVAL {self.lock_timeout_seconds} SECOND")
                ),
            )
        )
        # ... not completed
        query = query.filter(FileCollection.status != FileCollectionStatus.COMPLETED.value)
        # ... have not exceeded max collection time (time-based cutoff)
        query = query.filter(
            func.NOW() < func.DATE_ADD(
                FileCollection.insert_date, text(f"INTERVAL {self.max_collection_time_seconds} SECOND")
            )
        )
        query = query.order_by(FileCollection.insert_date.desc())

        collection_objects = query.all()

        # Filter by per-record exponential backoff delay
        ready_for_retry = []
        now = datetime.now(UTC)
        for c in collection_objects:
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

        target_ids = [c.id for c in ready_for_retry]

        if not target_ids:
            return []

        # attempt to lock found targets
        update = FileCollection.__table__.update()
        update = update.values(
            lock=lock_uuid,
            lock_time=datetime.now(UTC),
            status=FileCollectionStatus.IN_PROGRESS.value,
        )
        update = update.where(FileCollection.id.in_(target_ids))
        get_db().execute(update)
        get_db().commit()

        # fetch successfully locked targets
        query = get_db().query(FileCollection)
        query = query.filter(FileCollection.lock == lock_uuid)
        query = query.order_by(FileCollection.insert_date.desc())
        result = query.all()
        # Filter out None results (when alert not found)
        work_items = [create_file_collection_work_item(c) for c in result]
        return [item for item in work_items if item is not None]

    def collection_loop(self):
        self.collector_startup_event.set()
        while True:
            try:
                for work_item in self.collect_work_items():
                    self.notify_file_collection_listeners(work_item)
            except Exception as e:
                logging.error(f"error collecting file collections from database: {e}")
                report_exception()
            finally:
                try:
                    get_db().remove()
                except Exception as e:
                    logging.error(f"error removing database connection: {e}")
                    report_exception()

            if self.shutdown_event.is_set():
                break

            self.shutdown_event.wait(1)
