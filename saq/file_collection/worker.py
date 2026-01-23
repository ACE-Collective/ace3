from datetime import UTC, datetime
import logging
from queue import Empty, Queue
from threading import Event, Thread

from saq.database.model import FileCollection, FileCollectionHistory
from saq.database.pool import get_db
from saq.error.reporting import report_exception
from saq.file_collection.file_collector import FileCollector
from saq.file_collection.interface import FileCollectionListener
from saq.file_collection.types import FileCollectionWorkItem, FileCollectorResult, FileCollectorStatus


class FileCollectionWorker(FileCollectionListener):
    """Worker that executes file collection requests using a FileCollector implementation."""

    def __init__(self, file_collector: FileCollector):
        self.file_collector = file_collector
        self.work_queue: Queue[FileCollectionWorkItem] = Queue()
        self.worker_threads: list[Thread] = []
        self.startup_events: list[Event] = []
        self.shutdown_event = Event()
        # the timeout for the work queue get operation
        self.queue_wait_timeout = 1

    #
    # FileCollectionListener interface
    # ------------------------------------------------------------------------

    def handle_file_collection_request(self, work_item: FileCollectionWorkItem):
        if work_item.name != self.file_collector.name:
            raise ValueError(
                f"file collection name {work_item.name} does not match "
                f"file collector name {self.file_collector.name}"
            )

        logging.info(f"received file collection request for {work_item.type} {work_item.key}")
        self.work_queue.put(work_item)

    #
    # Worker implementation
    # ------------------------------------------------------------------------

    def start(self):
        logging.info(
            f"starting {self.file_collector.config.thread_count} threads "
            f"for file collector {self.file_collector.name}"
        )
        for index in range(self.file_collector.config.thread_count):
            startup_event = Event()
            self.startup_events.append(startup_event)
            thread = Thread(
                target=self.worker_loop,
                name=f"FileCollectionWorker-{self.file_collector.name}-{index}",
                args=(startup_event,),
            )
            self.worker_threads.append(thread)
            thread.start()

    def start_single_threaded(self):
        self.stop()
        self.worker_loop(Event())

    def wait_for_start(self, timeout: float) -> bool:
        for index, startup_event in enumerate(self.startup_events):
            if not startup_event.wait(timeout):
                logging.error(f"worker {index} did not start")
                return False

        return True

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        for thread in self.worker_threads:
            thread.join()

    def worker_loop(self, startup_event: Event):
        startup_event.set()
        while True:
            work = None

            try:
                work = self.work_queue.get(timeout=self.queue_wait_timeout)
            except Empty:
                pass

            try:
                if work:
                    self.collect(work)
            except Exception as e:
                logging.error(f"error executing work: {e}")
                report_exception()

            if self.shutdown_event.is_set():
                break

    def collect(self, target: FileCollectionWorkItem) -> FileCollectorResult:
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
