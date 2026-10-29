"""The database-polling queue service that remediation, external remediation checks and file
collection are built on (docs/SERVICES.md)."""

from abc import ABC, abstractmethod
import logging
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any, Generic, Iterable, Optional, Protocol, TypeVar
from uuid import uuid4

from sqlalchemy import or_, text
from sqlalchemy.orm import Query
from sqlalchemy.sql import func

from saq.database.pool import get_db, remove_all_sessions
from saq.error.reporting import log_loop_exception
from saq.service import ACEServiceInterface
from saq.shutdown import is_shutting_down

# every table drained this way shares these values of its status column
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_COMPLETED = "COMPLETED"


class WorkItem(Protocol):
    id: int
    # the name of the worker the item is for
    name: str


ItemT = TypeVar("ItemT", bound=WorkItem)


class QueueListener(Protocol[ItemT]):
    def handle_request(self, work_item: ItemT):
        ...


class QueueCollector(ABC, Generic[ItemT]):
    """Locks the due rows of `model` and dispatches them to the listener registered for each
    row's `name_column`. The model has the columns id, lock, lock_time, status and insert_date."""

    model: Any
    # a string, because a mapped column on the class would be a descriptor of the collector
    name_column: str = "name"
    # what the collected rows are called in log messages
    label: str

    def __init__(self, lock_timeout_seconds: int = 300, loop_interval_seconds: float = 1):
        self.lock_timeout_seconds = lock_timeout_seconds
        self.loop_interval_seconds = loop_interval_seconds
        # stays None when the collector runs single threaded
        self.collector_thread: Optional[Thread] = None
        self.collector_startup_event = Event()
        self.shutdown_event = Event()
        self.listeners: dict[str, QueueListener[ItemT]] = {}

    def filter_candidates(self, query: Query) -> Query:
        """Narrows the query for unlocked, unfinished rows to the ones that are due, in SQL."""
        return query

    def ready(self, rows: list) -> list:
        """Narrows the candidate rows to the ones that are due, for what SQL does not decide."""
        return rows

    @abstractmethod
    def build_work_item(self, row) -> Optional[ItemT]:
        """The work item for a row this collector locked, or None for a row with no work left.
        Before it returns None it finishes the row, and collect_work_items commits that write.
        A row left unfinished would be locked again at every lock timeout."""

    def start(self):
        self.collector_thread = Thread(target=self.collection_loop, name=type(self).__name__)
        self.collector_thread.start()

    def start_single_threaded(self):
        # execute the loop once and exit
        self.shutdown_event.set()
        self.collection_loop()

    def wait_for_start(self, timeout: float) -> bool:
        if not self.collector_startup_event.wait(timeout):
            logging.error(f"{self.label} collector thread did not start")
            return False

        return True

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        # the loop checks the shutdown event after each pass, and `ace service start` bounds wait()
        if self.collector_thread is not None:
            self.collector_thread.join()

    def register_listener(self, name: str, listener: QueueListener[ItemT]):
        """Any row collected for this name goes to this listener."""
        if name in self.listeners:
            raise ValueError(f"{self.label} listener {name} already registered")

        self.listeners[name] = listener

    def notify_listeners(self, work_item: ItemT):
        if work_item.name not in self.listeners:
            raise ValueError(f"{self.label} name {work_item.name} not registered")

        self.listeners[work_item.name].handle_request(work_item)

    def collect_work_items(self) -> list[ItemT]:
        """Locks the rows that are due for the registered listeners and returns their work items."""
        model = self.model
        lock_uuid = str(uuid4())

        query = get_db().query(model)
        # only rows that are ...
        # ... for the listeners we have
        query = query.filter(getattr(model, self.name_column).in_(self.listeners.keys()))
        # ... not locked, or locked but timed out
        query = query.filter(or_(
            model.lock == None, # noqa: E711
            func.NOW() >= func.DATE_ADD(model.lock_time, text(f"INTERVAL {self.lock_timeout_seconds} SECOND"))
        ))
        # ... not completed
        query = query.filter(model.status != STATUS_COMPLETED)
        query = self.filter_candidates(query)
        query = query.order_by(model.insert_date.desc())

        target_ids = [row.id for row in self.ready(query.all())]
        if not target_ids:
            return []

        update = model.__table__.update()
        update = update.values(
            lock=lock_uuid,
            # must come from the database clock: the lock timeout is evaluated server-side against
            # NOW(), and a client-side datetime rounds up into a DATETIME(0) column, where it can
            # land ahead of NOW() and keep the row from being reclaimed
            lock_time=func.NOW(),
            status=STATUS_IN_PROGRESS,
        )
        update = update.where(model.id.in_(target_ids))
        get_db().execute(update)
        get_db().commit()

        # fetch the rows we managed to lock
        query = get_db().query(model)
        query = query.filter(model.lock == lock_uuid)
        query = query.order_by(model.insert_date.desc())
        work_items = [self.build_work_item(row) for row in query.all()]
        # commits the rows build_work_item finished, once for the batch, because a commit per row
        # would expire the rows not built yet and reload each of them
        get_db().commit()
        return [work_item for work_item in work_items if work_item is not None]

    def collection_loop(self):
        self.collector_startup_event.set()
        while True:
            try:
                for work_item in self.collect_work_items():
                    self.notify_listeners(work_item)
            except Exception as e:
                log_loop_exception(e, f"error collecting {self.label} work items from database")
            finally:
                try:
                    remove_all_sessions()
                except Exception as e:
                    log_loop_exception(e, "error removing database connection")

            if self.shutdown_event.is_set():
                break

            self.shutdown_event.wait(self.loop_interval_seconds)


class QueueWorker(ABC, Generic[ItemT]):
    """Runs `thread_count` threads that take work items off an in-memory queue and process them."""

    def __init__(self):
        self.work_queue: Queue[ItemT] = Queue()
        self.worker_threads: list[Thread] = []
        self.startup_events: list[Event] = []
        self.shutdown_event = Event()
        # the timeout for the work queue get operation
        self.queue_wait_timeout = 1

    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the work items this worker takes."""

    @property
    @abstractmethod
    def thread_count(self) -> int:
        ...

    @abstractmethod
    def describe(self, work_item: ItemT) -> str:
        """The work item as it appears in log messages, with the identifiers needed to find it."""

    def log_extra(self, work_item: ItemT) -> dict:
        """The `extra` fields of the log record of a work item that failed."""
        return {}

    @abstractmethod
    def process_one(self, work_item: ItemT):
        ...

    def handle_request(self, work_item: ItemT):
        if work_item.name != self.name:
            raise ValueError(f"work item name {work_item.name} does not match worker name {self.name}")

        logging.info(f"received {self.describe(work_item)}")
        self.work_queue.put(work_item)

    def start(self):
        logging.info(f"starting {self.thread_count} threads for {type(self).__name__} {self.name}")
        for index in range(self.thread_count):
            startup_event = Event()
            self.startup_events.append(startup_event)
            thread = Thread(target=self.worker_loop, name=f"{type(self).__name__}-{self.name}-{index}", args=(startup_event,))
            self.worker_threads.append(thread)
            thread.start()

    def start_single_threaded(self):
        # with the shutdown event set each pass of the loop takes at most one item; the
        # process-wide flag is what a signal sets while this runs on the main thread
        self.stop()
        while not self.work_queue.empty() and not is_shutting_down():
            self.worker_loop(Event())

    def wait_for_start(self, timeout: float) -> bool:
        for index, startup_event in enumerate(self.startup_events):
            if not startup_event.wait(timeout):
                logging.error(f"{type(self).__name__} {self.name} thread {index} did not start")
                return False

        return True

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        # each thread checks the shutdown event after each item, and `ace service start` bounds wait()
        for thread in self.worker_threads:
            thread.join()

    def worker_loop(self, startup_event: Event):
        startup_event.set()
        while True:
            work_item = None

            try:
                work_item = self.work_queue.get(timeout=self.queue_wait_timeout)
            except Empty:
                # nothing queued: check the shutdown event and wait again
                pass

            try:
                if work_item is not None:
                    self.process_one(work_item)
            except Exception as e:
                log_loop_exception(e, f"error processing {self.describe(work_item)}", extra=self.log_extra(work_item))
            finally:
                if work_item is not None:
                    # a failed commit leaves this thread's session needing a rollback, and every
                    # later item on the thread would fail on it until the service restarts; a new
                    # session also starts the next item from a fresh snapshot of its table
                    try:
                        remove_all_sessions()
                    except Exception as e:
                        log_loop_exception(e, "error removing database connection")

            if self.shutdown_event.is_set():
                break


WorkerT = TypeVar("WorkerT", bound=QueueWorker)


class QueueManager(ABC, Generic[WorkerT]):
    """Owns the collector and the workers it dispatches to."""

    def __init__(self, collector: QueueCollector):
        # mapped by name, which keeps the names unique
        self.workers: dict[str, WorkerT] = {}
        self.collector = collector

    @abstractmethod
    def create_workers(self) -> Iterable[WorkerT]:
        """The workers the configuration asks for."""

    def load_workers(self):
        for worker in self.create_workers():
            self.add_worker(worker)

    def add_worker(self, worker: WorkerT):
        if worker.name in self.workers:
            raise ValueError(f"worker {worker.name} already exists")

        logging.info(f"loaded {type(worker).__name__} {worker.name}")
        self.workers[worker.name] = worker
        self.collector.register_listener(worker.name, worker)

    def start(self):
        self.load_workers()
        self.collector.start()
        for worker in self.workers.values():
            worker.start()

    def start_single_threaded(self):
        # one pass: collect what is due, then work through all of it in this thread
        self.load_workers()
        self.collector.start_single_threaded()
        for worker in self.workers.values():
            worker.start_single_threaded()

    def wait_for_start(self, timeout: float) -> bool:
        for worker in self.workers.values():
            if not worker.wait_for_start(timeout):
                logging.error(f"worker {worker.name} did not start")
                return False

        if not self.collector.wait_for_start(timeout):
            logging.error(f"{self.collector.label} collector did not start")
            return False

        return True

    def stop(self):
        for worker in self.workers.values():
            worker.stop()

        self.collector.stop()

    def wait(self):
        # each wait() is bounded the way it says, and `ace service start` bounds this one
        for worker in self.workers.values():
            worker.wait()

        self.collector.wait()


class QueueService(ACEServiceInterface):
    """An ACE service that runs one QueueManager."""

    @abstractmethod
    def create_manager(self) -> QueueManager:
        ...

    def start(self):
        self.manager = self.create_manager()
        self.manager.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.manager.wait_for_start(timeout)

    def start_single_threaded(self):
        self.manager = self.create_manager()
        self.manager.start_single_threaded()

    def stop(self):
        self.manager.stop()

    def wait(self):
        # bounded by `ace service start`, which runs it under the shutdown deadline
        self.manager.wait()
