"""The search indexer service: consumes index/payload/delete tasks from redis and applies them.

Tasks are submitted by saq.search.tasks (engine, GUI, dispositions, deletions). Each worker
process loads the embedding model once and keeps it. An `index` task takes the alert lock so it
never reads a tree the engine is still writing; `payload` and `delete` tasks touch only qdrant
and need no lock. Failures are retried a bounded number of times and then dead-lettered.

Logging follows the rule in saq/logging.py: the message is the event name, the fields ride in
extra={}. The events an operator cares about are `search_indexer_worker_ready` (this worker
attached to this collection with this model) and `search_index_task_complete` (one line per
task, carrying the op, the alert, the counts, the elapsed time and the remaining backlog).
"""

import logging
import os
import time
import uuid
from typing import Optional, Type

from pydantic import Field

from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import REDIS_DB_BG_TASKS, SERVICE_SEARCH_INDEXER
from saq.database.pool import remove_all_sessions
from saq.database.util.locking import acquire_lock, release_lock
from saq.environment import ACE_MP_CONTEXT
from saq.error.reporting import report_exception
from saq.logging import initialize_transaction_id
from saq.redis_client import get_redis_connection
from saq.search import index
from saq.search.model import get_model_name, load_model
from saq.search.tasks import (
    FAILED_TASK_KEY,
    OP_DELETE,
    OP_INDEX,
    OP_PAYLOAD,
    TASK_KEY,
    SearchIndexTask,
)
from saq.service import ACEServiceInterface

# how many times a task may fail with an error before it is moved to the dead letter list
MAX_TASK_ATTEMPTS = 3

# how many times a task may find its alert locked before it is moved to the dead letter list.
# the engine submits only after releasing its lock, so a deferral now means real contention
# (an analyst action, another node) rather than the normal case
MAX_TASK_DEFERRALS = 10

DEFAULT_WORKER_COUNT = 2

# how much of an unparseable task payload to put in the log
INVALID_PAYLOAD_LOG_LIMIT = 512


class AlertLockUnavailable(Exception):
    """Raised when the alert for an index task is locked by another process."""


class SearchIndexerServiceConfig(ServiceConfig):
    worker_count: int = Field(default=DEFAULT_WORKER_COUNT, ge=1, description="Number of indexer worker processes to spawn. Each loads its own copy of the embedding model.")


class SearchIndexWorker:
    def __init__(self, name: str):
        self.name = name
        self.process = None
        self.shutdown_event = ACE_MP_CONTEXT.Event()
        self.started_event = ACE_MP_CONTEXT.Event()
        self.model = None
        # the collection this worker attached to, set by prepare()
        self.collection = None
        # lifetime counters for the shutdown summary. these are incremented inside the forked
        # process, which is also where the summary is emitted
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.tasks_deferred = 0

    def __str__(self):
        return f"SearchIndexWorker({self.name})"

    @property
    def is_shutdown(self) -> bool:
        return self.shutdown_event.is_set()

    def start(self):
        logging.info("search_indexer_worker_starting", extra={"worker": self.name})
        self.process = ACE_MP_CONTEXT.Process(target=self.worker_loop, name=self.name)
        self.process.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.started_event.wait(timeout)

    def stop(self):
        logging.info("search_indexer_worker_stopping", extra={"worker": self.name})
        self.shutdown_event.set()

    def wait(self):
        if self.process is not None:
            self.process.join()

    def get_next_task(self) -> Optional[tuple[str, str]]:
        return get_redis_connection(REDIS_DB_BG_TASKS).blpop(TASK_KEY, timeout=1)

    def queue_depth(self) -> Optional[int]:
        """The backlog left behind this task, for the completion line.

        Never fails a task: a redis blip must not turn a successful index into a failure,
        so an unreachable queue reports None rather than raising."""
        try:
            return get_redis_connection(REDIS_DB_BG_TASKS).llen(TASK_KEY)
        except Exception:
            return None

    def prepare(self):
        """Loads the model and makes sure the collection exists; runs once per worker process."""
        started = time.monotonic()
        logging.info("search_indexer_loading_model", extra={"worker": self.name, "model": get_model_name()})
        self.model = load_model()
        model_load_ms = int((time.monotonic() - started) * 1000)

        self.collection = index.ensure_collection(index.get_qdrant_client(), self.model)
        logging.info(
            "search_indexer_worker_ready",
            extra={
                "worker": self.name,
                "pid": os.getpid(),
                "model": get_model_name(),
                "collection": self.collection,
                "model_load_ms": model_load_ms,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            },
        )

    def worker_loop(self):
        # a fresh transaction id per process, so lines from sibling workers can be told apart
        initialize_transaction_id()
        self.started_event.set()
        logging.info("search_indexer_worker_started", extra={"worker": self.name, "pid": os.getpid()})

        while not self.is_shutdown:
            try:
                if self.model is None:
                    self.prepare()

                self.worker_execute()
            except Exception as e:
                if self.is_shutdown:
                    break

                # ready=False means startup itself is failing (qdrant unreachable, model
                # download blocked) rather than a single task going wrong
                logging.error("search_indexer_worker_error", extra={"worker": self.name, "ready": self.model is not None, "error": str(e)})
                report_exception()
                # don't spin if there's a major issue
                self.shutdown_event.wait(1)

        logging.info(
            "search_indexer_worker_exiting",
            extra={
                "worker": self.name,
                "pid": os.getpid(),
                "tasks_completed": self.tasks_completed,
                "tasks_failed": self.tasks_failed,
                "tasks_deferred": self.tasks_deferred,
            },
        )

    def worker_execute(self):
        task = self.get_next_task()
        if not task:
            return

        try:
            task_data = SearchIndexTask.model_validate_json(task[1])
        except Exception as e:
            # BLPOP already removed it, so the payload only survives in this line
            logging.error(
                "search_index_task_invalid",
                extra={"worker": self.name, "error": str(e), "payload": str(task[1])[:INVALID_PAYLOAD_LOG_LIMIT]},
            )
            return

        logging.debug("search_index_task_start", extra={"worker": self.name, "op": task_data.op, "alert_uuid": task_data.alert_uuid})
        started = time.monotonic()

        try:
            outcome = self.execute_task(task_data)
            self.tasks_completed += 1
            logging.info(
                "search_index_task_complete",
                extra={
                    "worker": self.name,
                    "op": task_data.op,
                    "alert_uuid": task_data.alert_uuid,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "queue_depth": self.queue_depth(),
                    **outcome,
                },
            )
        except AlertLockUnavailable:
            self.tasks_deferred += 1
            self.defer_task(task_data)
        except Exception as e:
            self.tasks_failed += 1
            logging.error(
                "search_index_task_error",
                extra={
                    "worker": self.name,
                    "op": task_data.op,
                    "alert_uuid": task_data.alert_uuid,
                    "attempt": task_data.attempt,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": str(e),
                },
            )
            report_exception()
            self.requeue_task(task_data)
        finally:
            remove_all_sessions()

    def dead_letter_task(self, task: SearchIndexTask, reason: str):
        """Moves a task that will not be retried to the dead letter list."""
        logging.error(
            "search_index_task_dead_lettered",
            extra={
                "worker": self.name,
                "op": task.op,
                "alert_uuid": task.alert_uuid,
                "reason": reason,
                "attempt": task.attempt,
                "deferrals": task.deferrals,
                "queue": FAILED_TASK_KEY,
            },
        )
        get_redis_connection(REDIS_DB_BG_TASKS).rpush(FAILED_TASK_KEY, task.model_dump_json())

    def requeue_task(self, task: SearchIndexTask):
        """Puts a task that failed with an error back on the queue, up to MAX_TASK_ATTEMPTS."""
        task.attempt += 1

        if task.attempt >= MAX_TASK_ATTEMPTS:
            self.dead_letter_task(task, "error")
            return

        logging.warning(
            "search_index_task_requeued",
            extra={
                "worker": self.name,
                "op": task.op,
                "alert_uuid": task.alert_uuid,
                "attempt": task.attempt,
                "max_attempts": MAX_TASK_ATTEMPTS,
            },
        )
        # rpush rather than lpush: placing the retry at the tail of the queue is what keeps
        # a persistent failure from turning into a hot retry loop
        get_redis_connection(REDIS_DB_BG_TASKS).rpush(TASK_KEY, task.model_dump_json())

    def defer_task(self, task: SearchIndexTask):
        """Puts a task whose alert was locked back on the queue, up to MAX_TASK_DEFERRALS."""
        task.deferrals += 1

        if task.deferrals >= MAX_TASK_DEFERRALS:
            self.dead_letter_task(task, "locked")
            return

        logging.info(
            "search_index_task_deferred",
            extra={
                "worker": self.name,
                "op": task.op,
                "alert_uuid": task.alert_uuid,
                "deferrals": task.deferrals,
                "max_deferrals": MAX_TASK_DEFERRALS,
            },
        )
        get_redis_connection(REDIS_DB_BG_TASKS).rpush(TASK_KEY, task.model_dump_json())

    def execute_task(self, task: SearchIndexTask) -> dict:
        """Applies one task. Returns the fields describing what it did, for the completion line."""
        if task.op == OP_INDEX:
            return self.execute_index(task)
        elif task.op == OP_PAYLOAD:
            # False means the alert is gone; nothing was updated
            return {"updated": index.update_alert_payload(task.alert_uuid)}
        elif task.op == OP_DELETE:
            index.delete_alert(task.alert_uuid)
            return {}

        logging.error("search_index_unknown_op", extra={"worker": self.name, "op": task.op, "alert_uuid": task.alert_uuid})
        return {}

    def execute_index(self, task: SearchIndexTask) -> dict:
        lock_uuid = str(uuid.uuid4())
        if not acquire_lock(task.alert_uuid, lock_uuid, lock_owner=str(self)):
            raise AlertLockUnavailable(task.alert_uuid)

        try:
            result = index.index_alert(task.alert_uuid, model=self.model)
        finally:
            release_lock(task.alert_uuid, lock_uuid)

        outcome = {"documents": result.document_count, "points": result.point_count}
        # only when it was actually skipped: skipped=None on every line is noise
        if result.skipped:
            outcome["skipped"] = result.skipped

        return outcome


class SearchIndexManager:
    def __init__(self, worker_count: Optional[int] = None):
        self.worker_count = DEFAULT_WORKER_COUNT if worker_count is None else worker_count
        self.workers: list[SearchIndexWorker] = []

    def start(self):
        # logged before forking: this is the one line that says which collection the
        # deployment is writing to. collection_name() reads config only, no model load
        logging.info(
            "search_indexer_starting",
            extra={"worker_count": self.worker_count, "model": get_model_name(), "collection": index.collection_name()},
        )
        for index_ in range(self.worker_count):
            worker = SearchIndexWorker(name=f"worker-{index_}")
            worker.start()
            self.workers.append(worker)

    def wait_for_start(self, timeout: float = 5) -> bool:
        return all(worker.wait_for_start(timeout) for worker in self.workers)

    def stop(self):
        # self.worker_count, not len(self.workers): a forked worker inherits a copy of this
        # manager taken mid-fork, and signals reach the whole process group, so len() would
        # report whatever the list happened to hold when that child was forked
        logging.info("search_indexer_stopping", extra={"worker_count": self.worker_count})
        for worker in self.workers:
            worker.stop()

    def wait(self):
        for worker in self.workers:
            worker.wait()


class SearchIndexService(ACEServiceInterface):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.manager: Optional[SearchIndexManager] = None
        self.single_threaded_worker: Optional[SearchIndexWorker] = None

    def start(self):
        self.manager = SearchIndexManager(worker_count=get_service_config(SERVICE_SEARCH_INDEXER).worker_count)
        self.manager.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.manager.wait_for_start(timeout) if self.manager else False

    def start_single_threaded(self):
        """Runs one worker in the calling process until stop() is called."""
        self.single_threaded_worker = SearchIndexWorker(name="single_threaded")
        self.single_threaded_worker.worker_loop()

    def stop(self):
        if self.manager is not None:
            self.manager.stop()
        if self.single_threaded_worker is not None:
            self.single_threaded_worker.stop()

    def wait(self):
        if self.manager is not None:
            self.manager.wait()

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return SearchIndexerServiceConfig
