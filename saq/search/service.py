"""The search indexer service: consumes index/payload/delete tasks from redis and applies them.

Tasks are submitted by saq.search.tasks (engine, GUI, dispositions, deletions). Each worker
process loads the embedding model once and keeps it. An `index` task takes the alert lock so it
never reads a tree the engine is still writing; `payload` and `delete` tasks touch only qdrant
and need no lock. Failures are retried a bounded number of times and then dead-lettered.
"""

import logging
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
from saq.redis_client import get_redis_connection
from saq.search import index
from saq.search.model import load_model
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

    def __str__(self):
        return f"SearchIndexWorker({self.name})"

    @property
    def is_shutdown(self) -> bool:
        return self.shutdown_event.is_set()

    def start(self):
        logging.info(f"starting {self}")
        self.process = ACE_MP_CONTEXT.Process(target=self.worker_loop, name=self.name)
        self.process.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.started_event.wait(timeout)

    def stop(self):
        logging.info(f"stopping {self}")
        self.shutdown_event.set()

    def wait(self):
        if self.process is not None:
            self.process.join()

    def get_next_task(self) -> Optional[tuple[str, str]]:
        return get_redis_connection(REDIS_DB_BG_TASKS).blpop(TASK_KEY, timeout=1)

    def prepare(self):
        """Loads the model and makes sure the collection exists; runs once per worker process."""
        self.model = load_model()
        index.ensure_collection(index.get_qdrant_client(), self.model)

    def worker_loop(self):
        self.started_event.set()
        while not self.is_shutdown:
            try:
                if self.model is None:
                    self.prepare()

                self.worker_execute()
            except Exception as e:
                if self.is_shutdown:
                    break

                logging.error(f"error in {self} loop: {e}")
                report_exception()
                # don't spin if there's a major issue
                self.shutdown_event.wait(1)

        logging.info(f"{self} exiting")

    def worker_execute(self):
        task = self.get_next_task()
        if not task:
            return

        task_data = SearchIndexTask.model_validate_json(task[1])

        try:
            self.execute_task(task_data)
        except AlertLockUnavailable:
            self.defer_task(task_data)
        except Exception as e:
            logging.error(f"error executing search task {task_data}: {e}")
            report_exception()
            self.requeue_task(task_data)
        finally:
            remove_all_sessions()

    def requeue_task(self, task: SearchIndexTask):
        """Puts a task that failed with an error back on the queue, up to MAX_TASK_ATTEMPTS."""
        task.attempt += 1
        redis_connection = get_redis_connection(REDIS_DB_BG_TASKS)

        if task.attempt >= MAX_TASK_ATTEMPTS:
            logging.error(f"search {task.op} task for {task.alert_uuid} failed {task.attempt} times, moving to {FAILED_TASK_KEY}")
            redis_connection.rpush(FAILED_TASK_KEY, task.model_dump_json())
            return

        logging.warning(f"requeuing search {task.op} task for {task.alert_uuid} (attempt {task.attempt})")
        # rpush rather than lpush: placing the retry at the tail of the queue is what keeps
        # a persistent failure from turning into a hot retry loop
        redis_connection.rpush(TASK_KEY, task.model_dump_json())

    def defer_task(self, task: SearchIndexTask):
        """Puts a task whose alert was locked back on the queue, up to MAX_TASK_DEFERRALS."""
        task.deferrals += 1
        redis_connection = get_redis_connection(REDIS_DB_BG_TASKS)

        if task.deferrals >= MAX_TASK_DEFERRALS:
            logging.error(f"search {task.op} task for {task.alert_uuid} found the alert locked {task.deferrals} times, moving to {FAILED_TASK_KEY}")
            redis_connection.rpush(FAILED_TASK_KEY, task.model_dump_json())
            return

        logging.info(f"deferring search {task.op} task for {task.alert_uuid} (alert is locked, deferral {task.deferrals})")
        redis_connection.rpush(TASK_KEY, task.model_dump_json())

    def execute_task(self, task: SearchIndexTask):
        if task.op == OP_INDEX:
            self.execute_index(task)
        elif task.op == OP_PAYLOAD:
            index.update_alert_payload(task.alert_uuid)
        elif task.op == OP_DELETE:
            index.delete_alert(task.alert_uuid)
        else:
            logging.error(f"unknown search task op {task.op} for {task.alert_uuid}")

    def execute_index(self, task: SearchIndexTask):
        lock_uuid = str(uuid.uuid4())
        if not acquire_lock(task.alert_uuid, lock_uuid, lock_owner=str(self)):
            raise AlertLockUnavailable(task.alert_uuid)

        try:
            index.index_alert(task.alert_uuid, model=self.model)
        finally:
            release_lock(task.alert_uuid, lock_uuid)


class SearchIndexManager:
    def __init__(self, worker_count: Optional[int] = None):
        self.worker_count = DEFAULT_WORKER_COUNT if worker_count is None else worker_count
        self.workers: list[SearchIndexWorker] = []

    def start(self):
        for index_ in range(self.worker_count):
            worker = SearchIndexWorker(name=f"worker-{index_}")
            worker.start()
            self.workers.append(worker)

    def wait_for_start(self, timeout: float = 5) -> bool:
        return all(worker.wait_for_start(timeout) for worker in self.workers)

    def stop(self):
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
