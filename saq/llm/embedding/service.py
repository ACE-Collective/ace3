import logging
import multiprocessing
import uuid
from typing import Optional, Type

from pydantic import BaseModel, Field

from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import REDIS_DB_BG_TASKS, SERVICE_LLM_EMBEDDING
from saq.database.pool import remove_all_sessions
from saq.database.util.locking import acquire_lock, release_lock
from saq.environment import ACE_MP_CONTEXT
from saq.error.reporting import report_exception
from saq.llm.embedding.vector import vectorize
from saq.redis_client import get_redis_connection
from saq.service import ACEServiceInterface

TASK_KEY = "embedding_tasks"
FAILED_TASK_KEY = "embedding_tasks_failed"

# how many times a task may fail with an error before it is moved to the dead letter list
MAX_TASK_ATTEMPTS = 3

# how many times a task may find its alert locked before it is moved to the dead letter list.
# this is much higher than MAX_TASK_ATTEMPTS because a deferral means "not ready yet" rather
# than "broken": the engine submits the task while it still holds the root lock, so finding
# the alert locked is expected. the cap only exists so a permanently stale lock cannot cause
# a task to circulate forever.
MAX_TASK_DEFERRALS = 60

class AlertLockUnavailable(Exception):
    """Raised when the alert for an embedding task is locked by another process."""

class EmbeddingServiceConfig(ServiceConfig):
    worker_count: Optional[int] = Field(default=None, ge=1, description="Number of embedding worker processes to spawn. Defaults to the CPU count when omitted.")

class EmbeddingTask(BaseModel):
    alert_uuid: str
    # these default because tasks already sitting in the redis list when this change is
    # deployed were serialized without them and must still validate
    attempt: int = 0 # number of times execution of this task has failed
    deferrals: int = 0 # number of times this task found the alert locked

def submit_embedding_task(alert_uuid: str) -> bool:
    try:
        if not get_service_config(SERVICE_LLM_EMBEDDING).enabled:
            logging.debug(f"embedding service is not enabled, skipping task for {alert_uuid}")
            return False

        rc = get_redis_connection(REDIS_DB_BG_TASKS)
        rc.rpush(TASK_KEY, EmbeddingTask(alert_uuid=alert_uuid).model_dump_json())
        return True
    except Exception as e:
        logging.error(f"error submitting embedding task for {alert_uuid}: {e}")
        report_exception()
        return False

class EmbeddingWorker:
    def __init__(self, name: str):
        self.name = name
        self.process = None
        self.shutdown_event = ACE_MP_CONTEXT.Event()
        self.started_event = ACE_MP_CONTEXT.Event()

    def __str__(self):
        return f"EmbeddingWorker({self.name})"

    @property
    def is_shutdown(self) -> bool:
        return self.shutdown_event.is_set()

    def start(self):
        logging.info(f"starting {self}")
        self.process = ACE_MP_CONTEXT.Process(target=self.worker_loop, name=self.name)
        self.process.start()
    
    def wait_for_start(self, timeout: float = 5) -> bool:
        logging.info(f"waiting for {self} to start")
        return self.started_event.wait(timeout)

    def stop(self):
        logging.info(f"stopping {self}")
        self.shutdown_event.set()

    def wait(self):
        logging.info(f"waiting for {self}")
        self.process.join()

    def get_next_task(self) -> Optional[tuple[str, dict]]:
        redis_connection = get_redis_connection(REDIS_DB_BG_TASKS)
        return redis_connection.blpop(TASK_KEY, timeout=1)

    def worker_loop(self):
        while not self.is_shutdown:
            try:
                self.worker_execute()
            except Exception as e:
                if self.is_shutdown:
                    break

                logging.error(f"error in worker_loop: {e}")
                report_exception()

                # don't spin if there's a major issue
                self.shutdown_event.wait(1)

        logging.info(f"worker {self} exiting")

    def worker_execute(self):
        # read the next task from the redis queue
        task = self.get_next_task()
        if not task:
            return

        task_data = EmbeddingTask.model_validate_json(task[1])
        logging.info(f"worker {self} got task {task_data}")

        try:
            self.execute_task(task_data)
            logging.info(f"worker {self} executed task {task_data}")
        except AlertLockUnavailable:
            self.defer_task(task_data)
        except Exception as e:
            logging.error(f"error executing task {task_data}: {e}")
            report_exception()
            self.requeue_task(task_data)
        finally:
            remove_all_sessions()

    def requeue_task(self, task: EmbeddingTask):
        """Puts a task that failed with an error back on the queue, up to MAX_TASK_ATTEMPTS."""
        task.attempt += 1
        redis_connection = get_redis_connection(REDIS_DB_BG_TASKS)

        if task.attempt >= MAX_TASK_ATTEMPTS:
            logging.error(f"embedding task for {task.alert_uuid} failed {task.attempt} times, moving to {FAILED_TASK_KEY}")
            redis_connection.rpush(FAILED_TASK_KEY, task.model_dump_json())
            return

        logging.warning(f"requeuing embedding task for {task.alert_uuid} (attempt {task.attempt})")
        # rpush rather than lpush: placing the retry at the tail of the queue is what keeps
        # a persistent failure from turning into a hot retry loop
        redis_connection.rpush(TASK_KEY, task.model_dump_json())

    def defer_task(self, task: EmbeddingTask):
        """Puts a task whose alert was locked back on the queue, up to MAX_TASK_DEFERRALS."""
        task.deferrals += 1
        redis_connection = get_redis_connection(REDIS_DB_BG_TASKS)

        if task.deferrals >= MAX_TASK_DEFERRALS:
            logging.error(f"embedding task for {task.alert_uuid} found the alert locked {task.deferrals} times, moving to {FAILED_TASK_KEY}")
            redis_connection.rpush(FAILED_TASK_KEY, task.model_dump_json())
            return

        logging.info(f"deferring embedding task for {task.alert_uuid} (alert is locked, deferral {task.deferrals})")
        redis_connection.rpush(TASK_KEY, task.model_dump_json())

    def execute_task(self, task: EmbeddingTask):
        lock_uuid = str(uuid.uuid4())

        if not acquire_lock(task.alert_uuid, lock_uuid, lock_owner=str(self)):
            logging.warning(f"unable to acquire lock on {task.alert_uuid}, deferring embedding task")
            raise AlertLockUnavailable(task.alert_uuid)

        try:
            from saq.database.model import load_alert
            alert = load_alert(task.alert_uuid)
            if alert:
                vectorize(alert)
            else:
                logging.info(f"alert {task.alert_uuid} not found")
        finally:
            release_lock(task.alert_uuid, lock_uuid)

class EmbeddingManager:
    def __init__(self, worker_count: Optional[int] = None):
        # defaults to the cpu count when not specified in the configuration
        self.worker_count = multiprocessing.cpu_count() if worker_count is None else worker_count
        self.workers: list[EmbeddingWorker] = []

    def start(self):
        for index in range(self.worker_count):
            worker = EmbeddingWorker(name=f"worker-{index}")
            worker.start()
            self.workers.append(worker)

    def wait_for_start(self, timeout: float = 5) -> bool:
        for worker in self.workers:
            if not worker.wait_for_start(timeout):
                return False

        return True
    
    def stop(self):
        for worker in self.workers:
            worker.stop()

    def wait(self):
        for worker in self.workers:
            worker.wait()

class EmbeddingService(ACEServiceInterface):
    def start(self):
        self.manager = EmbeddingManager(worker_count=get_service_config(SERVICE_LLM_EMBEDDING).worker_count)
        self.manager.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.manager.wait_for_start(timeout)
    
    def start_single_threaded(self):
        worker = EmbeddingWorker(name="single_threaded")
        worker.execute()
    
    def stop(self):
        self.manager.stop()

    def wait(self):
        self.manager.wait()

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return EmbeddingServiceConfig