import logging
import multiprocessing
import uuid
from typing import Optional, Type

from pydantic import BaseModel

from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import REDIS_DB_BG_TASKS, SERVICE_LLM_EMBEDDING
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock, release_lock
from saq.error.reporting import report_exception
from saq.llm.embedding.vector import vectorize
from saq.redis_client import get_redis_connection
from saq.service import ACEServiceInterface

TASK_KEY = "embedding_tasks"

class EmbeddingTask(BaseModel):
    alert_uuid: str

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
        self.shutdown_event = multiprocessing.Event()
        self.started_event = multiprocessing.Event()

    def __str__(self):
        return f"EmbeddingWorker({self.name})"

    @property
    def is_shutdown(self) -> bool:
        return self.shutdown_event.is_set()

    def start(self):
        logging.info(f"starting {self}")
        self.process = multiprocessing.Process(target=self.worker_loop, name=self.name)
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
        except Exception as e:
            logging.error(f"error executing task {task_data}: {e}")
            report_exception()
        finally:
            get_db().remove()

    def execute_task(self, task: EmbeddingTask):
        lock_uuid = str(uuid.uuid4())

        if not acquire_lock(task.alert_uuid, lock_uuid, lock_owner=str(self)):
            logging.warning(f"unable to acquire lock on {task.alert_uuid}, skipping embedding task")
            return

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
    def __init__(self):
        self.workers: list[EmbeddingWorker] = []

    def start(self):
        for _ in range(multiprocessing.cpu_count()):
            worker = EmbeddingWorker(name=f"worker-{_}")
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
        self.manager = EmbeddingManager()
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
        return ServiceConfig