from datetime import UTC, datetime
import logging
from queue import Empty, Queue
from threading import Event, Thread

from saq.database.model import Remediation, RemediationHistory
from saq.database.pool import get_db
from saq.error.reporting import report_exception
from saq.remediation.interface import RemediationListener
from saq.remediation.remediator import Remediator
from saq.remediation.types import RemediationWorkItem, RemediatorResult, RemediatorStatus


class RemediationWorker(RemediationListener):
    def __init__(self, remediator: Remediator):
        self.remediator = remediator
        self.work_queue = Queue[RemediationWorkItem]()
        self.worker_threads: list[Thread] = []
        self.startup_events: list[Event] = []
        self.shutdown_event = Event()
        # the timeout for the work queue get operation
        self.queue_wait_timeout = 1

    #
    # RemediationListener interface
    # ------------------------------------------------------------------------

    def handle_remediation_request(self, remediation: RemediationWorkItem):
        if remediation.name != self.remediator.name:
            raise ValueError(f"remediation name {remediation.name} does not match remediator name {self.remediator.name}")

        logging.info(f"received remediation request for {remediation.type} {remediation.key}")
        self.work_queue.put(remediation)

    #
    # Worker implementation
    # ------------------------------------------------------------------------

    def start(self):
        logging.info(f"starting {self.remediator.config.thread_count} threads for remediator {self.remediator.name}")
        for index in range(self.remediator.config.thread_count):
            startup_event = Event()
            self.startup_events.append(startup_event)
            thread = Thread(target=self.worker_loop, name=f"RemediationWorker-{index}", args=(startup_event,))
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
                    self.remediate(work)
            except Exception as e:
                logging.error(f"error executing work: {e}")
                report_exception()

            if self.shutdown_event.is_set():
                break

    def remediate(self, target: RemediationWorkItem) -> RemediatorResult:
        logging.info(f"STARTED {target.action.value[:-1]}ing {target.name} {target.key}")

        try:
            # run the remediator on the target
            remediator_result = self.remediator.remediate(target)
        except Exception as e:
            # set the remediator result to error and log the error
            remediator_result = RemediatorResult(status=RemediatorStatus.ERROR, message=f"{e.__class__.__name__}: {e}")
            logging.error(f"{self.remediator.name} failed to {target.action.value} {target.type} {target.key}: {e}")
            #report_exception()

        update = Remediation.__table__.update()
        update = update.values(
            lock = None, # release the lock
            # the status of the remediation is based on the remediator result
            status = remediator_result.status.remediation_status.value,
            result = remediator_result.status.value,
            restore_key = remediator_result.restore_key,
            update_time = datetime.now(UTC),
        )
        update = update.where(Remediation.id == target.id)
        get_db().execute(update)
        get_db().flush()

        remediation_history = RemediationHistory(
            remediation_id = target.id,
            result = remediator_result.status.value,
            message = remediator_result.message,
            status = remediator_result.status.remediation_status.value,
        )
        get_db().add(remediation_history)
        get_db().commit()

        # log result
        logging.info(f"{remediator_result.status} {target.action.value[:-1]}ing {target.type} {target.key}")
        return remediator_result
