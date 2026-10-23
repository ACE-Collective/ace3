import logging


from saq.configuration import get_config
from saq.remediation.collector import RemediationCollector
from saq.remediation.remediator import load_remediator_from_config
from saq.remediation.worker import RemediationWorker


class RemediationManager:
    def __init__(self, lock_timeout_seconds: int=300, delay_time_seconds: int=60):
        # the dictionary of Remediator instances we're managing (mapped by type)
        # we use a map to avoid duplicate names
        self.workers: dict[str, RemediationWorker] = {}
        # the single collector that collects all the work and submits them to the workers for remediation
        self.collector: RemediationCollector = RemediationCollector(lock_timeout_seconds=lock_timeout_seconds, delay_time_seconds=delay_time_seconds)

    def load_workers(self):
        """Loads the workers from the configuration."""
        for remediator_config in get_config().remediators:
            remediator = load_remediator_from_config(remediator_config)
            self.add_worker(RemediationWorker(remediator))

    def add_worker(self, worker: RemediationWorker):
        """Adds a worker to the manager."""
        if worker.remediator.name in self.workers:
            raise ValueError(f"worker {worker.remediator.name} already exists")

        logging.info(f"loaded worker {worker.remediator.name}")
        self.workers[worker.remediator.name] = worker

        # tell the collector to collect this type of work and send to this queue
        self.collector.register_remediation_listener(worker.remediator.name, worker)

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
                logging.error(f"worker {worker.remediator.name} did not start")
                return False

        if not self.collector.wait_for_start(timeout):
            logging.error("remediation collector did not start")
            return False

        return True

    def stop(self):
        for worker in self.workers.values():
            worker.stop()

        self.collector.stop()

    def wait(self):
        for worker in self.workers.values():
            worker.wait()

        self.collector.wait()
