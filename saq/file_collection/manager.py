import logging

from saq.configuration import get_config
from saq.file_collection.collector import FileCollectionCollector
from saq.file_collection.file_collector import load_file_collector_from_config
from saq.file_collection.worker import FileCollectionWorker


class FileCollectionManager:
    """Manages file collection workers and the collector that distributes work to them."""

    def __init__(
        self,
        lock_timeout_seconds: int = 300,
        initial_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
        max_collection_time_seconds: int = 604800,
    ):
        # the dictionary of FileCollectionWorker instances we're managing (mapped by collector name)
        self.workers: dict[str, FileCollectionWorker] = {}
        # the single collector that collects all the work and submits them to the workers
        self.collector: FileCollectionCollector = FileCollectionCollector(
            lock_timeout_seconds=lock_timeout_seconds,
            initial_retry_delay_seconds=initial_retry_delay_seconds,
            max_retry_delay_seconds=max_retry_delay_seconds,
            max_collection_time_seconds=max_collection_time_seconds,
        )

    def load_workers(self):
        """Loads the workers from the configuration."""
        for collector_config in get_config().file_collectors:
            file_collector = load_file_collector_from_config(collector_config)
            self.add_worker(FileCollectionWorker(file_collector))

    def add_worker(self, worker: FileCollectionWorker):
        """Adds a worker to the manager."""
        if worker.file_collector.name in self.workers:
            raise ValueError(f"worker {worker.file_collector.name} already exists")

        logging.info(f"loaded file collection worker {worker.file_collector.name}")
        self.workers[worker.file_collector.name] = worker

        # tell the collector to collect this type of work and send to this worker
        self.collector.register_file_collection_listener(worker.file_collector.name, worker)

    def start(self):
        self.load_workers()
        self.collector.start()
        for worker in self.workers.values():
            worker.start()

    def start_single_threaded(self):
        pass

    def wait_for_start(self, timeout: float) -> bool:
        for worker in self.workers.values():
            if not worker.wait_for_start(timeout):
                logging.error(f"worker {worker.file_collector.name} did not start")
                return False

        if not self.collector.wait_for_start(timeout):
            logging.error("file collection collector did not start")
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
