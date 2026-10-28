from typing import Iterator

from saq.configuration import get_config
from saq.file_collection.collector import FileCollectionCollector
from saq.file_collection.file_collector import load_file_collector_from_config
from saq.file_collection.worker import FileCollectionWorker
from saq.queue_service import QueueManager


class FileCollectionManager(QueueManager[FileCollectionWorker]):
    """Manages file collection workers and the collector that distributes work to them."""

    def __init__(
        self,
        lock_timeout_seconds: int = 300,
        initial_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
        max_collection_time_seconds: int = 604800,
    ):
        super().__init__(FileCollectionCollector(
            lock_timeout_seconds=lock_timeout_seconds,
            initial_retry_delay_seconds=initial_retry_delay_seconds,
            max_retry_delay_seconds=max_retry_delay_seconds,
            max_collection_time_seconds=max_collection_time_seconds,
        ))

    def create_workers(self) -> Iterator[FileCollectionWorker]:
        for collector_config in get_config().file_collectors:
            yield FileCollectionWorker(load_file_collector_from_config(collector_config))
