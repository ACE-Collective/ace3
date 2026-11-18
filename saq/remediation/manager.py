from typing import Iterator

from saq.configuration import get_config
from saq.queue_service import QueueManager
from saq.remediation.collector import RemediationCollector
from saq.remediation.remediator import load_remediator_from_config
from saq.remediation.worker import RemediationWorker


class RemediationManager(QueueManager[RemediationWorker]):
    def __init__(self, lock_timeout_seconds: int=300, delay_time_seconds: int=60):
        super().__init__(RemediationCollector(lock_timeout_seconds=lock_timeout_seconds, delay_time_seconds=delay_time_seconds))

    def create_workers(self) -> Iterator[RemediationWorker]:
        for remediator_config in get_config().remediators:
            yield RemediationWorker(load_remediator_from_config(remediator_config))
