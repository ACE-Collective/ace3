from datetime import UTC, datetime
import logging

from saq.database.model import Remediation, RemediationHistory
from saq.database.pool import get_db
from saq.queue_service import QueueWorker
from saq.remediation.remediator import Remediator
from saq.remediation.types import RemediationWorkItem, RemediatorResult, RemediatorStatus


class RemediationWorker(QueueWorker[RemediationWorkItem]):
    def __init__(self, remediator: Remediator):
        super().__init__()
        self.remediator = remediator

    @property
    def name(self) -> str:
        return self.remediator.name

    @property
    def thread_count(self) -> int:
        return self.remediator.config.thread_count

    def describe(self, work_item: RemediationWorkItem) -> str:
        return f"remediation {work_item.id} ({work_item.name} {work_item.type} {work_item.key})"

    def process_one(self, work_item: RemediationWorkItem):
        self.remediate(work_item)

    def remediate(self, target: RemediationWorkItem) -> RemediatorResult:
        logging.info(f"STARTED {target.action.value[:-1]}ing {target.name} {target.key}")

        try:
            # run the remediator on the target
            remediator_result = self.remediator.remediate(target)
        except Exception as e:
            # set the remediator result to error and log the error
            remediator_result = RemediatorResult(status=RemediatorStatus.ERROR, message=f"{e.__class__.__name__}: {e}")
            logging.error(f"{self.remediator.name} failed to {target.action.value} {target.type} {target.key}: {e}")

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
