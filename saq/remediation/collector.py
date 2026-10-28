from sqlalchemy import or_, text
from sqlalchemy.orm import Query
from sqlalchemy.sql import func

from saq.database.model import Remediation
from saq.queue_service import QueueCollector
from saq.remediation.types import RemediationAction, RemediationWorkItem

def create_remediation_work_item(remediation: Remediation) -> RemediationWorkItem:
    return RemediationWorkItem(
        id=remediation.id,
        action=RemediationAction(remediation.action),
        name=remediation.name,
        type=remediation.type,
        key=remediation.key,
        restore_key=remediation.restore_key)

class RemediationCollector(QueueCollector[RemediationWorkItem]):
    """Responsible for collecting remediation jobs from the database and sending them to the appropriate queues."""
    model = Remediation
    label = "remediation"

    def __init__(self, lock_timeout_seconds: int=300, delay_time_seconds: int=60):
        super().__init__(lock_timeout_seconds=lock_timeout_seconds)
        self.delay_time_seconds = delay_time_seconds

    def filter_candidates(self, query: Query) -> Query:
        # only remediations that have never run, or were delayed and are now ready to run again
        return query.filter(or_(
            Remediation.update_time == None, # noqa
            func.NOW() >= func.DATE_ADD(Remediation.update_time, text(f"INTERVAL {self.delay_time_seconds} SECOND"))
        ))

    def build_work_item(self, row: Remediation) -> RemediationWorkItem:
        return create_remediation_work_item(row)
