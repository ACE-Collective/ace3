"""Submitting work to the search indexer service.

Kept separate from saq.search.service so that the engine worker, the GUI and the disposition
code can submit tasks without importing the indexer (which imports the analysis modules and,
transitively, the embedding model).
"""

import logging
from typing import Literal

from pydantic import BaseModel

from saq.configuration.config import get_service_config
from saq.constants import REDIS_DB_BG_TASKS, SERVICE_SEARCH_INDEXER
from saq.error.reporting import report_exception
from saq.redis_client import get_redis_connection

TASK_KEY = "search_index_tasks"
FAILED_TASK_KEY = "search_index_tasks_failed"

OP_INDEX = "index"
OP_PAYLOAD = "payload"
OP_DELETE = "delete"

TaskOp = Literal["index", "payload", "delete"]


class SearchIndexTask(BaseModel):
    alert_uuid: str
    # a task serialized by an older release carries only alert_uuid and must still validate
    op: TaskOp = OP_INDEX
    attempt: int = 0  # number of times execution of this task has failed
    deferrals: int = 0  # number of times this task found the alert locked


def indexer_enabled() -> bool:
    """True when the search indexer service is configured and enabled."""
    try:
        return bool(get_service_config(SERVICE_SEARCH_INDEXER).enabled)
    except ValueError:
        # no service_search_indexer section at all
        return False


def submit_task(alert_uuid: str, op: TaskOp) -> bool:
    """Queues a task for the indexer. Returns False (without raising) when it could not be queued."""
    try:
        if not indexer_enabled():
            logging.debug(f"search indexer is not enabled, skipping {op} task for {alert_uuid}")
            return False

        get_redis_connection(REDIS_DB_BG_TASKS).rpush(TASK_KEY, SearchIndexTask(alert_uuid=alert_uuid, op=op).model_dump_json())
        return True
    except Exception as e:
        logging.error(f"error submitting search {op} task for {alert_uuid}: {e}")
        report_exception()
        return False


def submit_index_task(alert_uuid: str) -> bool:
    """(Re)index the whole alert: documents are re-extracted, re-encoded and stale points removed."""
    return submit_task(alert_uuid, OP_INDEX)


def submit_payload_task(alert_uuid: str) -> bool:
    """Refresh the mutable metadata (disposition, queue, tags) on the alert's points without re-encoding."""
    return submit_task(alert_uuid, OP_PAYLOAD)


def submit_delete_task(alert_uuid: str) -> bool:
    """Remove every point of the alert from the index."""
    return submit_task(alert_uuid, OP_DELETE)
