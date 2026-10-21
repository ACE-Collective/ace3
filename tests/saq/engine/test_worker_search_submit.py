# tests for the hand-off between the orchestrator's "index this alert" decision and the
# worker's submission of the task AFTER the lock on the work item is released
import logging
import uuid
from unittest.mock import Mock, patch

import pytest

from saq.configuration.config import get_service_config
from saq.constants import ANALYSIS_MODE_CORRELATION, SERVICE_SEARCH_INDEXER
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.worker import Worker
from saq.search.tasks import submit_index_task
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.unit


def _worker(requested: bool) -> Worker:
    worker = Worker.__new__(Worker)
    worker.config = EngineConfiguration(single_threaded_mode=True)
    worker.lock_manager = Mock()
    worker.workload_manager = Mock()
    worker.tracking_message_manager = Mock()
    worker.current_execution_context = None

    def orchestrate(execution_context):
        execution_context.search_index_requested = requested
        return True

    worker.analysis_orchestrator = Mock()
    worker.analysis_orchestrator.orchestrate_analysis.side_effect = orchestrate
    return worker


def _root():
    return create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode=ANALYSIS_MODE_CORRELATION)


def test_submit_happens_after_the_lock_is_released():
    worker = _worker(requested=True)
    parent = Mock()
    parent.attach_mock(worker.workload_manager.clear_work_target, "clear_work_target")

    with patch("saq.engine.worker.submit_index_task", wraps=submit_index_task) as mock_submit:
        parent.attach_mock(mock_submit, "submit_index_task")
        root = _root()
        assert worker.execute(root) is True

    names = [call[0] for call in parent.mock_calls]
    assert names.index("clear_work_target") < names.index("submit_index_task")
    mock_submit.assert_called_once_with(root.uuid)


def test_no_submit_when_not_requested():
    worker = _worker(requested=False)
    with patch("saq.engine.worker.submit_index_task", wraps=submit_index_task) as mock_submit:
        assert worker.execute(_root()) is True

    mock_submit.assert_not_called()


def test_submit_failure_does_not_fail_the_work_item(monkeypatch, caplog):
    monkeypatch.setattr(get_service_config(SERVICE_SEARCH_INDEXER), "enabled", True)
    worker = _worker(requested=True)
    root = _root()
    with patch("saq.search.tasks.get_redis_connection", side_effect=RuntimeError("redis down")):
        assert worker.execute(root) is True

    errors = [record for record in caplog.records if record.levelno == logging.ERROR and record.exc_info]
    assert len(errors) == 1
    assert root.uuid in errors[0].getMessage()
