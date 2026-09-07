# tests for the hand-off between the orchestrator's "index this alert" decision and the
# worker's submission of the task AFTER the lock on the work item is released
import uuid
from unittest.mock import Mock, patch

import pytest

from saq.constants import ANALYSIS_MODE_CORRELATION
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.worker import Worker
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.unit


def _worker(requested: bool) -> Worker:
    worker = Worker.__new__(Worker)
    worker.config = Mock(spec=EngineConfiguration, single_threaded_mode=True)
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

    with patch("saq.engine.worker.get_engine_config") as mock_config, \
         patch("saq.engine.worker.submit_index_task") as mock_submit:
        mock_config.return_value.work_dir = None
        parent.attach_mock(mock_submit, "submit_index_task")
        root = _root()
        assert worker.execute(root) is True

    names = [call[0] for call in parent.mock_calls]
    assert names.index("clear_work_target") < names.index("submit_index_task")
    mock_submit.assert_called_once_with(root.uuid)


def test_no_submit_when_not_requested():
    worker = _worker(requested=False)
    with patch("saq.engine.worker.get_engine_config") as mock_config, \
         patch("saq.engine.worker.submit_index_task") as mock_submit:
        mock_config.return_value.work_dir = None
        assert worker.execute(_root()) is True

    mock_submit.assert_not_called()


def test_submit_failure_does_not_fail_the_work_item():
    worker = _worker(requested=True)
    with patch("saq.engine.worker.get_engine_config") as mock_config, \
         patch("saq.engine.worker.submit_index_task", side_effect=RuntimeError("redis down")), \
         patch("saq.engine.worker.report_exception") as mock_report:
        mock_config.return_value.work_dir = None
        assert worker.execute(_root()) is True

    mock_report.assert_called_once()
