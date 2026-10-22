# tests for the hand-off between the orchestrator's "index this alert" decision and the
# worker's submission of the task AFTER the lock on the work item is released
import logging
import socket
import threading
import uuid
from unittest.mock import Mock, patch

import pytest
import redis

from saq.configuration.config import get_config, get_service_config
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


def test_stalled_redis_times_out_and_is_logged_at_error(monkeypatch, caplog):
    """The submission runs after the lock is released, where no module deadline guards the worker,
    so only the redis socket timeout stops a stalled redis from blocking it forever."""
    monkeypatch.setattr(get_service_config(SERVICE_SEARCH_INDEXER), "enabled", True)

    # the kernel completes the handshake for a listening socket nobody accepts on, so the
    # client connects and then never gets a reply
    stalled = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stalled.bind(("127.0.0.1", 0))
    stalled.listen(8)
    redis_config = get_config().redis
    monkeypatch.setattr(redis_config, "host", "127.0.0.1")
    monkeypatch.setattr(redis_config, "port", stalled.getsockname()[1])
    monkeypatch.setattr(redis_config, "use_ssl", False)
    monkeypatch.setattr(redis_config, "ssl_ca_path", None)
    monkeypatch.setattr(redis_config, "socket_connect_timeout", 0.2)
    monkeypatch.setattr(redis_config, "socket_timeout", 0.2)

    worker = _worker(requested=True)
    root = _root()
    results = []
    thread = threading.Thread(target=lambda: results.append(worker.execute(root)), daemon=True)
    try:
        thread.start()
        # bounds the test rather than the code: without the timeout, execute() never returns
        thread.join(timeout=10)
        assert not thread.is_alive(), "the worker blocked on a stalled redis"
    finally:
        # resets the queued connection, which also releases a thread still blocked on it
        stalled.close()
        thread.join(timeout=10)

    assert results == [True]
    errors = [record for record in caplog.records if record.levelno == logging.ERROR and record.exc_info]
    assert len(errors) == 1
    assert errors[0].getMessage().startswith(f"error submitting search index task for {root.uuid}")
    assert isinstance(errors[0].exc_info[1], redis.TimeoutError)
