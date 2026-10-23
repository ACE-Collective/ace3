"""A worker that cannot start fails the engine's start rather than hanging it.

The manager used to wait for a worker's startup event forever: every 30 seconds it warned,
killed the worker's process tree and waited again on an event nothing would ever set. A
module that failed to load (a declared dependency cycle, which load_modules raises to fail
fast) left the engine stuck before its controller loop, where not even SIGTERM was noticed.
"""

import logging
import threading
from typing import Optional
from unittest.mock import Mock

import psutil
import pytest

from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode, EngineType
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.engine.worker_manager import WorkerManager
from tests.saq.helpers import wait_for_condition


def _configuration_manager(load_modules=None) -> ConfigurationManager:
    configuration_manager = ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=False))
    if load_modules is not None:
        # the worker process is forked, so it inherits this
        configuration_manager.load_modules = load_modules
    return configuration_manager


def _failing_load_modules():
    raise RuntimeError("circular analysis module dependency")


def _hanging_load_modules():
    threading.Event().wait()


def _worker(load_modules) -> Worker:
    return Worker("any-0", _configuration_manager(load_modules), Mock(spec=NodeManagerInterface))


def _wait_for_start(worker: Worker, timeout: Optional[float] = None):
    """Runs wait_for_start on a thread, so that a wait that never returns fails the test
    instead of hanging the run. None waits with the default timeout."""
    result = {}

    def _wait():
        result["started"] = worker.wait_for_start() if timeout is None else worker.wait_for_start(timeout)

    threading.Thread(target=_wait, daemon=True).start()
    wait_for_condition(lambda: "started" in result, timeout=(timeout or 30) + 15)
    return result["started"]


@pytest.fixture
def started_workers():
    """Kills whatever worker process a test leaves running."""
    workers = []
    yield workers
    for worker in workers:
        if worker.process is not None and psutil.pid_exists(worker.process.pid):
            worker.kill()


@pytest.mark.unit
def test_a_worker_that_exits_before_starting_is_reported(started_workers, caplog):
    worker = _worker(_failing_load_modules)
    started_workers.append(worker)
    worker.start(execution_mode=EngineExecutionMode.NORMAL)

    with caplog.at_level(logging.ERROR):
        assert _wait_for_start(worker) is False

    record = next(r for r in caplog.records if "exited with code" in r.getMessage())
    assert record.worker_name == "any-0"
    assert not worker.is_alive()


@pytest.mark.unit
def test_a_worker_that_does_not_start_in_time_is_killed(started_workers, caplog):
    worker = _worker(_hanging_load_modules)
    started_workers.append(worker)
    worker.start(execution_mode=EngineExecutionMode.NORMAL)

    with caplog.at_level(logging.ERROR):
        assert _wait_for_start(worker, timeout=2) is False

    assert any("did not start within 2 seconds" in r.getMessage() for r in caplog.records)
    # kill_process_tree reaps the process itself, so the pid is what tells us it is gone
    assert not psutil.pid_exists(worker.process.pid)


@pytest.mark.unit
def test_shutdown_stops_the_wait_for_a_worker_to_start(started_workers):
    worker = _worker(_hanging_load_modules)
    started_workers.append(worker)
    worker.start(execution_mode=EngineExecutionMode.NORMAL)
    worker.immediate_shutdown()

    assert _wait_for_start(worker) is False


class _StartingWorker:
    def __init__(self, name: str, starts: bool):
        self.name = name
        self.starts = starts
        self.shutdown_requested = False

    def start(self, execution_mode, pending_failure=None):
        pass

    def wait_for_start(self):
        return self.starts

    def immediate_shutdown(self):
        self.shutdown_requested = True

    def is_alive(self) -> bool:
        return not self.shutdown_requested


def _manager(workers) -> WorkerManager:
    manager = WorkerManager(_configuration_manager(), Mock(spec=NodeManagerInterface))
    manager.workers = list(workers)
    return manager


@pytest.mark.unit
def test_the_engine_fails_to_start_when_a_worker_does_not_start():
    workers = [_StartingWorker("any-0", starts=True), _StartingWorker("any-1", starts=False)]
    manager = _manager(workers)

    with pytest.raises(RuntimeError, match="workers did not start: any-1"):
        manager.start_workers(execution_mode=EngineExecutionMode.NORMAL)

    # the workers that did start are not left running behind the failed engine
    assert all(worker.shutdown_requested for worker in workers)


@pytest.mark.unit
def test_shutdown_during_startup_is_not_a_startup_failure(monkeypatch):
    workers = [_StartingWorker("any-0", starts=False)]
    manager = _manager(workers)
    monkeypatch.setattr("saq.engine.worker_manager.is_shutting_down", lambda: True)

    manager.start_workers(execution_mode=EngineExecutionMode.NORMAL)

    # the controller loop notices the shutdown and stops the pool itself
    assert not workers[0].shutdown_requested
