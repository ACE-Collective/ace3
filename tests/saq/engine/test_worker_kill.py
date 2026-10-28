"""A killed worker is reaped through multiprocessing, so the manager sees it die.

A worker reaped outside multiprocessing (os.waitpid) never gets an exit code in its Process,
which then reports it alive forever and refuses to close, so every worker killed for an
analysis timeout or its memory use left its pipes behind.
"""

import logging
import signal
import subprocess
import threading
from unittest.mock import Mock

import psutil
import pytest

from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode, EngineType, WorkerStatus
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.engine.worker_manager import WorkerManager
from tests.saq.helpers import process_is_gone, wait_for_condition


def _hanging_load_modules():
    threading.Event().wait()


def _load_modules_with_a_child():
    # an analysis module's external tool, which outlives the worker unless it is killed too
    subprocess.Popen(["sleep", "600"])
    threading.Event().wait()


@pytest.fixture
def manager():
    """A manager whose workers are real forked processes that never finish loading their
    modules, so they stay alive until killed."""
    configuration_manager = ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=False))
    # the worker process is forked, so it inherits this
    configuration_manager.load_modules = _hanging_load_modules
    manager = WorkerManager(configuration_manager, Mock(spec=NodeManagerInterface))
    manager.execution_mode = EngineExecutionMode.NORMAL
    yield manager
    for worker in manager.workers:
        worker.kill()


def _started_worker(manager: WorkerManager) -> Worker:
    worker = manager.add_worker(name="any-0", idle_timeout_max=5)
    worker.start(execution_mode=EngineExecutionMode.NORMAL)
    wait_for_condition(lambda: psutil.pid_exists(worker.process.pid))
    return worker


@pytest.mark.unit
def test_a_killed_worker_is_seen_dead(manager):
    worker = _started_worker(manager)

    worker.kill()

    assert not worker.is_alive()
    assert worker.process.exitcode == -signal.SIGKILL


@pytest.mark.unit
def test_killing_a_worker_kills_what_it_started(manager):
    manager.configuration_manager.load_modules = _load_modules_with_a_child
    worker = _started_worker(manager)
    wait_for_condition(lambda: psutil.Process(worker.process.pid).children())
    child = psutil.Process(worker.process.pid).children()[0]

    worker.kill()

    wait_for_condition(lambda: process_is_gone(child.pid))
    assert not worker.is_alive()


@pytest.mark.unit
def test_killing_a_worker_that_already_exited_is_harmless(manager, caplog):
    worker = _started_worker(manager)
    worker.process.kill()
    worker.process.join(5)

    with caplog.at_level(logging.WARNING):
        worker.kill()

    assert not worker.is_alive()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def _restart_closes_the_dead_process(manager: WorkerManager, worker: Worker, caplog):
    with caplog.at_level(logging.WARNING):
        manager.restart_worker(worker)

    # a closed Process refuses every query; one the manager could not close answers it
    with pytest.raises(ValueError, match="closed"):
        worker.process.is_alive()
    assert not [r for r in caplog.records if "unable to close process" in r.getMessage()]
    assert manager.workers[0] is not worker


@pytest.mark.unit
def test_a_worker_killed_for_its_analysis_time_is_closed_on_restart(manager, caplog):
    worker = _started_worker(manager)
    worker.analysis_has_timed_out = lambda record: True

    assert manager.check(worker) == WorkerStatus.DEAD
    assert not worker.is_alive()

    _restart_closes_the_dead_process(manager, worker, caplog)


@pytest.mark.unit
def test_a_worker_killed_for_its_memory_is_closed_on_restart(manager, monkeypatch, caplog):
    worker = _started_worker(manager)
    monkeypatch.setattr(manager.config, "memory_limit_kill", 0)

    assert manager.check(worker) == WorkerStatus.DEAD
    assert not worker.is_alive()

    _restart_closes_the_dead_process(manager, worker, caplog)


@pytest.mark.unit
def test_a_dead_process_that_cannot_be_closed_is_logged(manager, monkeypatch, caplog):
    worker = _started_worker(manager)
    worker.kill()

    def _close():
        raise ValueError("Cannot close a process while it is still running")

    monkeypatch.setattr(worker.process, "close", _close)

    with caplog.at_level(logging.WARNING):
        manager.restart_worker(worker)

    record = next(r for r in caplog.records if "unable to close process" in r.getMessage())
    assert record.levelno == logging.WARNING
    assert record.worker_name == "any-0"
    assert manager.workers[0] is not worker
