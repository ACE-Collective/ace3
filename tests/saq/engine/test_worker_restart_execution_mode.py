"""Tests for execution mode propagation across worker restarts (see docs/ENGINE.md §19.11).

``WorkerManager.start_workers(execution_mode)`` forks every worker with the mode
the engine was started in, but the mode was only ever a parameter — nothing kept
it. Both restart paths then started the replacement bare:

    new_worker.start()          # restart_worker(), one dead worker
    worker.start()              # restart_workers(), the SIGHUP path

which falls back to ``Worker.start``'s ``EngineExecutionMode.NORMAL`` default. A
worker replaced during a ``SINGLE_SHOT`` or ``UNTIL_COMPLETE`` run came back as a
normal worker: it never sets the controlled-shutdown event ``UNTIL_COMPLETE``
relies on, and never breaks after one work item the way ``SINGLE_SHOT`` does — it
polls forever instead.

``main_controller_loop`` breaks out to ``_controlled_stop()`` on its first
iteration for both non-normal modes, so ``check_workers()`` never runs there and
the defect is currently unreachable end to end. That is why these are unit tests
over ``WorkerManager`` rather than an engine run: the mode a replacement worker
is started with is the observable behavior, and the last test follows it all the
way into the ``Process`` kwargs through the real ``Worker.start``.
"""
from unittest.mock import MagicMock, Mock, patch

import pytest

from saq.constants import LockManagerType, WorkloadManagerType
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.enums import EngineExecutionMode, WorkerStatus
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.engine.worker_manager import WorkerManager


class FakeWorker:
    """Stand-in for ``Worker`` that records what mode it was started with.

    ``WorkerManager`` only ever touches the attributes reproduced here. A worker
    is "dead" once it has a ``process`` with an ``exitcode``, which is what
    ``WorkerManager.check()`` looks at.
    """

    def __init__(self, name, configuration_manager, node_manager, idle_timeout_max=None, analysis_mode_priority=None):
        self.name = name
        self.configuration_manager = configuration_manager
        self.node_manager = node_manager
        self.idle_timeout_max = idle_timeout_max
        self.analysis_mode_priority = analysis_mode_priority
        self.process = None
        self.start_modes = []

    def start(self, execution_mode: EngineExecutionMode = EngineExecutionMode.NORMAL):
        self.start_modes.append(execution_mode)
        self.process = MagicMock()
        self.process.pid = 1000 + len(self.start_modes)
        self.process.exitcode = None
        return self.process

    def wait_for_start(self):
        pass

    def analysis_has_timed_out(self) -> bool:
        return False

    def controlled_shutdown(self):
        pass

    def die(self, exitcode: int = 1):
        """Make ``WorkerManager.check()`` report this worker as DEAD."""
        self.process.exitcode = exitcode


@pytest.fixture
def configuration_manager() -> ConfigurationManager:
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.single_threaded_mode = False
    configuration_manager.config.analysis_pools = {"correlation": 2}
    configuration_manager.config.pool_size_limit = None
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.auto_refresh_frequency = 0
    configuration_manager.config.memory_limit_warning = 1024 * 1024 * 1024
    configuration_manager.config.memory_limit_kill = 2 * 1024 * 1024 * 1024
    return configuration_manager


@pytest.fixture
def manager(configuration_manager) -> WorkerManager:
    """A real WorkerManager whose workers are ``FakeWorker`` instances."""
    with patch("saq.engine.worker_manager.Worker", FakeWorker):
        worker_manager = WorkerManager(configuration_manager, Mock(spec=NodeManagerInterface))
        worker_manager.initialize_workers()
        yield worker_manager


@pytest.mark.unit
def test_start_workers_records_execution_mode(manager):
    """The mode the pool was started in is state of the pool, not just an argument."""
    manager.start_workers(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert manager.execution_mode == EngineExecutionMode.SINGLE_SHOT
    assert all(worker.start_modes == [EngineExecutionMode.SINGLE_SHOT] for worker in manager.workers)


@pytest.mark.unit
@pytest.mark.parametrize("execution_mode", [
    EngineExecutionMode.SINGLE_SHOT,
    EngineExecutionMode.UNTIL_COMPLETE,
    EngineExecutionMode.NORMAL,
])
def test_restart_worker_preserves_execution_mode(manager, execution_mode):
    """A replacement worker comes back in the mode the engine is running in."""
    manager.start_workers(execution_mode=execution_mode)
    dead_worker = manager.workers[0]
    dead_worker.die()

    manager.restart_worker(dead_worker)

    assert dead_worker not in manager.workers
    new_worker = manager.workers[-1]
    assert new_worker.start_modes == [execution_mode]


@pytest.mark.unit
def test_restart_worker_defaults_to_normal(manager):
    """Without a ``start_workers()`` the manager falls back to the same default
    ``Worker.start`` carries."""
    dead_worker = manager.workers[0]
    dead_worker.start(execution_mode=EngineExecutionMode.NORMAL)
    dead_worker.start_modes.clear()
    dead_worker.die()

    manager.restart_worker(dead_worker)

    assert manager.execution_mode == EngineExecutionMode.NORMAL
    assert manager.workers[-1].start_modes == [EngineExecutionMode.NORMAL]


@pytest.mark.unit
def test_check_workers_restarts_dead_worker_with_execution_mode(manager):
    """Same assertion through the real caller: the supervision path in the
    controller loop."""
    manager.start_workers(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    dead_worker = manager.workers[0]
    dead_worker.die()

    assert manager.check(dead_worker) == WorkerStatus.DEAD

    # the surviving worker has no real process behind its pid
    with patch("saq.engine.worker_manager.psutil.Process") as mock_process:
        mock_process.return_value.memory_info.return_value.rss = 0
        manager.check_workers()

    assert dead_worker not in manager.workers
    assert len(manager.workers) == 2
    assert manager.workers[-1].start_modes == [EngineExecutionMode.UNTIL_COMPLETE]


@pytest.mark.unit
def test_restart_workers_preserves_execution_mode(manager):
    """The SIGHUP path recycles every worker and must not downgrade the pool."""
    manager.start_workers(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    manager.restart_workers()

    assert all(
        worker.start_modes == [EngineExecutionMode.SINGLE_SHOT, EngineExecutionMode.SINGLE_SHOT]
        for worker in manager.workers
    )


@pytest.mark.unit
def test_restart_worker_preserves_worker_identity(manager):
    """Everything the replacement already carried over still carries over."""
    manager.start_workers(execution_mode=EngineExecutionMode.NORMAL)
    dead_worker = manager.workers[0]
    dead_worker.die()

    manager.restart_worker(dead_worker)

    new_worker = manager.workers[-1]
    assert new_worker is not dead_worker
    assert new_worker.name == dead_worker.name
    assert new_worker.idle_timeout_max == dead_worker.idle_timeout_max
    assert new_worker.analysis_mode_priority == dead_worker.analysis_mode_priority


@pytest.mark.unit
def test_restarted_worker_process_receives_execution_mode(configuration_manager):
    """End to end through the real ``Worker.start``: the mode reaches the kwargs
    of the forked ``worker_loop``, which is the only place it has any effect."""
    with patch("saq.engine.worker.ACE_MP_CONTEXT") as mock_mp_context:
        manager = WorkerManager(configuration_manager, Mock(spec=NodeManagerInterface))
        manager.initialize_workers()
        # one worker per pool entry keeps the Process call list unambiguous
        manager.workers = manager.workers[:1]

        manager.start_workers(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
        dead_worker = manager.workers[0]
        assert isinstance(dead_worker, Worker)

        manager.restart_worker(dead_worker)

        assert len(mock_mp_context.Process.call_args_list) == 2
        for call in mock_mp_context.Process.call_args_list:
            assert call.kwargs["kwargs"] == {"execution_mode": EngineExecutionMode.UNTIL_COMPLETE}
