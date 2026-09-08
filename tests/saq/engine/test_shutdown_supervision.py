"""Tests for how the engine stops: bounded, and not by being killed from outside.

The behavior these pin down is the reason `docker compose stop` used to end in a SIGKILL.
Workers were joined one at a time for 60 seconds each, so a pool of N workers had a worst
case of N x 60s against a 10 second container grace period. The pool never finished
shutting down, so nothing released the locks it held, and the work those locks were
blocking sat unclaimable until they expired five minutes later.
"""

import time
from unittest.mock import Mock

import pytest

from saq.constants import LockManagerType, WorkloadManagerType
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.enums import EngineExecutionMode, WorkerManagerState
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.engine.worker_manager import WorkerManager
from saq.shutdown import get_shutdown_coordinator, reset_shutdown_coordinator


@pytest.fixture(autouse=True)
def _reset_coordinator():
    reset_shutdown_coordinator()
    yield
    reset_shutdown_coordinator()


class FakeWorker:
    """A worker the manager can supervise, scripted to exit or to refuse to.

    ``exits_after`` is how many poll cycles it takes to notice the shutdown; None means
    it never does -- an analysis module stuck in a CPU loop, which is the case the
    escalation exists for.
    """

    def __init__(self, name: str, exits_after=0):
        self.name = name
        self.process = Mock()
        self._exits_after = exits_after
        self._checks = 0
        self.killed = False
        self.shutdown_requested = False

    def immediate_shutdown(self):
        self.shutdown_requested = True

    def controlled_shutdown(self):
        self.shutdown_requested = True

    def is_alive(self) -> bool:
        if self.killed:
            return False
        if self._exits_after is None:
            return True

        self._checks += 1
        return self._checks <= self._exits_after

    def kill(self):
        self.killed = True


def make_manager(workers) -> WorkerManager:
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()

    manager = WorkerManager(configuration_manager, Mock(spec=NodeManagerInterface))
    manager.workers = list(workers)
    # the watchdog keeps checking analysis timeouts while we wait; that path needs the
    # real tracking reader and is covered elsewhere, so neutralize it here
    manager.check = Mock()
    return manager


@pytest.mark.unit
def test_cooperative_workers_shut_down_promptly():
    get_shutdown_coordinator(deadline_seconds=10)
    workers = [FakeWorker(f"w{i}", exits_after=0) for i in range(4)]
    manager = make_manager(workers)

    started = time.monotonic()
    manager.immediate_shutdown()
    elapsed = time.monotonic() - started

    assert all(w.shutdown_requested for w in workers)
    assert not any(w.killed for w in workers)
    # the old code joined each worker for up to 60s in turn; this must be nothing like it
    assert elapsed < 2


@pytest.mark.unit
def test_a_stuck_worker_is_killed_within_the_deadline():
    """The escalation that keeps a wedged analysis module from holding up the container.

    Without it the manager waited on a worker that was never going to exit, and docker
    SIGKILLed the whole tree -- including the workers that had shut down properly."""
    get_shutdown_coordinator(deadline_seconds=2)
    stuck = FakeWorker("stuck", exits_after=None)
    healthy = FakeWorker("healthy", exits_after=0)
    manager = make_manager([stuck, healthy])

    started = time.monotonic()
    manager.immediate_shutdown()
    elapsed = time.monotonic() - started

    assert stuck.killed is True
    assert healthy.killed is False
    # bounded by the shared budget (half the remaining deadline), not by a per-worker join
    assert elapsed < 5


@pytest.mark.unit
def test_workers_are_waited_on_together_not_one_at_a_time():
    """Three slow workers must overlap. Sequentially they would take three times as long,
    which is exactly how the pool used to blow past its grace period."""
    get_shutdown_coordinator(deadline_seconds=20)
    workers = [FakeWorker(f"slow{i}", exits_after=3) for i in range(3)]
    manager = make_manager(workers)

    started = time.monotonic()
    manager.supervise_shutdown(poll_interval=0.05)
    elapsed = time.monotonic() - started

    assert not any(w.killed for w in workers)
    # 3 polls at 0.05s if overlapped; 9 if taken in turn
    assert elapsed < 0.5


@pytest.mark.unit
def test_shutdown_sets_the_manager_state():
    get_shutdown_coordinator(deadline_seconds=10)
    manager = make_manager([FakeWorker("w", exits_after=0)])

    manager.controlled_shutdown()

    assert manager.state == WorkerManagerState.SHUTTING_DOWN


@pytest.mark.unit
def test_watchdog_keeps_running_while_waiting():
    """The analysis-timeout and memory watchdog used to stop the moment the controller
    loop broke for shutdown -- precisely when a stuck module is most likely to be the
    thing holding everything up."""
    get_shutdown_coordinator(deadline_seconds=2)
    stuck = FakeWorker("stuck", exits_after=None)
    manager = make_manager([stuck])

    manager.immediate_shutdown()

    assert manager.check.call_count > 0


@pytest.mark.unit
def test_worker_cancels_in_flight_analysis_on_shutdown():
    """Abandon-and-requeue in one step.

    cancel_analysis() makes the executor's analysis loop stop at its next check and
    unwind through its own finally blocks, releasing the work item's lock. Without this
    the shutdown event was only ever read between work items, so a worker that had just
    claimed a long analysis ran it until it was killed -- leaving the lock held and the
    workload row stranded behind it.
    """
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.single_threaded_mode = True
    configuration_manager.config.auto_refresh_frequency = 0

    worker = Worker(
        name="test_worker",
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )

    context = Mock()
    worker.current_execution_context = context

    worker._start_shutdown_watcher()
    worker.immediate_shutdown()

    for _ in range(200):
        if context.cancel_analysis.called:
            break
        time.sleep(0.01)

    context.cancel_analysis.assert_called_once()


@pytest.mark.unit
def test_shutdown_watcher_is_harmless_when_idle():
    """A worker between work items has no context to cancel; the loop notices the event
    on its own."""
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.single_threaded_mode = True
    configuration_manager.config.auto_refresh_frequency = 0

    worker = Worker(
        name="test_worker",
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )
    worker.current_execution_context = None

    worker._start_shutdown_watcher()
    worker.immediate_shutdown()
    time.sleep(0.1)  # nothing to assert but that it did not raise
