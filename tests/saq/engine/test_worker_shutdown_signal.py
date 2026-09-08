"""Tests for how the manager signals a worker to stop.

The engine kills workers abruptly on purpose -- AnalysisModuleMonitor calls os._exit(1)
when a module runs past its maximum_analysis_time, and WorkerManager.check() SIGKILLs the
process tree on a timeout or a memory limit. Neither of those unwinds anything inside the
worker.

That is why the shutdown signal may not be a multiprocessing.Event. Condition.wait()
registers a sleeper (``_sleeping_count.release()``) *before* it sleeps, and
Condition.notify_all() ends by waiting for one wake per registered sleeper
(``_woken_count.acquire()``). A worker killed while its shutdown watcher thread was parked
in wait() leaves a sleeper that will never wake, so the next set() in the manager blocks
forever. That deadlock wedged the whole engine controller: it never reached
supervise_shutdown(), so the rest of the pool was never signalled, the node's locks were
never released and the node was never marked stopped.

Every test here bounds itself. A hanging test wedges the pytest session lock, which is
exactly the thing we are trying to make cheap to diagnose.
"""

import os
import signal
import threading
import time
from unittest.mock import Mock

import pytest

from saq.constants import LockManagerType, WorkloadManagerType
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.environment import ACE_MP_CONTEXT


def _make_worker(name: str = "test_worker") -> Worker:
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.single_threaded_mode = True
    configuration_manager.config.auto_refresh_frequency = 0

    return Worker(
        name=name,
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )


def _call_bounded(callback, timeout: float = 5.0) -> bool:
    """Run callback on a daemon thread, returning True if it finished inside timeout.

    The point is to fail rather than hang when it does not: an abandoned daemon thread
    cannot hold up interpreter exit, so the session lock is released either way.
    """
    finished = threading.Event()

    def _run():
        callback()
        finished.set()

    threading.Thread(target=_run, daemon=True).start()
    return finished.wait(timeout)


def _park_in_shutdown_watcher(worker: Worker, ready_fd: int):
    """Runs in the forked child: become a waiter on the worker's shutdown signal.

    This is what every NORMAL mode worker does for its whole life -- see
    Worker._start_shutdown_watcher() -- and it is the state the process is in when the
    monitor os._exit(1)s it.
    """
    worker.current_execution_context = None
    worker._start_shutdown_watcher()

    # give the watcher a moment to actually reach its wait before we report ready
    time.sleep(0.5)
    os.write(ready_fd, b"x")

    # the parent kills us from here; long enough that a missed kill fails the test
    # against the clock rather than leaving the child behind
    time.sleep(30)


def _kill_a_parked_worker(worker: Worker) -> None:
    """Fork a child that parks on ``worker``'s shutdown signal, then SIGKILL it."""
    read_fd, write_fd = os.pipe()
    process = ACE_MP_CONTEXT.Process(
        target=_park_in_shutdown_watcher, args=(worker, write_fd)
    )
    process.start()
    worker.process = process

    try:
        os.close(write_fd)
        assert os.read(read_fd, 1) == b"x", "the child never parked on the shutdown signal"
    finally:
        os.close(read_fd)

    os.kill(process.pid, signal.SIGKILL)
    process.join(10)
    assert not process.is_alive(), "the child survived SIGKILL"


@pytest.mark.unit
def test_shutdown_signal_returns_after_the_worker_was_killed():
    """The deadlock, isolated. A worker killed while parked on its shutdown signal must
    not be able to wedge the manager that signals it.

    immediate_shutdown() is the one that reproduces the historical hang -- the watcher
    thread is a registered sleeper only on that signal. controlled_shutdown() is asserted
    alongside it because restart_workers() signals through it and both must be built out
    of something a dead process cannot orphan.
    """
    worker = _make_worker()
    _kill_a_parked_worker(worker)

    assert _call_bounded(worker.immediate_shutdown), \
        "immediate_shutdown() blocked on a worker that was killed while waiting on it"
    assert worker.is_immediate_shutdown()

    assert _call_bounded(worker.controlled_shutdown), \
        "controlled_shutdown() blocked on a worker that was killed while waiting on it"
    assert worker.is_controlled_shutdown()


def _report_immediate_shutdown(worker: Worker, write_fd: int):
    """Runs in the forked child: report what the inherited flag says, once."""
    os.write(write_fd, b"1" if worker.is_immediate_shutdown() else b"0")


def _wait_then_report_immediate_shutdown(worker: Worker, write_fd: int):
    """Runs in the forked child: report once the parent sets the flag."""
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if worker.is_immediate_shutdown():
            os.write(write_fd, b"1")
            return
        time.sleep(0.05)

    os.write(write_fd, b"0")


@pytest.mark.unit
def test_shutdown_flag_set_before_the_fork_is_inherited():
    """The property the multiprocessing event was there for, kept."""
    worker = _make_worker()
    worker.immediate_shutdown()

    read_fd, write_fd = os.pipe()
    process = ACE_MP_CONTEXT.Process(
        target=_report_immediate_shutdown, args=(worker, write_fd)
    )
    process.start()
    os.close(write_fd)

    try:
        assert os.read(read_fd, 1) == b"1"
    finally:
        os.close(read_fd)

    process.join(10)
    assert process.exitcode == 0


@pytest.mark.unit
def test_shutdown_flag_set_after_the_fork_reaches_a_running_worker():
    """And the one that actually matters at shutdown: the manager sets the flag while the
    worker is already running."""
    worker = _make_worker()

    read_fd, write_fd = os.pipe()
    process = ACE_MP_CONTEXT.Process(
        target=_wait_then_report_immediate_shutdown, args=(worker, write_fd)
    )
    process.start()
    os.close(write_fd)

    # let the child get into its poll before the flag flips, so this proves propagation
    # to a running process rather than inheritance
    time.sleep(0.5)
    worker.immediate_shutdown()

    try:
        assert os.read(read_fd, 1) == b"1", "the running worker never saw the shutdown flag"
    finally:
        os.close(read_fd)

    process.join(10)
    assert process.exitcode == 0


@pytest.mark.unit
def test_wait_for_immediate_shutdown_wakes_when_the_flag_is_set():
    """The worker's wait is wired to its own flag. The polling primitive underneath is
    saq.shutdown.wait_for_shared_flag, covered in tests/saq/test_shutdown.py."""
    worker = _make_worker()

    def _set_soon():
        time.sleep(0.2)
        worker.immediate_shutdown()

    threading.Thread(target=_set_soon, daemon=True).start()

    started = time.monotonic()
    assert worker._wait_for_immediate_shutdown(10) is True
    assert time.monotonic() - started < 5

