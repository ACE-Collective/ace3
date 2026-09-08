import os
import signal
import threading
import time
from pathlib import Path

import pytest

from saq.shutdown import (
    ShutdownCoordinator,
    get_shutdown_coordinator,
    is_shutting_down,
    reset_shutdown_coordinator,
    run_bounded,
    wait_for_shared_flag,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _reset_coordinator():
    reset_shutdown_coordinator()
    yield
    reset_shutdown_coordinator()


@pytest.fixture
def make_coordinator():
    """Build coordinators and stand their watchdogs down afterwards.

    A coordinator that has been asked to shut down arms a watchdog thread which
    force-exits the process once its deadline passes. One left armed by a test kills the
    test run some seconds later, somewhere else entirely -- which reads as the suite
    simply stopping partway through, with a success exit code.
    """
    built = []

    def _make(**kwargs) -> ShutdownCoordinator:
        coordinator = ShutdownCoordinator(**kwargs)
        built.append(coordinator)
        return coordinator

    yield _make

    for coordinator in built:
        coordinator.mark_complete()


@pytest.mark.unit
def test_starts_not_shutting_down(make_coordinator):
    coordinator = make_coordinator(deadline_seconds=5)
    assert not coordinator.is_shutting_down
    assert coordinator.reason is None
    assert coordinator.deadline_remaining() == 5


@pytest.mark.unit
def test_request_shutdown_sets_state(make_coordinator):
    coordinator = make_coordinator(deadline_seconds=5)
    coordinator.request_shutdown("because")

    assert coordinator.is_shutting_down
    assert coordinator.reason == "because"


@pytest.mark.unit
def test_request_shutdown_is_idempotent(make_coordinator):
    """A second signal must not restart the clock -- an impatient operator sending
    SIGTERM twice should not extend the deadline they are waiting on."""
    coordinator = make_coordinator(deadline_seconds=5)
    coordinator.request_shutdown("first")
    first_remaining = coordinator.deadline_remaining()

    time.sleep(0.1)
    coordinator.request_shutdown("second")

    assert coordinator.reason == "first"
    assert coordinator.deadline_remaining() < first_remaining


@pytest.mark.unit
def test_deadline_remaining_decreases_and_floors_at_zero(make_coordinator):
    coordinator = make_coordinator(deadline_seconds=0.2)
    coordinator.request_shutdown("test")

    time.sleep(0.3)
    assert coordinator.deadline_remaining() == 0.0


@pytest.mark.unit
def test_sleep_returns_early_on_shutdown(make_coordinator):
    coordinator = make_coordinator(deadline_seconds=5)

    def _request():
        time.sleep(0.1)
        coordinator.request_shutdown("test")

    threading.Thread(target=_request, daemon=True).start()

    started = time.monotonic()
    assert coordinator.sleep(30) is True
    assert time.monotonic() - started < 5


@pytest.mark.unit
def test_sleep_returns_false_when_not_shutting_down(make_coordinator):
    coordinator = make_coordinator(deadline_seconds=5)
    assert coordinator.sleep(0.05) is False


@pytest.mark.unit
def test_signal_handler_only_sets_flag(make_coordinator):
    """The handler must not do shutdown work. If it ever calls into service code again,
    this test deadlocks or fails rather than the behavior silently regressing."""
    coordinator = make_coordinator(deadline_seconds=5)
    coordinator.install_signal_handlers()

    try:
        os.kill(os.getpid(), signal.SIGTERM)
        # the handler runs on the main thread between bytecodes; give it a moment
        for _ in range(100):
            if coordinator.is_shutting_down:
                break
            time.sleep(0.01)

        assert coordinator.is_shutting_down
        assert "SIGTERM" in coordinator.reason
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.default_int_handler)


@pytest.mark.unit
def test_hooks_run_in_order(make_coordinator):
    coordinator = make_coordinator(deadline_seconds=5)
    calls = []

    coordinator.register("third", lambda: calls.append("third"), order=30)
    coordinator.register("first", lambda: calls.append("first"), order=10)
    coordinator.register("second", lambda: calls.append("second"), order=20)

    coordinator.request_shutdown("test")
    coordinator.run_hooks()

    assert calls == ["first", "second", "third"]


@pytest.mark.unit
def test_failing_hook_does_not_stop_the_others(make_coordinator):
    coordinator = make_coordinator(deadline_seconds=5)
    calls = []

    def _boom():
        raise RuntimeError("boom")

    coordinator.register("boom", _boom, order=10)
    coordinator.register("after", lambda: calls.append("after"), order=20)

    coordinator.request_shutdown("test")
    coordinator.run_hooks()

    assert calls == ["after"]


@pytest.mark.unit
def test_hooks_skipped_once_deadline_exceeded(make_coordinator):
    coordinator = make_coordinator(deadline_seconds=0.1)
    calls = []
    coordinator.register("late", lambda: calls.append("late"), order=10)

    coordinator.request_shutdown("test")
    time.sleep(0.2)
    coordinator.run_hooks()

    assert calls == []


@pytest.mark.unit
def test_flag_is_visible_across_a_fork(make_coordinator):
    """A forked child must observe a shutdown requested by its parent after the fork.

    This is why the mirror lives in shared memory and not in a plain bool: the child
    inherits a copy of everything else, including the local threading.Event, and the
    parent can never set that copy. It is a lock free flag rather than an mp.Event
    because a child killed while reading or waiting on an Event orphans its condition --
    see test_request_shutdown_returns_after_a_waiting_child_was_killed.
    """
    coordinator = make_coordinator(deadline_seconds=5)

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        # child
        try:
            os.close(read_fd)
            observed = False
            for _ in range(200):
                if coordinator.is_shutting_down:
                    observed = True
                    break
                time.sleep(0.01)
            os.write(write_fd, b"1" if observed else b"0")
            os.close(write_fd)
        finally:
            os._exit(0)

    os.close(write_fd)
    try:
        # requested in the parent *after* the fork
        time.sleep(0.1)
        coordinator.request_shutdown("parent")

        result = os.read(read_fd, 1)
        os.waitpid(pid, 0)
        assert result == b"1"
    finally:
        os.close(read_fd)


@pytest.mark.unit
def test_get_shutdown_coordinator_is_a_singleton():
    first = get_shutdown_coordinator(deadline_seconds=7)
    second = get_shutdown_coordinator()

    assert first is second
    assert second.deadline_seconds == 7


@pytest.mark.unit
def test_is_shutting_down_without_a_coordinator():
    """Library code calls this from processes that never built a coordinator; it must
    answer False rather than creating one as a side effect."""
    assert is_shutting_down() is False

    from saq import shutdown
    assert shutdown._coordinator is None


@pytest.mark.unit
def test_is_shutting_down_tracks_the_coordinator():
    coordinator = get_shutdown_coordinator(deadline_seconds=5)
    assert is_shutting_down() is False

    coordinator.request_shutdown("test")
    assert is_shutting_down() is True


@pytest.mark.unit
def test_run_bounded_completes():
    calls = []
    assert run_bounded(lambda: calls.append(1), 5, "quick") is True
    assert calls == [1]


@pytest.mark.unit
def test_run_bounded_gives_up_on_a_wedged_call():
    """The whole reason this helper exists: a stop() blocked on a dead peer must not
    prevent the rest of shutdown from running."""
    started = time.monotonic()
    assert run_bounded(lambda: time.sleep(30), 0.2, "wedged") is False
    assert time.monotonic() - started < 5


@pytest.mark.unit
def test_run_bounded_swallows_exceptions():
    def _boom():
        raise RuntimeError("boom")

    assert run_bounded(_boom, 5, "boom") is True


@pytest.mark.unit
def test_watchdog_stands_down_when_shutdown_completes(make_coordinator):
    """The watchdog is a deadline for *completing* shutdown, not a timer that always
    fires. A coordinator whose shutdown finished must not force-exit the process
    afterwards -- an armed watchdog left over from a finished shutdown will happily take
    down a process that had every right to still be running.

    The assertion is indirect but decisive: if the watchdog did not stand down, it calls
    os._exit and this test process dies rather than reporting a failure.
    """
    coordinator = make_coordinator(deadline_seconds=0.1)
    coordinator.request_shutdown("test")
    coordinator.mark_complete()

    # comfortably past deadline + WATCHDOG_GRACE
    time.sleep(0.3)
    assert coordinator.is_shutting_down


@pytest.mark.unit
def test_reset_stands_the_watchdog_down(make_coordinator):
    """reset_shutdown_coordinator() drops the global reference, but the watchdog thread
    holds its own reference and survives. It has to be told to stand down explicitly."""
    coordinator = get_shutdown_coordinator(deadline_seconds=0.1)
    coordinator.request_shutdown("test")

    reset_shutdown_coordinator()

    assert coordinator._complete.is_set()


# The body of test_sigterm_while_waiting_does_not_deadlock, run as a subprocess.
#
# It has to be a subprocess: the failure mode is a hang, not an exception, and an
# in-process version would wedge the whole suite rather than fail.
_SIGTERM_DEADLOCK_PROGRAM = """
import os, signal, sys, threading
sys.path.insert(0, {repo!r})
from saq.shutdown import get_shutdown_coordinator

coordinator = get_shutdown_coordinator(deadline_seconds=20.0)
coordinator.install_signal_handlers()

def _fire():
    import time
    time.sleep(0.5)
    os.kill(os.getpid(), signal.SIGTERM)

threading.Thread(target=_fire, daemon=True).start()

# the main thread blocks on the very event the handler is about to set. this is the
# shape every threaded ACE service runs in (see saq/cli/commands/service.py).
if coordinator.wait_for_shutdown(10):
    print("WOKE")
    sys.exit(0)

print("TIMED OUT")
sys.exit(1)
"""


@pytest.mark.unit
def test_sigterm_while_waiting_does_not_deadlock(tmp_path):
    """SIGTERM must wake a thread that is blocked in wait_for_shutdown().

    This is the shape every threaded service runs in, and it used to deadlock outright.
    The coordinator's flag was a multiprocessing.Event, and setting one from a signal
    handler that interrupted a wait on that same event blocks forever: mp's
    Condition.notify() waits for a sleeper to wake, and the only sleeper is the thread
    suspended inside the handler. Services hung until docker SIGKILLed them at the end of
    their grace period, which read as "shutdown is very slow".
    """
    import subprocess
    import sys as _sys

    program = tmp_path / "sigterm_wait.py"
    program.write_text(_SIGTERM_DEADLOCK_PROGRAM.format(repo=str(REPO_ROOT)))

    result = subprocess.run(
        [_sys.executable, str(program)],
        capture_output=True, text=True, timeout=30,
    )

    assert "WOKE" in result.stdout, f"stdout={result.stdout!r} stderr={result.stderr[-2000:]!r}"
    assert result.returncode == 0


@pytest.mark.unit
def test_signal_handler_touches_no_blocking_primitive(make_coordinator):
    """The handler must not log, take the coordinator lock, or set the mp mirror.

    Each of those can block, and the handler runs on a thread that may be holding the
    very lock it would need. The follow-on work belongs on the observer thread.
    """
    coordinator = make_coordinator(deadline_seconds=5)
    coordinator._start_observer()

    # hold the coordinator lock, then run the handler as a signal would
    with coordinator._lock:
        coordinator._signal_handler(signal.SIGTERM, None)

        # the flag is set without ever needing the lock we are holding
        assert coordinator.is_shutting_down
        assert coordinator.reason == "received SIGTERM"

        # and the shared mirror is NOT set from the handler
        assert not coordinator._mp_flag.value

    # the observer picks it up once we are out of the way
    for _ in range(200):
        if coordinator._mp_flag.value:
            break
        time.sleep(0.01)

    assert coordinator._mp_flag.value


#
# the fork mirror must not be something a killed child can wedge
#
# A multiprocessing.Event is exactly that. Condition.wait() registers a sleeper before it
# sleeps and Condition.notify_all() waits for one wake per registered sleeper, so a child
# killed mid-wait leaves a sleeper that never wakes and the parent's next set() blocks
# forever. Event.is_set() takes the same condition's lock, so even the read path is
# exposed -- and is_shutting_down() is read from hot loops inside forked engine workers,
# which this engine kills abruptly by design. The mirror is therefore a lock free shared
# flag; see saq/engine/worker.py for the same argument applied to the worker's own
# signals.
#
# Every test below bounds itself: a hanging test wedges the pytest session lock.
#


def _finishes_within(callback, timeout: float = 5.0) -> bool:
    """Run callback on a daemon thread, returning True if it finished inside timeout.

    Deliberately not run_bounded(): this *is* the assertion, and it has to fail rather
    than hang. The abandoned thread is a daemon, so it cannot hold up interpreter exit.
    """
    finished = threading.Event()

    def _run():
        callback()
        finished.set()

    threading.Thread(target=_run, daemon=True).start()
    return finished.wait(timeout)


def _fork_a_waiter(coordinator) -> int:
    """Fork a child blocked in ``coordinator.wait_for_shutdown()``; returns its pid.

    Raw os.fork() to match test_flag_is_visible_across_a_fork, and because the child does
    nothing that needs multiprocessing's after-fork bookkeeping.
    """
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        # child
        try:
            os.close(read_fd)
            os.write(write_fd, b"x")
            os.close(write_fd)
            coordinator.wait_for_shutdown()
        finally:
            os._exit(0)

    os.close(write_fd)
    try:
        assert os.read(read_fd, 1) == b"x", "the child never reached the wait"
    finally:
        os.close(read_fd)

    # the pipe only says it is about to wait, so give it a moment to actually be inside
    time.sleep(0.5)
    return pid


def _kill_the_waiter(pid: int):
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


@pytest.mark.unit
def test_request_shutdown_returns_after_a_waiting_child_was_killed(make_coordinator):
    """The deadlock, isolated: a child killed while waiting on the mirror must not be
    able to wedge the parent that requests shutdown."""
    coordinator = make_coordinator(deadline_seconds=5)

    _kill_the_waiter(_fork_a_waiter(coordinator))

    assert _finishes_within(lambda: coordinator.request_shutdown("test")), \
        "request_shutdown() blocked on a child killed while waiting on the mirror"
    assert coordinator.is_shutting_down


@pytest.mark.unit
def test_is_shutting_down_is_not_blocked_by_a_killed_child(make_coordinator):
    """The read path matters as much as the write: is_shutting_down() is called from hot
    loops in forked workers, so it must never be able to block.

    Unlike the test above this does not reliably fail against an mp.Event -- orphaning
    the condition's lock is a race, not a certainty. It guards the property that makes
    the whole subsystem safe to call from library code.
    """
    coordinator = make_coordinator(deadline_seconds=5)

    _kill_the_waiter(_fork_a_waiter(coordinator))

    answers = []
    assert _finishes_within(lambda: answers.append(coordinator.is_shutting_down)), \
        "is_shutting_down blocked after a child was killed"
    assert answers == [False]


@pytest.mark.unit
def test_wait_for_shutdown_wakes_a_forked_child(make_coordinator):
    """A child blocked in wait_for_shutdown() wakes when the parent requests shutdown.

    The child cannot see the parent's threading.Event -- it holds a stale copy the parent
    can never set -- so this is the shared flag doing the work.
    """
    coordinator = make_coordinator(deadline_seconds=5)

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        # child
        try:
            os.close(read_fd)
            woke = coordinator.wait_for_shutdown(15)
            os.write(write_fd, b"1" if woke else b"0")
            os.close(write_fd)
        finally:
            os._exit(0)

    os.close(write_fd)
    try:
        # requested in the parent *after* the child is already blocked
        time.sleep(0.5)
        coordinator.request_shutdown("parent")

        result = os.read(read_fd, 1)
        os.waitpid(pid, 0)
        assert result == b"1", "the forked child never woke"
    finally:
        os.close(read_fd)


#
# wait_for_shared_flag: the polling primitive both the coordinator and Worker wait on
#


class _FakeFlag:
    """Stands in for a multiprocessing Value: the helper only reads ``.value``."""

    def __init__(self, value: bool = False):
        self.value = value


@pytest.mark.unit
def test_wait_for_shared_flag_wakes_when_the_flag_is_set():
    flag = _FakeFlag()

    def _set_soon():
        time.sleep(0.2)
        flag.value = True

    threading.Thread(target=_set_soon, daemon=True).start()

    started = time.monotonic()
    assert wait_for_shared_flag(flag, 10) is True
    assert time.monotonic() - started < 5


@pytest.mark.unit
def test_wait_for_shared_flag_times_out():
    started = time.monotonic()
    assert wait_for_shared_flag(_FakeFlag(), 0.5) is False
    assert time.monotonic() - started >= 0.5


@pytest.mark.unit
def test_wait_for_shared_flag_with_zero_timeout_just_reads_the_flag():
    """Worker.worker_loop's idle backoff starts at zero, so this is the common case."""
    assert wait_for_shared_flag(_FakeFlag(False), 0) is False
    assert wait_for_shared_flag(_FakeFlag(True), 0) is True
