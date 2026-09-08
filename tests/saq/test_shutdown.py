import os
import signal
import threading
import time

import pytest

from saq.shutdown import (
    ShutdownCoordinator,
    get_shutdown_coordinator,
    is_shutting_down,
    reset_shutdown_coordinator,
    run_bounded,
)


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
    """Engine workers are forked, so a worker must observe a shutdown requested by the
    parent after the fork. This is why the flag is an mp.Event and not a plain bool."""
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
