import logging
import threading
from unittest.mock import patch

import pytest

from tests.saq.helpers import wait_for_condition
from tests.saq.monitoring.conftest import ConcreteTestMonitor


@pytest.mark.unit
class TestACEThreadedMonitor:
    def test_start_creates_thread(self):
        monitor = ConcreteTestMonitor(frequency=0.05)
        try:
            monitor.start()
            assert monitor.main_thread.is_alive()
            assert monitor.main_thread.name == "test_monitor"
        finally:
            monitor.stop()
            monitor.wait()

    # log_loop_exception logs the traceback, and the root logger's ErrorReportHandler writes
    # the report from that record. patched only to keep the test from writing a real
    # error-report file; the assertions below are about the log.
    @patch("saq.error.reporting.write_error_report")
    def test_main_loop_logs_error_on_exception(self, mock_report, caplog):
        error = ValueError("something went wrong")
        monitor = ConcreteTestMonitor(name="error_monitor", frequency=0.05, execute_side_effect=error)
        try:
            monitor.start()
            # a second execution means the loop survived the first exception
            wait_for_condition(lambda: monitor.execute_count >= 2)
        finally:
            monitor.stop()
            monitor.wait()

        records = [r for r in caplog.records if r.getMessage() == "error in error_monitor monitor: something went wrong"]
        assert records
        assert all(r.levelno == logging.ERROR and r.exc_info[1] is error for r in records)


class BlockingMonitor(ConcreteTestMonitor):
    """A monitor whose execute() does not return until it is released."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.entered = threading.Event()
        self.release = threading.Event()

    def execute(self):
        super().execute()
        self.entered.set()
        self.release.wait(30)


def _wait_in_thread(monitor) -> threading.Event:
    """Runs monitor.wait() on a daemon thread and returns the event set when it returns, so a
    wait() that hangs fails the test instead of hanging it."""
    returned = threading.Event()

    def _wait():
        monitor.wait()
        returned.set()

    threading.Thread(target=_wait, daemon=True).start()
    return returned


@pytest.mark.unit
class TestACEThreadedMonitorLifecycle:
    def test_wait_for_start_is_true_once_started(self):
        monitor = ConcreteTestMonitor(frequency=3600)
        try:
            monitor.start()
            assert monitor.wait_for_start(timeout=5) is True
        finally:
            monitor.stop()
            monitor.wait()

    def test_wait_for_start_is_false_when_never_started(self):
        assert ConcreteTestMonitor().wait_for_start(timeout=0.01) is False

    def test_stop_wakes_a_monitor_waiting_out_its_frequency(self):
        monitor = ConcreteTestMonitor(frequency=3600)
        monitor.start()
        wait_for_condition(lambda: monitor.execute_count == 1)

        monitor.stop()
        returned = _wait_in_thread(monitor)

        assert returned.wait(5)
        assert not monitor.main_thread.is_alive()
        assert monitor.execute_count == 1

    def test_wait_blocks_until_stop(self):
        # `ace service start` reads a wait() that returns as the service having finished
        monitor = ConcreteTestMonitor(frequency=3600)
        monitor.stop_timeout = 0.01
        monitor.start()
        try:
            returned = _wait_in_thread(monitor)
            assert not returned.wait(0.5)
        finally:
            monitor.stop()

        assert returned.wait(5)

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
    def test_wait_returns_when_the_thread_dies_on_its_own(self):
        # main_loop catches Exception, not SystemExit
        monitor = ConcreteTestMonitor(frequency=3600, execute_side_effect=SystemExit())
        monitor.start()

        assert _wait_in_thread(monitor).wait(5)
        assert not monitor.main_thread.is_alive()
        assert not monitor.shutdown_event.is_set()

    def test_wait_gives_up_on_a_monitor_whose_execute_does_not_return(self, caplog):
        monitor = BlockingMonitor(name="stuck_monitor", frequency=3600)
        monitor.stop_timeout = 0.1
        monitor.start()
        try:
            assert monitor.entered.wait(5)
            monitor.stop()

            returned = _wait_in_thread(monitor)
            assert returned.wait(5)
            assert monitor.main_thread.is_alive()
        finally:
            monitor.release.set()
            monitor.main_thread.join(5)

        records = [r for r in caplog.records if r.getMessage() == "monitor stuck_monitor did not stop within 0.1 seconds"]
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING
        assert records[0].monitor == "stuck_monitor"

    def test_wait_returns_when_the_monitor_never_started_a_thread(self):
        # single threaded mode runs execute() once and starts no thread
        monitor = ConcreteTestMonitor()
        monitor.start_single_threaded()

        assert _wait_in_thread(monitor).wait(5)
