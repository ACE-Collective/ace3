import threading
from unittest.mock import patch

import pytest

from tests.saq.monitoring.conftest import ConcreteTestMonitor


@pytest.mark.unit
class TestACEThreadedMonitor:
    def test_init_sets_name_and_frequency(self):
        monitor = ConcreteTestMonitor(name="my_monitor", frequency=5.0)
        assert monitor.name == "my_monitor"
        assert monitor.frequency == 5.0

    def test_init_creates_unset_events(self):
        monitor = ConcreteTestMonitor()
        assert isinstance(monitor.started_event, threading.Event)
        assert isinstance(monitor.shutdown_event, threading.Event)
        assert not monitor.started_event.is_set()
        assert not monitor.shutdown_event.is_set()

    def test_start_single_threaded_calls_execute(self):
        monitor = ConcreteTestMonitor()
        monitor.start_single_threaded()
        assert monitor.execute_count == 1

    def test_stop_sets_shutdown_event(self):
        monitor = ConcreteTestMonitor()
        assert not monitor.shutdown_event.is_set()
        monitor.stop()
        assert monitor.shutdown_event.is_set()

    def test_start_creates_thread(self):
        monitor = ConcreteTestMonitor(frequency=0.05)
        try:
            monitor.start()
            # give the thread a moment to start
            assert monitor.main_thread.is_alive()
            assert monitor.main_thread.name == "test_monitor"
        finally:
            monitor.stop()
            monitor.wait()

    def test_main_loop_calls_execute(self):
        monitor = ConcreteTestMonitor(frequency=0.05)
        try:
            monitor.start()
            # wait for at least one execute call
            for _ in range(100):
                if monitor.execute_count >= 1:
                    break
                threading.Event().wait(0.01)
            assert monitor.execute_count >= 1
        finally:
            monitor.stop()
            monitor.wait()

    @patch("saq.monitoring.threaded_monitor.report_exception")
    def test_main_loop_catches_exception(self, mock_report):
        error = RuntimeError("test error")
        monitor = ConcreteTestMonitor(frequency=0.05, execute_side_effect=error)
        try:
            monitor.start()
            # wait for at least two executions to verify the loop continues
            for _ in range(100):
                if monitor.execute_count >= 2:
                    break
                threading.Event().wait(0.01)
            assert monitor.execute_count >= 2
            mock_report.assert_called_with(error)
        finally:
            monitor.stop()
            monitor.wait()

    @patch("saq.monitoring.threaded_monitor.report_exception")
    def test_main_loop_logs_error_on_exception(self, mock_report, caplog):
        error = ValueError("something went wrong")
        monitor = ConcreteTestMonitor(name="error_monitor", frequency=0.05, execute_side_effect=error)
        try:
            monitor.start()
            for _ in range(100):
                if monitor.execute_count >= 1:
                    break
                threading.Event().wait(0.01)
        finally:
            monitor.stop()
            monitor.wait()

        assert any("error_monitor" in record.message for record in caplog.records)

    def test_stop_and_wait_joins_thread(self):
        monitor = ConcreteTestMonitor(frequency=0.05)
        monitor.start()
        monitor.stop()
        monitor.wait()
        assert not monitor.main_thread.is_alive()

    def test_wait_for_start_true_when_set(self):
        monitor = ConcreteTestMonitor()
        monitor.started_event.set()
        assert monitor.wait_for_start(timeout=0.1) is True

    def test_wait_for_start_false_on_timeout(self):
        monitor = ConcreteTestMonitor()
        assert monitor.wait_for_start(timeout=0.01) is False
