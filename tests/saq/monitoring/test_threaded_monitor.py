import logging
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
