import logging
import os
import sys

import pytest

import saq.error.reporting
import saq.shutdown
from saq.configuration.config import get_config
from saq.environment import get_base_dir, get_data_dir
from saq.error.reporting import ErrorReportHandler, log_loop_exception, write_error_report
from saq.logging import _install_error_report_handler, suppress_external_logging, transaction_id
from saq.monitor import enable_monitor_cache, get_emitter
from saq.monitor_definitions import MONITOR_ERROR_REPORT


def _error_reporting_dir() -> str:
    return os.path.join(get_data_dir(), get_config().global_settings.error_reporting_dir)


@pytest.fixture
def reports(monkeypatch) -> list[logging.LogRecord]:
    """The records ErrorReportHandler asked for a report on, in place of writing one."""
    records = []
    monkeypatch.setattr(saq.error.reporting, "write_error_report", lambda exc_info, record=None: records.append(record))
    return records


@pytest.mark.unit
def test_root_logger_has_one_error_report_handler():
    def _count():
        return sum(isinstance(h, ErrorReportHandler) for h in logging.getLogger().handlers)

    # initialize_logging() installed it when the test session started
    assert _count() == 1
    _install_error_report_handler()
    assert _count() == 1


def _log_exception():
    try:
        1 / 0
    except ZeroDivisionError:
        logging.exception("division failed")


def _log_error_exc_info():
    try:
        1 / 0
    except ZeroDivisionError:
        logging.error("division failed", exc_info=True)


def _log_critical_after_except():
    try:
        1 / 0
    except ZeroDivisionError as e:
        error = e

    logging.critical("division failed", exc_info=error)


@pytest.mark.unit
@pytest.mark.parametrize("log", [_log_exception, _log_error_exc_info, _log_critical_after_except])
def test_traceback_at_error_writes_report(log, reports):
    log()

    assert len(reports) == 1
    assert reports[0].getMessage() == "division failed"
    assert isinstance(reports[0].exc_info[1], ZeroDivisionError)


@pytest.mark.unit
def test_no_report_without_traceback_or_below_error(reports):
    logging.error("no traceback")
    # outside an except block this records (None, None, None)
    logging.exception("nothing being handled")

    try:
        1 / 0
    except ZeroDivisionError:
        logging.warning("only a warning", exc_info=True)

    assert reports == []


def _traceback_record(pathname: str) -> logging.LogRecord:
    try:
        1 / 0
    except ZeroDivisionError:
        exc_info = sys.exc_info()

    return logging.LogRecord("uvicorn.error", logging.ERROR, pathname, 1, "division failed", None, exc_info)


@pytest.mark.unit
def test_no_report_from_third_party_code(reports):
    logging.getLogger().handle(_traceback_record("/venv/lib/python3.14/site-packages/uvicorn/protocols/http.py"))
    # a sibling directory that only shares the checkout's name as a prefix
    logging.getLogger().handle(_traceback_record(get_base_dir() + "-other/module.py"))
    assert reports == []


@pytest.mark.unit
def test_report_from_script_run_by_relative_path(reports, monkeypatch):
    # ./ace records its own frames under the path it was run by
    monkeypatch.chdir(get_base_dir())
    logging.getLogger().handle(_traceback_record("./ace"))
    assert len(reports) == 1


@pytest.mark.unit
def test_no_report_during_shutdown(reports, monkeypatch):
    monkeypatch.setattr(saq.shutdown, "is_shutting_down", lambda: True)
    _log_exception()
    assert reports == []


@pytest.mark.unit
def test_no_report_while_external_logging_suppressed(reports):
    with suppress_external_logging():
        _log_exception()

    assert reports == []


@pytest.mark.unit
def test_report_that_logs_a_traceback_does_not_recurse(monkeypatch):
    calls = []

    def _write_error_report(exc_info, record=None):
        calls.append(record)
        _log_exception()

    monkeypatch.setattr(saq.error.reporting, "write_error_report", _write_error_report)
    _log_exception()

    assert len(calls) == 1

    # the guard is cleared afterwards
    _log_exception()
    assert len(calls) == 2


@pytest.mark.unit
def test_write_error_report_failure_is_logged_not_raised(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(saq.error.reporting, "get_data_dir", lambda: str(tmp_path / "missing"))

    try:
        1 / 0
    except ZeroDivisionError:
        exc_info = sys.exc_info()

    assert write_error_report(exc_info) is None
    assert any("uncaught exception when reporting an exception" in r.getMessage() for r in caplog.records)

    # and through the handler, the log call still returns
    _log_exception()


@pytest.mark.unit
def test_logged_exception_report_contents():
    enable_monitor_cache()
    existing = set(os.listdir(_error_reporting_dir()))

    with transaction_id("11111111-2222-3333-4444-555555555555"):
        try:
            1 / 0
        except ZeroDivisionError:
            logging.exception("unable to divide %s", "test-marker", extra={"alert_uuid": "abc-123"})

    new_reports = []
    for name in set(os.listdir(_error_reporting_dir())) - existing:
        with open(os.path.join(_error_reporting_dir(), name)) as fp:
            content = fp.read()
        if "unable to divide test-marker" in content:
            new_reports.append(content)

    assert len(new_reports) == 1
    content = new_reports[0]
    assert content.startswith("LOG MESSAGE\nunable to divide test-marker\n")
    assert f"LOGGED AT {__file__}:" in content
    assert "TRANSACTION ID: 11111111-2222-3333-4444-555555555555" in content
    assert "alert_uuid=abc-123" in content
    assert "EXCEPTION\ndivision by zero" in content
    assert "STACK TRACE" in content

    event = get_emitter().cache[MONITOR_ERROR_REPORT.path].value
    assert event["message"] == "unable to divide test-marker"
    assert event["transaction_id"] == "11111111-2222-3333-4444-555555555555"
    assert event["exception"] == "division by zero"


@pytest.mark.unit
def test_log_loop_exception_reports_once_with_traceback(reports, caplog):
    error = RuntimeError("loop failed")
    log_loop_exception(error, "doing work")

    assert len(reports) == 1
    record = reports[0]
    assert record.levelno == logging.ERROR
    assert record.getMessage() == "doing work: loop failed"
    assert record.exc_info[1] is error


@pytest.mark.unit
def test_log_loop_exception_during_shutdown(reports, monkeypatch, caplog):
    monkeypatch.setattr(saq.shutdown, "is_shutting_down", lambda: True)
    caplog.set_level(logging.INFO)
    log_loop_exception(RuntimeError("loop failed"), "doing work")

    assert reports == []
    records = [r for r in caplog.records if r.getMessage() == "doing work during shutdown: loop failed"]
    assert len(records) == 1
    assert records[0].levelno == logging.INFO
    assert records[0].exc_info is None
