import logging
import os
import sys

import pytest

import saq.error.reporting
import saq.shutdown
from saq.configuration.config import get_config
from saq.environment import get_base_dir, get_data_dir
from saq.error.reporting import (
    MAX_REMEMBERED_CAUSES,
    REPEAT_WINDOW_SECONDS,
    ErrorReportHandler,
    log_loop_exception,
    log_peer_unavailable,
    write_error_report,
)
from saq.logging import _install_error_report_handler, suppress_external_logging, transaction_id
from saq.monitor import enable_monitor_cache, get_emitter
from saq.monitor_definitions import MONITOR_ERROR_REPORT
from tests.saq.helpers import certificate_verification_failure, tls_handshake_failure


def _error_reporting_dir() -> str:
    return os.path.join(get_data_dir(), get_config().global_settings.error_reporting_dir)


@pytest.fixture
def reports(monkeypatch) -> list[logging.LogRecord]:
    """The records ErrorReportHandler asked for a report on, in place of writing one."""
    records = []
    monkeypatch.setattr(saq.error.reporting, "write_error_report",
                        lambda exc_info, record=None, skipped=0: records.append(record))
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


def _log_critical_after_except():
    try:
        1 / 0
    except ZeroDivisionError as e:
        error = e

    logging.critical("division failed", exc_info=error)


@pytest.mark.unit
@pytest.mark.parametrize("log", [_log_exception, _log_critical_after_except])
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

    def _write_error_report(exc_info, record=None, skipped=0):
        calls.append(record)
        _log_exception()

    monkeypatch.setattr(saq.error.reporting, "write_error_report", _write_error_report)
    _log_exception()

    assert len(calls) == 1

    # the guard is cleared afterwards (logged from another line, which is another cause)
    _log_critical_after_except()
    assert len(calls) == 2


def _fail(message: str):
    """Logs RuntimeError(message) with its traceback, always from the same line."""
    try:
        raise RuntimeError(message)
    except RuntimeError:
        logging.exception("work failed")


@pytest.fixture
def reported(monkeypatch) -> list[tuple[str, int]]:
    """(exception text, repeats skipped before it) of each report the handler asked for."""
    calls = []
    monkeypatch.setattr(saq.error.reporting, "write_error_report",
                        lambda exc_info, record=None, skipped=0: calls.append((str(exc_info[1]), skipped)))
    return calls


@pytest.fixture
def clock(monkeypatch) -> list[float]:
    """The handler's monotonic clock, which a test moves by changing clock[0]."""
    now = [1000.0]
    monkeypatch.setattr(saq.error.reporting, "_monotonic", lambda: now[0])
    return now


@pytest.mark.unit
def test_a_repeated_cause_is_reported_once_per_window(reported, clock):
    """A failure that hits every item the same way writes one report, not one per item, and the next
    report after the window says how many it skipped."""
    for _ in range(3):
        _fail("peer is down")
    clock[0] += REPEAT_WINDOW_SECONDS - 1
    _fail("peer is down")
    assert reported == [("peer is down", 0)]

    clock[0] += 1
    _fail("peer is down")
    assert reported == [("peer is down", 0), ("peer is down", 3)]

    # the count starts again from each report
    _fail("peer is down")
    clock[0] += REPEAT_WINDOW_SECONDS
    _fail("peer is down")
    assert reported[-1] == ("peer is down", 1)


@pytest.mark.unit
def test_every_record_is_still_logged_while_its_report_is_skipped(reported, caplog):
    _fail("peer is down")
    _fail("peer is down")

    assert len(reported) == 1
    assert [r.levelno for r in caplog.records if r.getMessage() == "work failed"] == [logging.ERROR, logging.ERROR]


@pytest.mark.unit
def test_another_exception_text_or_line_is_another_cause(reported, clock):
    _fail("peer is down")
    _fail("disk is full")
    # the same exception logged from another line
    try:
        raise RuntimeError("peer is down")
    except RuntimeError:
        logging.exception("work failed")

    assert reported == [("peer is down", 0), ("disk is full", 0), ("peer is down", 0)]


@pytest.mark.unit
def test_the_causes_remembered_are_bounded(reported, clock):
    for index in range(MAX_REMEMBERED_CAUSES + 1):
        _fail(f"item {index} failed")

    # the oldest cause was forgotten, so it is reported again; the newest is still remembered
    _fail("item 0 failed")
    _fail(f"item {MAX_REMEMBERED_CAUSES} failed")
    assert len(reported) == MAX_REMEMBERED_CAUSES + 2
    assert reported[-1] == ("item 0 failed", 0)


@pytest.mark.unit
def test_the_cause_reported_longest_ago_is_forgotten_first(reported, clock):
    _fail("peer is down")
    _fail("disk is full")
    clock[0] += REPEAT_WINDOW_SECONDS
    # reported again, so it is now the newest report and "disk is full" the oldest
    _fail("peer is down")
    for index in range(MAX_REMEMBERED_CAUSES - 1):
        _fail(f"item {index} failed")

    count = len(reported)
    _fail("peer is down")
    assert len(reported) == count


@pytest.mark.unit
def test_an_exception_whose_text_cannot_be_read_is_still_reported(reports):
    class _Unprintable(Exception):
        def __str__(self):
            raise ValueError("no text")

    for _ in range(2):
        try:
            raise _Unprintable()
        except _Unprintable:
            logging.exception("work failed")

    # not known to be a repeat, so both are reported
    assert len(reports) == 2


@pytest.mark.unit
def test_a_report_names_the_repeats_it_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(saq.error.reporting, "get_data_dir", lambda: str(tmp_path))
    os.makedirs(tmp_path / get_config().global_settings.error_reporting_dir)
    enable_monitor_cache()

    try:
        raise RuntimeError("peer is down")
    except RuntimeError:
        path = write_error_report(sys.exc_info(), skipped=7)

    with open(path) as fp:
        assert "SKIPPED REPEATS: 7 since the last report of this cause\n\nEXCEPTION\npeer is down" in fp.read()
    assert get_emitter().cache[MONITOR_ERROR_REPORT.path].value["skipped_repeats"] == 7


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
def test_report_for_an_exception_naming_an_undecodable_file():
    """A file name that is not UTF-8 reaches ACE with lone surrogates (surrogateescape). The report
    is written with them escaped, and its monitor event is emitted."""
    enable_monitor_cache()
    existing = set(os.listdir(_error_reporting_dir()))
    path = "/opt/ace/data/" + b"\xe9.pdf".decode("utf-8", "surrogateescape")

    # outside the logger hierarchy: pytest-xdist cannot send the controller a report whose captured
    # log holds a surrogate
    logger = logging.Logger("test_undecodable_error_report")
    logger.addHandler(ErrorReportHandler())
    try:
        raise RuntimeError(f"unable to open {path}")
    except RuntimeError:
        logger.exception("failed on %s", path)

    new_reports = set(os.listdir(_error_reporting_dir())) - existing
    assert len(new_reports) == 1
    with open(os.path.join(_error_reporting_dir(), new_reports.pop())) as fp:
        content = fp.read()
    assert content.startswith("LOG MESSAGE\nfailed on /opt/ace/data/\\udce9.pdf\n")
    assert "EXCEPTION\nunable to open /opt/ace/data/\\udce9.pdf" in content
    assert "EXCEPTION SOURCE" in content

    assert get_emitter().cache[MONITOR_ERROR_REPORT.path].value["message"] == f"failed on {path}"


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
def test_log_loop_exception_callers_are_separate_causes(reports):
    """Two loops that fail the same way are each reported, and each report says where its loop logged it."""
    log_loop_exception(KeyError("uuid"), "catalog refresh failed")
    log_loop_exception(KeyError("uuid"), "coverage refresh failed")

    assert [r.getMessage() for r in reports] == ["catalog refresh failed: 'uuid'", "coverage refresh failed: 'uuid'"]
    assert all(r.pathname == __file__ for r in reports)


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


@pytest.mark.parametrize("shutting_down", [False, True])
@pytest.mark.unit
def test_log_loop_exception_puts_extra_on_record(reports, monkeypatch, caplog, shutting_down):
    monkeypatch.setattr(saq.shutdown, "is_shutting_down", lambda: shutting_down)
    caplog.set_level(logging.INFO)
    log_loop_exception(RuntimeError("loop failed"), "doing work", extra={"alert_uuid": "uuid-1"})

    records = [r for r in caplog.records if r.getMessage().startswith("doing work")]
    assert len(records) == 1
    assert records[0].alert_uuid == "uuid-1"


class _ClientTransportError(Exception):
    """A client library's transport error, which is not an OSError (httpx, azure-core)."""


@pytest.mark.unit
def test_log_peer_unavailable_accepts_the_callers_client_errors(reports, caplog):
    caplog.set_level(logging.INFO)
    assert log_peer_unavailable(_ClientTransportError("connect failed"), "reading x", unreachable=(_ClientTransportError,))

    assert reports == []
    records = [r for r in caplog.records if r.getMessage().startswith("reading x")]
    assert [(r.levelno, r.getMessage()) for r in records] == [(logging.WARNING, "reading x unavailable: connect failed")]


class _ClientAuthenticationError(Exception):
    """What a client raises in place of the transport error it hit (azure-identity's credentials)."""


@pytest.mark.unit
def test_log_peer_unavailable_follows_the_cause_chain(reports, caplog):
    try:
        try:
            raise _ClientTransportError("connect failed")
        except _ClientTransportError as cause:
            raise _ClientAuthenticationError("token request failed") from cause
    except _ClientAuthenticationError as e:
        wrapped = e

    caplog.set_level(logging.INFO)
    assert log_peer_unavailable(wrapped, "reading x", unreachable=(_ClientTransportError,))

    assert reports == []
    records = [r for r in caplog.records if r.getMessage().startswith("reading x")]
    assert [r.levelno for r in records] == [logging.WARNING]


@pytest.mark.unit
def test_log_peer_unavailable_accepts_connection_errors(reports, caplog):
    caplog.set_level(logging.INFO)
    assert log_peer_unavailable(ConnectionResetError("reset"), "reading x")

    assert reports == []
    records = [r for r in caplog.records if r.getMessage().startswith("reading x")]
    assert [r.levelno for r in records] == [logging.WARNING]


@pytest.mark.unit
@pytest.mark.parametrize("error", [
    FileNotFoundError(2, "No such file or directory", "/opt/ace/ssl/client.pem"),
    PermissionError(13, "Permission denied", "/opt/ace/ssl/client.pem"),
])
def test_log_peer_unavailable_rejects_local_file_errors(error, caplog):
    caplog.set_level(logging.INFO)
    assert not log_peer_unavailable(error, "reading x")

    assert [r for r in caplog.records if r.getMessage().startswith("reading x")] == []


@pytest.mark.unit
def test_log_peer_unavailable_rejects_a_wrapped_local_file_error(caplog):
    try:
        try:
            raise FileNotFoundError(2, "No such file or directory", "/opt/ace/ssl/client.pem")
        except FileNotFoundError as cause:
            raise _ClientAuthenticationError("token request failed") from cause
    except _ClientAuthenticationError as e:
        wrapped = e

    caplog.set_level(logging.INFO)
    assert not log_peer_unavailable(wrapped, "reading x", unreachable=(_ClientTransportError,))

    assert [r for r in caplog.records if r.getMessage().startswith("reading x")] == []


@pytest.mark.unit
def test_log_peer_unavailable_rejects_a_certificate_that_does_not_verify(caplog):
    # a peer whose certificate does not verify is misconfigured, not down
    caplog.set_level(logging.INFO)
    assert not log_peer_unavailable(certificate_verification_failure(), "reading x")

    assert [r for r in caplog.records if r.getMessage().startswith("reading x")] == []


@pytest.mark.unit
def test_log_peer_unavailable_accepts_a_tls_handshake_failure(reports, caplog):
    caplog.set_level(logging.INFO)
    assert log_peer_unavailable(tls_handshake_failure(), "reading x")

    assert reports == []
    records = [r for r in caplog.records if r.getMessage().startswith("reading x")]
    assert [r.levelno for r in records] == [logging.WARNING]


@pytest.mark.unit
def test_log_peer_unavailable_client_error_during_shutdown(reports, monkeypatch, caplog):
    monkeypatch.setattr(saq.shutdown, "is_shutting_down", lambda: True)
    caplog.set_level(logging.INFO)
    assert log_peer_unavailable(_ClientTransportError("connect failed"), "reading x", unreachable=(_ClientTransportError,))

    assert reports == []
    records = [r for r in caplog.records if r.getMessage().startswith("reading x")]
    assert [(r.levelno, r.getMessage()) for r in records] == [(logging.INFO, "reading x unavailable during shutdown: connect failed")]
