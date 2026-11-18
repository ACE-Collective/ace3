from collections import OrderedDict
from datetime import datetime
import logging
import os
import ssl
import threading
import time
from types import TracebackType
from typing import Optional

from saq.configuration.config import get_config
from saq.environment import get_base_dir, get_data_dir
from saq.logging import format_extra_field, iter_extra_fields
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_ERROR_REPORT


ExcInfo = tuple[Optional[type[BaseException]], Optional[BaseException], Optional[TracebackType]]

# a failure that hits every item the same way (a peer that is down, a tool this node cannot run) would write
# one report per item: ErrorReportHandler reports a cause once per window, and its next report of that cause
# says how many it skipped. A cause is where the record was logged and the exception's type and text
REPEAT_WINDOW_SECONDS = 600
# an exception's text can name the item it failed on, so every item can be a cause of its own
MAX_REMEMBERED_CAUSES = 1024

_monotonic = time.monotonic


def write_error_report(exc_info: ExcInfo, record: Optional[logging.LogRecord]=None, skipped: int = 0) -> Optional[str]:
    """Write an error report for exc_info and emit the error report monitor event. skipped is how many
    repeats of its cause ErrorReportHandler did not report since it last reported it.

    Returns the path of the report, or None if it could not be written. Never raises: it
    runs on paths that are already handling a failure, including inside a log call."""

    exc_type, reported_exception, tb = exc_info

    try:
        output_dir = os.path.join(get_data_dir(), get_config().global_settings.error_reporting_dir)
        error_report_path = os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f'))
        message = record.getMessage() if record is not None else None
        transaction_id = getattr(record, "transactionId", None)

        # a file name ACE did not choose can hold lone surrogates (surrogateescape); escaped the way
        # saq.logging.utf8_safe escapes them, rather than losing the report
        with open(error_report_path, 'w', errors='backslashreplace') as fp:
            if record is not None:
                fp.write("LOG MESSAGE\n")
                fp.write(message)
                fp.write("\n\nLOGGED AT {}:{} in {}\n".format(record.pathname, record.lineno, record.funcName))
                # the worker sets this to the root uuid of the work item it is analyzing
                if transaction_id:
                    fp.write("TRANSACTION ID: {}\n".format(transaction_id))
                for key, value in iter_extra_fields(record):
                    fp.write(format_extra_field(key, value))
                    fp.write("\n")
                fp.write("\n")

            if skipped:
                fp.write(f"SKIPPED REPEATS: {skipped} since the last report of this cause\n\n")

            fp.write("EXCEPTION\n")
            fp.write(str(reported_exception))
            fp.write("\n\nSTACK TRACE\n")

            from saq.error.formatter import ExceptionFormatter
            formatter = ExceptionFormatter()
            stack_trace, final_source = formatter.format_traceback(tb)

            fp.write(stack_trace)
            fp.write("\n\nEXCEPTION SOURCE\n")
            fp.write(final_source)
            fp.write("\n")

        emit_monitor(MONITOR_ERROR_REPORT, {
            "message": message,
            "transaction_id": transaction_id,
            "exception": str(reported_exception),
            "stack_trace": stack_trace,
            "exception_source": final_source,
            "skipped_repeats": skipped,
        })

        return error_report_path

    except Exception as e:
        logging.error("uncaught exception when reporting an exception: {}".format(e))
        return None


class ErrorReportHandler(logging.Handler):
    """Writes an error report for every record at ERROR or above that carries a traceback
    and was logged by ACE's own code, so logging.exception() is all a caller has to know
    about, once per cause per REPEAT_WINDOW_SECONDS. initialize_logging() installs it on the
    root logger."""

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self._reporting = threading.local()
        # cause -> [when it was last reported, repeats skipped since], oldest report first. Only emit() uses it,
        # which logging calls with the handler's lock held
        self._causes: OrderedDict[tuple, list] = OrderedDict()

    def _skipped_since_last_report(self, record: logging.LogRecord) -> Optional[int]:
        """None when record's cause was reported within the window, else the repeats skipped since its last
        report (0 for a cause not reported before)."""
        exc_type, exception, _ = record.exc_info
        try:
            text = str(exception)
        except Exception:
            # without its text this is not known to be a repeat of anything, so it is reported
            return 0

        cause = (record.pathname, record.lineno, exc_type.__module__, exc_type.__qualname__, text)
        now = _monotonic()
        last = self._causes.get(cause)
        if last is not None and now - last[0] < REPEAT_WINDOW_SECONDS:
            last[1] += 1
            return None

        self._causes[cause] = [now, 0]
        self._causes.move_to_end(cause)
        while len(self._causes) > MAX_REMEMBERED_CAUSES:
            self._causes.popitem(last=False)
        return last[1] if last is not None else 0

    def emit(self, record: logging.LogRecord):
        # logging.exception() outside an except block records (None, None, None)
        if not record.exc_info or record.exc_info[0] is None:
            return

        # only code in the checkout (integrations included) writes reports. a third-party
        # library picks its own levels, and some log routine failures at ERROR. abspath
        # because a script run by a relative path (./ace) records that path
        base_dir = get_base_dir()
        if base_dir and not os.path.abspath(record.pathname).startswith(os.path.join(base_dir, "")):
            return

        # see log_loop_exception: during shutdown a traceback is usually the shutdown itself
        from saq.shutdown import is_shutting_down

        if is_shutting_down():
            return

        # writing the report logs its own failure, and the monitor emitter can log too. a
        # record with a traceback logged from in there must not start another report
        if getattr(self._reporting, "active", False):
            return

        skipped = self._skipped_since_last_report(record)
        if skipped is None:
            return

        self._reporting.active = True
        try:
            write_error_report(record.exc_info, record=record, skipped=skipped)
        finally:
            self._reporting.active = False


# connection-level failures that mean "the peer went away" rather than "the peer is
# broken". during shutdown these are expected: containers stop in dependency order, so
# every process spends its last moments talking to peers that have already exited.
_EXPECTED_SHUTDOWN_ERRORS = (
    ConnectionError,        # covers ConnectionRefused/Reset/Aborted
    BrokenPipeError,
    EOFError,
    TimeoutError,
    OSError,                # socket.error, and pymysql wraps some failures in this
)


def log_loop_exception(e: Exception, context: str, extra: Optional[dict] = None):
    """Log an exception caught by a long-running loop's catch-all handler.

    Long-running ACE loops are all shaped like::

        while not shutting_down:
            try:
                work()
            except Exception as e:
                log_loop_exception(e, "doing work")

    The distinction this makes is between a failure that needs investigating and a
    failure that is just the shutdown itself being observed from inside the loop. During
    shutdown the peers a loop depends on -- the database, redis, qdrant, the network
    semaphore, rabbitmq -- are being stopped alongside it, so every iteration until the
    process exits would otherwise emit an ERROR *and* write an error-report file *and*
    emit a monitor event. Multiplied by every loop in every worker in every service,
    that is the burst of noise that made shutdown look like a failure.

    While shutting down this logs at INFO without the traceback, so no error report is
    written. Otherwise it logs at ERROR with the traceback, and ErrorReportHandler writes
    the report. `extra` goes on the record either way.
    """
    # imported here rather than at module level: saq.shutdown is deliberately dependency
    # free, but saq.error.reporting is imported by nearly everything, and a module-level
    # import creates a cycle through saq.environment
    from saq.shutdown import is_shutting_down

    # stacklevel=2: the record names the loop that caught e, which is part of the cause ErrorReportHandler
    # reports once per window, so two loops that fail the same way are each reported
    if is_shutting_down():
        logging.info("%s during shutdown: %s", context, e, extra=extra, stacklevel=2)
        return

    logging.error("%s: %s", context, e, exc_info=e, extra=extra, stacklevel=2)


# OSErrors that a misconfigured local path raises (a client certificate, a key file). A peer
# being down never raises one, and an operator needs to hear about them as errors
_LOCAL_FILE_ERRORS = (
    FileNotFoundError,
    PermissionError,
    IsADirectoryError,
    NotADirectoryError,
    FileExistsError,
)


def is_certificate_failure(e: BaseException) -> bool:
    """True when e failed a TLS certificate check: a peer whose certificate does not verify is
    misconfigured, not down, although requests raises it as a ConnectionError."""
    # requests keeps the ssl error only as __context__: its SSLError was raised while handling
    # urllib3's MaxRetryError, whose reason holds the ssl.SSLCertVerificationError
    seen = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if isinstance(e, ssl.SSLCertVerificationError):
            return True
        e = e.__cause__ or e.__context__
    return False


def _is_peer_unavailable(e: BaseException, unreachable: tuple[type[BaseException], ...]) -> bool:
    if is_certificate_failure(e):
        return False

    # client libraries wrap a transport failure in an exception of their own and keep the
    # original as __cause__ (azure-identity's credentials raise ClientAuthenticationError)
    types = _EXPECTED_SHUTDOWN_ERRORS + unreachable
    seen = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if isinstance(e, types) and not isinstance(e, _LOCAL_FILE_ERRORS):
            return True
        e = e.__cause__
    return False


def log_peer_unavailable(e: Exception, context: str, unreachable: tuple[type[BaseException], ...] = (),
                         extra: Optional[dict] = None) -> bool:
    """Log a connection-level failure to a peer service, returning True if it was one.

    Use for the narrower case of a call to a specific peer (redis, qdrant, a remote ACE
    node) where a connection failure is not worth an error report even outside shutdown,
    because the peer being down is an operational condition rather than an ACE bug. This
    generalizes the pattern already used in saq/collectors/remote_node.py.

    `unreachable` names the transport errors of the caller's client library that are not
    OSErrors (httpx.TransportError, azure-core's ServiceRequestError). An exception counts
    when it, or an exception in its __cause__ chain, is one of these or a connection-level
    OSError; a missing or unreadable local file, or a certificate that does not verify, never
    counts.

    Returns False without logging if the exception is not connection-level, so the
    caller can fall through to its normal handling.
    """
    from saq.shutdown import is_shutting_down

    if not _is_peer_unavailable(e, unreachable):
        return False

    if is_shutting_down():
        logging.info("%s unavailable during shutdown: %s", context, e, extra=extra)
    else:
        logging.warning("%s unavailable: %s", context, e, extra=extra)

    return True
