from datetime import datetime
import logging
import os
import sys
import threading
from types import TracebackType
from typing import TYPE_CHECKING, Optional

from saq.configuration.config import get_config
if TYPE_CHECKING:
    from saq.engine.execution_context import EngineExecutionContext
from saq.environment import get_base_dir, get_data_dir
from saq.logging import format_extra_field, iter_extra_fields
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_ERROR_REPORT


ExcInfo = tuple[Optional[type[BaseException]], Optional[BaseException], Optional[TracebackType]]


def report_exception(execution_context: Optional["EngineExecutionContext"]=None):
    """Write an error report for the exception currently being handled.

    A record logged with logging.exception() (or exc_info at ERROR) writes the same report
    through ErrorReportHandler, so calling this as well writes it twice."""
    return write_error_report(sys.exc_info(), execution_context=execution_context)


def write_error_report(
    exc_info: ExcInfo,
    execution_context: Optional["EngineExecutionContext"]=None,
    record: Optional[logging.LogRecord]=None,
) -> Optional[str]:
    """Write an error report for exc_info and emit the error report monitor event.

    Returns the path of the report, or None if it could not be written. Never raises: it
    runs on paths that are already handling a failure, including inside a log call."""

    exc_type, reported_exception, tb = exc_info

    try:
        output_dir = os.path.join(get_data_dir(), get_config().global_settings.error_reporting_dir)
        error_report_path = os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f'))
        message = record.getMessage() if record is not None else None
        transaction_id = getattr(record, "transactionId", None)

        with open(error_report_path, 'w') as fp:
            if execution_context:
                fp.write("CURRENT ANALYSIS TARGET: {}\n".format(execution_context.root))
                if execution_context.root:
                    fp.write("CURRENT ANALYSIS MODE: {}\n".format(execution_context.root.analysis_mode))

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
            "current_analysis_target": str(execution_context.root) if execution_context else None,
            "current_analysis_mode": str(execution_context.root.analysis_mode) if execution_context and execution_context.root else None,
            "message": message,
            "transaction_id": transaction_id,
            "exception": str(reported_exception),
            "stack_trace": stack_trace,
            "exception_source": final_source,
        })

        return error_report_path

    except Exception as e:
        logging.error("uncaught exception when reporting an exception: {}".format(e))
        return None


class ErrorReportHandler(logging.Handler):
    """Writes an error report for every record at ERROR or above that carries a traceback
    and was logged by ACE's own code, so logging.exception() is all a caller has to know
    about. initialize_logging() installs it on the root logger."""

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self._reporting = threading.local()

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

        self._reporting.active = True
        try:
            write_error_report(record.exc_info, record=record)
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


def log_loop_exception(e: Exception, context: str):
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
    the report.
    """
    # imported here rather than at module level: saq.shutdown is deliberately dependency
    # free, but saq.error.reporting is imported by nearly everything, and a module-level
    # import creates a cycle through saq.environment
    from saq.shutdown import is_shutting_down

    if is_shutting_down():
        logging.info("%s during shutdown: %s", context, e)
        return

    logging.error("%s: %s", context, e, exc_info=e)


def log_peer_unavailable(e: Exception, context: str) -> bool:
    """Log a connection-level failure to a peer service, returning True if it was one.

    Use for the narrower case of a call to a specific peer (redis, qdrant, a remote ACE
    node) where a connection failure is not worth an error report even outside shutdown,
    because the peer being down is an operational condition rather than an ACE bug. This
    generalizes the pattern already used in saq/collectors/remote_node.py.

    Returns False without logging if the exception is not connection-level, so the
    caller can fall through to its normal handling.
    """
    from saq.shutdown import is_shutting_down

    if not isinstance(e, _EXPECTED_SHUTDOWN_ERRORS):
        return False

    if is_shutting_down():
        logging.info("%s unavailable during shutdown: %s", context, e)
    else:
        logging.warning("%s unavailable: %s", context, e)

    return True
