from datetime import datetime
import logging
import os
import shutil
import sys
from typing import TYPE_CHECKING, Optional

from saq.configuration.config import get_config, get_engine_config
if TYPE_CHECKING:
    from saq.engine.execution_context import EngineExecutionContext
from saq.environment import get_data_dir
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_ERROR_REPORT


def report_exception(execution_context: Optional["EngineExecutionContext"]=None):

    exc_type, reported_exception, tb = sys.exc_info()

    try:
        output_dir = os.path.join(get_data_dir(), get_config().global_settings.error_reporting_dir)
        error_report_path = os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f'))
        with open(error_report_path, 'w') as fp:
            if execution_context:
                fp.write("CURRENT ANALYSIS TARGET: {}\n".format(execution_context.root))
                if execution_context.root:
                    fp.write("CURRENT ANALYSIS MODE: {}\n".format(execution_context.root.analysis_mode))

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
            "exception": str(reported_exception),
            "stack_trace": stack_trace,
            "exception_source": final_source,
        })

        if get_engine_config().copy_analysis_on_error:
            if execution_context:
                if os.path.isdir(execution_context.root.storage_dir):
                    analysis_dir = '{}.ace'.format(error_report_path)
                    try:
                        shutil.copytree(execution_context.root.storage_dir, analysis_dir)
                        logging.warning("copied analysis from {} to {} for review".format(execution_context.root.storage_dir, analysis_dir))
                    except Exception as e:
                        logging.error("unable to copy from {} to {}: {}".format(execution_context.root.storage_dir, analysis_dir, e))

        return error_report_path

    except Exception as e:
        logging.error("uncaught exception when reporting an exception: {}".format(e))
        return None

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


def log_loop_exception(e: Exception, context: str, execution_context: Optional["EngineExecutionContext"]=None):
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

    While shutting down this logs at INFO and does not call report_exception(). Outside
    shutdown behavior is unchanged.
    """
    # imported here rather than at module level: saq.shutdown is deliberately dependency
    # free, but saq.error.reporting is imported by nearly everything, and a module-level
    # import creates a cycle through saq.environment
    from saq.shutdown import is_shutting_down

    if is_shutting_down():
        logging.info("%s during shutdown: %s", context, e)
        return

    logging.error("%s: %s", context, e)
    report_exception(execution_context)


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
