import logging
import time

from saq.configuration.config import get_config

from sqlalchemy import event
from sqlalchemy.engine import Engine

def _log_sql_exec_times() -> bool:
    """Whether query timing is enabled.

    These listeners are registered on the Engine class, so they fire for *every* engine in
    the process, including ones created before the configuration is loaded (the test suite
    seeds its per-session databases that way). No configuration means no timing."""
    config = get_config()
    return config is not None and config.global_settings.log_sql_exec_times


@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if _log_sql_exec_times():
        context._query_start_time = time.time()
        logging.debug("START QUERY {} ({})".format(statement, parameters))
    # Modification for StackOverflow answer:
    # Show parameters, which might be too verbose, depending on usage..
    #logging.debug("Parameters:\n%r" % (parameters,))

@event.listens_for(Engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if _log_sql_exec_times():
        total = time.time() - context._query_start_time
        logging.debug("END QUERY {:02f} {} ({})".format(total * 1000, statement, parameters))

    # Modification for StackOverflow: times in milliseconds
    #logger.debug("Total Time: %.02fms" % (total*1000))