
import contextlib
import contextvars
from datetime import datetime
import logging
import logging.config
import os
import sys
import threading
from typing import Optional
import uuid
import yaml

from fluent.handler import FluentRecordFormatter


class ExtraAwareFluentFormatter(FluentRecordFormatter):
    """``FluentRecordFormatter`` that surfaces ``extra={}`` keys as
    top-level fields in the structured output, in addition to the
    renames produced by the configured ``fmt`` dict.

    Why: the upstream formatter's dict mode emits only the keys listed
    in its ``fmt`` mapping. Anything passed via ``extra={}`` lives on
    the ``LogRecord`` but never reaches the wire, so Splunk's JSON-mode
    auto-KV extraction can't break the values out as searchable fields
    and operators have to ``rex`` them back out of the ``message`` text.

    This subclass runs the parent's formatting first (preserving the
    ``severity`` / ``logSource`` renames defined in the YAML config),
    then walks ``record.__dict__`` and copies any attribute that
        - isn't a standard ``LogRecord`` attribute (skips the noisy
          built-ins like ``args``, ``msecs``, ``pathname``),
        - isn't already present in the formatted output (avoids
          clobbering the configured renames).

    Net effect: ``logging.info("event", extra={"k": v})`` produces a
    Splunk record with ``k`` as a top-level field while the human-
    readable ``message`` text continues to work for free-text search.
    """

    # Standard LogRecord attributes set by the logging framework. Walking
    # record.__dict__ would otherwise dump all of these into every event,
    # which is a lot of noise (and includes the legacy ``module`` name —
    # which can confuse Splunk by colliding with module-execution fields).
    # ``hostname`` is added by the parent formatter itself.
    _STANDARD_LOGRECORD_ATTRS = frozenset({
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "hostname", "levelname", "levelno", "lineno",
        "message", "module", "msecs", "msg", "name", "pathname",
        "process", "processName", "relativeCreated", "stack_info",
        "taskName", "thread", "threadName",
    })

    def format(self, record):
        data = super().format(record)
        for key, value in record.__dict__.items():
            if key in self._STANDARD_LOGRECORD_ATTRS:
                continue
            if key in data:
                continue
            data[key] = value
        return data


class CustomFileHandler(logging.StreamHandler):
    def __init__(self, log_dir: Optional[str]=".", filename_format: Optional[str]="%Y-%m-%d-%H.log"):
        assert isinstance(log_dir, str) and log_dir
        assert isinstance(filename_format, str) and filename_format
        super().__init__()

        # let this go because later the logic is to close the existing stream
        self.stream = None

        # the directory to store the log files in
        self.log_dir = log_dir

        # the format to use to generate the filename
        self.filename_format = filename_format

        # the current file name we're using
        self.current_filename = None
        self._update_stream()

    def _update_stream(self):
        assert self.filename_format
        assert self.log_dir

        # what should the file name be right now?
        current_filename = datetime.now().strftime(self.filename_format)

        # did the name change?
        if self.current_filename != current_filename:
            # close the current stream
            if self.stream:
                try:
                    self.stream.close()
                except OSError as e:
                    sys.stderr.write(f"error closing stream for {self.current_filename}: {e}\n")
            
            # and open a new one
            self.stream = open(os.path.join(self.log_dir, current_filename), 'a')
            self.current_filename = current_filename

    def emit(self, record: logging.LogRecord):
        self.acquire()
        try:
            self._update_stream()
            super().emit(record)
        finally:
            self.release()

# thread-local flag indicating the current thread is running inside a context
# where logs must not reach the production root-logger handlers (fluent / console
# / file).
_suppression_state = threading.local()


def _external_logging_suppressed() -> bool:
    """return True if the calling thread is inside a suppress_external_logging context"""
    return getattr(_suppression_state, "suppressed", False)


@contextlib.contextmanager
def suppress_external_logging():
    """While active on the calling thread, log records are dropped by the production
    handlers attached to the root logger. Handlers added to the root logger after
    initialize_logging() ran (e.g. the per-request ListLogHandler used by /hunt/validate)
    are not affected, so a caller-facing capture handler still receives every record.

    re-entrant safe: nesting restores the prior value rather than always clearing it"""
    previous = getattr(_suppression_state, "suppressed", False)
    _suppression_state.suppressed = True
    try:
        yield
    finally:
        _suppression_state.suppressed = previous


class ThreadSuppressionFilter(logging.Filter):
    """logging filter that drops records when the calling thread is inside a
    suppress_external_logging context. installed on the production root handlers
    by initialize_logging()"""

    def filter(self, record: logging.LogRecord) -> bool:
        return not _external_logging_suppressed()


def _install_suppression_filter():
    """install a ThreadSuppressionFilter on every handler currently attached to the
    root logger. idempotent: a handler that already has the filter is skipped"""
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if not any(isinstance(f, ThreadSuppressionFilter) for f in handler.filters):
            handler.addFilter(ThreadSuppressionFilter())


_DEFAULT_TRANSACTION_ID = "00000000-0000-0000-0000-000000000000"
_transaction_id = contextvars.ContextVar("transactionId", default=_DEFAULT_TRANSACTION_ID)


def initialize_transaction_id() -> str:
    """generate a fresh uuid4 and set it as the current transaction id for this
    process/thread/context. called at process startup so logs from distinct
    processes are distinguishable. returns the new id"""
    new_id = str(uuid.uuid4())
    _transaction_id.set(new_id)
    return new_id


def get_transaction_id() -> str:
    """return the transaction id in effect for the calling context, or the
    process/thread default if none has been set"""
    return _transaction_id.get()


def set_transaction_id(new_id: str) -> contextvars.Token:
    """set the transaction id for the calling context. returns the Token used to
    restore the prior value (see transaction_id())"""
    assert isinstance(new_id, str) and new_id
    return _transaction_id.set(new_id)


@contextlib.contextmanager
def transaction_id(new_id: Optional[str]=None):
    """set the transaction id for the duration of the with-block then restore the
    prior value. generates a fresh uuid4 if none is passed. re-entrant safe:
    nesting restores the value in effect before the block (via the ContextVar
    Token). yields the id in effect inside the block"""
    if new_id is None:
        new_id = str(uuid.uuid4())

    token = _transaction_id.set(new_id)
    try:
        yield new_id
    finally:
        _transaction_id.reset(token)


class TransactionIdFilter(logging.Filter):
    """logging filter that stamps the current transaction id onto every record as
    record.transactionId so the fluent formatter's %(transactionId)s always
    resolves. installed on the production root handlers by initialize_logging().
    always returns True -- it annotates, it does not drop"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.transactionId = get_transaction_id()
        return True


def _install_transaction_id_filter():
    """install a TransactionIdFilter on every handler attached to the root logger.
    idempotent: a handler that already has the filter is skipped"""
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if not any(isinstance(f, TransactionIdFilter) for f in handler.filters):
            handler.addFilter(TransactionIdFilter())


# base configuration for logging
LOGGING_BASE_CONFIG = {
    'version': 1,
    'formatters': {
        'base': {
            'format': 
                '[%(asctime)s] [%(pathname)s:%(funcName)s:%(lineno)d] [%(threadName)s] [%(process)d] [%(levelname)s] - %(message)s',
        },
    },
}

def initialize_logging(logging_config_path: str, log_sql: Optional[bool]=False, fluent_bit_tag: Optional[str]=None):
    assert isinstance(logging_config_path, str) and logging_config_path

    try:
        with open(logging_config_path, "r", encoding="utf-8") as config_file:
            logging_config = yaml.safe_load(config_file)

        if not isinstance(logging_config, dict):
            raise ValueError("logging configuration YAML must parse to a dict")

        if "disable_existing_loggers" not in logging_config:
            logging_config["disable_existing_loggers"] = False

        # allow dynamic fluent-bit tagging
        if fluent_bit_tag:
            if "handlers" in logging_config:
                if "fluent" in logging_config["handlers"]:
                    logging_config["handlers"]["fluent"]["tag"] = fluent_bit_tag

        logging.config.dictConfig(logging_config)

    except Exception as e:
        sys.stderr.write("unable to load logging configuration from {}: {}".format(logging_config_path, e))
        raise e

    # adjust the logging on third party libraries as needed
    logging.getLogger('plyara').setLevel(logging.ERROR)
    logging.getLogger('plyara.core').setLevel(logging.ERROR)
    logging.getLogger('plyara.util').setLevel(logging.ERROR)
    logging.getLogger('olevba').setLevel(logging.CRITICAL)
    logging.getLogger('whois').setLevel(logging.CRITICAL)

    # log all SQL commands if we are running in debug mode
    if log_sql:
        logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.dialects').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.pool').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.orm').setLevel(logging.DEBUG)

    # disable the verbose logging in the requests module
    logging.getLogger("requests").setLevel(logging.WARNING)

    # support supression filtering for production logging
    _install_suppression_filter()

    # stamp a per-task transaction id onto every record for log correlation
    _install_transaction_id_filter()
    initialize_transaction_id()
