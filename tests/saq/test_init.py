import io
import logging
import pytest

from saq.configuration import get_config
from saq.configuration.schema import ACEConfig
from saq.environment import get_global_runtime_settings, set_node
from saq.logging import CustomFileHandler

@pytest.mark.unit
def test_custom_file_handler(tmpdir, monkeypatch):
    handler = CustomFileHandler(str(tmpdir))
    assert isinstance(handler.filename_format, str) # should default
    assert isinstance(handler.current_filename, str) # should reference a file name after init
    assert isinstance(handler.stream, io.TextIOBase) # should be open file handle
    record = logging.LogRecord("name", logging.DEBUG, "path", 1, "msg", None, None)
    handler.emit(record)

    # fake rotation
    handler.current_filename = None
    handler.emit(record)

    # force error
    def _fail():
        raise OSError()

    handler.current_filename = None
    monkeypatch.setattr(handler.stream, "close", lambda: _fail())
    handler.emit(record)

@pytest.mark.integration
def test_set_node():
    assert get_global_runtime_settings().saq_node == "localhost"
    old_node_id = get_global_runtime_settings().saq_node_id
    assert isinstance(old_node_id, int)


    set_node("some_name")
    assert get_global_runtime_settings().saq_node == "some_name"
    assert get_global_runtime_settings().saq_node_id != old_node_id

    # XXX remove this after you fix the reset issue
    get_global_runtime_settings().saq_node_id = old_node_id
    get_global_runtime_settings().saq_node = "localhost"

@pytest.mark.unit
def test_thread_suppression_filter():
    from saq.logging import ThreadSuppressionFilter, suppress_external_logging

    filter_ = ThreadSuppressionFilter()
    record = logging.LogRecord("name", logging.INFO, "path", 1, "msg", None, None)

    # outside the context the record passes
    assert filter_.filter(record) is True

    # inside the context the record is dropped
    with suppress_external_logging():
        assert filter_.filter(record) is False

    # and passes again after the context exits
    assert filter_.filter(record) is True


@pytest.mark.unit
def test_suppress_external_logging_nested():
    from saq.logging import _external_logging_suppressed, suppress_external_logging

    assert _external_logging_suppressed() is False
    with suppress_external_logging():
        assert _external_logging_suppressed() is True
        with suppress_external_logging():
            assert _external_logging_suppressed() is True
        # inner exit must not clear suppression for the still-active outer context
        assert _external_logging_suppressed() is True
    assert _external_logging_suppressed() is False


@pytest.mark.integration
def test_suppress_external_logging_is_thread_scoped():
    import threading

    from saq.logging import _external_logging_suppressed, suppress_external_logging

    worker_suppressed = []
    proceed = threading.Event()

    def worker():
        proceed.wait(timeout=5)
        worker_suppressed.append(_external_logging_suppressed())

    t = threading.Thread(target=worker)
    t.start()
    with suppress_external_logging():
        # while this thread is suppressed, a separate thread must not be
        proceed.set()
        t.join(timeout=5)

    assert worker_suppressed == [False]


@pytest.mark.unit
def test_install_suppression_filter_idempotent():
    from saq.logging import ThreadSuppressionFilter, _install_suppression_filter

    root_logger = logging.getLogger()
    handler = logging.NullHandler()
    root_logger.addHandler(handler)
    try:
        _install_suppression_filter()
        _install_suppression_filter()
        suppression_filters = [
            f for f in handler.filters if isinstance(f, ThreadSuppressionFilter)
        ]
        assert len(suppression_filters) == 1
    finally:
        root_logger.removeHandler(handler)


@pytest.mark.unit
def test_get_config():
    assert isinstance(get_config(), ACEConfig)
