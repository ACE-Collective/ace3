import configparser
import io
import logging
import pytest

from saq.configuration import get_config
from saq.configuration.schema import ACEConfig
from saq.environment import get_global_runtime_settings, set_node
from saq.logging import CustomFileHandler, initialize_logging

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

@pytest.mark.skip("cannot reset logging now")
@pytest.mark.unit
def test_initialize_logging(datadir, monkeypatch):
    # valid configuration
    initialize_logging(str(datadir / "debug_logging.yaml"))

    # invalid configuration
    with pytest.raises(Exception):
        initialize_logging(str(datadir / "invalid_file.yaml"))

    # logging sql commands
    config = configparser.ConfigParser()
    config.read_string("""[global]
                       log_sql = yes""")
    

    import saq.configuration
    monkeypatch.setattr(saq.configuration, "get_config", lambda: config)
    initialize_logging(str(datadir / "debug_logging.yaml"))

    # TODO not sure what to check for here

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
def test_get_config():
    assert isinstance(get_config(), ACEConfig)
