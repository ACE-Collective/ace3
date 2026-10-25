import logging
import os
import sys

import pytest

from saq.configuration.config import get_database_config
from saq.constants import DB_ACE
from saq.database import pool
from saq.database.pool import (
    _build_database_url,
    _build_engine_options,
    _QuietDuringShutdown,
    _track_connection,
    get_db,
    remove_all_sessions,
)
from saq.environment import get_base_dir


def _logged(caplog, level, text):
    return any(r.levelno == level and text in r.getMessage() for r in caplog.records)


@pytest.fixture
def ace_config(monkeypatch):
    """The ace database config, restored after the test."""
    config = get_database_config(DB_ACE)
    for field in ("ssl_ca", "ssl_cert", "ssl_key", "unix_socket"):
        monkeypatch.setattr(config, field, getattr(config, field))
    return config


@pytest.mark.unit
def test_engine_options_client_certificate_without_ca(ace_config):
    # a client certificate without a CA used to raise TypeError from abs_path(None)
    ace_config.ssl_ca = None
    ace_config.ssl_cert = "etc/ssl/client.pem"
    ace_config.ssl_key = "/etc/ssl/client.key"

    assert _build_engine_options(ace_config)["connect_args"]["ssl"] == {
        "cert": os.path.join(get_base_dir(), "etc/ssl/client.pem"), "key": "/etc/ssl/client.key"}


@pytest.mark.unit
def test_engine_options_ssl(ace_config):
    ace_config.ssl_ca = "/etc/ssl/ca.pem"
    ace_config.ssl_cert = None
    ace_config.ssl_key = None

    assert _build_engine_options(ace_config)["connect_args"]["ssl"] == {"ca": "/etc/ssl/ca.pem"}

    # a unix socket is never TLS
    ace_config.unix_socket = "/var/run/mysqld/mysqld.sock"
    assert "ssl" not in _build_engine_options(ace_config)["connect_args"]
    url = _build_database_url(ace_config)
    assert (url.host, url.port, url.database) == ("localhost", None, ace_config.database)
    assert url.query == {"unix_socket": "/var/run/mysqld/mysqld.sock", "charset": "utf8mb4"}


def _reset_record() -> logging.LogRecord:
    try:
        raise OSError("the database went away")
    except OSError:
        return logging.getLogger("sqlalchemy.pool.impl.QueuePool").makeRecord(
            "sqlalchemy.pool.impl.QueuePool", logging.ERROR, __file__, 0, "Exception during %s", ("reset or similar",),
            sys.exc_info())


@pytest.mark.unit
def test_pool_errors_drop_to_debug_during_shutdown(monkeypatch):
    monkeypatch.setattr("saq.shutdown.is_shutting_down", lambda: True)
    record = _reset_record()

    assert _QuietDuringShutdown().filter(record)
    assert record.levelno == logging.DEBUG
    assert record.levelname == "DEBUG"
    assert record.getMessage() == "Exception during reset or similar (shutting down): the database went away"
    assert record.exc_info is None


@pytest.mark.unit
def test_pool_errors_are_left_alone_otherwise(monkeypatch):
    monkeypatch.setattr("saq.shutdown.is_shutting_down", lambda: False)
    record = _reset_record()

    assert _QuietDuringShutdown().filter(record)
    assert record.levelno == logging.ERROR
    assert record.getMessage() == "Exception during reset or similar"
    assert record.exc_info is not None


@pytest.mark.unit
def test_remove_all_sessions_survives_a_failing_session(monkeypatch, caplog):
    class _Broken:
        def remove(self):
            raise OSError("nope")

    monkeypatch.setitem(pool._db_sessions, "broken", _Broken())
    monkeypatch.setitem(pool._db_sessions, "unset", None)

    remove_all_sessions()

    assert _logged(caplog, logging.WARNING, "error removing broken session: nope")
    assert get_db(None) is get_db()


@pytest.mark.unit
def test_track_connection_failure():
    # an object that cannot take the pid attribute is skipped
    _track_connection(object())
