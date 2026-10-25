import logging
import os

import pytest

from saq.configuration.config import get_database_config
from saq.constants import DB_ACE
from saq.database import pool
from saq.database.pool import (
    _build_database_url,
    _build_engine_options,
    _database_pool,
    _log_pool_issue,
    _track_connection,
    get_db,
    get_db_connection,
    get_pool,
    remove_all_sessions,
)
from saq.environment import get_base_dir


def _explode(*args, **kwargs):
    raise OSError("nope")


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
    assert _build_database_url(ace_config).endswith(
        f"@localhost/{ace_config.database}?unix_socket=/var/run/mysqld/mysqld.sock&charset=utf8mb4")


@pytest.mark.unit
def test_raw_pool_ssl_files(ace_config, tmp_path, caplog):
    ca = tmp_path / "ca.pem"
    ca.write_text("ca")
    ace_config.ssl_ca = str(ca)
    ace_config.ssl_cert = str(tmp_path / "missing-cert.pem")
    ace_config.ssl_key = str(tmp_path / "missing-key.pem")

    # a missing file is left out and logged
    assert _database_pool(DB_ACE).kwargs["ssl"] == {"ca": str(ca)}
    assert _logged(caplog, logging.ERROR, "ssl_cert file")
    assert _logged(caplog, logging.ERROR, "ssl_key file")

    ace_config.ssl_ca = str(tmp_path / "missing-ca.pem")
    assert _database_pool(DB_ACE).kwargs["ssl"] == {}
    assert _logged(caplog, logging.ERROR, "ssl_ca file")

    ace_config.unix_socket = "/var/run/mysqld/mysqld.sock"
    assert _database_pool(DB_ACE).kwargs["unix_socket"] == "/var/run/mysqld/mysqld.sock"


@pytest.mark.unit
def test_get_connection_replaces_a_connection_that_cannot_roll_back(monkeypatch, caplog):
    get_pool().clear()
    with get_db_connection() as first:
        pass

    monkeypatch.setattr(first, "rollback", _explode)
    with get_db_connection() as second:
        assert second is not first
        assert get_pool().in_use_count == 1

    assert _logged(caplog, logging.WARNING, "unable to rollback connection on get_connection")
    get_pool().clear()


@pytest.mark.unit
def test_return_connection_destroys_a_connection_that_cannot_roll_back(monkeypatch, caplog):
    get_pool().clear()
    with get_db_connection() as connection:
        monkeypatch.setattr(connection, "rollback", _explode)

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 0
    assert _logged(caplog, logging.WARNING, "on return to pool")

    # destroying one the pool doesn't know about is logged, not raised
    get_pool().destroy_connection(connection)
    assert _logged(caplog, logging.WARNING, "attempted to remove missing database connection")


@pytest.mark.unit
def test_close_and_clear_survive_failures(monkeypatch, caplog):
    database_pool = get_pool()
    database_pool.clear()
    with get_db_connection() as in_use:
        with get_db_connection() as available:
            pass

        for connection in (in_use, available):
            monkeypatch.setattr(connection, "close", _explode)
            monkeypatch.setattr(connection, "_force_close", _explode)

        database_pool.clear()
        assert _logged(caplog, logging.WARNING, "unable to close database connection")

        database_pool.in_use.append(in_use)
        database_pool.available.append(available)
        database_pool.close()
        assert database_pool.in_use_count == 0
        assert database_pool.available_count == 0

        database_pool.close_connection(in_use)
        assert _logged(caplog, logging.WARNING, "unable to close database connection: nope")

        # the context manager returns it to a pool that no longer knows it
        database_pool.in_use.append(in_use)

    monkeypatch.undo()
    database_pool.clear()
    available.close()


@pytest.mark.unit
def test_pool_created_by_another_process_is_replaced():
    original = get_pool()
    original.pid = -1

    replacement = get_pool()
    assert replacement is not original
    assert replacement.pid == os.getpid()
    assert get_pool(None) is replacement


@pytest.mark.unit
def test_log_pool_issue_during_shutdown(monkeypatch, caplog):
    monkeypatch.setattr("saq.shutdown.is_shutting_down", lambda: True)
    caplog.set_level(logging.DEBUG)

    _log_pool_issue("unable to close", OSError("the database went away"))

    assert _logged(caplog, logging.DEBUG, "unable to close (shutting down): the database went away")
    assert not _logged(caplog, logging.WARNING, "unable to close")


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
