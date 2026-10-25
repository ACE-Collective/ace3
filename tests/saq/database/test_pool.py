import logging
import threading
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from saq.environment import ACE_MP_CONTEXT

from saq.configuration.config import get_database_config
from saq.constants import DB_ACE, DB_BROCESS, DB_EMAIL_ARCHIVE
from saq.database import pool
from saq.database.admin import superuser_connection
from saq.database.pool import (
    _build_database_url,
    _build_engine_options,
    _get_engine,
    execute_with_db_cursor,
    get_db,
    get_db_connection,
    initialize_database,
    remove_all_sessions,
)
from saq.monitor_definitions import MONITOR_DB_POOL_AVAILABLE_COUNT, MONITOR_DB_POOL_IN_USE_COUNT
from tests.saq.helpers import recv_test_message, send_test_message, wait_for_condition


def _connection_id(db) -> int:
    cursor = db.cursor()
    cursor.execute("SELECT CONNECTION_ID()")
    return cursor.fetchone()[0]


@pytest.fixture
def empty_ace_pool():
    """The ace engine with nothing pooled, so a test can count what it checks out."""
    remove_all_sessions()
    engine = _get_engine(DB_ACE)
    engine.dispose()
    return engine


@pytest.fixture
def isolated_registry(monkeypatch):
    """Copies of the session and engine registries, so a test can replace what they hold."""
    monkeypatch.setattr(pool, "_db_sessions", dict(pool._db_sessions))
    monkeypatch.setattr(pool, "_db_engine_by_name", dict(pool._db_engine_by_name))
    monkeypatch.setattr(pool, "_db_engines", set(pool._db_engines))


@pytest.mark.unit
def test_execute_with_db_cursor():
    def _target(db, cursor, param1):
        assert param1 == "test"
        cursor.execute("SELECT 1")
        assert cursor.fetchone() == (1,)
        db.commit()

    execute_with_db_cursor(DB_ACE, _target, "test")

@pytest.mark.unit
def test_connection():
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT 1")

@pytest.mark.unit
def test_engine_options_come_from_the_database_config(monkeypatch):
    config = get_database_config(DB_ACE)
    monkeypatch.setattr(config, "pool_size", 2)
    monkeypatch.setattr(config, "max_overflow", 3)
    monkeypatch.setattr(config, "max_connection_lifetime", "00:15:00")

    options = _build_engine_options(config)
    assert options["pool_size"] == 2
    assert options["max_overflow"] == 3
    assert options["pool_recycle"] == 900
    assert options["isolation_level"] == "READ COMMITTED"
    # what replaces a pooled connection the server dropped (test_a_dead_pooled_connection_is_replaced_on_checkout)
    assert options["pool_pre_ping"] is True

@pytest.mark.integration
def test_raw_connections_come_from_the_orm_pool(empty_ace_pool):
    assert get_db().get_bind() is empty_ace_pool

    with get_db_connection() as db:
        raw = db.dbapi_connection
        assert empty_ace_pool.pool.checkedout() == 1

    assert empty_ace_pool.pool.checkedin() == 1

    # the only pooled connection is the one cursor code just returned
    get_db().execute(text("SELECT 1"))
    assert get_db().connection().connection.dbapi_connection is raw
    remove_all_sessions()

@pytest.mark.integration
def test_a_dead_pooled_connection_is_replaced_on_checkout(empty_ace_pool):
    with get_db_connection() as db:
        dead_id = _connection_id(db)

    assert empty_ace_pool.pool.checkedin() == 1

    # the server drops the idle pooled connection, as a MySQL restart or wait_timeout does
    config = get_database_config(DB_ACE)
    killer = create_engine(_build_database_url(config), **_build_engine_options(config))
    try:
        with killer.connect() as connection:
            connection.exec_driver_sql(f"KILL {int(dead_id)}")

            def _gone():
                return connection.exec_driver_sql(
                    f"SELECT COUNT(*) FROM information_schema.processlist WHERE ID = {int(dead_id)}").scalar() == 0

            wait_for_condition(_gone, timeout=10)
    finally:
        killer.dispose()

    with get_db_connection() as db:
        assert _connection_id(db) != dead_id
        cursor = db.cursor()
        cursor.execute("SELECT 1")
        assert cursor.fetchone() == (1,)

    assert empty_ace_pool.pool.checkedin() == 1


@pytest.mark.integration
def test_a_password_with_url_characters_connects(monkeypatch):
    # brocess and the email archive used to hand their password to pymysql directly. In a formatted
    # URL "@" would end it and "%41" would decode to "A"
    config = get_database_config(DB_BROCESS)
    user, password = f"ace-url-{uuid.uuid4().hex[:8]}", "p@ss%41/:#?x"
    with superuser_connection() as admin:
        cursor = admin.cursor()
        cursor.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (user, password))
        try:
            cursor.execute(f"GRANT SELECT ON `{config.database}`.* TO %s@'%%'", (user,))
            monkeypatch.setattr(config, "username", user)
            monkeypatch.setattr(config, "password", password)

            engine = create_engine(_build_database_url(config), **_build_engine_options(config))
            try:
                with engine.connect() as connection:
                    assert connection.exec_driver_sql("SELECT CURRENT_USER()").scalar() == f"{user}@%"
            finally:
                engine.dispose()
        finally:
            cursor.execute("DROP USER %s@'%%'", (user,))


@pytest.mark.integration
@pytest.mark.parametrize("name", [DB_ACE, DB_BROCESS, DB_EMAIL_ARCHIVE])
def test_raw_connections_share_the_engine_of_every_database(name):
    assert _get_engine(name) is get_db(name).get_bind()

    with get_db_connection(name) as db:
        cursor = db.cursor()
        cursor.execute("SELECT DATABASE(), @@transaction_isolation")
        assert cursor.fetchone() == (get_database_config(name).database, "READ-COMMITTED")

@pytest.mark.integration
def test_raw_connections_are_bounded_by_the_pool(monkeypatch):
    config = get_database_config(DB_ACE)
    options = {**_build_engine_options(config), "pool_size": 1, "max_overflow": 0, "pool_timeout": 0.1}
    engine = create_engine(_build_database_url(config), **options)
    monkeypatch.setitem(pool._db_engine_by_name, DB_ACE, engine)

    try:
        with get_db_connection() as first:
            raw = first.dbapi_connection
            with pytest.raises(PoolTimeoutError):
                with get_db_connection():
                    pass

        # once it is returned it is the one handed out next
        with get_db_connection() as second:
            assert second.dbapi_connection is raw
    finally:
        engine.dispose()

@pytest.mark.integration
def test_returning_a_connection_rolls_back_what_was_left_uncommitted(empty_ace_pool):
    with get_db_connection() as db:
        raw = db.dbapi_connection
        db.cursor().execute("INSERT INTO `config` ( `key`, `value` ) VALUES ( 'test_uncommitted', '1' )")

    with get_db_connection() as db:
        # the same session, which would still see its own insert had it not been rolled back
        assert db.dbapi_connection is raw
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM `config` WHERE `key` = 'test_uncommitted'")
        assert cursor.fetchone() == (0,)

def _explode(*args, **kwargs):
    raise OSError("nope")

@pytest.mark.integration
def test_a_connection_that_cannot_roll_back_is_not_reused(empty_ace_pool, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger="sqlalchemy.pool")
    with get_db_connection() as db:
        broken = db.dbapi_connection
        monkeypatch.setattr(broken, "rollback", _explode)
        # what happens to every pooled connection when the database stops before this process does
        monkeypatch.setattr("saq.shutdown.is_shutting_down", lambda: True)

    monkeypatch.undo()

    # SQLAlchemy's "Exception during reset or similar", at DEBUG because it was expected
    records = [r for r in caplog.records if r.name.startswith("sqlalchemy.pool")]
    assert any(r.levelno == logging.DEBUG and "(shutting down): nope" in r.getMessage() for r in records)
    assert not any(r.levelno > logging.DEBUG for r in records)

    with get_db_connection() as db:
        assert db.dbapi_connection is not broken
        db.cursor().execute("SELECT 1")

@pytest.mark.integration
def test_get_db_connection_creates_the_ace_engine_on_first_use(isolated_registry):
    pool._db_sessions.pop(DB_ACE, None)
    pool._db_engine_by_name.pop(DB_ACE, None)

    try:
        with get_db_connection() as db:
            db.cursor().execute("SELECT 1")

        # and it is the engine behind get_db()'s session
        assert get_db().get_bind() is pool._db_engine_by_name[DB_ACE]
    finally:
        pool._db_engine_by_name[DB_ACE].dispose()

@pytest.mark.integration
def test_threads_get_their_own_connections():
    results = []

    with get_db_connection() as first:
        def f():
            with get_db_connection() as second:
                results.append(_connection_id(second))

        t = threading.Thread(target=f)
        t.start()
        t.join(timeout=30)
        assert not t.is_alive()

        assert results and results[0] != _connection_id(first)

@pytest.mark.system
def test_a_forked_process_gets_its_own_connections(test_comms):
    with get_db_connection() as db:
        parent_id = _connection_id(db)

        def f():
            with get_db_connection() as child:
                send_test_message(_connection_id(child))

        process = ACE_MP_CONTEXT.Process(target=f)
        process.start()
        child_id = recv_test_message()
        process.join(timeout=30)

        assert child_id != parent_id
        # and the parent's connection survived the child
        assert _connection_id(db) == parent_id

@pytest.mark.integration
def test_checkout_and_checkin_report_the_pool(empty_ace_pool, monkeypatch):
    emitted = []
    monkeypatch.setattr(pool, "emit_monitor", lambda monitor, value, *args: emitted.append((monitor, value)))

    with get_db_connection():
        assert (MONITOR_DB_POOL_IN_USE_COUNT, 1) in emitted
        assert (MONITOR_DB_POOL_AVAILABLE_COUNT, 0) in emitted
        emitted.clear()

    # what an idle process last reported: nothing in use, one available
    assert emitted[-2:] == [(MONITOR_DB_POOL_AVAILABLE_COUNT, 1), (MONITOR_DB_POOL_IN_USE_COUNT, 0)]


@pytest.fixture
def no_sessions(monkeypatch):
    """Starts the test with no session or engine registered, and disposes the engines it creates."""
    monkeypatch.setattr(pool, "_db_sessions", {})
    monkeypatch.setattr(pool, "_db_engine_by_name", {})
    monkeypatch.setattr(pool, "_db_engines", set())
    yield
    for session in pool._db_sessions.values():
        session.remove()
    for engine in pool._db_engines:
        engine.dispose()


@pytest.mark.integration
def test_get_db_creates_the_ace_session_on_first_request(no_sessions):
    # like every other database's, so nothing has to register it first
    session = get_db()
    assert session is get_db(DB_ACE)

    engine = session.get_bind()
    assert engine in pool._db_engines
    assert engine.url.database == get_database_config(DB_ACE).database
    assert session.execute(text("SELECT @@transaction_isolation")).scalar() == "READ-COMMITTED"


@pytest.mark.integration
def test_initialize_database_creates_the_ace_session_once(no_sessions):
    initialize_database()
    session = pool._db_sessions[DB_ACE]

    initialize_database()
    assert pool._db_sessions[DB_ACE] is session
    assert len(pool._db_engines) == 1
