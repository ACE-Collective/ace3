import logging
import threading
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

import aceapi_v2.database
from saq.environment import ACE_MP_CONTEXT

from saq.configuration.config import get_config, get_database_config
from saq.constants import DB_ACE
from saq.database import pool
from saq.database.pool import execute_with_db_cursor, get_db, get_db_connection, get_pool, initialize_database, reset_pools
from tests.saq.helpers import log_count, recv_test_message, send_test_message

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
def test_pooling():
    get_pool().clear()
    with get_db_connection() as db_1:
        # we should have one database connection ready
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0
        with get_db_connection() as db_2:
            assert get_pool().in_use_count == 2
            assert get_pool().available_count ==0
            assert db_1 is not db_2

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 1

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 2

@pytest.mark.integration
def test_pooling_old_connection():
    get_pool().clear()

    # make them invalid immediately
    get_database_config(DB_ACE).max_connection_lifetime = "00:00:00"

    # this is needed to reset the timeouts on the existing connections
    reset_pools()

    with get_db_connection() as _:
        pass

    assert log_count('got new database connection to') ==  1

    with get_db_connection() as _:
        pass

    assert log_count('got new database connection to') == 2

    # change it back and then we should start re-using the connections again
    get_database_config(DB_ACE).max_connection_lifetime = "00:01:00"
    reset_pools()

    with get_db_connection() as _:
        pass

    assert log_count('got new database connection to') == 3

    with get_db_connection() as _:
        pass

    assert log_count('got new database connection to') == 3

@pytest.mark.integration
def test_pooling_without_contextmanager():
    get_pool().clear()
    db = get_pool().get_connection()

    assert get_pool().in_use_count == 1
    assert get_pool().available_count == 0

    c = db.cursor()
    c.execute("SELECT 1")
    db.commit()
    get_pool().return_connection(db)

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

@pytest.mark.integration
def test_pooling_bad_sql():
    get_pool().clear()
    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        with pytest.raises(Exception):
            c = db_1.cursor()
            c.execute("INVALID SQL")

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        c = db_1.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        db_1.commit()

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

@pytest.mark.integration
def test_pooling_broken_connection():
    get_pool().clear()
    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0
        db_1.close()

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 0

    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        c = db_1.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        db_1.commit()

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

    # close the connection while not being used
    for connection in get_pool().available:
        connection.close()

    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        c = db_1.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        db_1.commit()

@pytest.mark.integration
def test_pooling_threaded():
    get_pool().clear()

    with get_db_connection() as conn_1:
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        def f():
            with get_db_connection() as conn_2:
                assert conn_1 is not conn_2
                assert get_pool().in_use_count == 2
                assert get_pool().available_count == 0

            # but asked a second time this should be the same as before
            with get_db_connection() as conn_3:
                assert conn_3 is conn_2
                assert get_pool().in_use_count == 2
                assert get_pool().available_count == 0
            
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0
        t = threading.Thread(target=f)
        t.start()
        t.join()
                
    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 2

    # make sure we can get, and use, the connection created in the other thread

    conn_1 = get_pool().get_connection()
    conn_2 = get_pool().get_connection()

    assert get_pool().in_use_count == 2
    assert get_pool().available_count == 0

    c = conn_2.cursor()
    c.execute("SELECT 1")
    c.fetchone()

    get_pool().return_connection(conn_1)
    get_pool().return_connection(conn_2)

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 2

@pytest.mark.system
def test_pooling_multi_process(test_comms):
    get_pool().clear()
    with get_db_connection() as conn_1:
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        def f():
            # once we've entered into the new process, the pool changes
            send_test_message(get_pool().in_use_count == 0)
            send_test_message(get_pool().available_count == 0)

            # so this connection should be different than conn_1
            with get_db_connection() as conn_2:
                send_test_message(conn_1 is not conn_2)
                send_test_message(get_pool().in_use_count == 1)
                send_test_message(get_pool().available_count == 0)

            send_test_message(get_pool().in_use_count == 0)
            send_test_message(get_pool().available_count == 1)

        process = ACE_MP_CONTEXT.Process(target=f)
        process.start()

        assert recv_test_message()
        assert recv_test_message()
        assert recv_test_message()
        assert recv_test_message()

        process.join()

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

    with get_db_connection() as conn_4:
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0
        assert conn_1 is conn_4


def _open_on_server(thread_ids):
    """The MySQL thread ids, of those given, whose connections are still open on the server."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM information_schema.processlist")
        return set(thread_ids) & {row[0] for row in cursor.fetchall()}


@pytest.mark.integration
def test_returning_a_burst_keeps_only_pool_size_idle(monkeypatch):
    monkeypatch.setattr(pool, "POOL_SIZE", 2)
    database_pool = get_pool()
    database_pool.clear()

    burst = [database_pool.get_connection() for _ in range(5)]
    thread_ids = [connection.thread_id() for connection in burst]
    for connection in burst:
        database_pool.return_connection(connection)

    assert database_pool.in_use_count == 0
    assert database_pool.available_count == 2
    assert len(_open_on_server(thread_ids)) == 2


@pytest.mark.integration
def test_a_connection_returned_past_its_lifetime_is_closed():
    database_pool = get_pool()
    database_pool.clear()

    connection = database_pool.get_connection()
    connection.termination_date = datetime.now() - timedelta(seconds=1)
    thread_id = connection.thread_id()
    database_pool.return_connection(connection)

    assert database_pool.in_use_count == 0
    assert database_pool.available_count == 0
    assert not _open_on_server([thread_id])


@pytest.mark.integration
def test_expired_idle_connections_are_closed_by_the_next_return():
    # the pool reuses the connection returned last, so one request only ever checks the top of the
    # stack: the connections under it used to stay open past their lifetime for as long as the
    # traffic stayed below the burst that opened them
    database_pool = get_pool()
    database_pool.clear()

    idle = [database_pool.get_connection() for _ in range(3)]
    thread_ids = [connection.thread_id() for connection in idle]
    for connection in idle:
        database_pool.return_connection(connection)
        connection.termination_date = datetime.now() - timedelta(seconds=1)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()

    assert database_pool.available_count == 1
    assert not _open_on_server(thread_ids)


@pytest.mark.integration
def test_opening_past_the_soft_cap_warns_at_each_new_peak(monkeypatch, caplog):
    monkeypatch.setattr(pool, "POOL_SIZE", 1)
    monkeypatch.setattr(pool, "POOL_MAX_OVERFLOW", 1)
    database_pool = get_pool()
    database_pool.clear()

    def _warnings():
        return [r for r in caplog.records if r.levelno == logging.WARNING and hasattr(r, "open_connections")]

    # the cap is soft: the third connection is opened, and the warning says so
    held = [database_pool.get_connection() for _ in range(3)]
    assert database_pool.in_use_count == 3
    assert [(r.open_connections, r.database) for r in _warnings()] == [(3, DB_ACE)]

    # the same peak again is not a new warning, a higher one is
    for connection in held:
        database_pool.return_connection(connection)
    held = [database_pool.get_connection() for _ in range(4)]
    assert [r.open_connections for r in _warnings()] == [3, 4]

    for connection in held:
        database_pool.return_connection(connection)
    database_pool.clear()


@pytest.mark.integration
def test_a_discarded_connection_that_fails_to_close_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(pool, "POOL_SIZE", 1)
    database_pool = get_pool()
    database_pool.clear()

    first = database_pool.get_connection()
    second = database_pool.get_connection()
    database_pool.return_connection(first)

    def _explode():
        raise OSError("nope")

    # the oldest idle connection is the one trimmed
    monkeypatch.setattr(first, "close", _explode)
    database_pool.return_connection(second)

    assert database_pool.in_use_count == 0
    assert list(database_pool.available) == [second]
    assert any(r.levelno == logging.WARNING and "unable to close database connection: nope" in r.getMessage()
               for r in caplog.records)

    monkeypatch.undo()
    first.close()
    database_pool.clear()


@pytest.fixture
def no_sessions(monkeypatch):
    """Starts the test with no session or engine registered, and disposes the engines it creates."""
    monkeypatch.setattr(pool, "_db_sessions", {})
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
def test_initialize_database_leaves_the_ace_session_to_first_use(no_sessions):
    # building the engine imports SQLAlchemy, which a process that never queries through the ORM does not need
    initialize_database()
    assert DB_ACE not in pool._db_sessions
    assert not pool._db_engines

    session = get_db()
    initialize_database()
    assert pool._db_sessions[DB_ACE] is session
    assert len(pool._db_engines) == 1


@pytest.mark.unit
def test_sql_exec_times_logged_when_enabled(monkeypatch, caplog):
    monkeypatch.setattr(get_config().global_settings, "log_sql_exec_times", True)
    with caplog.at_level(logging.DEBUG):
        get_db().execute(text("SELECT 1"))

    messages = [record.getMessage() for record in caplog.records]
    assert any(message.startswith("START QUERY SELECT 1") for message in messages)
    assert any(message.startswith("END QUERY") and "SELECT 1" in message for message in messages)


@pytest.mark.unit
def test_sql_exec_times_not_logged_when_disabled(monkeypatch, caplog):
    monkeypatch.setattr(get_config().global_settings, "log_sql_exec_times", False)
    with caplog.at_level(logging.DEBUG):
        get_db().execute(text("SELECT 1"))

    assert not [record for record in caplog.records if "QUERY" in record.getMessage()]


@pytest.mark.unit
def test_registering_the_timing_listeners_again_logs_each_query_once(monkeypatch, caplog):
    pool.register_sql_timing_listeners()
    pool.register_sql_timing_listeners()
    monkeypatch.setattr(get_config().global_settings, "log_sql_exec_times", True)
    with caplog.at_level(logging.DEBUG):
        get_db().execute(text("SELECT 1"))

    assert len([record for record in caplog.records if record.getMessage().startswith("START QUERY SELECT 1")]) == 1


@pytest.mark.unit
def test_the_api_engines_register_the_timing_listeners(monkeypatch):
    registered = []
    monkeypatch.setattr(aceapi_v2.database, "register_sql_timing_listeners", lambda: registered.append(True))
    monkeypatch.setattr(aceapi_v2.database, "create_async_engine", lambda *args, **kwargs: object())

    aceapi_v2.database.create_engine_for("ace")
    assert registered == [True]

