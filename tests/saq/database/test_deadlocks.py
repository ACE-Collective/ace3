"""execute_with_retry and retry_on_deadlock against the deadlocks, lock wait timeouts and lost
connections MySQL really produces. Each deadlock is built the same way: the main thread holds
row A (and more, so that InnoDB picks the other side as the victim), the retried transaction
takes row B and waits for A, and the main thread then asks for B."""

import logging
import threading
from uuid import uuid4

import pymysql
import pytest
from sqlalchemy import text

from saq.configuration.config import get_config
from saq.database.pool import get_db, get_db_connection
from saq.database.retry import execute_with_retry, retry_function_on_deadlock, retry_sql_on_deadlock
from tests.saq.helpers import wait_for_condition

INSERT_LOCK = "INSERT INTO locks ( uuid, lock_time ) VALUES ( %s, NOW() )"
UPDATE_OWNER = "UPDATE locks SET lock_owner = %s WHERE uuid = %s"


@pytest.fixture
def rows():
    """Row A, row B and three rows that only make the main thread's transaction the heavier one."""
    uuids = {name: str(uuid4()) for name in ("a", "b", "h1", "h2", "h3")}
    with get_db_connection() as db:
        cursor = db.cursor()
        for value in uuids.values():
            cursor.execute(INSERT_LOCK, (value,))
        db.commit()
    return uuids


def _owners(rows: dict[str, str]) -> dict[str, str]:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT uuid, lock_owner FROM locks WHERE uuid IN %s", (tuple(rows.values()),))
        by_uuid = dict(cursor.fetchall())
    return {name: by_uuid[value] for name, value in rows.items()}


def _waiting_for_a_lock(marker: str) -> bool:
    """True while a statement containing marker waits in this user's processlist."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE INFO LIKE %s AND INFO NOT LIKE %s",
            (f"%{marker}%", "%PROCESSLIST%"))
        return cursor.fetchone()[0] > 0


def _deadlock_against(rows: dict[str, str], run_victim) -> threading.Thread:
    """Holds A and the heavy rows, runs run_victim() on a thread, waits until the victim waits
    for A, then takes B: InnoDB detects the deadlock there and rolls the lighter victim back."""
    with get_db_connection() as db:
        cursor = db.cursor()
        for name in ("a", "h1", "h2", "h3"):
            cursor.execute(UPDATE_OWNER, ("main", rows[name]))

        victim = threading.Thread(target=run_victim)
        victim.start()
        wait_for_condition(lambda: _waiting_for_a_lock(rows["a"]))

        # this is the statement that closes the cycle; the victim's retry then waits for this commit
        cursor.execute(UPDATE_OWNER, ("main", rows["b"]))
        db.commit()

    victim.join(30)
    assert not victim.is_alive()
    return victim


@pytest.mark.integration
def test_execute_with_retry_runs_a_deadlocked_transaction_again(rows, caplog):
    results = []

    def victim():
        with get_db_connection() as db:
            cursor = db.cursor()
            results.append(execute_with_retry(db, cursor,
                [UPDATE_OWNER, UPDATE_OWNER],
                [("victim", rows["b"]), ("victim", rows["a"])],
                commit=True))

    _deadlock_against(rows, victim)

    assert results == [[1, 1]]
    # the victim committed after the main thread did, and the retry ran both of its statements
    assert _owners(rows) == {"a": "victim", "b": "victim", "h1": "main", "h2": "main", "h3": "main"}
    assert [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING] == [
        "deadlock detected -- trying again (attempt #1)"]


@pytest.mark.integration
def test_retry_function_on_deadlock_runs_a_deadlocked_function_again(rows, caplog):
    calls = []

    def update_b_then_a():
        calls.append(1)
        get_db().execute(text("UPDATE locks SET lock_owner = 'victim' WHERE uuid = :uuid"), {"uuid": rows["b"]})
        get_db().execute(text("UPDATE locks SET lock_owner = 'victim' WHERE uuid = :uuid"), {"uuid": rows["a"]})

    def victim():
        try:
            retry_function_on_deadlock(update_b_then_a, commit=True)
        finally:
            # this thread's session would otherwise hold its connection after the test
            get_db().remove()

    with caplog.at_level(logging.DEBUG):
        _deadlock_against(rows, victim)

    assert len(calls) == 2
    assert _owners(rows) == {"a": "victim", "b": "victim", "h1": "main", "h2": "main", "h3": "main"}
    assert any(r.getMessage().startswith("DEADLOCK STATEMENT attempt #1") for r in caplog.records)


@pytest.mark.integration
def test_a_lock_wait_timeout_is_retried_until_the_attempts_run_out(rows, caplog):
    with get_db_connection() as holder:
        holder.cursor().execute(UPDATE_OWNER, ("holder", rows["a"]))

        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SET SESSION innodb_lock_wait_timeout = 1")
            try:
                with pytest.raises(pymysql.err.OperationalError) as e:
                    execute_with_retry(db, cursor, UPDATE_OWNER, ("waiter", rows["a"]), attempts=2)
            finally:
                cursor.execute("SET SESSION innodb_lock_wait_timeout = DEFAULT")

        holder.rollback()

    assert e.value.args[0] == 1205
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings[0] == "deadlock detected -- trying again (attempt #1)"
    # the statement that gave up is in the log, with its parameters
    assert warnings[1] == f"FAILED STATEMENT #0 (1205) SQL {UPDATE_OWNER} PARAMS waiter,{rows['a']}"
    assert len(warnings) == 2


@pytest.mark.integration
def test_a_lost_connection_is_not_retried_or_logged_as_a_failed_statement(caplog):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT CONNECTION_ID()")
        connection_id = cursor.fetchone()[0]
        with get_db_connection() as other:
            other.cursor().execute("KILL %s", (connection_id,))

        with pytest.raises(pymysql.err.OperationalError) as e:
            execute_with_retry(db, cursor, "SELECT 1")

    assert e.value.args[0] in (2006, 2013)
    messages = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any(m.startswith("database connection lost: ") for m in messages)
    assert not [m for m in messages if "FAILED STATEMENT" in m or "deadlock" in m]


@pytest.mark.integration
def test_a_rollback_that_fails_raises_the_deadlock_and_logs_the_rollback_failure(rows, caplog, monkeypatch):
    with get_db_connection() as db:
        cursor = db.cursor()

        def deadlocked(sql, params=None):
            raise pymysql.err.OperationalError(1213, "Deadlock found when trying to get lock")

        def rollback_fails():
            raise pymysql.err.InterfaceError(0, "rollback failed")

        monkeypatch.setattr(cursor, "execute", deadlocked)
        monkeypatch.setattr(db, "rollback", rollback_fails)
        with pytest.raises(pymysql.err.OperationalError) as e:
            execute_with_retry(db, cursor, UPDATE_OWNER, ("x", rows["a"]))
        # the pool rolls the connection back when it is returned
        monkeypatch.undo()

    assert e.value.args[0] == 1213
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert errors[0].getMessage().startswith("rollback failed for transaction in deadlock")
    # with the traceback of the rollback failure, so it gets an error report
    assert errors[0].exc_info and isinstance(errors[0].exc_info[1], pymysql.err.InterfaceError)


@pytest.mark.integration
def test_statements_without_parameters_run_with_none_and_a_mismatch_is_refused(rows, monkeypatch, caplog):
    with get_db_connection() as db:
        cursor = db.cursor()
        assert execute_with_retry(db, cursor, ["SELECT 1", "SELECT 2"], None) == [1, 1]

        monkeypatch.setattr(get_config().global_settings, "log_sql", True)
        with caplog.at_level(logging.DEBUG):
            execute_with_retry(db, cursor, "SELECT %s", (1,))
        assert any(r.getMessage() == "executing with retry (attempt #1) sql SELECT %s with paramters (1,)"
                   for r in caplog.records)

        with pytest.raises(ValueError):
            execute_with_retry(db, cursor, ["SELECT 1", "SELECT 2"], [()])


@pytest.mark.integration
def test_retry_sql_on_deadlock_executes_the_statement_on_the_session(rows):
    statement = text("UPDATE locks SET lock_owner = 'sql' WHERE uuid = :uuid").bindparams(uuid=rows["a"])

    retry_sql_on_deadlock(statement, commit=True)

    assert _owners(rows)["a"] == "sql"
