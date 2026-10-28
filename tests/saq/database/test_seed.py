"""seed() runs against the primary database on every start (docker/startup/setup.sh), so each
test seeds a database of its own, migrated to head, never the suite's: these rows are the ones
the suite's reset deletes and re-creates itself."""

import os
import subprocess
import sys
import uuid

import pytest

from saq.database.admin import superuser_connection
from saq.database.seed import ANALYST_USER_ID, AUTOMATION_USER_ID, seed
from tests.unittest_database import DATABASE_CHARSET, DATABASE_COLLATION, UPGRADE_TIMEOUT, get_project_root


@pytest.fixture
def database():
    # matches the orphan pattern bin/cleanup-unittest-databases.py looks for, should a killed
    # run leave it behind
    name = f"ace-seed-unittest-{uuid.uuid4().hex[:8]}"
    with superuser_connection() as db:
        db.cursor().execute(f"CREATE DATABASE `{name}` CHARACTER SET {DATABASE_CHARSET} COLLATE {DATABASE_COLLATION}")
    try:
        # a subprocess: the repository's alembic/ shadows the alembic package under pytest
        result = subprocess.run(
            [sys.executable, os.path.join(get_project_root(), "bin", "upgrade_databases.py"), "--ace", name],
            cwd=get_project_root(), capture_output=True, text=True, timeout=UPGRADE_TIMEOUT)
        assert result.returncode == 0, result.stderr
        yield name
    finally:
        with superuser_connection() as db:
            db.cursor().execute(f"DROP DATABASE IF EXISTS `{name}`")


def _query(database: str, sql: str, params=()) -> list[tuple]:
    with superuser_connection(database) as db:
        cursor = db.cursor()
        cursor.execute(sql, params)
        return list(cursor.fetchall())


def _execute(database: str, sql: str, params=()) -> None:
    with superuser_connection(database) as db:
        db.cursor().execute(sql, params)


@pytest.mark.integration
def test_seed_creates_what_a_new_database_needs(database):
    seed(database)

    assert _query(database, "SELECT id, name FROM company") == [(1, "default")]
    assert _query(database, "SELECT id, name FROM tags") == [(1, "whitelisted")]
    assert _query(database, "SELECT id, username FROM users ORDER BY id") == [
        (AUTOMATION_USER_ID, "ace"), (ANALYST_USER_ID, "analyst")]
    assert _query(database, "SELECT user_id, major, minor FROM auth_user_permission ORDER BY user_id") == [
        (AUTOMATION_USER_ID, "*", "*"), (ANALYST_USER_ID, "*", "*")]
    assert _query(database, "SELECT analysis_mode, priority FROM analysis_mode_priority") == [("correlation", 1)]
    assert {v for (v,) in _query(database, "SELECT value FROM event_status")} == {"OPEN", "CLOSED", "IGNORE"}
    assert ("ransomware",) in _query(database, "SELECT name FROM threat_type")
    assert _query(database, "SELECT COUNT(*) FROM auth_permission_catalog")[0][0] > 0


@pytest.mark.integration
def test_seeding_again_adds_nothing_twice(database):
    tables = ["company", "tags", "users", "auth_user_permission", "analysis_mode_priority", "event_status",
              "event_remediation", "event_vector", "event_risk_level", "event_prevention_tool", "event_type",
              "threat_type", "auth_permission_catalog"]
    seed(database)
    counts = {t: _query(database, f"SELECT COUNT(*) FROM `{t}`")[0][0] for t in tables}

    seed(database)

    assert {t: _query(database, f"SELECT COUNT(*) FROM `{t}`")[0][0] for t in tables} == counts


@pytest.mark.integration
def test_seeding_again_keeps_what_an_operator_changed(database):
    seed(database)
    _execute(database, "UPDATE users SET password_hash = 'changed', email = 'soc@example.com', timezone = 'US/Eastern' WHERE id = %s", (ANALYST_USER_ID,))
    _execute(database, "UPDATE users SET display_name = 'ACE automation' WHERE id = %s", (AUTOMATION_USER_ID,))
    _execute(database, "UPDATE company SET name = 'example corp' WHERE id = 1")
    _execute(database, "UPDATE analysis_mode_priority SET priority = 5 WHERE analysis_mode = 'correlation'")

    # the next start
    seed(database)

    assert _query(database, "SELECT password_hash, email, timezone FROM users WHERE id = %s", (ANALYST_USER_ID,)) == [
        ("changed", "soc@example.com", "US/Eastern")]
    assert _query(database, "SELECT display_name FROM users WHERE id = %s", (AUTOMATION_USER_ID,)) == [("ACE automation",)]
    assert _query(database, "SELECT name FROM company WHERE id = 1") == [("example corp",)]
    assert _query(database, "SELECT priority FROM analysis_mode_priority WHERE analysis_mode = 'correlation'") == [(5,)]


@pytest.mark.integration
def test_seeding_again_does_not_bring_back_a_deleted_analyst(database):
    seed(database)
    # what an operator does with a default account that has a known password
    _execute(database, "DELETE FROM auth_user_permission WHERE user_id = %s", (ANALYST_USER_ID,))
    _execute(database, "DELETE FROM users WHERE id = %s", (ANALYST_USER_ID,))

    # the next start
    seed(database)

    assert _query(database, "SELECT id FROM users WHERE username = 'analyst'") == []
    assert _query(database, "SELECT user_id FROM auth_user_permission WHERE user_id = %s", (ANALYST_USER_ID,)) == []
