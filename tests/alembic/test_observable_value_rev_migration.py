"""Tests for 87cae96b23b0, which adds observables.value_rev and its index on a live table.

Both ALTERs are online, but each still waits for a metadata lock that any open transaction on
observables holds, and every later query of the table queues behind the wait. These hold such a
transaction open and run the revision's own upgrade()."""

import importlib.util
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError

from saq.database.admin import create_superuser_engine
from saq.database.pool import get_db

pytestmark = pytest.mark.integration

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic" / "ace" / "versions" / "87cae96b23b0_observable_value_rev_for_suffix_patterns.py"
)


@pytest.fixture
def migration(monkeypatch):
    spec = importlib.util.spec_from_file_location("observable_value_rev_migration", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # the shortest wait MySQL allows
    monkeypatch.setattr(module, "LOCK_WAIT_TIMEOUT_SECONDS", 1)
    return module


@pytest.fixture
def ddl():
    """A superuser connection to the session's ace database (ace-user may not ALTER), on which
    the column has been dropped again, and is put back however the test ends."""
    get_db().commit()
    engine = create_superuser_engine(get_db().get_bind().url.database)
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            connection.execute(text("SET SESSION lock_wait_timeout = 30"))
            connection.execute(text("ALTER TABLE observables DROP INDEX i_obs_value_rev"))
            connection.execute(text("ALTER TABLE observables DROP COLUMN value_rev"))
            yield connection
            get_db().rollback()
            if not _has_value_rev(connection):
                connection.execute(text(
                    "ALTER TABLE observables ADD COLUMN value_rev VARBINARY(255) "
                    "GENERATED ALWAYS AS (LEFT(REVERSE(`value`), 255)) VIRTUAL"))
            if "i_obs_value_rev" not in {index["name"] for index in inspect(connection).get_indexes("observables")}:
                connection.execute(text("ALTER TABLE observables ADD INDEX i_obs_value_rev (value_rev)"))
    finally:
        engine.dispose()


def _has_value_rev(connection) -> bool:
    connection.commit()  # inspect() reads a fresh view of the schema
    return any(column["name"] == "value_rev" for column in inspect(connection).get_columns("observables"))


def _hold_the_table():
    """An open transaction that has read observables, as a request mid-way through does."""
    get_db().execute(text("SELECT COUNT(*) FROM observables")).scalar()


def _upgrade(migration, ddl) -> None:
    with Operations.context(MigrationContext.configure(connection=ddl)):
        migration.upgrade()


def test_an_alter_that_waits_too_long_lets_the_queue_through_and_tries_again(migration, ddl, monkeypatch, caplog):
    _hold_the_table()
    # the transaction ends during the pause between attempts
    monkeypatch.setattr(migration, "time", SimpleNamespace(sleep=lambda seconds: get_db().commit()))

    with caplog.at_level(logging.WARNING):
        _upgrade(migration, ddl)

    assert _has_value_rev(ddl)
    retries = [r for r in caplog.records if r.getMessage().startswith("gave up waiting 1s for the lock on observables")]
    assert len(retries) == 1 and "ADD COLUMN value_rev" in retries[0].getMessage()
    # the connection is alembic's, and the next revision runs on it
    assert ddl.execute(text("SELECT @@SESSION.lock_wait_timeout")).scalar() == 30


def test_an_alter_that_never_gets_its_lock_fails_the_migration(migration, ddl, monkeypatch):
    _hold_the_table()
    monkeypatch.setattr(migration, "ATTEMPTS", 2)
    monkeypatch.setattr(migration, "time", SimpleNamespace(sleep=lambda seconds: None))

    with pytest.raises(OperationalError) as error:
        _upgrade(migration, ddl)

    assert error.value.orig.args[0] == migration.ER_LOCK_WAIT_TIMEOUT
    get_db().commit()
    assert not _has_value_rev(ddl)
    assert ddl.execute(text("SELECT @@SESSION.lock_wait_timeout")).scalar() == 30
