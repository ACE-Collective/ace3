"""Tests for 04a424e8da0b, which makes file_collection.alert_uuid nullable on a database that got the
column NOT NULL from the hand-written pre-Alembic migration. The chain builds the test databases with
it nullable, so the fixture puts the old column back before running the revision's upgrade()."""

import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from saq.constants import F_HOSTNAME
from saq.database.admin import create_superuser_engine
from saq.database.model import FileCollection
from saq.database.pool import get_db
from saq.file_collection.database import queue_file_collection

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic" / "ace" / "versions" / "04a424e8da0b_file_collection_alert_uuid_nullable_on_.py"
)


@pytest.fixture
def migration():
    spec = importlib.util.spec_from_file_location("file_collection_alert_uuid_migration", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def ddl():
    """A superuser connection to the session's ace database: ace-user, which the tests connect as,
    may not ALTER, and migrations run as the superuser."""
    # an ALTER waits for any transaction that has touched the table, so the session's ends first
    get_db().commit()
    engine = create_superuser_engine(get_db().get_bind().url.database)
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            # fail instead of hanging the run on a transaction still open on the table
            connection.execute(text("SET SESSION lock_wait_timeout = 30"))
            yield connection
    finally:
        engine.dispose()


@pytest.fixture
def pre_alembic_column(ddl):
    """file_collection.alert_uuid as sql/migrations/add_file_collection_tables.sql created it."""
    ddl.execute(text("ALTER TABLE file_collection MODIFY alert_uuid VARCHAR(36) NOT NULL"))
    yield
    get_db().rollback()
    ddl.execute(text("ALTER TABLE file_collection MODIFY alert_uuid VARCHAR(36) NULL"))


def _alert_uuid_nullable(ddl) -> bool:
    columns = inspect(ddl).get_columns("file_collection")
    return next(column for column in columns if column["name"] == "alert_uuid")["nullable"]


def _upgrade(migration, ddl) -> None:
    with Operations.context(MigrationContext.configure(connection=ddl)):
        migration.upgrade()


def _queue_without_alert() -> int:
    collection_id = queue_file_collection(
        collector_name="test_collector", observable_type=F_HOSTNAME, observable_value="WS01")
    get_db().commit()
    return collection_id


@pytest.mark.integration
def test_upgrade_makes_pre_alembic_column_nullable(migration, ddl, pre_alembic_column):
    assert not _alert_uuid_nullable(ddl)
    with pytest.raises(IntegrityError, match="alert_uuid"):
        _queue_without_alert()
    # ends the failed transaction, which holds the table the upgrade alters
    get_db().rollback()

    _upgrade(migration, ddl)

    assert _alert_uuid_nullable(ddl)
    collection_id = _queue_without_alert()
    assert get_db().get(FileCollection, collection_id).alert_uuid is None


@pytest.mark.integration
def test_upgrade_leaves_nullable_column_alone(migration, ddl):
    """A database the chain built needs no table rebuild."""
    assert _alert_uuid_nullable(ddl)
    with patch.object(migration.op, "alter_column") as alter_column:
        _upgrade(migration, ddl)
    alter_column.assert_not_called()
