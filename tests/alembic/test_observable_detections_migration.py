"""Tests for the observable_detections backfill.

The migration is the only place existing detections cross from the observables table into their own,
and two of its decisions are judgement calls that would fail silently if wrong: which rows are
copied, and what happens to an expires_on that the ingest path -- not an analyst -- wrote.

These execute the migration's own BACKFILL_SQL, imported from the revision, so a change to the
statement cannot drift away from what is asserted here.
"""

import hashlib
import importlib.util
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from saq.constants import MAX_DETECTION_VALUE_LENGTH
from saq.database.model import ObservableDetection
from saq.database.pool import get_db

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic" / "ace" / "versions" / "c9e3f70a15d2_add_observable_detections_table.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("observable_detections_migration", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def migration():
    return _load_migration()


@pytest.fixture(autouse=True)
def clean_tables():
    session = get_db()
    session.execute(text("DELETE FROM observable_detections"))
    session.execute(text("DELETE FROM observables"))
    session.commit()
    yield
    session.execute(text("DELETE FROM observable_detections"))
    session.execute(text("DELETE FROM observables"))
    session.commit()


def _seed_observable(otype: str, value: str, **columns):
    """Insert a row shaped like the pre-migration observables table."""
    session = get_db()
    row = {"type": otype, "value": value.encode(), "sha256": hashlib.sha256(value.encode()).digest()}
    row.update(columns)
    names = ", ".join(f"`{name}`" for name in row)
    placeholders = ", ".join(f":{name}" for name in row)
    session.execute(text(f"INSERT INTO observables ({names}) VALUES ({placeholders})"), row)
    session.commit()


def _run_backfill(migration):
    session = get_db()
    session.execute(text(migration.BACKFILL_SQL), {"max_length": migration.VALUE_LENGTH})
    session.commit()


def _migrated() -> list[ObservableDetection]:
    return get_db().query(ObservableDetection).order_by(ObservableDetection.value).all()


@pytest.mark.integration
def test_value_length_matches_the_constant(migration):
    """The migration hardcodes the column width; it must agree with the code that validates it."""
    assert migration.VALUE_LENGTH == MAX_DETECTION_VALUE_LENGTH


@pytest.mark.integration
def test_only_enabled_rows_are_migrated(migration):
    _seed_observable("ipv4", "1.1.1.1", for_detection=1)
    _seed_observable("ipv4", "2.2.2.2", for_detection=0)
    # a row that merely carries disable history is not an active detection
    _seed_observable("ipv4", "3.3.3.3", for_detection=0, detection_context="disabled last year")

    _run_backfill(migration)

    assert [d.value for d in _migrated()] == ["1.1.1.1"]


@pytest.mark.integration
def test_context_and_batch_are_carried_over(migration):
    _seed_observable("fqdn", "evil.example.com", for_detection=1,
                     detection_context="from threat intel", batch_id="batch-1")

    _run_backfill(migration)

    detection = _migrated()[0]
    assert detection.type == "fqdn"
    assert detection.detection_context == "from threat intel"
    assert detection.batch_id == "batch-1"


@pytest.mark.integration
def test_a_future_expiration_is_preserved(migration):
    future = (datetime.now() + timedelta(days=30)).replace(microsecond=0)
    _seed_observable("fqdn", "future.example.com", for_detection=1, expires_on=future)

    _run_backfill(migration)

    assert _migrated()[0].expires_on == future


@pytest.mark.integration
def test_an_already_expired_expiration_becomes_never(migration):
    """Fails safe.

    On an enabled observables row, expires_on was written by ingest -- now + the per-type mapping, at
    the moment the value was first seen -- not by an analyst. Copying it verbatim would silently
    switch off live detections at cutover for anything last seen a while ago.
    """
    _seed_observable("fqdn", "stale.example.com", for_detection=1,
                     expires_on=datetime.now() - timedelta(days=1))

    _run_backfill(migration)

    assert _migrated()[0].expires_on is None


@pytest.mark.integration
def test_an_overlong_value_is_skipped_rather_than_truncated(migration):
    """A truncated detection value would silently never match anything at runtime."""
    _seed_observable("url", "https://example.com/" + ("x" * MAX_DETECTION_VALUE_LENGTH), for_detection=1)
    _seed_observable("ipv4", "4.4.4.4", for_detection=1)

    _run_backfill(migration)

    assert [d.value for d in _migrated()] == ["4.4.4.4"]


@pytest.mark.integration
def test_hash_is_carried_over_verbatim_so_the_join_back_still_works(migration):
    """observables.sha256 becomes value_sha256 unchanged, which is what makes the LEFT JOIN back to
    the index line up -- including for file observables, whose hash is of the file's content rather
    than of the value string."""
    value = "join.example.com"
    _seed_observable("fqdn", value, for_detection=1)

    _run_backfill(migration)

    assert _migrated()[0].value_sha256 == hashlib.sha256(value.encode()).digest()


@pytest.mark.integration
def test_migrated_detections_are_immediately_active(migration):
    """The end of the pipeline: what is migrated is what the detection cache will publish."""
    from saq.database.util.observable_detection import get_active_detections_by_type

    _seed_observable("fqdn", "active.example.com", for_detection=1)
    _seed_observable("fqdn", "stale.example.com", for_detection=1,
                     expires_on=datetime.now() - timedelta(days=1))
    _seed_observable("fqdn", "disabled.example.com", for_detection=0)

    _run_backfill(migration)

    active = get_active_detections_by_type()
    # the stale one is active because its ingest-written expiration was nulled, not copied
    assert {d["value"] for d in active["fqdn"]} == {"active.example.com", "stale.example.com"}
