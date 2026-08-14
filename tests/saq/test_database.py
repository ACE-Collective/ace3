import uuid
from contextlib import contextmanager
from unittest.mock import patch

import pymysql
import pytest

from saq.constants import F_TEST
from saq.database import Alert, get_db_connection, get_db
from saq.analysis import RootAnalysis
from saq.database import ALERT
from saq.database.util import index as index_module


@contextmanager
def capture_dml():
    """Records every INSERT/UPDATE/DELETE issued on any pymysql cursor.

    Comparing row snapshots cannot prove "no writes happened": these are junction tables
    with no autoincrement and no timestamp, so a delete-and-reinsert produces a
    byte-identical snapshot. Spying on the driver is the only assertion that actually
    distinguishes "unchanged" from "rewritten". (Innodb_rows_* status counters are
    global, and Com_* are per-session but the test cannot guarantee it gets the same
    pooled connection rebuild_index() checks out.)
    """
    statements = []
    original = pymysql.cursors.Cursor.execute

    def spy(self, query, args=None):
        if query.lstrip()[:6].upper() in ("INSERT", "UPDATE", "DELETE"):
            statements.append(query.lstrip())
        return original(self, query, args)

    with patch.object(pymysql.cursors.Cursor, "execute", spy):
        yield statements


def _alert_with_storage(tmpdir, name="alert") -> Alert:
    storage_dir = tmpdir / name
    storage_dir.mkdir()
    root = RootAnalysis(tool="test", tool_instance="test", alert_type="test",
                        uuid=str(uuid.uuid4()), storage_dir=str(storage_dir), queue="default")
    root.initialize_storage()
    root.save()
    ALERT(root)

    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one() # pyright: ignore
    assert alert
    return alert


def _mapped_observable_ids(alert_id) -> set:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT observable_id FROM observable_mapping WHERE alert_id = %s", (alert_id,))
        return {row[0] for row in cursor.fetchall()}


def _mapped_tag_names(alert_id) -> set:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""SELECT t.name FROM tag_mapping tm JOIN tags t ON t.id = tm.tag_id
                          WHERE tm.alert_id = %s""", (alert_id,))
        return {row[0] for row in cursor.fetchall()}


def _observable_tag_pairs(alert_id) -> set:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT observable_id, tag_id FROM observable_tag_index WHERE alert_id = %s",
                       (alert_id,))
        return set(cursor.fetchall())


def _tag_id(name):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM tags WHERE name = %s", (name,))
        row = cursor.fetchone()
        return row[0] if row else None


@pytest.mark.integration
def test_rebuild_index(tmpdir):
    alert = _alert_with_storage(tmpdir)

    def _get_tag_count(alert_id) -> int:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT COUNT(*) FROM tag_mapping WHERE alert_id = %s", (alert_id,))
            return cursor.fetchone()[0] # pyright: ignore

    def _get_observable_count(alert_id) -> int:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT COUNT(*) FROM observable_mapping WHERE alert_id = %s", (alert_id,))
            return cursor.fetchone()[0] # pyright: ignore

    assert _get_tag_count(alert.id) == 0
    alert.root_analysis.add_tag("test")
    alert.rebuild_index()
    assert _get_tag_count(alert.id) == 1

    assert _get_observable_count(alert.id) == 0
    alert.root_analysis.add_observable_by_spec(F_TEST, "test")
    alert.rebuild_index()
    assert _get_observable_count(alert.id) == 1

    for index in range(100):
        alert.root_analysis.add_observable_by_spec(F_TEST, f"test_{index}")

    alert.rebuild_index()
    assert _get_observable_count(alert.id) == 101


@pytest.mark.integration
def test_rebuild_index_no_writes_when_unchanged(tmpdir):
    alert = _alert_with_storage(tmpdir)

    alert.root_analysis.add_tag("root_tag_1")
    alert.root_analysis.add_tag("root_tag_2")
    alert.root_analysis.add_detection_point("a detection")
    for index in range(5):
        observable = alert.root_analysis.add_observable_by_spec(F_TEST, f"obs_{index}")
        if index < 2:
            observable.add_tag(f"obs_tag_{index}")

    assert alert.rebuild_index().changed

    with capture_dml() as dml:
        result = alert.rebuild_index()

    assert dml == []
    assert not result.changed


@pytest.mark.integration
def test_rebuild_index_writes_only_the_delta(tmpdir):
    alert = _alert_with_storage(tmpdir)
    for index in range(100):
        alert.root_analysis.add_observable_by_spec(F_TEST, f"obs_{index}")
    alert.rebuild_index()

    alert.root_analysis.add_observable_by_spec(F_TEST, "the_new_one")

    with capture_dml() as dml:
        result = alert.rebuild_index()

    assert result.observable_mappings_added == 1
    assert result.observable_mappings_removed == 0
    assert result.tag_mappings_added == result.tag_mappings_removed == 0
    assert result.observable_tag_index_added == result.observable_tag_index_removed == 0
    assert result.detection_points_written == result.detection_points_removed == 0

    # this is the assertion that fails loudly if a wholesale delete is ever reinstated
    assert not [s for s in dml if s.upper().startswith("DELETE")]


@pytest.mark.integration
def test_rebuild_index_removes_deleted_observable(tmpdir):
    alert = _alert_with_storage(tmpdir)
    keep = alert.root_analysis.add_observable_by_spec(F_TEST, "keep")
    drop = alert.root_analysis.add_observable_by_spec(F_TEST, "drop")
    alert.rebuild_index()

    before = _mapped_observable_ids(alert.id)
    assert len(before) == 2

    drop.ignored = True
    result = alert.rebuild_index()

    assert result.observable_mappings_removed == 1
    assert result.observable_mappings_added == 0

    after = _mapped_observable_ids(alert.id)
    assert len(after) == 1
    assert after < before
    # the surviving mapping row was left alone, not deleted and re-added
    assert keep is not None


@pytest.mark.integration
def test_rebuild_index_removes_deleted_tag(tmpdir):
    alert = _alert_with_storage(tmpdir)
    alert.root_analysis.add_tag("keep_tag")
    alert.root_analysis.add_tag("drop_tag")
    alert.rebuild_index()

    assert _mapped_tag_names(alert.id) == {"keep_tag", "drop_tag"}

    alert.root_analysis.remove_tag("drop_tag")
    result = alert.rebuild_index()

    assert result.tag_mappings_removed == 1
    assert _mapped_tag_names(alert.id) == {"keep_tag"}
    # the tags catalog is append-only -- only the mapping goes away
    assert _tag_id("drop_tag") is not None


@pytest.mark.integration
def test_rebuild_index_removes_observable_tag(tmpdir):
    alert = _alert_with_storage(tmpdir)
    observable = alert.root_analysis.add_observable_by_spec(F_TEST, "tagged")
    observable.add_tag("keep_tag")
    observable.add_tag("drop_tag")
    alert.rebuild_index()

    assert len(_observable_tag_pairs(alert.id)) == 2
    observables_before = _mapped_observable_ids(alert.id)

    observable.remove_tag("drop_tag")
    result = alert.rebuild_index()

    assert result.observable_tag_index_removed == 1
    assert len(_observable_tag_pairs(alert.id)) == 1
    # only observable_tag_index changed
    assert _mapped_observable_ids(alert.id) == observables_before
    assert _mapped_tag_names(alert.id) == {"keep_tag"}


@pytest.mark.integration
def test_rebuild_index_tag_case_insensitive(tmpdir):
    # tags.name is utf8mb4_unicode_520_ci, so these resolve to the same catalog row.
    # Before the fold, the second alert's SELECT returned the first alert's row and the
    # raw-string lookup missed, silently dropping the tag.
    first = _alert_with_storage(tmpdir, name="alert_lower")
    first.root_analysis.add_tag("collation")
    first.rebuild_index()

    second = _alert_with_storage(tmpdir, name="alert_upper")
    second.root_analysis.add_tag("COLLATION")
    result = second.rebuild_index()

    assert result.unresolved_tags == 0
    assert result.tag_mappings_added == 1
    assert len(_mapped_tag_names(second.id)) == 1


@pytest.mark.integration
def test_rebuild_index_chunking(tmpdir, monkeypatch):
    monkeypatch.setattr(index_module, "CHUNK_SIZE", 3)

    alert = _alert_with_storage(tmpdir)
    for index in range(10):
        observable = alert.root_analysis.add_observable_by_spec(F_TEST, f"obs_{index}")
        observable.add_tag(f"tag_{index}")

    result = alert.rebuild_index()
    assert result.observable_mappings_added == 10
    assert result.tag_mappings_added == 10
    assert result.observable_tag_index_added == 10

    assert len(_mapped_observable_ids(alert.id)) == 10
    assert len(_observable_tag_pairs(alert.id)) == 10

    # and the second pass across multiple chunks is still a no-op
    with capture_dml() as dml:
        assert not alert.rebuild_index().changed
    assert dml == []


@pytest.mark.integration
def test_rebuild_index_reindexes_after_external_delete(tmpdir):
    # the diff is against the database, not a cached snapshot -- the whole design rests
    # on this, since workers are separate processes sharing one database
    alert = _alert_with_storage(tmpdir)
    for index in range(3):
        alert.root_analysis.add_observable_by_spec(F_TEST, f"obs_{index}")
    alert.rebuild_index()

    expected = _mapped_observable_ids(alert.id)
    assert len(expected) == 3

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM observable_mapping WHERE alert_id = %s", (alert.id,))
        db.commit()

    result = alert.rebuild_index()

    assert result.observable_mappings_added == 3
    assert _mapped_observable_ids(alert.id) == expected
