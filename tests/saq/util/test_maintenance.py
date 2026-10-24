from datetime import datetime, timedelta
import logging
import os.path
import time
from types import SimpleNamespace

from saq.analysis import RootAnalysis
from saq.analysis.blob_store import (
    GlobalMaintenanceStats,
    LocalCacheBudget,
    LocalHardlinkBlobStore,
    LocalHardlinkBlobStoreConfig,
    LocalMaintenanceStats,
)
from saq.database import ALERT, Alert, Event, get_db
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE, DISPOSITION_SIMULATED, ENV_ACE_IS_PRIMARY_NODE
from saq.database.model import DetectionPoint
from saq.environment import get_base_dir
from saq.signatures.builtin import BUILTIN_SIGNATURE_UUID
from saq.util.maintenance import (
    archive_fp_alerts,
    archive_simulated_alerts,
    cleanup_alerts,
    cleanup_ignored_alerts,
    distribute_old_alerts,
)
from tests.saq.helpers import insert_alert, insert_alert_with_detections, make_simulated

import saq.util.maintenance

import pytest
from sqlalchemy import func, text

@pytest.mark.parametrize("days,target,insert_alert,alert_age_days,add_to_event,expected_raises,upload_failure,non_success,expected_count,alert_still_exists,dry_run", [
    #days  target   insrt  age event  raise  fail   n-succ cnt isdir  dry
    (0,   "target", False, 0,  False, True,  False, False, 0,  True,  False), # invalid days
    (1,   "",       False, 0,  False, True,  False, False, 0,  True,  False), # invalid target
    (1,   "target", False, 0,  False, False, False, False, 0,  True,  False), # no alerts
    (30,  "target", True,  3,  False, False, False, False, 0,  True,  False), # alert to new to distribute
    (1,   "target", True,  3,  False, False, False, False, 1,  False, False), # alert distributed
    (1,   "target", True,  3,  True,  False, False, False, 0,  True,  False), # alert added to event
    (1,   "target", True,  3,  False, False, False, False, 1,  True,  True), # dry run
    (1,   "target", True,  3,  False, False, True,  False, 0,  True,  False), # upload failure
    (1,   "target", True,  3,  False, False, False, True,  0,  True,  False), # non-success
])
@pytest.mark.integration
def test_distribute_old_alerts(days, target, insert_alert, alert_age_days, add_to_event, expected_raises, upload_failure, non_success, expected_count, alert_still_exists, dry_run, monkeypatch, tmpdir):
    def mock_upload(*args, **kwargs):
        assert kwargs["remote_host"] == target
        assert kwargs["api_key"] == "key"
        if upload_failure:
            raise RuntimeError("upload failure")
        if non_success:
            return { "result": False }
        else:
            return { "result": True }

    monkeypatch.setattr(saq.util.maintenance, "upload", mock_upload)
    monkeypatch.setattr(get_config().api, "api_key", "key")

    if insert_alert:
        storage_dir = tmpdir / "alert"
        storage_dir.mkdir()

        root = RootAnalysis(
            storage_dir=str(storage_dir),
            tool="test",
            tool_instance="test",
            alert_type="test",
        )
        root.initialize_storage()
        root.save()
        ALERT(root)

        alert = get_db().query(Alert).filter(Alert.uuid==root.uuid).one()
        alert.insert_date = datetime.now() - timedelta(days=alert_age_days)
        get_db().add(alert)
        get_db().commit()

        # blech
        from saq.database import EventStatus, EventRemediation, EventVector, EventRiskLevel, EventPreventionTool, EventType, EventMapping
        event_status = EventStatus(value="test")
        event_remediation = EventRemediation(value="test")
        event_vector = EventVector(value="test")
        event_risk_level = EventRiskLevel(value="test")
        event_prevention_tool = EventPreventionTool(value="test")
        event_type = EventType(value="test")

        if add_to_event:
            event = Event(
                name="test",
                status=event_status,
                remediation=event_remediation,
                vector=event_vector,
                risk_level=event_risk_level,
                prevention_tool=event_prevention_tool,
                type=event_type,
                creation_date=datetime.now(),
            )
            get_db().add(event)
            get_db().commit()

            alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
            event = get_db().query(Event).filter(Event.name == "test").one()

            mapping = EventMapping(alert_id=alert.id, event_id=event.id)
            get_db().add(mapping)
            get_db().commit()

    if expected_raises:
        with pytest.raises(AssertionError):
            assert distribute_old_alerts(days, dry_run, target) == expected_count
    else:
        assert distribute_old_alerts(days, dry_run, target) == expected_count

    if insert_alert:
        assert storage_dir.isdir() == alert_still_exists


@pytest.mark.unit
def test_cache_stats_skips_when_not_primary(monkeypatch, caplog):
    """The cache stats heartbeat is global maintenance — non-primary nodes
    must skip it (no cache_stats line emitted)."""
    import logging as _logging
    import saq.util.maintenance as maintenance
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
    with caplog.at_level(_logging.INFO):
        maintenance.emit_cache_stats()
    assert not [r for r in caplog.records if "cache_stats" in r.getMessage()]


@pytest.mark.unit
def test_gc_durable_blobs_skips_when_not_primary(monkeypatch):
    """Durable blob GC is global maintenance — non-primary nodes must skip it."""
    import saq.util.maintenance as maintenance
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
    stats = maintenance.gc_durable_blobs()
    assert stats.blobs_scanned == 0
    assert stats.blobs_deleted == 0


@pytest.mark.integration
def test_emit_cache_stats_emits_heartbeat(caplog):
    """Each run emits a cache_stats heartbeat for Splunk."""
    import logging as _logging
    from saq.util.maintenance import emit_cache_stats

    with caplog.at_level(_logging.INFO):
        emit_cache_stats()

    stats_lines = [r for r in caplog.records if "cache_stats" in r.getMessage()]
    assert stats_lines, "expected cache_stats heartbeat"
    # the fields ride in extra={} so Splunk can timechart them without a rex
    record = stats_lines[0]
    for field in ("total_rows", "total_on_disk_bytes", "blob_refs_rows"):
        assert hasattr(record, field), f"cache_stats line missing field {field!r}"


#
# SIMULATED (test-run) alerts are archived after svs.simulated_days and never deleted
#

def _db_days_ago(days: int):
    # the database's clock, which is the one that sets disposition_time
    return func.date_sub(func.now(), text(f"INTERVAL {int(days)} DAY"))


def _simulated_alert(days_ago: int) -> Alert:
    alert = insert_alert_with_detections([
        {"description": "test signature fired", "signature_uuid": BUILTIN_SIGNATURE_UUID, "fqdn": "test.example.com"},
    ])
    make_simulated(alert)
    db = get_db()
    db.query(Alert).filter(Alert.id == alert.id).update(
        {Alert.disposition_time: _db_days_ago(days_ago)}, synchronize_session=False)
    db.commit()
    return alert


def _fp_alert(days_ago: int) -> Alert:
    alert = insert_alert()
    db = get_db()
    db.query(Alert).filter(Alert.id == alert.id).update(
        {Alert.disposition: DISPOSITION_FALSE_POSITIVE, Alert.disposition_time: _db_days_ago(days_ago)},
        synchronize_session=False)
    db.commit()
    return alert


def _reloaded(alert: Alert) -> Alert:
    db = get_db()
    db.expire_all()
    return db.get(Alert, alert.id)


@pytest.mark.integration
def test_simulated_alerts_are_archived_after_simulated_days():
    old, recent = _simulated_alert(days_ago=31), _simulated_alert(days_ago=1)

    archive_simulated_alerts(30, dry_run=False)

    old, recent = _reloaded(old), _reloaded(recent)
    assert old.archived and not recent.archived
    # the row, its disposition and its detections stay: verdicts, labels and attributions derive from them
    assert old.disposition == DISPOSITION_SIMULATED
    assert get_db().query(DetectionPoint).filter(DetectionPoint.alert_id == old.id).count() == 1


@pytest.mark.integration
def test_cleanup_archives_simulated_alerts_and_deletes_none():
    alert = _simulated_alert(days_ago=2)

    cleanup_alerts(fp_days_old=1, ignore_days_old=1, simulated_days_old=1)

    alert = _reloaded(alert)
    assert alert is not None and alert.archived
    assert alert.disposition == DISPOSITION_SIMULATED


@pytest.mark.integration
def test_cleanup_defaults_to_simulated_days(monkeypatch):
    alert = _simulated_alert(days_ago=5)
    monkeypatch.setattr(get_config().svs, "simulated_days", 4)

    cleanup_alerts(fp_days_old=1, ignore_days_old=1)

    assert _reloaded(alert).archived


@pytest.mark.integration
def test_simulated_dry_run_archives_nothing(caplog):
    alert = _simulated_alert(days_ago=31)

    archive_simulated_alerts(30, dry_run=True)

    assert not _reloaded(alert).archived
    assert "1 SIMULATED alerts would be archived" in caplog.text


def _archive_error_records(caplog, alert: Alert) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.ERROR and getattr(r, "alert_uuid", None) == alert.uuid]


def _fail_for(alert: Alert, real_method, exception: Exception):
    def _method(self, *args, **kwargs):
        if self.uuid == alert.uuid:
            raise exception
        return real_method(self, *args, **kwargs)

    return _method


@pytest.mark.integration
def test_archive_failure_is_logged_and_archiving_continues(monkeypatch, caplog):
    failing, other = _simulated_alert(days_ago=31), _simulated_alert(days_ago=31)
    monkeypatch.setattr(Alert, "archive", _fail_for(failing, Alert.archive, OSError("disk full")))

    with caplog.at_level(logging.ERROR):
        archive_simulated_alerts(30, dry_run=False)

    # left for the next run
    assert not _reloaded(failing).archived
    assert _reloaded(other).archived

    records = _archive_error_records(caplog, failing)
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None


@pytest.mark.integration
def test_archive_load_failure_is_logged_with_traceback(caplog):
    failing, other = _simulated_alert(days_ago=31), _simulated_alert(days_ago=31)
    os.remove(os.path.join(get_base_dir(), failing.storage_dir, "data.json"))

    with caplog.at_level(logging.ERROR):
        archive_simulated_alerts(30, dry_run=False)

    assert not _reloaded(failing).archived
    assert _reloaded(other).archived

    records = _archive_error_records(caplog, failing)
    assert len(records) == 1
    assert records[0].exc_info is not None


@pytest.mark.integration
def test_archive_commit_failure_does_not_break_the_next_alert(monkeypatch, caplog):
    failing, other = _simulated_alert(days_ago=31), _simulated_alert(days_ago=31)
    real_sync = Alert.sync

    def _sync(self, *args, **kwargs):
        if self.uuid == failing.uuid:
            self.tool = None # NOT NULL: the commit fails and the session needs a rollback
        return real_sync(self, *args, **kwargs)

    monkeypatch.setattr(Alert, "sync", _sync)

    with caplog.at_level(logging.ERROR):
        archive_simulated_alerts(30, dry_run=False)

    assert not _reloaded(failing).archived
    assert _reloaded(other).archived
    assert len(_archive_error_records(caplog, failing)) == 1


#
# IGNORE alerts are deleted after ignore_days
#

def _ignored_alert(days_ago: int) -> tuple[int, str, str]:
    """Returns the id, uuid and full storage path of a new IGNORE alert (plain values, since the
    row is deleted under the test)."""
    alert = insert_alert()
    db = get_db()
    db.query(Alert).filter(Alert.id == alert.id).update(
        {Alert.disposition: DISPOSITION_IGNORE, Alert.disposition_time: _db_days_ago(days_ago)},
        synchronize_session=False)
    db.commit()
    return alert.id, alert.uuid, os.path.join(get_base_dir(), alert.storage_dir)


def _alert_row_exists(alert_id: int) -> bool:
    db = get_db()
    db.expire_all()
    return db.get(Alert, alert_id) is not None


@pytest.mark.integration
def test_ignored_alert_row_is_deleted_before_its_storage(monkeypatch):
    alert_id, alert_uuid, storage_dir = _ignored_alert(days_ago=2)
    deleted_tasks = []
    monkeypatch.setattr(saq.util.maintenance, "submit_delete_task", deleted_tasks.append)
    real_rmtree = saq.util.maintenance.shutil.rmtree
    row_exists_at_rmtree = []

    def _rmtree(path):
        row_exists_at_rmtree.append(_alert_row_exists(alert_id))
        real_rmtree(path)

    monkeypatch.setattr(saq.util.maintenance.shutil, "rmtree", _rmtree)

    cleanup_ignored_alerts(1, dry_run=False)

    # a reader of the alerts table never finds the alert without its files
    assert row_exists_at_rmtree == [False]
    assert deleted_tasks == [alert_uuid]
    assert not _alert_row_exists(alert_id)
    assert not os.path.exists(storage_dir)


@pytest.mark.integration
def test_ignored_alert_storage_delete_failure_is_logged_and_cleanup_continues(monkeypatch, caplog):
    failing_id, failing_uuid, failing_dir = _ignored_alert(days_ago=2)
    other_id, _, other_dir = _ignored_alert(days_ago=2)
    monkeypatch.setattr(saq.util.maintenance, "submit_delete_task", lambda alert_uuid: True)
    real_rmtree = saq.util.maintenance.shutil.rmtree

    def _rmtree(path):
        if path == failing_dir:
            raise PermissionError(f"permission denied: {path}")
        real_rmtree(path)

    monkeypatch.setattr(saq.util.maintenance.shutil, "rmtree", _rmtree)

    with caplog.at_level(logging.ERROR):
        cleanup_ignored_alerts(1, dry_run=False)

    # the row is gone and the directory is left behind as an orphan
    assert not _alert_row_exists(failing_id)
    assert os.path.exists(failing_dir)
    assert not _alert_row_exists(other_id)
    assert not os.path.exists(other_dir)

    records = [r for r in caplog.records if getattr(r, "alert_uuid", None) == failing_uuid]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None
    assert records[0].storage_dir == failing_dir


#
# the cutoffs come from the database's clock, which wrote disposition_time, not the node's
#

class _NodeClockAhead(datetime):
    """The node's clock, 30 days ahead of the database's (e.g. a different time zone)."""

    @classmethod
    def now(cls, tz=None):
        return datetime.now(tz) + timedelta(days=30)


@pytest.fixture
def node_clock_ahead(monkeypatch):
    # only the maintenance module sees the skewed clock
    monkeypatch.setattr(saq.util.maintenance, "datetime", SimpleNamespace(datetime=_NodeClockAhead, timedelta=timedelta))


@pytest.mark.integration
def test_ignore_cutoff_uses_the_database_clock(node_clock_ahead, monkeypatch):
    old_id, _, _ = _ignored_alert(days_ago=8)
    recent_id, _, recent_dir = _ignored_alert(days_ago=2)
    monkeypatch.setattr(saq.util.maintenance, "submit_delete_task", lambda alert_uuid: True)

    cleanup_ignored_alerts(7, dry_run=False)

    assert not _alert_row_exists(old_id)
    assert _alert_row_exists(recent_id)
    assert os.path.exists(recent_dir)


@pytest.mark.parametrize("make_alert,archive", [
    (_fp_alert, archive_fp_alerts),
    (_simulated_alert, archive_simulated_alerts),
])
@pytest.mark.integration
def test_archive_cutoff_uses_the_database_clock(node_clock_ahead, make_alert, archive):
    old, recent = make_alert(days_ago=8), make_alert(days_ago=2)

    archive(7, dry_run=False)

    assert _reloaded(old).archived
    assert not _reloaded(recent).archived


#
# cleanup_alerts runs every step even when one fails
#

@pytest.mark.unit
def test_cleanup_alerts_a_failing_step_does_not_stop_the_others(monkeypatch, caplog):
    called = []

    def _failing(name):
        def _step(*args):
            called.append(name)
            raise RuntimeError(f"{name} failed")
        return _step

    for name in ("cleanup_ignored_alerts", "archive_fp_alerts", "archive_simulated_alerts", "distribute_old_alerts"):
        monkeypatch.setattr(saq.util.maintenance, name, _failing(name))

    with caplog.at_level(logging.ERROR):
        cleanup_alerts(fp_days_old=1, ignore_days_old=1, simulated_days_old=1, distribute_days_old=1)

    assert called == ["cleanup_ignored_alerts", "archive_fp_alerts", "archive_simulated_alerts", "distribute_old_alerts"]
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 4
    assert all(r.exc_info is not None for r in errors)


@pytest.mark.unit
def test_cleanup_alerts_does_not_distribute_when_disabled(monkeypatch):
    distributed = []
    for name in ("cleanup_ignored_alerts", "archive_fp_alerts", "archive_simulated_alerts"):
        monkeypatch.setattr(saq.util.maintenance, name, lambda *args: None)
    monkeypatch.setattr(saq.util.maintenance, "distribute_old_alerts", lambda *args: distributed.append(args))
    monkeypatch.setattr(get_config().global_settings, "distribute_days_old", 0)

    cleanup_alerts()

    assert distributed == []


@pytest.mark.integration
def test_ignored_dry_run_deletes_nothing(monkeypatch, caplog):
    first_id, _, first_dir = _ignored_alert(days_ago=2)
    second_id, _, _ = _ignored_alert(days_ago=2)
    monkeypatch.setattr(saq.util.maintenance, "submit_delete_task", lambda alert_uuid: pytest.fail("dry run deleted"))

    with caplog.at_level(logging.INFO):
        cleanup_ignored_alerts(1, dry_run=True)

    assert _alert_row_exists(first_id) and _alert_row_exists(second_id)
    assert os.path.exists(first_dir)
    assert "2 ignored alerts would be deleted" in caplog.text


#
# distribute_old_alerts
#

def _old_alert(tmp_path, name: str) -> str:
    """Returns the storage directory of a new alert inserted three days ago, in no event."""
    storage_dir = tmp_path / name
    storage_dir.mkdir()
    root = RootAnalysis(storage_dir=str(storage_dir), tool="test", tool_instance="test", alert_type="test")
    root.initialize_storage()
    root.save()
    ALERT(root)
    get_db().query(Alert).filter(Alert.uuid == root.uuid).update(
        {Alert.insert_date: _db_days_ago(3)}, synchronize_session=False)
    get_db().commit()
    return str(storage_dir)


@pytest.fixture
def uploads(monkeypatch):
    """The storage directories uploaded, each answered with success."""
    uploaded = []

    def _upload(uuid, storage_dir, **kwargs):
        uploaded.append(storage_dir)
        return {"result": True}

    monkeypatch.setattr(saq.util.maintenance, "upload", _upload)
    return uploaded


@pytest.mark.integration
def test_distribute_stops_at_max_count_and_logs_the_summary(tmp_path, uploads, caplog):
    _old_alert(tmp_path, "first")
    _old_alert(tmp_path, "second")

    with caplog.at_level(logging.INFO):
        assert distribute_old_alerts(1, False, "target", max_count=1) == 1

    assert len(uploads) == 1
    assert "stopping at max count 1" in caplog.text
    assert "uploaded 1 alerts (0 failures)" in caplog.text


@pytest.mark.integration
def test_distribute_counts_a_missing_storage_dir_as_a_failure(tmp_path, uploads, caplog):
    missing = _old_alert(tmp_path, "missing")
    present = _old_alert(tmp_path, "present")
    saq.util.maintenance.shutil.rmtree(missing)

    with caplog.at_level(logging.INFO):
        assert distribute_old_alerts(1, False, "target") == 1

    assert uploads == [present]
    assert f"alert storage_dir {missing} does not exist" in caplog.text
    assert "uploaded 1 alerts (1 failures)" in caplog.text


@pytest.mark.integration
def test_distribute_local_delete_failure_is_logged(tmp_path, uploads, monkeypatch, caplog):
    storage_dir = _old_alert(tmp_path, "alert")

    def _rmtree(path):
        raise PermissionError(f"permission denied: {path}")

    monkeypatch.setattr(saq.util.maintenance.shutil, "rmtree", _rmtree)

    with caplog.at_level(logging.INFO):
        assert distribute_old_alerts(1, False, "target") == 0

    assert uploads == [storage_dir]
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert storage_dir in errors[0].getMessage()
    assert errors[0].exc_info is not None
    assert "uploaded 0 alerts (1 failures)" in caplog.text


#
# analysis cache maintenance
#

@pytest.mark.unit
def test_emit_cache_stats_failure_is_logged_with_traceback(monkeypatch, caplog):
    def _collect():
        raise RuntimeError("cache database unavailable")

    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")
    monkeypatch.setattr(saq.util.maintenance, "collect_cache_stats", _collect)

    with caplog.at_level(logging.INFO):
        saq.util.maintenance.emit_cache_stats()

    errors = [r for r in caplog.records if "failed to collect cache_stats" in r.getMessage()]
    assert len(errors) == 1
    assert errors[0].levelno == logging.ERROR
    assert errors[0].exc_info is not None


def _record(caplog, message: str) -> logging.LogRecord:
    records = [r for r in caplog.records if r.getMessage() == message]
    assert len(records) == 1
    return records[0]


@pytest.mark.integration
def test_gc_durable_blobs_deletes_orphans_and_logs_the_stats(tmp_path, monkeypatch, caplog):
    store = LocalHardlinkBlobStore(LocalHardlinkBlobStoreConfig(root_dir=str(tmp_path / "blob_store")))
    orphan = store.put(b"orphan blob")
    fresh = store.put(b"fresh blob")
    past = time.time() - 3600
    os.utime(store._path_for(orphan), (past, past))
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")
    monkeypatch.setattr(saq.util.maintenance, "get_blob_store", lambda: store)
    monkeypatch.setattr(get_config().analysis_cache, "blob_gc_grace_seconds", 300)

    with caplog.at_level(logging.INFO):
        stats = saq.util.maintenance.gc_durable_blobs()

    assert not store.exists(orphan)
    assert store.exists(fresh)
    assert (stats.blobs_scanned, stats.blobs_deleted, stats.skipped_within_grace) == (2, 1, 1)
    record = _record(caplog, "blob_gc")
    assert (record.blobs_scanned, record.blobs_deleted, record.skipped_within_grace) == (2, 1, 1)
    assert record.bytes_reclaimed == len(b"orphan blob")
    assert record.dry_run is False


class _FailingBlobStore:
    def maintain_global(self, grace_period, dry_run=False):
        raise OSError("blob store unavailable")

    def maintain_local(self, budget, dry_run=False):
        raise OSError("blob store unavailable")


@pytest.mark.unit
def test_gc_durable_blobs_failure_is_logged(monkeypatch, caplog):
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")
    monkeypatch.setattr(saq.util.maintenance, "get_blob_store", _FailingBlobStore)

    with caplog.at_level(logging.INFO):
        stats = saq.util.maintenance.gc_durable_blobs()

    assert stats == GlobalMaintenanceStats()
    record = _record(caplog, "error running durable blob gc: blob store unavailable")
    assert record.levelno == logging.ERROR and record.exc_info is not None
    assert not [r for r in caplog.records if r.getMessage() == "blob_gc"]


@pytest.mark.unit
def test_maintain_local_cache_passes_the_configured_budget_and_logs_the_stats(monkeypatch, caplog):
    budgets = []

    class _Store:
        def maintain_local(self, budget, dry_run=False):
            budgets.append((budget, dry_run))
            return LocalMaintenanceStats(cache_entries_scanned=3, cache_entries_evicted=2, bytes_reclaimed=10)

    monkeypatch.setattr(saq.util.maintenance, "get_blob_store", _Store)
    monkeypatch.setattr(get_config().analysis_cache, "local_cache_max_bytes", 1024)
    monkeypatch.setattr(get_config().analysis_cache, "local_cache_max_age_seconds", 60)

    with caplog.at_level(logging.INFO):
        stats = saq.util.maintenance.maintain_local_cache(dry_run=True)

    assert budgets == [(LocalCacheBudget(max_bytes=1024, max_age=timedelta(seconds=60)), True)]
    assert stats.cache_entries_evicted == 2
    record = _record(caplog, "local_cache_maintenance")
    assert (record.entries_scanned, record.entries_evicted, record.bytes_reclaimed) == (3, 2, 10)
    assert record.dry_run is True


@pytest.mark.unit
def test_maintain_local_cache_failure_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(saq.util.maintenance, "get_blob_store", _FailingBlobStore)

    with caplog.at_level(logging.INFO):
        stats = saq.util.maintenance.maintain_local_cache()

    assert stats == LocalMaintenanceStats()
    record = _record(caplog, "error running local blob cache maintenance: blob store unavailable")
    assert record.levelno == logging.ERROR and record.exc_info is not None
