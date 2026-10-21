from datetime import datetime, timedelta

from saq.analysis import RootAnalysis
from saq.database import ALERT, Alert, Event, get_db
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_SIMULATED, ENV_ACE_IS_PRIMARY_NODE
from saq.database.model import DetectionPoint
from saq.signatures.builtin import BUILTIN_SIGNATURE_UUID
from saq.util.maintenance import archive_simulated_alerts, cleanup_alerts, distribute_old_alerts
from tests.saq.helpers import insert_alert_with_detections, make_simulated

import saq.util.maintenance

import pytest

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

def _simulated_alert(days_ago: int) -> Alert:
    alert = insert_alert_with_detections([
        {"description": "test signature fired", "signature_uuid": BUILTIN_SIGNATURE_UUID, "fqdn": "test.example.com"},
    ])
    make_simulated(alert)
    db = get_db()
    db.query(Alert).filter(Alert.id == alert.id).update(
        {Alert.disposition_time: datetime.now() - timedelta(days=days_ago)})
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
