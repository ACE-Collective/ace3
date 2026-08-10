import json
import uuid
from datetime import datetime

import pytest
from sqlalchemy.exc import IntegrityError

from saq.analysis.analysis import Analysis
from saq.analysis.detection_point import DetectionPoint
from saq.constants import F_FQDN, F_URL
from saq.database import db_DetectionPoint
from saq.database.model import Alert, load_alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.signatures.builtin import BUILTIN_SIGNATURE_UUID, get_builtin_signature_version
from tests.saq.helpers import create_root_analysis, insert_alert


class ProviderAnalysis(Analysis):
    """stand-in for a clicker-style provider analysis whose detections we later delete."""
    pass


def _rows_for(alert_id):
    return get_db().query(db_DetectionPoint).filter(db_DetectionPoint.alert_id == alert_id).all()


def _make_row(alert_id, content_hash="hash-1", **kwargs):
    fields = dict(
        alert_id=alert_id,
        description="matched a rule",
        details=json.dumps({"k": "v"}),
        queue="default",
        signature_uuid="11111111-1111-1111-1111-111111111111",
        signature_version="deadbeef",
        content_hash=content_hash,
    )
    fields.update(kwargs)
    return db_DetectionPoint(**fields)


@pytest.mark.integration
def test_insert_and_read_back():
    alert = insert_alert()
    row = _make_row(alert.id)
    get_db().add(row)
    get_db().commit()

    read = get_db().query(db_DetectionPoint).filter(db_DetectionPoint.id == row.id).one()
    assert read.alert_id == alert.id
    assert read.description == "matched a rule"
    assert read.queue == "default"
    assert read.signature_uuid == "11111111-1111-1111-1111-111111111111"
    assert read.signature_version == "deadbeef"
    assert read.content_hash == "hash-1"
    assert read.insert_date is not None
    # details is JSON-as-text
    assert json.loads(read.details) == {"k": "v"}


@pytest.mark.integration
def test_cascade_delete_with_alert():
    alert = insert_alert()
    alert_id = alert.id
    row = _make_row(alert_id, content_hash="cascade-hash")
    get_db().add(row)
    get_db().commit()
    dp_id = row.id

    # delete the alert -> the detection_points row should be gone (ON DELETE CASCADE)
    get_db().query(Alert).filter(Alert.id == alert_id).delete()
    get_db().commit()

    assert get_db().query(db_DetectionPoint).filter(db_DetectionPoint.id == dp_id).first() is None


@pytest.mark.integration
def test_unique_alert_content_hash():
    alert = insert_alert()
    get_db().add(_make_row(alert.id, content_hash="dup"))
    get_db().commit()

    get_db().add(_make_row(alert.id, content_hash="dup"))
    with pytest.raises(IntegrityError):
        get_db().commit()
    get_db().rollback()


@pytest.mark.integration
@pytest.mark.parametrize("missing", ["alert_id", "signature_uuid", "signature_version", "content_hash"])
def test_not_null_columns(missing):
    alert = insert_alert()
    kwargs = dict(
        alert_id=alert.id,
        signature_uuid="u",
        signature_version="v",
        content_hash="c-" + missing,
    )
    kwargs[missing] = None
    row = db_DetectionPoint(description="d", **kwargs)
    get_db().add(row)
    with pytest.raises(IntegrityError):
        get_db().commit()
    get_db().rollback()


@pytest.mark.integration
def test_details_nullable():
    alert = insert_alert()
    row = _make_row(alert.id, content_hash="null-details", details=None)
    get_db().add(row)
    get_db().commit()
    read = get_db().query(db_DetectionPoint).filter(db_DetectionPoint.id == row.id).one()
    assert read.details is None


# --- sync-path tests: exercise Alert.sync() actually populating the table ---

YARA_SIGNATURE_UUID = "11111111-1111-1111-1111-111111111111"
YARA_SIGNATURE_VERSION = "deadbeef"


def _alert_with_detections():
    """builds and syncs an alert carrying a root-level detection and a yara-style
    observable detection. returns the loaded Alert."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()

    root.add_detection_point("real detection")

    o = root.add_observable_by_spec(F_FQDN, "evil.example.com")
    o.add_detection_point(
        "yara hit",
        details={"rule": "r"},
        queue="experimental",
        signature_uuid=YARA_SIGNATURE_UUID,
        signature_version=YARA_SIGNATURE_VERSION)

    root.save()
    ALERT(root)  # creates the alert and syncs (build_index=True by default)
    return load_alert(root.uuid)


@pytest.mark.integration
def test_sync_writes_detection_points():
    alert = _alert_with_detections()

    rows = _rows_for(alert.id)
    assert len(rows) == 2

    by_hash = {r.content_hash: r for r in rows}

    yara_dp = DetectionPoint(
        "yara hit", details={"rule": "r"},
        signature_uuid=YARA_SIGNATURE_UUID, signature_version=YARA_SIGNATURE_VERSION)
    yara_row = by_hash[yara_dp.content_hash]
    assert yara_row.description == "yara hit"
    assert yara_row.queue == "experimental"
    assert yara_row.signature_uuid == YARA_SIGNATURE_UUID
    assert yara_row.signature_version == YARA_SIGNATURE_VERSION
    assert json.loads(yara_row.details) == {"rule": "r"}

    builtin_dp = DetectionPoint("real detection")
    builtin_row = by_hash[builtin_dp.content_hash]
    assert builtin_row.description == "real detection"
    assert builtin_row.signature_uuid == BUILTIN_SIGNATURE_UUID
    assert builtin_row.signature_version == get_builtin_signature_version()
    assert builtin_row.details is None


@pytest.mark.integration
def test_sync_is_idempotent():
    alert = _alert_with_detections()

    first = {r.content_hash: (r.id, r.insert_date) for r in _rows_for(alert.id)}
    assert len(first) == 2

    # re-sync: no duplicate rows, same ids, insert_date preserved
    alert.sync()

    second = {r.content_hash: (r.id, r.insert_date) for r in _rows_for(alert.id)}
    assert second == first


@pytest.mark.integration
def test_sync_no_detection_points():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.add_observable_by_spec(F_FQDN, "benign.example.com")
    root.save()
    ALERT(root)
    alert = load_alert(root.uuid)

    assert _rows_for(alert.id) == []


@pytest.mark.integration
def test_sync_non_json_native_details():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    o = root.add_observable_by_spec(F_FQDN, "evil.example.com")
    o.add_detection_point("ts detection", details={"when": datetime(2026, 6, 17, 12, 0, 0)})
    root.save()
    ALERT(root)
    alert = load_alert(root.uuid)

    rows = _rows_for(alert.id)
    assert len(rows) == 1
    # the value survives serialization (the analysis-layer JSON round-trip renders
    # the datetime as an ISO string; default=str is the fallback for anything it misses)
    assert json.loads(rows[0].details)["when"] == "2026-06-17T12:00:00.000000"


@pytest.mark.integration
def test_sync_delayed_skips_detection_points():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    o = root.add_observable_by_spec(F_FQDN, "evil.example.com")
    o.add_detection_point("yara hit")
    root.save()
    ALERT(root)
    alert = load_alert(root.uuid)

    # delayed sync does not rebuild the index, so no detection points are written
    get_db().query(db_DetectionPoint).filter(db_DetectionPoint.alert_id == alert.id).delete()
    get_db().commit()
    alert.sync(build_index=False)
    assert _rows_for(alert.id) == []

    # a normal sync writes them
    alert.sync()
    assert len(_rows_for(alert.id)) == 1


# --- detection_count is computed on the fly from detection_points ---


@pytest.mark.integration
def test_detection_count_matches_rows():
    alert = _alert_with_detections()
    assert len(_rows_for(alert.id)) == 2
    assert alert.detection_count == 2


@pytest.mark.integration
def test_detection_count_zero_without_detections():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.add_observable_by_spec(F_FQDN, "benign.example.com")
    root.save()
    ALERT(root)
    alert = load_alert(root.uuid)

    assert _rows_for(alert.id) == []
    # computed value is 0, not None
    assert alert.detection_count == 0


@pytest.mark.integration
def test_detection_count_tracks_row_changes():
    alert = _alert_with_detections()
    alert_id = alert.id
    assert alert.detection_count == 2

    # adding a row is reflected without any explicit write to the alert
    get_db().add(_make_row(alert_id, content_hash="extra-hash"))
    get_db().commit()
    get_db().expire_all()
    assert get_db().query(Alert).filter(Alert.id == alert_id).one().detection_count == 3

    # removing all rows -> count is 0
    get_db().query(db_DetectionPoint).filter(db_DetectionPoint.alert_id == alert_id).delete()
    get_db().commit()
    get_db().expire_all()
    assert get_db().query(Alert).filter(Alert.id == alert_id).one().detection_count == 0


@pytest.mark.integration
def test_detection_count_query_expression():
    alert = _alert_with_detections()
    # the hybrid property's class-level expression is usable directly in a query
    count = get_db().query(Alert.detection_count).filter(Alert.id == alert.id).scalar()
    assert count == 2


# --- reconcile-on-sync: detections removed from the tree are removed from the table ---


def _alert_with_provider_detection():
    """builds and syncs an alert carrying a root-level detection plus a provider analysis
    that generated a child observable with its own detection. returns the loaded Alert."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()

    root.add_detection_point("real detection")  # root-level, must survive a delete

    obs = root.add_observable_by_spec(F_FQDN, "evil.example.com")
    analysis = ProviderAnalysis()
    obs.add_analysis(analysis)
    child = analysis.add_observable_by_spec(F_URL, "https://evil.example.com/clicked")
    child.add_detection_point(
        "someone clicked",
        signature_uuid=YARA_SIGNATURE_UUID,
        signature_version=YARA_SIGNATURE_VERSION)

    root.save()
    ALERT(root)
    return load_alert(root.uuid)


@pytest.mark.integration
def test_sync_reconciles_deleted_analysis_detection_points():
    alert = _alert_with_provider_detection()
    assert len(_rows_for(alert.id)) == 2

    obs = alert.root_analysis.get_observables_by_type(F_FQDN)[0]
    analysis = obs.get_analysis(ProviderAnalysis)
    assert analysis is not None

    obs.delete_analysis(analysis)
    alert.sync()

    # the provider's detection is gone; the root-level detection survives
    rows = _rows_for(alert.id)
    assert len(rows) == 1
    assert rows[0].content_hash == DetectionPoint("real detection").content_hash

    get_db().expire_all()
    assert get_db().query(Alert).filter(Alert.id == alert.id).one().detection_count == 1


@pytest.mark.integration
def test_sync_reconciles_to_zero_when_all_detections_removed():
    """covers the empty-set branch: deleting the only detection clears every row."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()

    obs = root.add_observable_by_spec(F_FQDN, "evil.example.com")
    analysis = ProviderAnalysis()
    obs.add_analysis(analysis)
    child = analysis.add_observable_by_spec(F_URL, "https://evil.example.com/clicked")
    child.add_detection_point("someone clicked")

    root.save()
    ALERT(root)
    alert = load_alert(root.uuid)
    assert len(_rows_for(alert.id)) == 1

    target = alert.root_analysis.get_observables_by_type(F_FQDN)[0]
    target.delete_analysis(target.get_analysis(ProviderAnalysis))
    alert.sync()

    assert _rows_for(alert.id) == []
