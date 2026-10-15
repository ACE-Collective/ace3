"""What one alert's page shows of SVS (saq.svs.alert_status.alert_svs_view; docs/SVS.md, Part 3,
*What analysts see*): its status, the runs it is attributed to, which detection each holds, and the
markers in it that disagree with their run."""

import json
from datetime import datetime

import pytest
from sqlalchemy import update

from saq.database.model import Alert, DetectionPoint, SVSAttribution, SVSRun
from saq.database.pool import get_db
from saq.signatures.builtin import SVS_MARKER_MISMATCH
from saq.svs.alert_status import AlertSVSView, MarkerMismatch, RunRef, alert_svs_view
from saq.svs.constants import SVSStatus
from tests.saq.helpers import insert_alert
from tests.saq.svs.conftest import SIGNATURE_UUID, attribute_to_run

pytestmark = pytest.mark.integration

A, B = "a" * 64, "b" * 64
TEST_GUID = "dddddddd-4444-4444-8444-444444444444"  # attribute_to_run's test


def _detections(alert: Alert, *hashes: str) -> None:
    db = get_db()
    for content_hash in hashes:
        db.add(DetectionPoint(alert_id=alert.id, description=f"detection {content_hash[:4]}",
                              signature_uuid="6f3a1b2c-1111-2222-3333-444455556666", signature_version="v1",
                              content_hash=content_hash))
    db.commit()


def _mismatch(alert: Alert, marker: str, result: str, content_hash: str = "c" * 64, details=None) -> None:
    db = get_db()
    db.add(DetectionPoint(alert_id=alert.id, description=f"SVS test run marker {marker} does not match its run",
                          details=json.dumps({"marker": marker, "result": result}) if details is None else details,
                          signature_uuid=SVS_MARKER_MISMATCH.uuid, signature_version="v1", content_hash=content_hash))
    db.commit()


def _attribute(alert: Alert, run: SVSRun, content_hash: str, removed: bool = False) -> None:
    db = get_db()
    db.add(SVSAttribution(run_id=run.id, alert_uuid=alert.uuid, content_hash=content_hash,
                          signature_uuid=SIGNATURE_UUID, confidence="marker", source="router", actor="svs",
                          created_at=datetime.now(), removed_at=datetime.now() if removed else None))
    db.commit()


def _ref(run: SVSRun, state: str = "started") -> RunRef:
    return RunRef(run.uuid, state, TEST_GUID, "PowerShell download")


def test_an_alert_svs_never_touched():
    alert = insert_alert()
    _detections(alert, A)
    assert alert_svs_view(alert.id, alert.uuid) is None


def test_a_test_alert_held_by_two_runs():
    alert = insert_alert()
    _detections(alert, A, B)
    run = attribute_to_run(alert.uuid, content_hash=A)
    other = attribute_to_run(alert.uuid, content_hash=B, state="closed")
    _attribute(alert, run, B)

    assert alert_svs_view(alert.id, alert.uuid) == AlertSVSView(
        status=SVSStatus.TEST,
        runs=(_ref(run), _ref(other, "closed")),
        detections={A: (run.uuid,), B: (run.uuid, other.uuid)})


def test_a_partial_alert_names_only_what_holds():
    alert = insert_alert()
    _detections(alert, A, B)
    run = attribute_to_run(alert.uuid, content_hash=A)
    _attribute(alert, run, B, removed=True)

    view = alert_svs_view(alert.id, alert.uuid)
    assert (view.status, view.runs, view.detections) == (SVSStatus.PARTIAL, (_ref(run),), {A: (run.uuid,)})


def test_a_test_alert_by_context():
    alert = insert_alert()
    _detections(alert, A)
    attribute_to_run(alert.uuid, content_hash=A)
    db = get_db()
    db.execute(update(SVSAttribution).where(SVSAttribution.alert_uuid == alert.uuid).values(confidence="context"))
    db.commit()
    assert alert_svs_view(alert.id, alert.uuid).status == SVSStatus.TEST_CONTEXT


def test_a_run_whose_test_left_the_catalog_has_no_name():
    alert = insert_alert()
    _detections(alert, A)
    run = attribute_to_run(alert.uuid, content_hash=A)
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(test_guid="eeeeeeee-5555-4555-8555-555555555555"))
    db.commit()
    (ref,) = alert_svs_view(alert.id, alert.uuid).runs
    assert (ref.test_guid, ref.test_name) == ("eeeeeeee-5555-4555-8555-555555555555", None)


def test_markers_that_disagree_name_their_run():
    elsewhere = insert_alert()
    run = attribute_to_run(elsewhere.uuid)

    alert = insert_alert()
    _detections(alert, A)
    # a marker may appear in any case in an alert; runs store it lower case
    _mismatch(alert, run.marker.upper(), "other host")
    _mismatch(alert, "svs-" + "q" * 26, "unknown", content_hash="d" * 64)
    # a detection whose details can't be read is left out
    _mismatch(alert, "", "", content_hash="e" * 64, details="not json")

    view = alert_svs_view(alert.id, alert.uuid)
    assert (view.status, view.runs, view.detections) == (SVSStatus.MISMATCH, (), {})
    assert view.mismatches == (MarkerMismatch(run.marker.upper(), "other host", _ref(run)),
                               MarkerMismatch("svs-" + "q" * 26, "unknown", None))
