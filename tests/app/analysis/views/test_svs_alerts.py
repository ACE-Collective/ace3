"""Test alerts in the alert list and on the alert page (docs/SVS.md, Part 3, *What analysts see*):
the SVS status as text linking to the run, the banner with its runs, markers and actions, the
detections greyed out on a PARTIAL TEST alert, and what the disposition dialog says of a SIMULATED
alert."""

import json

import pytest
from flask import url_for
from sqlalchemy import update

from saq.analysis.detection_identity import detection_content_hash, node_identity
from saq.constants import F_TEST, QUEUE_DEFAULT
from saq.database.model import Alert, DetectionPoint, SVSAttribution
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission
from saq.signatures.builtin import SVS_MARKER_MISMATCH
from tests.app.analysis.views.test_manage import _seed_manage_session
from tests.saq.helpers import make_simulated
from tests.saq.svs.conftest import attribute_to_run

pytestmark = pytest.mark.integration


@pytest.fixture
def alert_with_two_detections(root_analysis):
    """An alert with a detection on each of two observables; returns (alert, hash one, hash two)."""
    first = root_analysis.add_observable_by_spec(F_TEST, "one")
    second = root_analysis.add_observable_by_spec(F_TEST, "two")
    one = first.add_detection_point("first", signature_uuid="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    two = second.add_detection_point("second", signature_uuid="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    root_analysis.save()
    ALERT(root_analysis)
    alert = get_db().query(Alert).filter(Alert.uuid == root_analysis.uuid).one()
    return (alert, detection_content_hash(node_identity(first), one),
            detection_content_hash(node_identity(second), two))


def _page(client, alert: Alert) -> str:
    with client.session_transaction() as sess:
        sess['prune'] = False
        sess['prune_volatile'] = False
    response = client.get(url_for("analysis.index"), query_string={"direct": alert.uuid})
    assert response.status_code == 200
    return response.data.decode()


def _context_only(alert: Alert) -> None:
    db = get_db()
    db.execute(update(SVSAttribution).where(SVSAttribution.alert_uuid == alert.uuid).values(confidence="context"))
    db.commit()


def _attribute(alert: Alert, run, content_hash: str) -> None:
    db = get_db()
    db.add(SVSAttribution(run_id=run.id, alert_uuid=alert.uuid, content_hash=content_hash,
                          signature_uuid="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", confidence="marker", source="router",
                          actor="svs", created_at=run.created_at))
    db.commit()


class TestTheAlertPage:
    def test_an_alert_svs_never_touched_has_no_banner(self, web_client, alert_with_two_detections):
        alert, _, _ = alert_with_two_detections
        body = _page(web_client, alert)
        assert 'id="svs_alert_banner"' not in body
        assert "var current_alert_frozen = false;" in body

    def test_partial_greys_out_the_test_detections(self, web_client, alert_with_two_detections):
        alert, one, two = alert_with_two_detections
        run = attribute_to_run(alert.uuid, content_hash=one)
        body = _page(web_client, alert)

        assert 'id="svs_alert_banner"' in body and 'data-status="partial"' in body
        assert "bi-crosshair\" aria-hidden=\"true\"></span> PARTIAL TEST</span>" in body
        assert "Triage the others as usual." in body
        # the run, linked
        assert f'href="{url_for("svs.run_detail", run_id=run.uuid)}">PowerShell download (run {run.uuid[:8]}, started)</a>' in body
        # only the attributed detection is greyed out, in the tree and in the Detection Chains card
        assert f'id="detection_{one}" class="btn btn-danger btn-xs opacity-50"' in body
        assert f'id="detection_{two}" class="btn btn-danger btn-xs"' in body
        assert '<li class="opacity-50" title="from an SVS test run">' in body
        # the analyst can give it back; it isn't TEST?, so not "not a test"
        assert 'data-svs-action="disassociate"' in body and 'data-svs-action="not-a-test"' not in body
        assert 'id="svs_alert_modal"' in body and "/js/svs_alert.js?" in body

    def test_a_test_alert_held_by_context_offers_not_a_test(self, web_client, alert_with_two_detections):
        alert, one, two = alert_with_two_detections
        run = attribute_to_run(alert.uuid, content_hash=one)
        _attribute(alert, run, two)
        _context_only(alert)
        body = _page(web_client, alert)

        assert 'data-status="test?"' in body and "TEST?</span>" in body
        assert 'data-svs-action="not-a-test"' in body
        # nothing is greyed out on an alert that is all test
        assert "opacity-50" not in body

    def test_a_simulated_alert_says_why_its_disposition_is_frozen(self, web_client, alert_with_two_detections):
        alert, one, two = alert_with_two_detections
        run = attribute_to_run(alert.uuid, content_hash=one, state="reviewed")
        _attribute(alert, run, two)
        make_simulated(alert)
        body = _page(web_client, alert)

        assert 'data-status="test"' in body
        assert "ACE set SIMULATED when the run closed. To treat this as a real alert, use Disassociate from run." in body
        assert "var current_alert_frozen = true;" in body
        # the disposition dialog's note (selection_guard.js), as JSON: tojson escapes the apostrophe
        assert (f'var current_alert_frozen_note = "Part of SVS test run PowerShell download ({run.uuid[:8]}). '
                'Only ACE sets SIMULATED, so the disposition can\\u0027t be changed by hand. To treat this as a real '
                'alert, use Disassociate from run.";') in body

    def test_a_marker_mismatch_names_its_marker_and_run(self, web_client, alert_with_two_detections):
        alert, _, _ = alert_with_two_detections
        # a run of another alert, whose marker turns up in this one
        run = attribute_to_run("ffffffff-0000-4000-8000-000000000000")
        db = get_db()
        for marker, result, content_hash in ((run.marker, "other host", "c" * 64), ("svs-" + "q" * 26, "unknown", "d" * 64)):
            db.add(DetectionPoint(alert_id=alert.id, description="mismatch", signature_uuid=SVS_MARKER_MISMATCH.uuid,
                                  signature_version="v1", content_hash=content_hash,
                                  details=json.dumps({"marker": marker, "result": result})))
        db.commit()
        body = _page(web_client, alert)

        assert 'class="alert alert-danger py-2 mb-2"' in body and 'data-status="mismatch"' in body
        assert "MARKER MISMATCH</span>" in body and "Treat it as suspicious and investigate." in body
        assert f'<span class="font-monospace">{run.marker}</span>' in body
        assert f"the alert involves none of the targets of run <a href=\"{url_for('svs.run_detail', run_id=run.uuid)}\">" in body
        assert "no test run has it." in body
        # nothing holds it, so there is nothing to give back
        assert 'data-svs-action=' not in body

    def test_what_a_user_sees_follows_their_permissions(self, app, alert_with_two_detections):
        alert, one, _ = alert_with_two_detections
        run = attribute_to_run(alert.uuid, content_hash=one)
        user = add_user(username="svs_alert_reader", email="svs_alert_reader@localhost", display_name="reader",
                        password="TestPass123!", queue=QUEUE_DEFAULT, timezone="UTC")
        add_user_permission(user.id, "alert", "read")
        try:
            with app.test_client() as client:
                client.post(url_for("auth.login"), data={"username": "svs_alert_reader", "password": "TestPass123!"})
                body = _page(client, alert)
            # without svs:run_read the run is named, not linked; without alert:write nothing is offered
            assert f"PowerShell download (run {run.uuid[:8]}, started)" in body
            assert url_for("svs.run_detail", run_id=run.uuid) not in body
            assert 'data-svs-action=' not in body and 'id="svs_alert_modal"' not in body
        finally:
            delete_user("svs_alert_reader")


class TestTheAlertList:
    def test_the_status_is_text_linking_to_the_run(self, web_client, analyst, alert_with_two_detections):
        alert, one, _ = alert_with_two_detections
        run = attribute_to_run(alert.uuid, content_hash=one)
        make_simulated(alert)
        with web_client.session_transaction() as sess:
            _seed_manage_session(sess, analyst)

        html = web_client.get(url_for("analysis.manage_refresh")).data.decode()
        row = html[html.index(f'id="alert_row_{alert.uuid}"'):]
        row = row[:row.index("</tr>")]
        assert 'data-frozen="1"' in row
        status = (f'<a class="svs-status small text-nowrap text-decoration-none text-body" title="Some detections are from '
                  f'an SVS test run. Triage the others as usual." href="{url_for("svs.run_detail", run_id=run.uuid)}">'
                  '<span class="bi bi-crosshair" aria-hidden="true"></span> PARTIAL TEST</a>')
        assert status in row
        # text, not a badge
        assert "badge" not in row[row.index("svs-status") - 200:row.index("PARTIAL TEST")]
