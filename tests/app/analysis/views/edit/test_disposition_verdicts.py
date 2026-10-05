"""The disposition dialog's detection verdict step (POST /set_disposition with verdict_* fields)."""

import pytest
from flask import url_for
from sqlalchemy import select

from saq.database.model import DetectionPointVerdictHistory
from saq.database.pool import get_db
from saq.detection_verdicts.query import list_alert_detection_points
from tests.saq.helpers import insert_alert_with_detections

pytestmark = pytest.mark.integration

SIG_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SIG_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
MULTI = [{"description": "generic logo rule", "signature_uuid": SIG_A, "fqdn": "one.example.com"},
         {"description": "phish kit", "signature_uuid": SIG_B}]


def _rows(alert) -> dict[str, dict]:
    get_db().expire_all()
    return {row["description"]: row for row in list_alert_detection_points(alert.id)}


def _post(web_client, alert, disposition="DELIVERY", **fields):
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": disposition, "alert_uuid": alert.uuid, **fields})
    assert response.status_code == 302
    return response


def test_marked_detections_become_fp_and_the_rest_confirmed(web_client):
    alert = insert_alert_with_detections(MULTI)
    noise = _rows(alert)["generic logo rule"]["content_hash"]

    _post(web_client, alert, verdict_listed="1", verdict_fp=[noise], verdict_confirm="1")

    rows = _rows(alert)
    assert (rows["generic logo rule"]["verdict"], rows["generic logo rule"]["verdict_source"]) == ("fp", "explicit")
    assert (rows["phish kit"]["verdict"], rows["phish kit"]["verdict_source"]) == ("tp", "explicit")


def test_an_unopened_section_changes_nothing(web_client):
    # its inputs are disabled until it is opened, so verdict_listed is not sent
    alert = insert_alert_with_detections(MULTI)

    _post(web_client, alert, verdict_fp=[_rows(alert)["phish kit"]["content_hash"]])

    assert {row["verdict_source"] for row in _rows(alert).values()} == {"inherited_multi"}
    assert get_db().execute(select(DetectionPointVerdictHistory)).first() is None


def test_unchecking_clears_an_earlier_fp(web_client):
    alert = insert_alert_with_detections(MULTI)
    noise = _rows(alert)["generic logo rule"]["content_hash"]
    _post(web_client, alert, verdict_listed="1", verdict_fp=[noise])
    assert _rows(alert)["generic logo rule"]["override"] == "fp"

    _post(web_client, alert, verdict_listed="1")

    assert _rows(alert)["generic logo rule"]["override"] is None


def test_no_verdict_step_for_an_fp_disposition(web_client):
    alert = insert_alert_with_detections(MULTI)
    noise = _rows(alert)["generic logo rule"]["content_hash"]

    _post(web_client, alert, disposition="FALSE_POSITIVE", verdict_listed="1", verdict_fp=[noise])

    assert {row["override"] for row in _rows(alert).values()} == {None}


def test_no_verdict_step_from_the_manage_page(web_client):
    alert = insert_alert_with_detections(MULTI)
    noise = _rows(alert)["generic logo rule"]["content_hash"]

    web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": "DELIVERY", "alert_uuids": alert.uuid,
        "verdict_listed": "1", "verdict_fp": [noise]})

    assert {row["override"] for row in _rows(alert).values()} == {None}
