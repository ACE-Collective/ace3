"""A SIMULATED alert is never reset or re-analyzed from the GUI, and gets no new observables: the
detections its test run's review froze stay as they are (docs/SVS_RUNS.md). The observable actions
are API v2 endpoints, tested in tests/aceapi_v2/alerts/test_observable_actions.py."""

from io import BytesIO

import pytest
from flask import url_for

from saq.database.model import Alert, load_alert
from tests.saq.helpers import insert_alert, make_simulated, workload_count

pytestmark = pytest.mark.integration


@pytest.fixture
def simulated():
    alert = insert_alert()
    make_simulated(alert)
    return alert


def _flashes(web_client) -> list[str]:
    with web_client.session_transaction() as sess:
        return [message for _category, message in sess.get("_flashes", [])]


def _observable_count(alert: Alert) -> int:
    alert = load_alert(alert.uuid)
    alert.load()
    return len(alert.root_analysis.observables)


def _refusal(alert: Alert) -> str:
    return f"alert {alert.uuid} is SIMULATED, a disposition only ACE sets"


def test_analyze_alert_refuses(web_client, simulated):
    response = web_client.post(url_for("analysis.analyze_alert"), data={"alert_uuid": simulated.uuid})

    assert response.status_code == 302
    assert f"direct={simulated.uuid}" in response.location
    assert workload_count(simulated.uuid) == 0
    assert _flashes(web_client)[0].startswith(_refusal(simulated))


def test_analyze_alert_still_analyzes_other_alerts(web_client):
    alert = insert_alert()
    before = workload_count(alert.uuid)

    web_client.post(url_for("analysis.analyze_alert"), data={"alert_uuid": alert.uuid})

    assert workload_count(alert.uuid) == before + 1


def test_upload_file_to_the_alert_refuses(web_client, simulated):
    observables = _observable_count(simulated)

    response = web_client.post(url_for("analysis.upload_file"), data={
        "file_path": (BytesIO(b"more evidence"), "more.txt"),
        "comment": "",
        "alert_uuid": simulated.uuid,
    }, content_type="multipart/form-data")

    assert response.status_code == 302
    assert _observable_count(simulated) == observables
    assert workload_count(simulated.uuid) == 0
    assert _flashes(web_client)[0].startswith(_refusal(simulated))


def test_add_observable_refuses(web_client, simulated):
    observables = _observable_count(simulated)

    response = web_client.post(url_for("analysis.add_observable"), data={
        "alert_uuid": simulated.uuid,
        "add_observable_type": "ipv4",
        "add_observable_value": "192.0.2.10",
        "add_observable_time": "",
    })

    assert response.status_code == 302
    assert _observable_count(simulated) == observables
    assert workload_count(simulated.uuid) == 0
    assert _flashes(web_client)[0].startswith(_refusal(simulated))
