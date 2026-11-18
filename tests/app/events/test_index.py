"""The event analysis page (events.index): how it finds its event, and what it costs to render."""

import logging
from datetime import date

import pytest
from flask import url_for

from saq.database.model import (
    Alert,
    Comment,
    Event,
    EventMapping,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventType,
    EventVector,
    Malware,
)
from saq.database.pool import get_db
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.integration


def _event(*alerts) -> Event:
    db = get_db()
    event = Event(
        name="index test event",
        creation_date=date.today(),
        status=EventStatus(value="OPEN"),
        remediation=EventRemediation(value="index_remediation"),
        risk_level=EventRiskLevel(value="index_risk_level"),
        prevention_tool=EventPreventionTool(value="index_prevention_tool"),
        type=EventType(value="index_type"),
        vector=EventVector(value="index_vector"),
    )
    db.add(event)
    db.flush()
    for alert in alerts:
        db.add(EventMapping(event_id=event.id, alert_id=alert.id))
    db.commit()
    return event


def _cold_session():
    """Forgets what the fixtures loaded: the web client shares this session, and an Alert keeps the
    RootAnalysis it was created with."""
    get_db().expire_all()
    for obj in list(get_db().identity_map.values()):
        if isinstance(obj, Alert):
            obj._root_analysis = None


def test_event_page_shows_alerts_and_comments_without_loading_them(web_client, analyst, monkeypatch):
    alerts = [insert_alert(), insert_alert()]
    event = _event(*alerts)
    db = get_db()
    db.add(Comment(uuid=alerts[0].uuid, user_id=analyst, comment="looks like the invoice campaign"))
    db.add(Comment(uuid=alerts[0].uuid, user_id=analyst, comment="blocked the sender"))
    db.commit()
    _cold_session()

    loads = []
    original_load = Alert.load
    monkeypatch.setattr(Alert, "load", lambda self, *args, **kwargs: (loads.append(self.uuid), original_load(self, *args, **kwargs))[1])

    response = web_client.get(url_for("events.index", direct=event.id))

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    for alert in alerts:
        assert alert.uuid in html
    assert "looks like the invoice campaign" in html
    assert "blocked the sender" in html
    # nothing on the page comes from an alert's analysis on disk
    assert loads == []


@pytest.mark.parametrize("parameter", ["direct", "event_id"])
def test_event_page_by_id(web_client, parameter):
    event = _event(insert_alert())

    response = web_client.get(url_for("events.index", **{parameter: event.id}))

    assert response.status_code == 200
    assert "index test event" in response.get_data(as_text=True)


def test_event_page_by_uuid(web_client):
    event = _event(insert_alert())
    # a uuid that starts with digits must not be read as the id those digits spell
    # the id overwrites the start of the uuid instead of being prepended to it, so the uuid stays
    # 36 characters however many events earlier tests on this worker created
    template = "00000000-719b-4f5d-b52a-feea593095fb"
    event.uuid = f"{event.id}{template[len(str(event.id)):]}"
    get_db().commit()

    response = web_client.get(url_for("events.index", direct=event.uuid))

    assert response.status_code == 200
    assert "index test event" in response.get_data(as_text=True)


@pytest.mark.parametrize("event_id", ["999999", "00000000-0000-0000-0000-000000000000"])
def test_unknown_event_redirects_to_the_manage_page(web_client, caplog, event_id):
    with caplog.at_level(logging.ERROR):
        response = web_client.get(url_for("events.index", direct=event_id))

    assert response.status_code == 302
    assert response.headers["Location"].endswith(url_for("events.manage"))
    assert f"Could not get event {event_id}" in caplog.text


def test_new_malware_option(web_client):
    db = get_db()
    db.add(Malware(name="index_test_malware"))
    db.commit()

    response = web_client.get(url_for("events.new_malware_option", index=3))

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "index_test_malware" in html
