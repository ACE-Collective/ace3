from datetime import date, timedelta

from flask import url_for
import pytest

from saq.constants import CLOSED_EVENT_LIMIT
from saq.database.model import (
    Event,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventType,
    EventVector,
)
from saq.database.pool import get_db


@pytest.fixture
def closed_events():
    """Creates CLOSED_EVENT_LIMIT * 2 closed events, newest first."""
    db = get_db()

    prevention_tool = EventPreventionTool(value="test_prevention_tool")
    remediation = EventRemediation(value="test_remediation")
    risk_level = EventRiskLevel(value="test_risk_level")
    status = EventStatus(value="CLOSED")
    event_type = EventType(value="test_type")
    vector = EventVector(value="test_vector")
    db.add_all([prevention_tool, remediation, risk_level, status, event_type, vector])

    events = []
    for index in range(CLOSED_EVENT_LIMIT * 2):
        event = Event(
            name=f"closed event {index}",
            # unique creation dates so the creation_date DESC ordering is deterministic
            creation_date=date.today() - timedelta(days=index),
            prevention_tool=prevention_tool,
            remediation=remediation,
            risk_level=risk_level,
            status=status,
            type=event_type,
            vector=vector,
        )
        events.append(event)

    db.add_all(events)
    db.commit()

    yield events


@pytest.mark.integration
def test_load_more_events_returns_next_batch(web_client, closed_events):
    """The first page shows CLOSED_EVENT_LIMIT events, so asking for more returns the next batch."""
    response = web_client.get(url_for("analysis.load_more_events", count=CLOSED_EVENT_LIMIT))
    assert response.status_code == 200

    html = response.get_data(as_text=True)

    # events are ordered by creation_date descending, which is the order they were created in
    for event in closed_events[CLOSED_EVENT_LIMIT:]:
        assert f'id="event_container_div_{event.id}"' in html

    # ... and none of the events already on the page
    for event in closed_events[:CLOSED_EVENT_LIMIT]:
        assert f'id="event_container_div_{event.id}"' not in html


@pytest.mark.integration
def test_load_more_events_end_of_list(web_client, closed_events):
    """The Show more... button is dropped once there is nothing left to load."""
    response = web_client.get(url_for("analysis.load_more_events", count=CLOSED_EVENT_LIMIT))
    assert response.status_code == 200
    assert "load-more-events-btn" not in response.get_data(as_text=True)

    # but it is still there while events remain
    response = web_client.get(url_for("analysis.load_more_events", count=1))
    assert response.status_code == 200
    assert "load-more-events-btn" in response.get_data(as_text=True)


@pytest.mark.integration
def test_load_more_events_button_carries_absolute_url(web_client, closed_events):
    """The button passes itself to the handler along with a blueprint-resolved URL.

    The handler used to fetch a path relative to the current page, which 404'd from
    /events/manage since that blueprint has a url_prefix.
    """
    response = web_client.get(url_for("analysis.load_more_events", count=1))
    html = response.get_data(as_text=True)

    assert f'data-url="{url_for("analysis.load_more_events")}"' in html
    assert "loadMoreClosedEvents(this)" in html


@pytest.mark.integration
def test_load_more_events_shows_save_button(web_client, closed_events):
    """Selecting a dynamically loaded event has to reveal the Save button, same as the
    events rendered inline by base.html."""
    response = web_client.get(url_for("analysis.load_more_events", count=CLOSED_EVENT_LIMIT))
    html = response.get_data(as_text=True)

    assert "toggleNewEventDialog();showEventSaveButton()" in html


#
# add_to_event
#

@pytest.fixture
def event_lookups():
    """add_to_event gives a new event the first row of each lookup table."""
    db = get_db()
    rows = [EventPreventionTool(value="test_prevention_tool"), EventRemediation(value="test_remediation"),
            EventRiskLevel(value="test_risk_level"), EventStatus(value="OPEN"), EventType(value="test_type"),
            EventVector(value="test_vector")]
    db.add_all(rows)
    db.commit()
    yield rows
    # the analyst fixture deletes its user on the way out, which events.owner_id would block
    db.query(Event).update({Event.owner_id: None})
    db.commit()


def _alerts(count: int):
    from tests.saq.helpers import insert_alert
    return [insert_alert() for _ in range(count)]


def _mapped(event_id: int) -> set[int]:
    from saq.database.model import EventMapping

    get_db().expire_all()
    return {m.alert_id for m in get_db().query(EventMapping).filter(EventMapping.event_id == event_id)}


def _add(web_client, **form):
    return web_client.post(url_for("analysis.add_to_event"), data={"event_name": "", **form})


@pytest.mark.integration
def test_add_to_new_event(web_client, event_lookups, analyst):
    from saq.database.model import Alert, CompanyMapping

    alerts = _alerts(2)
    # the event is dated by its oldest alert
    get_db().query(Alert).filter(Alert.id == alerts[0].id).update({Alert.insert_date: "2026-01-02 03:04:05"})
    get_db().commit()
    with web_client.session_transaction() as session:
        session["checked"] = [a.uuid for a in alerts]

    response = _add(web_client, event="NEW", event_name="  new event  ", event_comment="first look",
                    event_time="2026-01-01 00:00:00", alert_time="2026-01-02 03:04:05",
                    alert_uuids=",".join(a.uuid for a in alerts))

    assert response.status_code == 302
    assert response.headers["Location"].endswith(url_for("analysis.manage"))
    event = get_db().query(Event).filter(Event.name == "new event").one()
    assert str(event.creation_date) == "2026-01-02"
    assert event.comment == "first look"
    assert event.owner_id == analyst
    assert str(event.event_time) == "2026-01-01 00:00:00"
    assert (event.status.value, event.type.value, event.vector.value) == ("OPEN", "test_type", "test_vector")
    assert _mapped(event.id) == {a.id for a in alerts}
    assert get_db().query(CompanyMapping).filter(CompanyMapping.event_id == event.id).count() == 1
    with web_client.session_transaction() as session:
        # the selected alerts are cleared
        assert "checked" not in session


@pytest.mark.integration
def test_add_to_new_event_with_the_name_of_an_existing_one(web_client, event_lookups):
    first, second = _alerts(2)
    _add(web_client, event="NEW", event_name="same name", alert_uuids=first.uuid)
    _add(web_client, event="NEW", event_name="same name", alert_uuids=second.uuid)

    [event] = get_db().query(Event).filter(Event.name == "same name").all()
    assert _mapped(event.id) == {first.id, second.id}


@pytest.mark.integration
def test_add_to_existing_event(web_client, event_lookups):
    first, second = _alerts(2)
    _add(web_client, event="NEW", event_name="existing", alert_uuids=first.uuid)
    event = get_db().query(Event).filter(Event.name == "existing").one()

    response = _add(web_client, event=str(event.id), alert_uuids=second.uuid, redirect_to="events_manage")

    assert response.headers["Location"].endswith(url_for("events.manage"))
    assert _mapped(event.id) == {first.id, second.id}


@pytest.mark.integration
def test_add_to_event_skips_alerts_that_no_longer_exist(web_client, event_lookups):
    [alert] = _alerts(1)

    response = _add(web_client, event="NEW", event_name="partly gone", alert_uuids=f"{alert.uuid},00000000-0000-0000-0000-000000000000")

    assert response.status_code == 302
    event = get_db().query(Event).filter(Event.name == "partly gone").one()
    assert _mapped(event.id) == {alert.id}
    with web_client.session_transaction() as session:
        assert "1 of the selected alerts no longer exist" in str(session.get("_flashes"))


@pytest.mark.integration
def test_add_to_new_event_when_no_alert_exists(web_client, event_lookups):
    response = _add(web_client, event="NEW", event_name="all gone", alert_uuids="00000000-0000-0000-0000-000000000000")

    assert response.status_code == 302
    event = get_db().query(Event).filter(Event.name == "all gone").one()
    assert event.creation_date == date.today()
    assert _mapped(event.id) == set()


@pytest.mark.integration
def test_add_to_event_rejects_dates_out_of_order(web_client, event_lookups):
    [alert] = _alerts(1)

    response = _add(web_client, event="NEW", event_name="bad dates", alert_uuids=alert.uuid,
                    event_time="2026-01-02 00:00:00", alert_time="2026-01-01 00:00:00")

    assert response.headers["Location"].endswith(url_for("analysis.manage"))
    assert get_db().query(Event).filter(Event.name == "bad dates").count() == 0
    with web_client.session_transaction() as session:
        assert "out of valid order" in str(session.get("_flashes"))
