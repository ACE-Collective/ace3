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
