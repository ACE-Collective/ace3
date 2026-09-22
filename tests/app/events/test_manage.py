from datetime import date, timedelta
from uuid import uuid4

from flask import url_for
import pytest

from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE
from saq.database.model import (
    Alert,
    Campaign,
    Event,
    EventMapping,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventTagMapping,
    EventType,
    EventVector,
    Malware,
    MalwareMapping,
    Tag,
    TagMapping,
    Threat,
    ThreatType,
)
from saq.database.pool import get_db
from tests.saq.helpers import count_queries

pytestmark = pytest.mark.integration

ALERTS_PER_EVENT = 3


@pytest.fixture
def lookups(analyst):
    db = get_db()
    threat_type = ThreatType(name="test_threat_type")
    malware = Malware(name="test_malware")
    rows = {
        "prevention_tool": EventPreventionTool(value="test_prevention_tool"),
        "remediation": EventRemediation(value="test_remediation"),
        "risk_level": EventRiskLevel(value="test_risk_level"),
        "status": EventStatus(value="OPEN"),
        "type": EventType(value="test_type"),
        "vector": EventVector(value="test_vector"),
        "campaign": Campaign(name="test_campaign"),
        "threat_type": threat_type,
        "malware": malware,
        "event_tag": Tag(name="event_tag"),
        "alert_tag": Tag(name="alert_tag"),
    }
    db.add_all(rows.values())
    db.flush()
    db.add(Threat(malware_id=malware.id, threat_type_id=threat_type.id))
    db.commit()
    rows["owner_id"] = analyst
    yield rows

    # the analyst fixture deletes its user on the way out, which events.owner_id would block
    db.query(Event).update({Event.owner_id: None})
    db.commit()


def _make_events(lookups: dict, count: int, name: str = "event", disposition: str = DISPOSITION_DELIVERY,
                 alerts_per_event: int = ALERTS_PER_EVENT) -> list[Event]:
    """Creates fully populated events: every column the manage page renders has something
    behind it, so every lazy load the page could trigger is reachable."""
    db = get_db()
    events = []
    for index in range(count):
        event = Event(
            name=f"{name} {index}",
            # unique creation dates so the default creation_date ordering is deterministic
            creation_date=date.today() - timedelta(days=index),
            prevention_tool=lookups["prevention_tool"],
            remediation=lookups["remediation"],
            risk_level=lookups["risk_level"],
            status=lookups["status"],
            type=lookups["type"],
            vector=lookups["vector"],
            campaign=lookups["campaign"],
            owner_id=lookups["owner_id"],
        )
        db.add(event)
        db.flush()
        db.add(MalwareMapping(event_id=event.id, malware_id=lookups["malware"].id))
        db.add(EventTagMapping(event_id=event.id, tag_id=lookups["event_tag"].id))
        for _ in range(alerts_per_event):
            alert = Alert(
                uuid=str(uuid4()),
                location="test-location",
                storage_dir=f"storage/{uuid4()}",
                tool="test-tool",
                tool_instance="test-tool-instance",
                alert_type="test",
                disposition=disposition,
            )
            db.add(alert)
            db.flush()
            db.add(TagMapping(alert_id=alert.id, tag_id=lookups["alert_tag"].id))
            db.add(EventMapping(event_id=event.id, alert_id=alert.id))
        events.append(event)

    db.commit()
    return events


# what the filter form posts when nothing is selected: every <select> sends ANY
UNFILTERED_FORM = {
    "filter_event_type": "ANY",
    "filter_event_vector": "ANY",
    "filter_event_prevention_tool": "ANY",
    "filter_event_risk_level": "ANY",
    "filter_observable_type": "ANY",
}


def _render(web_client, **form) -> tuple[str, list[str]]:
    # nothing the fixtures loaded may satisfy a lazy load for free. expire rather than
    # remove(): the logged-in user lives in this session too
    get_db().expire_all()
    with count_queries() as statements:
        if form:
            response = web_client.post(url_for("events.manage"), data={**UNFILTERED_FORM, **form})
        else:
            response = web_client.get(url_for("events.manage"))
    assert response.status_code == 200
    return response.get_data(as_text=True), statements


def test_manage_renders_every_column(web_client, lookups):
    event = _make_events(lookups, 1)[0]
    html, _ = _render(web_client)

    assert f'id="event_row_{event.id}"' in html
    for expected in ("test_type - test_vector", "test_campaign", "test_threat_type", "test_malware",
                     "test_risk_level", DISPOSITION_DELIVERY, "test_prevention_tool",
                     "test_remediation", "event_tag"):
        assert expected in html
    # only the event's own tags are listed, not the ones its alerts carry
    assert "alert_tag" not in html


def test_manage_query_count_does_not_grow_with_events(web_client, lookups):
    _make_events(lookups, 2)
    _, small = _render(web_client)

    _make_events(lookups, 8, name="more")
    html, large = _render(web_client)

    assert html.count('id="event_row_') == 10
    assert len(large) == len(small), f"{len(small)} queries for 2 events, {len(large)} for 10"


def test_manage_filters_by_disposition_and_tag(web_client, lookups):
    delivery = _make_events(lookups, 1, name="delivery")[0]
    false_positive = _make_events(lookups, 1, name="fp", disposition=DISPOSITION_FALSE_POSITIVE)[0]

    html, _ = _render(web_client, filter_event_disposition=DISPOSITION_FALSE_POSITIVE)
    assert f'id="event_row_{false_positive.id}"' in html
    assert f'id="event_row_{delivery.id}"' not in html

    html, _ = _render(web_client, **{"reset-filters": "1"})
    assert f'id="event_row_{delivery.id}"' in html

    html, _ = _render(web_client, filter_event_tag="no_such_tag")
    assert 'id="event_row_' not in html

    html, _ = _render(web_client, filter_event_tag="event_tag")
    assert f'id="event_row_{delivery.id}"' in html
    assert f'id="event_row_{false_positive.id}"' in html


def test_manage_event_details_query_count_does_not_grow_with_alerts(web_client, lookups):
    few, many = (_make_events(lookups, 1, name=name, alerts_per_event=count)[0].id
                 for name, count in (("few", 2), ("many", 10)))

    counts = {}
    for event_id in (few, many):
        get_db().expire_all()
        with count_queries() as statements:
            response = web_client.get(url_for("events.manage_event_details", event_id=event_id))
        assert response.status_code == 200
        assert "alert_tag" in response.get_data(as_text=True)
        counts[event_id] = len(statements)

    assert counts[many] == counts[few], f"{counts[few]} queries for 2 alerts, {counts[many]} for 10"
