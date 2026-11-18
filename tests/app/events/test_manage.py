import hashlib
import re
from datetime import date, datetime, timedelta
from uuid import uuid4

from flask import url_for
import pytest

from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE
from saq.database.model import (
    Alert,
    Campaign,
    Comment,
    Company,
    CompanyMapping,
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
    Observable,
    ObservableMapping,
    Tag,
    TagMapping,
    Threat,
    ThreatType,
)
from saq.configuration.config import get_config
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


def _rows(html: str) -> list[str]:
    """The event ids listed, in order, as many times as each is listed."""
    return re.findall(r'id="event_row_(\d+)"', html)


def _ids(*events) -> list[str]:
    return [str(event.id) for event in events]


def test_manage_redirects_when_events_are_not_displayed(web_client, monkeypatch):
    monkeypatch.setattr(get_config().gui, "display_events", False)

    response = web_client.get(url_for("events.manage"))

    assert response.status_code == 302
    assert response.headers["Location"].endswith(url_for("analysis.index"))


def test_manage_filters_by_date_range(web_client, lookups):
    today = _make_events(lookups, 1, name="today")[0]
    ten_days_ago = _make_events(lookups, 1, name="old")[0]
    ten_days_ago.creation_date = date.today() - timedelta(days=10)
    get_db().commit()

    start = (datetime.now() - timedelta(days=2)).strftime("%m-%d-%Y %H:%M")
    end = (datetime.now() + timedelta(days=1)).strftime("%m-%d-%Y %H:%M")
    html, _ = _render(web_client, event_daterange=f"{start} - {end}")
    assert _rows(html) == _ids(today)

    # a range that does not parse falls back to the last 7 days, and says so
    html, _ = _render(web_client, event_daterange="last tuesday")
    assert "error parsing date range, using default 7 days" in html
    assert _rows(html) == _ids(today)


def test_manage_filters_by_status_and_owner(web_client, lookups):
    owned = _make_events(lookups, 1, name="owned")[0]
    unowned = _make_events(lookups, 1, name="unowned")[0]
    unowned.owner_id = None
    closed_status = EventStatus(value="CLOSED")
    closed = _make_events(lookups, 1, name="closed")[0]
    closed.status = closed_status
    get_db().commit()

    # OPEN is the default
    html, _ = _render(web_client)
    assert sorted(_rows(html)) == sorted(_ids(owned, unowned))

    html, _ = _render(web_client, filter_event_status="CLOSED")
    assert _rows(html) == _ids(closed)

    html, _ = _render(web_client, filter_event_status="OPEN", filter_event_owner=str(lookups["owner_id"]))
    assert _rows(html) == _ids(owned)

    html, _ = _render(web_client, filter_event_status="OPEN", filter_event_owner="None")
    assert _rows(html) == _ids(unowned)


@pytest.mark.parametrize("field,lookup", [
    ("filter_event_type", "type"),
    ("filter_event_vector", "vector"),
    ("filter_event_prevention_tool", "prevention_tool"),
    ("filter_event_risk_level", "risk_level"),
])
def test_manage_filters_by_event_attribute(web_client, lookups, field, lookup):
    event = _make_events(lookups, 1)[0]

    html, _ = _render(web_client, **{field: lookups[lookup].value})
    assert _rows(html) == _ids(event)

    html, _ = _render(web_client, **{field: "no such value"})
    assert _rows(html) == []


def test_manage_filters_by_malware_company_and_campaign(web_client, lookups):
    tagged = _make_events(lookups, 1, name="tagged")[0]
    plain = _make_events(lookups, 1, name="plain")[0]
    db = get_db()
    company = Company(name="test_company")
    db.add(company)
    db.flush()
    db.add(CompanyMapping(event_id=tagged.id, company_id=company.id))
    db.query(MalwareMapping).filter(MalwareMapping.event_id == plain.id).delete()
    plain.campaign = None
    db.commit()

    for form in ({f"malz_{lookups['malware'].id}": "on"},
                 {f"company_{company.id}": "on"},
                 {f"campaign_{lookups['campaign'].id}": "on"}):
        html, _ = _render(web_client, **form)
        assert _rows(html) == _ids(tagged), form


def _add_observable(alert_ids: list[int], observable_type: str, value: str) -> Observable:
    db = get_db()
    observable = Observable(type=observable_type, value=value.encode(), sha256=hashlib.sha256(value.encode()).digest())
    db.add(observable)
    db.flush()
    for alert_id in alert_ids:
        db.add(ObservableMapping(observable_id=observable.id, alert_id=alert_id))
    db.commit()
    return observable


def _alert_ids(event: Event) -> list[int]:
    return [mapping.alert_id for mapping in get_db().query(EventMapping).filter(EventMapping.event_id == event.id)]


def test_manage_filters_by_observable(web_client, lookups):
    with_ip = _make_events(lookups, 1, name="with ip")[0]
    with_fqdn = _make_events(lookups, 1, name="with fqdn")[0]
    # every alert of the event carries it: the event is still listed once
    _add_observable(_alert_ids(with_ip), "ipv4", "10.20.30.40")
    _add_observable(_alert_ids(with_fqdn)[:1], "fqdn", "evil.example.com")

    html, _ = _render(web_client, filter_observable_type="ipv4", filter_observable_value="10.20.30.40")
    assert _rows(html) == _ids(with_ip)

    html, _ = _render(web_client, filter_observable_type="ipv4", filter_observable_value="10.20.30.41")
    assert _rows(html) == []

    html, _ = _render(web_client, filter_observable_type="fqdn")
    assert _rows(html) == _ids(with_fqdn)

    html, _ = _render(web_client, filter_observable_type="ipv4")
    assert _rows(html) == _ids(with_ip)

    html, _ = _render(web_client, filter_observable_value="evil.example.com")
    assert _rows(html) == _ids(with_fqdn)


@pytest.mark.parametrize("sort_field", ["date", "event", "campaign", "prevention", "remediation", "status",
                                        "risk_level", "owner", "disposition"])
def test_manage_sorts_without_losing_events(web_client, lookups, sort_field):
    owned = _make_events(lookups, 1, name="owned")[0]
    # no owner and no campaign: nothing is required to sort by them
    unowned = _make_events(lookups, 1, name="unowned", disposition=DISPOSITION_FALSE_POSITIVE)[0]
    unowned.owner_id = None
    unowned.campaign = None
    # and a different value in every other sort column, so the order is never a tie
    unowned.creation_date = date.today() - timedelta(days=1)
    unowned.type = EventType(value="other_type")
    unowned.vector = EventVector(value="other_vector")
    unowned.prevention_tool = EventPreventionTool(value="other_prevention_tool")
    unowned.remediation = EventRemediation(value="other_remediation")
    unowned.risk_level = EventRiskLevel(value="other_risk_level")
    unowned.status = EventStatus(value="CLOSED")
    get_db().commit()
    both_statuses = {"filter_event_status": ["OPEN", "CLOSED"]}

    # the first post sorts by the field, the second the other way round
    first, _ = _render(web_client, sort_field=sort_field, **both_statuses)
    second, _ = _render(web_client, sort_field=sort_field, **both_statuses)

    assert sorted(_rows(first)) == sorted(_ids(owned, unowned))
    assert _rows(second) == list(reversed(_rows(first)))


def test_manage_event_details_shows_alert_comments(web_client, lookups, analyst):
    event = _make_events(lookups, 1, alerts_per_event=2)[0]
    alerts = get_db().query(Alert).filter(Alert.id.in_(_alert_ids(event))).all()
    db = get_db()
    db.add(Comment(uuid=alerts[0].uuid, user_id=analyst, comment="first look"))
    db.add(Comment(uuid=alerts[0].uuid, user_id=analyst, comment="second look"))
    db.commit()

    response = web_client.get(url_for("events.manage_event_details", event_id=event.id))

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "first look" in html and "second look" in html
