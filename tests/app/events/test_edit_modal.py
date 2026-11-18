from flask import url_for
import pytest

from saq.database.model import (
    AuthUserPermission,
    Campaign,
    Event,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventType,
    EventVector,
    Malware,
    MalwareMapping,
    Threat,
)
from saq.database.pool import get_db
from saq.permissions.user import add_user_permission
from tests.app.events.test_manage import _make_events, lookups  # noqa: F401 -- lookups is a fixture

pytestmark = pytest.mark.integration


@pytest.fixture
def event(lookups):  # noqa: F811
    return _make_events(lookups, 1, alerts_per_event=0)[0]


@pytest.fixture
def options(lookups):  # noqa: F811
    """A second value for every lookup, to change the event to."""
    db = get_db()
    rows = {
        "type": EventType(value="other_type"),
        "vector": EventVector(value="other_vector"),
        "risk_level": EventRiskLevel(value="other_risk_level"),
        "prevention_tool": EventPreventionTool(value="other_prevention_tool"),
        "status": EventStatus(value="IN PROGRESS"),
        "closed": EventStatus(value="CLOSED"),
        "remediation": EventRemediation(value="other_remediation"),
    }
    db.add_all(rows.values())
    db.commit()
    return rows


def _form(event, lookups, **overrides):  # noqa: F811
    form = {
        "event_id": event.id,
        "event_name": "renamed event",
        "event_type": "other_type",
        "event_vector": "other_vector",
        "event_risk_level": "other_risk_level",
        "event_prevention": "other_prevention_tool",
        "event_comment": "a comment",
        "event_status": "IN PROGRESS",
        "event_remediation": "other_remediation",
        "event_disposition": "",
        "event_owner": str(lookups["owner_id"]),
        "campaign_id": str(lookups["campaign"].id),
    }
    form.update(overrides)
    return form


def _event(event_id: int) -> Event:
    get_db().expire_all()
    return get_db().query(Event).filter(Event.id == event_id).one()


def _only_permission(analyst_id: int, major: str, minor: str):
    get_db().query(AuthUserPermission).filter(AuthUserPermission.user_id == analyst_id).delete()
    get_db().commit()
    add_user_permission(analyst_id, major, minor)


#
# the modal
#

def test_modal(web_client, event, options):
    response = web_client.get(url_for("events.edit_event_modal", event_id=event.id))

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert event.name in html
    assert "other_type" in html
    # an open event can't be closed from here (closing it runs the close tasks)
    assert "IN PROGRESS" in html
    assert ">CLOSED<" not in html


def test_modal_for_a_closed_event_offers_closed(web_client, event, options):
    event.status = options["closed"]
    get_db().commit()

    response = web_client.get(url_for("events.edit_event_modal", event_id=event.id))

    assert response.status_code == 200
    assert "CLOSED" in response.get_data(as_text=True)


def test_modal_needs_event_read(web_client, event, analyst):
    _only_permission(analyst, "alert", "read")

    assert web_client.get(url_for("events.edit_event_modal", event_id=event.id)).status_code == 403


#
# saving
#

def test_edit(web_client, event, options, lookups):  # noqa: F811
    response = web_client.post(url_for("events.edit_event"), data=_form(event, lookups, event_time="2026-01-01 00:00:00",
                               alert_time="2026-01-01 01:00:00", remediation_time="2026-01-02 00:00:00"),
                               headers={"Referer": "https://ace.example.com/ace/events/manage"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith(url_for("events.manage"))
    edited = _event(event.id)
    assert (edited.name, edited.type.value, edited.vector.value, edited.risk_level.value, edited.prevention_tool.value,
            edited.status.value, edited.remediation.value, edited.comment) == (
        "renamed event", "other_type", "other_vector", "other_risk_level", "other_prevention_tool",
        "IN PROGRESS", "other_remediation", "a comment")
    assert str(edited.event_time) == "2026-01-01 00:00:00"
    assert str(edited.alert_time) == "2026-01-01 01:00:00"
    assert str(edited.remediation_time) == "2026-01-02 00:00:00"
    # the malware mapping is replaced by what the form selected: nothing
    assert get_db().query(MalwareMapping).filter(MalwareMapping.event_id == event.id).count() == 0


def test_edit_without_a_referrer(web_client, event, options, lookups):  # noqa: F811
    """Browsers can be set not to send one."""
    response = web_client.post(url_for("events.edit_event"), data=_form(event, lookups))

    assert response.status_code == 302
    assert url_for("events.index") in response.headers["Location"]
    assert _event(event.id).name == "renamed event"


def test_edit_rejects_dates_out_of_order(web_client, event, options, lookups):  # noqa: F811
    original = _event(event.id).name

    response = web_client.post(url_for("events.edit_event"), data=_form(event, lookups,
                               event_time="2026-01-02 00:00:00", alert_time="2026-01-01 00:00:00"))

    assert response.status_code == 302
    assert response.headers["Location"].endswith(url_for("events.manage"))
    with web_client.session_transaction() as session:
        assert "out of valid order" in str(session.get("_flashes"))
    assert _event(event.id).name == original


def test_edit_closed_event_keeps_its_dates(web_client, event, options, lookups):  # noqa: F811
    event.status = options["closed"]
    get_db().commit()

    web_client.post(url_for("events.edit_event"), data=_form(event, lookups, event_status="CLOSED", event_time="2026-01-01 00:00:00"))

    edited = _event(event.id)
    assert edited.name == "renamed event"
    assert edited.event_time is None


def test_edit_campaign(web_client, event, options, lookups):  # noqa: F811
    web_client.post(url_for("events.edit_event"), data=_form(event, lookups, campaign_id="NEW", new_campaign="new campaign"))
    assert _event(event.id).campaign.name == "new campaign"

    # naming an existing campaign reuses it
    web_client.post(url_for("events.edit_event"), data=_form(event, lookups, campaign_id="NEW", new_campaign="test_campaign"))
    assert _event(event.id).campaign.id == lookups["campaign"].id
    assert get_db().query(Campaign).filter(Campaign.name == "test_campaign").count() == 1

    # "0" removes it
    web_client.post(url_for("events.edit_event"), data=_form(event, lookups, campaign_id="0"))
    assert _event(event.id).campaign is None


def test_edit_malware(web_client, event, options, lookups):  # noqa: F811
    threat_type_id = str(lookups["threat_type"].id)
    form = _form(event, lookups,
                 malware_selection_0=str(lookups["malware"].id),
                 malware_selection_1="NEW", mal_name_1="new malware", threats_1=threat_type_id)

    web_client.post(url_for("events.edit_event"), data=form)

    new_malware = get_db().query(Malware).filter(Malware.name == "new malware").one()
    assert get_db().query(Threat).filter(Threat.malware_id == new_malware.id).count() == 1
    mapped = {m.malware_id for m in get_db().query(MalwareMapping).filter(MalwareMapping.event_id == event.id)}
    assert mapped == {lookups["malware"].id, new_malware.id}

    # posting it again reuses the malware and its threat
    web_client.post(url_for("events.edit_event"), data=_form(event, lookups, malware_selection_0="NEW", mal_name_0="new malware", threats_0=threat_type_id))
    assert get_db().query(Malware).filter(Malware.name == "new malware").count() == 1
    assert get_db().query(Threat).filter(Threat.malware_id == new_malware.id).count() == 1


def test_edit_needs_event_write(web_client, event, options, lookups, analyst):  # noqa: F811
    _only_permission(analyst, "event", "read")

    assert web_client.post(url_for("events.edit_event"), data=_form(event, lookups)).status_code == 403
    assert _event(event.id).name != "renamed event"


#
# removing alerts, and finding the event a page is about
#

def test_remove_alerts(web_client, lookups):  # noqa: F811
    from saq.database.model import EventMapping

    event = _make_events(lookups, 1, alerts_per_event=2)[0]
    mappings = get_db().query(EventMapping).filter(EventMapping.event_id == event.id).all()
    keep, remove = mappings

    # no referrer: browsers can be set not to send one
    response = web_client.post(url_for("events.remove_alerts"), data={"event_mappings": f"{event.id}_{remove.alert_id}"})

    assert response.status_code == 302
    assert f"direct={event.id}" in response.headers["Location"]
    get_db().expire_all()
    assert [m.alert_id for m in get_db().query(EventMapping).filter(EventMapping.event_id == event.id)] == [keep.alert_id]

    response = web_client.post(url_for("events.remove_alerts"), data={"event_mappings": f"{event.id}_{keep.alert_id}"},
                               headers={"Referer": "https://ace.example.com/ace/events/manage"})
    assert response.headers["Location"].endswith(url_for("events.manage"))


@pytest.mark.parametrize("referrer", [None, "https://ace.example.com/ace/events/manage", "https://ace.example.com/ace/events/analysis?direct=abc"])
def test_event_page_without_an_event(web_client, referrer):
    headers = {"Referer": referrer} if referrer else {}

    response = web_client.get(url_for("events.index"), headers=headers)

    assert response.status_code == 302
    assert response.headers["Location"].endswith(url_for("events.manage"))


def test_event_page_from_its_referrer(web_client, event):
    response = web_client.get(url_for("events.index"), headers={"Referer": f"https://ace.example.com/ace/events/analysis?direct={event.id}"})

    assert response.status_code == 200
    assert event.name in response.get_data(as_text=True)


#
# tagging events
#

def _event_tags(event_id: int) -> set[str]:
    from saq.database.model import EventTagMapping, Tag

    get_db().expire_all()
    return {t.name for t in get_db().query(Tag).join(EventTagMapping, EventTagMapping.tag_id == Tag.id).filter(EventTagMapping.event_id == event_id)}


def test_add_tags_from_the_event_page(web_client, event):
    response = web_client.post(url_for("events.add_tag"), data={"tag": "phish  urgent", "ids": str(event.id), "redirect": "analysis"})

    assert response.status_code == 302
    assert f"direct={event.id}" in response.headers["Location"]
    assert _event_tags(event.id) == {"event_tag", "phish", "urgent"}


def test_add_tags_from_the_management_page(web_client, lookups):  # noqa: F811
    first, second = _make_events(lookups, 2, alerts_per_event=0)

    response = web_client.post(url_for("events.add_tag"), data={"tag": "campaign_x", "ids": f"{first.id},{second.id}", "redirect": "management"})

    assert response.headers["Location"].endswith(url_for("events.manage"))
    assert "campaign_x" in _event_tags(first.id) and "campaign_x" in _event_tags(second.id)
    with web_client.session_transaction() as session:
        # the tagged events stay checked on the management page
        assert session["checked"] == [str(first.id), str(second.id)]


def test_add_tags_with_an_unknown_redirect(web_client, event, caplog):
    response = web_client.post(url_for("events.add_tag"), data={"tag": "phish", "ids": str(event.id), "redirect": "elsewhere"})

    assert response.headers["Location"].endswith(url_for("events.manage"))
    assert "phish" in _event_tags(event.id)
    assert any("invalid redirection value elsewhere" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("missing", ["tag", "ids", "redirect"])
def test_add_tags_missing_a_field(web_client, event, missing, caplog):
    form = {"tag": "phish", "ids": str(event.id), "redirect": "analysis"}
    del form[missing]

    response = web_client.post(url_for("events.add_tag"), data=form)

    assert response.headers["Location"].endswith(url_for("events.manage"))
    assert "phish" not in _event_tags(event.id)
    assert any(f"missing expected form item {missing}" in r.getMessage() for r in caplog.records)


def test_add_tags_to_an_event_that_fails(web_client, event, monkeypatch, caplog):
    def _fail(event_id, tag):
        raise RuntimeError("database is gone")

    monkeypatch.setattr("app.events.views.edit.tag.add_event_tag_mapping", _fail)

    web_client.post(url_for("events.add_tag"), data={"tag": "phish", "ids": str(event.id), "redirect": "analysis"})

    assert any(f"unable to add tag to event {event.id}" in r.getMessage() for r in caplog.records)
    with web_client.session_transaction() as session:
        assert "unable to be tagged" in str(session.get("_flashes"))
