import logging
import uuid

import pytest
from flask import url_for

from saq.configuration.config import get_config
from saq.configuration.schema import DispositionConfig
from saq.constants import (
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_REVIEW_CORRECT,
    DISPOSITION_REVIEW_INCORRECT,
    DISPOSITION_REVIEW_UNREVIEWED,
    DISPOSITION_WEAPONIZATION,
    REVIEW_COMMENT_PREFIX,
)
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
    load_alert,
)
from saq.database.pool import get_db
from saq.database.util.alert import set_dispositions
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.user_management import add_user, delete_user
from tests.saq.helpers import audit_actor_of, audit_record, insert_alert, make_simulated

pytestmark = pytest.mark.integration

EVENT_ID = "1"


def _reloaded_root(alert):
    reloaded = load_alert(alert.uuid)
    reloaded.load()
    return reloaded.root_analysis


def _make_event_with_alert(alert) -> Event:
    from datetime import date

    db = get_db()
    status = EventStatus(value="bulk_status")
    remediation = EventRemediation(value="bulk_remediation")
    risk_level = EventRiskLevel(value="bulk_risk_level")
    prevention_tool = EventPreventionTool(value="bulk_prevention_tool")
    event_type = EventType(value="bulk_type")
    vector = EventVector(value="bulk_vector")
    db.add_all([status, remediation, risk_level, prevention_tool, event_type, vector])
    db.flush()

    event = Event(
        name="bulk test event",
        creation_date=date.today(),
        status=status,
        remediation=remediation,
        risk_level=risk_level,
        prevention_tool=prevention_tool,
        type=event_type,
        vector=vector,
    )
    db.add(event)
    db.flush()
    db.add(EventMapping(event_id=event.id, alert_id=alert.id))
    db.commit()
    return event



def test_bulk_add_tag_success(web_client, session_actor, caplog):
    caplog.set_level(logging.INFO)
    alert1 = insert_alert()
    alert2 = insert_alert()

    response = web_client.post(url_for("events.bulk_add_tag"), data={
        "event_id": EVENT_ID,
        "alert_uuids": f"{alert1.uuid},{alert2.uuid}",
        "tag": "bulk_tag another_tag",
    })

    assert response.status_code == 302
    assert "events/analysis" in response.location
    assert f"direct={EVENT_ID}" in response.location
    audit = audit_record(caplog, "user john added tags")
    assert (*audit_actor_of(audit), audit.alert_uuids, audit.tags) == (
        *session_actor, [alert1.uuid, alert2.uuid], ["bulk_tag", "another_tag"])

    for alert in (alert1, alert2):
        root = _reloaded_root(alert)
        assert root.has_tag("bulk_tag")
        assert root.has_tag("another_tag")


def test_bulk_remove_tag_success(web_client, session_actor, caplog):
    caplog.set_level(logging.INFO)
    alert = insert_alert()
    web_client.post(url_for("events.bulk_add_tag"), data={
        "event_id": EVENT_ID,
        "alert_uuids": alert.uuid,
        "tag": "bulk_tag",
    })
    assert _reloaded_root(alert).has_tag("bulk_tag")

    response = web_client.post(url_for("events.bulk_remove_tag"), data={
        "event_id": EVENT_ID,
        "alert_uuids": alert.uuid,
        "tag": "bulk_tag",
    })

    assert response.status_code == 302
    assert not _reloaded_root(alert).has_tag("bulk_tag")
    audit = audit_record(caplog, "user john removed tags")
    assert (*audit_actor_of(audit), audit.alert_uuids, audit.tags) == (*session_actor, [alert.uuid], ["bulk_tag"])


def test_bulk_add_tag_no_alerts_selected(web_client):
    response = web_client.post(url_for("events.bulk_add_tag"), data={
        "event_id": EVENT_ID,
        "alert_uuids": "",
        "tag": "bulk_tag",
    })

    assert response.status_code == 302
    assert f"direct={EVENT_ID}" in response.location


def test_bulk_add_comment_success(web_client, session_actor, caplog):
    caplog.set_level(logging.INFO)
    alert1 = insert_alert()
    alert2 = insert_alert()

    response = web_client.post(url_for("events.bulk_add_comment"), data={
        "event_id": EVENT_ID,
        "alert_uuids": f"{alert1.uuid},{alert2.uuid}",
        "comment": "bulk comment",
    })

    assert response.status_code == 302
    assert f"direct={EVENT_ID}" in response.location

    db = get_db()
    comments = db.query(Comment).filter(
        Comment.uuid.in_([alert1.uuid, alert2.uuid]),
        Comment.comment == "bulk comment",
    ).all()
    assert len(comments) == 2
    audit = audit_record(caplog, "user john added comment bulk comment")
    assert (*audit_actor_of(audit), audit.alert_uuids) == (*session_actor, [alert1.uuid, alert2.uuid])


def test_bulk_add_comment_empty_rejected(web_client):
    alert = insert_alert()

    response = web_client.post(url_for("events.bulk_add_comment"), data={
        "event_id": EVENT_ID,
        "alert_uuids": alert.uuid,
        "comment": "   ",
    })

    assert response.status_code == 302
    db = get_db()
    assert db.query(Comment).filter(Comment.uuid == alert.uuid).count() == 0


def test_bulk_set_disposition_success(web_client, session_actor, caplog):
    caplog.set_level(logging.INFO)
    alert1 = insert_alert()
    alert2 = insert_alert()

    response = web_client.post(url_for("events.bulk_set_disposition"), data={
        "event_id": EVENT_ID,
        "alert_uuids": f"{alert1.uuid},{alert2.uuid}",
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "comment": "bulk disposition",
    })

    assert response.status_code == 302
    assert f"direct={EVENT_ID}" in response.location

    db = get_db()
    for alert in (alert1, alert2):
        db.refresh(alert)
        assert alert.disposition == DISPOSITION_FALSE_POSITIVE
        assert alert.disposition_user_id is not None

    comments = db.query(Comment).filter(
        Comment.uuid.in_([alert1.uuid, alert2.uuid]),
        Comment.comment == "bulk disposition",
    ).all()
    assert len(comments) == 2
    audit = audit_record(caplog, "user john set disposition of alerts")
    assert (*audit_actor_of(audit), audit.alert_uuids, audit.disposition) == (
        *session_actor, [alert1.uuid, alert2.uuid], DISPOSITION_FALSE_POSITIVE)


def test_bulk_set_disposition_respects_ownership(web_client, analyst):
    """The event page's bulk disposition goes through the same ownership check: an alert
    another analyst owns changes only when it is taken."""
    jane = add_user("jane_owner", "jane_owner@localhost", "Jane", "password")
    try:
        left_alone = insert_alert()
        taken = insert_alert()
        db = get_db()
        db.query(Alert).filter(Alert.id.in_([left_alone.id, taken.id])).update({Alert.owner_id: jane.id})
        db.commit()

        response = web_client.post(url_for("events.bulk_set_disposition"), data={
            "event_id": EVENT_ID,
            "alert_uuids": f"{left_alone.uuid},{taken.uuid}",
            "disposition": DISPOSITION_FALSE_POSITIVE,
            "take_owned": f"{taken.uuid}:{jane.id}",
        })

        assert response.status_code == 302
        db.expire_all()
        assert db.get(Alert, left_alone.id).disposition != DISPOSITION_FALSE_POSITIVE
        assert db.get(Alert, left_alone.id).owner_id == jane.id
        assert db.get(Alert, taken.id).disposition == DISPOSITION_FALSE_POSITIVE
        assert db.get(Alert, taken.id).owner_id == analyst
    finally:
        delete_user("jane_owner")


def test_bulk_set_disposition_invalid_rejected(web_client):
    alert = insert_alert()
    db = get_db()
    db.refresh(alert)
    original_disposition = alert.disposition

    response = web_client.post(url_for("events.bulk_set_disposition"), data={
        "event_id": EVENT_ID,
        "alert_uuids": alert.uuid,
        "disposition": "NOT_A_DISPOSITION",
    })

    assert response.status_code == 302
    db.refresh(alert)
    assert alert.disposition == original_disposition


def test_bulk_review_disposition_correct(web_client):
    alert = insert_alert()
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("events.bulk_review_disposition"), data={
        "event_id": EVENT_ID,
        "alert_uuids": alert.uuid,
        "review_result": DISPOSITION_REVIEW_CORRECT,
        "comment": "looks right",
    })

    assert response.status_code == 302
    assert f"direct={EVENT_ID}" in response.location

    db = get_db()
    db.refresh(alert)
    assert alert.disposition_review == DISPOSITION_REVIEW_CORRECT
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE
    assert alert.incorrect_disposition is None

    comment = db.query(Comment).filter(Comment.uuid == alert.uuid).first()
    assert comment is not None
    assert comment.comment == f"{REVIEW_COMMENT_PREFIX}looks right"


def test_bulk_review_disposition_incorrect_corrects_and_preserves(web_client, session_actor, caplog):
    caplog.set_level(logging.INFO)
    alert = insert_alert()
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("events.bulk_review_disposition"), data={
        "event_id": EVENT_ID,
        "alert_uuids": alert.uuid,
        "review_result": DISPOSITION_REVIEW_INCORRECT,
        "corrected_disposition": DISPOSITION_WEAPONIZATION,
        "comment": "actually malicious",
    })

    assert response.status_code == 302

    db = get_db()
    db.refresh(alert)
    assert alert.disposition_review == DISPOSITION_REVIEW_INCORRECT
    assert alert.disposition == DISPOSITION_WEAPONIZATION
    assert alert.incorrect_disposition == DISPOSITION_FALSE_POSITIVE
    audit = audit_record(caplog, "user john reviewed disposition of alerts")
    assert (*audit_actor_of(audit), audit.alert_uuids, audit.review_result, audit.corrected_disposition) == (
        *session_actor, [alert.uuid], DISPOSITION_REVIEW_INCORRECT, DISPOSITION_WEAPONIZATION)


def test_bulk_review_disposition_incorrect_requires_comment(web_client):
    alert = insert_alert()
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("events.bulk_review_disposition"), data={
        "event_id": EVENT_ID,
        "alert_uuids": alert.uuid,
        "review_result": DISPOSITION_REVIEW_INCORRECT,
        "corrected_disposition": DISPOSITION_WEAPONIZATION,
        "comment": "",
    })

    assert response.status_code == 302
    db = get_db()
    db.refresh(alert)
    # unchanged because the review was rejected
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE
    assert alert.disposition_review == DISPOSITION_REVIEW_UNREVIEWED


def test_event_page_renders_bulk_controls(web_client):
    alert = insert_alert()
    event = _make_event_with_alert(alert)

    response = web_client.get(url_for("events.index", direct=event.id))

    assert response.status_code == 200
    # the bulk action buttons and their modals render
    assert "btn-event-bulk-set-disposition" in response.text
    assert "btn-event-bulk-review-disposition" in response.text
    assert "event_bulk_disposition_modal" in response.text
    assert "event_bulk_review_modal" in response.text
    # the select-all checkbox is present in the alerts table header
    assert "event-alerts-master-checkbox" in response.text
    # the checkbox carries the alert uuid used by the bulk handlers
    assert f'data-alert-uuid="{alert.uuid}"' in response.text


def test_manage_event_details_renders_select_all(web_client):
    # events/event_alerts.html has a second render path: the manage page fetches it per
    # expanded event. the select-all hook has to be a class, because an id here would be
    # duplicated across the document as soon as two events are expanded.
    alert = insert_alert()
    event = _make_event_with_alert(alert)

    response = web_client.get(url_for("events.manage_event_details", event_id=event.id))

    assert response.status_code == 200
    assert "event-alerts-master-checkbox" in response.text
    assert "event_alerts_master_checkbox" not in response.text
    assert f'data-alert-uuid="{alert.uuid}"' in response.text



def test_bulk_set_disposition_rejects_a_disposition_analysts_may_not_set(web_client, monkeypatch):
    monkeypatch.setitem(get_config().dispositions, "GRAYWARE",
                        DispositionConfig(rank=60, css="secondary", analyst_selectable=False))
    alert = insert_alert()
    db = get_db()
    db.refresh(alert)
    original_disposition = alert.disposition

    response = web_client.post(url_for("events.bulk_set_disposition"), data={
        "event_id": EVENT_ID,
        "alert_uuids": alert.uuid,
        "disposition": "GRAYWARE",
    })

    assert response.status_code == 302
    db.refresh(alert)
    assert alert.disposition == original_disposition


def _flashes(web_client) -> list[str]:
    with web_client.session_transaction() as sess:
        return [message for _category, message in sess.get("_flashes", [])]


def test_bulk_set_disposition_skips_and_reports_a_simulated_alert(web_client):
    simulated = insert_alert()
    make_simulated(simulated)
    other = insert_alert()

    response = web_client.post(url_for("events.bulk_set_disposition"), data={
        "event_id": EVENT_ID,
        "alert_uuids": f"{simulated.uuid},{other.uuid}",
        "disposition": DISPOSITION_FALSE_POSITIVE,
    })

    assert response.status_code == 302
    db = get_db()
    db.expire_all()
    assert db.get(Alert, simulated.id).disposition == "SIMULATED"
    assert db.get(Alert, other.id).disposition == DISPOSITION_FALSE_POSITIVE
    assert _flashes(web_client) == [
        "disposition set for 1 alerts; left 1 SIMULATED alert alone (only ACE sets that disposition)"]


def test_bulk_review_disposition_skips_and_reports_a_simulated_alert(web_client):
    simulated = insert_alert()
    make_simulated(simulated)
    other = insert_alert()
    set_dispositions([other.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("events.bulk_review_disposition"), data={
        "event_id": EVENT_ID,
        "alert_uuids": f"{simulated.uuid},{other.uuid}",
        "review_result": DISPOSITION_REVIEW_INCORRECT,
        "corrected_disposition": DISPOSITION_WEAPONIZATION,
        "comment": "actually malicious",
    })

    assert response.status_code == 302
    db = get_db()
    db.expire_all()
    assert db.get(Alert, simulated.id).disposition == "SIMULATED"
    assert db.get(Alert, other.id).disposition == DISPOSITION_WEAPONIZATION
    assert _flashes(web_client) == [
        "disposition review recorded for 1 alerts; left 1 SIMULATED alert alone (only ACE sets that disposition)"]


#
# the paths the tests above do not take
#

def test_bulk_action_without_an_event_returns_to_the_manage_page(web_client):
    response = web_client.post(url_for("events.bulk_add_tag"), data={"alert_uuids": "", "tag": "bulk_tag"})

    assert response.status_code == 302
    assert response.location.endswith(url_for("events.manage"))


@pytest.mark.parametrize("endpoint", ["events.bulk_add_tag", "events.bulk_remove_tag", "events.bulk_add_comment",
                                      "events.bulk_set_disposition", "events.bulk_review_disposition"])
def test_bulk_actions_need_selected_alerts(web_client, endpoint):
    response = web_client.post(url_for(endpoint), data={"event_id": EVENT_ID, "alert_uuids": ",",
                                                        "tag": "bulk_tag", "comment": "a comment"})

    assert response.status_code == 302
    assert _flashes(web_client) == ["you must select one or more alerts"]


@pytest.mark.parametrize("endpoint,message", [
    ("events.bulk_add_tag", "you must specify one or more tags to add"),
    ("events.bulk_remove_tag", "you must specify one or more tags to remove"),
])
def test_bulk_tag_actions_need_tags(web_client, endpoint, message):
    alert = insert_alert()

    web_client.post(url_for(endpoint), data={"event_id": EVENT_ID, "alert_uuids": alert.uuid, "tag": "  "})

    assert _flashes(web_client) == [message]


@pytest.mark.parametrize("endpoint", ["events.bulk_add_tag", "events.bulk_remove_tag"])
def test_bulk_tag_skips_an_alert_being_analyzed(web_client, endpoint):
    locked, unlocked = insert_alert(), insert_alert()
    engine_lock = str(uuid.uuid4())
    assert acquire_lock(locked.uuid, engine_lock)
    try:
        web_client.post(url_for(endpoint), data={
            "event_id": EVENT_ID,
            # an alert that no longer exists is skipped silently
            "alert_uuids": f"{locked.uuid},{uuid.uuid4()},{unlocked.uuid}",
            "tag": "bulk_tag",
        })
    finally:
        release_lock(locked.uuid, engine_lock)

    assert _flashes(web_client) == ["unable to modify some alerts: alert is currently being analyzed"]
    assert not _reloaded_root(locked).has_tag("bulk_tag")
    if endpoint == "events.bulk_add_tag":
        assert _reloaded_root(unlocked).has_tag("bulk_tag")


def test_bulk_tag_failure_is_logged_with_its_traceback(web_client, monkeypatch, caplog):
    alert = insert_alert()

    def broken_sync(self):
        raise RuntimeError("the database went away")

    monkeypatch.setattr("saq.gui.alert.GUIAlert.sync", broken_sync)

    with caplog.at_level(logging.ERROR):
        web_client.post(url_for("events.bulk_add_tag"), data={
            "event_id": EVENT_ID, "alert_uuids": alert.uuid, "tag": "bulk_tag"})

    [record] = [r for r in caplog.records if "unable to modify tags on" in r.getMessage()]
    assert record.levelno == logging.ERROR
    assert record.exc_info is not None
    assert _flashes(web_client) == ["unable to modify some alerts: alert is currently being analyzed"]
    # the lock was released on the way out, so the next attempt can take it
    lock = str(uuid.uuid4())
    assert acquire_lock(alert.uuid, lock)
    release_lock(alert.uuid, lock)


def test_bulk_set_disposition_failure(web_client, monkeypatch, caplog):
    alert = insert_alert()

    def broken(*args, **kwargs):
        raise RuntimeError("deadlock")

    monkeypatch.setattr("app.events.views.edit.bulk.set_dispositions", broken)

    web_client.post(url_for("events.bulk_set_disposition"), data={
        "event_id": EVENT_ID, "alert_uuids": alert.uuid, "disposition": DISPOSITION_FALSE_POSITIVE})

    assert _flashes(web_client) == ["unable to set disposition (review error logs)"]
    [record] = [r for r in caplog.records if "unable to set disposition for 1 alerts" in r.getMessage()]
    assert record.exc_info is not None


def test_bulk_review_disposition_rejects_bad_input(web_client):
    alert = insert_alert()

    web_client.post(url_for("events.bulk_review_disposition"), data={
        "event_id": EVENT_ID, "alert_uuids": alert.uuid, "review_result": "MAYBE"})
    assert _flashes(web_client) == ["invalid review result: MAYBE"]

    web_client.post(url_for("events.bulk_review_disposition"), data={
        "event_id": EVENT_ID, "alert_uuids": alert.uuid, "review_result": DISPOSITION_REVIEW_INCORRECT,
        "corrected_disposition": "NOT_A_DISPOSITION", "comment": "wrong"})
    # nothing has displayed the first flash yet, so both are pending
    assert _flashes(web_client) == ["invalid review result: MAYBE", "invalid corrected disposition: NOT_A_DISPOSITION"]


def test_bulk_review_disposition_failure(web_client, monkeypatch, caplog):
    alert = insert_alert()

    def broken(*args, **kwargs):
        raise RuntimeError("deadlock")

    monkeypatch.setattr("app.events.views.edit.bulk.set_disposition_reviews", broken)

    web_client.post(url_for("events.bulk_review_disposition"), data={
        "event_id": EVENT_ID, "alert_uuids": alert.uuid, "review_result": DISPOSITION_REVIEW_CORRECT})

    assert _flashes(web_client) == ["unable to record disposition review (review error logs)"]
    [record] = [r for r in caplog.records if "unable to review disposition for 1 alerts" in r.getMessage()]
    assert record.exc_info is not None
