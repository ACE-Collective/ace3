import pytest
from flask import url_for

from saq.constants import (
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_REVIEW_CORRECT,
    DISPOSITION_REVIEW_INCORRECT,
    DISPOSITION_REVIEW_UNREVIEWED,
    DISPOSITION_WEAPONIZATION,
    REVIEW_COMMENT_PREFIX,
)
from saq.database.model import (
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
from tests.saq.helpers import insert_alert

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



def test_bulk_add_tag_success(web_client):
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

    for alert in (alert1, alert2):
        root = _reloaded_root(alert)
        assert root.has_tag("bulk_tag")
        assert root.has_tag("another_tag")


def test_bulk_remove_tag_success(web_client):
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


def test_bulk_add_tag_no_alerts_selected(web_client):
    response = web_client.post(url_for("events.bulk_add_tag"), data={
        "event_id": EVENT_ID,
        "alert_uuids": "",
        "tag": "bulk_tag",
    })

    assert response.status_code == 302
    assert f"direct={EVENT_ID}" in response.location


def test_bulk_add_comment_success(web_client):
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


def test_bulk_set_disposition_success(web_client):
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


def test_bulk_review_disposition_incorrect_corrects_and_preserves(web_client):
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
    assert "event_alerts_master_checkbox" in response.text
    # the checkbox carries the alert uuid used by the bulk handlers
    assert f'data-alert-uuid="{alert.uuid}"' in response.text

