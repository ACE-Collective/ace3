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
from saq.database.model import Alert, Comment
from saq.database.pool import get_db
from saq.database.util.alert import set_dispositions
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission
from tests.saq.helpers import insert_alert


@pytest.mark.integration
def test_review_disposition_correct_single_alert(web_client):
    """Test recording a 'correct' review for a single alert from the analysis page."""
    alert = insert_alert()
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("analysis.review_disposition"), data={
        "review_result": DISPOSITION_REVIEW_CORRECT,
        "comment": "confirmed",
        "alert_uuid": alert.uuid,
    })

    # should redirect to the analysis page
    assert response.status_code == 302
    assert "analysis" in response.location

    db = get_db()
    db.refresh(alert)
    assert alert.disposition_review == DISPOSITION_REVIEW_CORRECT
    assert alert.review_user_id is not None
    assert alert.review_time is not None
    # the disposition is unchanged
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE
    assert alert.incorrect_disposition is None

    comment = db.query(Comment).filter(Comment.uuid == alert.uuid).first()
    assert comment is not None
    assert comment.comment == f"{REVIEW_COMMENT_PREFIX}confirmed"


@pytest.mark.integration
def test_review_disposition_incorrect_single_alert(web_client):
    """Test correcting a disposition from the analysis page preserves the original."""
    alert = insert_alert()
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("analysis.review_disposition"), data={
        "review_result": DISPOSITION_REVIEW_INCORRECT,
        "corrected_disposition": DISPOSITION_WEAPONIZATION,
        "comment": "actually malicious",
        "alert_uuid": alert.uuid,
    })

    assert response.status_code == 302
    assert "analysis" in response.location

    db = get_db()
    db.refresh(alert)
    assert alert.disposition_review == DISPOSITION_REVIEW_INCORRECT
    assert alert.disposition == DISPOSITION_WEAPONIZATION
    assert alert.incorrect_disposition == DISPOSITION_FALSE_POSITIVE
    assert alert.incorrect_disposition_user_id == 1


@pytest.mark.integration
def test_review_disposition_incorrect_requires_comment(web_client):
    """Test that marking a disposition incorrect without a comment is rejected."""
    alert = insert_alert()
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("analysis.review_disposition"), data={
        "review_result": DISPOSITION_REVIEW_INCORRECT,
        "corrected_disposition": DISPOSITION_WEAPONIZATION,
        "comment": "   ",  # whitespace only
        "alert_uuid": alert.uuid,
    })

    assert response.status_code == 302

    db = get_db()
    db.refresh(alert)
    # nothing should have changed
    assert alert.disposition_review == DISPOSITION_REVIEW_UNREVIEWED
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE
    assert alert.incorrect_disposition is None


@pytest.mark.integration
def test_review_disposition_incorrect_requires_corrected_disposition(web_client):
    """Test that marking a disposition incorrect without a valid corrected disposition is rejected."""
    alert = insert_alert()
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("analysis.review_disposition"), data={
        "review_result": DISPOSITION_REVIEW_INCORRECT,
        "corrected_disposition": "NOT_A_REAL_DISPOSITION",
        "comment": "should be rejected",
        "alert_uuid": alert.uuid,
    })

    assert response.status_code == 302

    db = get_db()
    db.refresh(alert)
    assert alert.disposition_review == DISPOSITION_REVIEW_UNREVIEWED
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE


@pytest.mark.integration
def test_review_disposition_invalid_result(web_client):
    """Test that an invalid review result is rejected."""
    alert = insert_alert()
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    response = web_client.post(url_for("analysis.review_disposition"), data={
        "review_result": "MAYBE",
        "alert_uuid": alert.uuid,
    })

    assert response.status_code == 302

    db = get_db()
    db.refresh(alert)
    assert alert.disposition_review == DISPOSITION_REVIEW_UNREVIEWED


@pytest.mark.integration
def test_review_disposition_multiple_alerts_clears_session(web_client):
    """Test batch review from the manage page and that the checked session is cleared."""
    alert1 = insert_alert()
    alert2 = insert_alert()
    set_dispositions([alert1.uuid, alert2.uuid], DISPOSITION_FALSE_POSITIVE, 1)

    with web_client.session_transaction() as sess:
        sess["checked"] = [alert1.uuid, alert2.uuid]

    response = web_client.post(url_for("analysis.review_disposition"), data={
        "review_result": DISPOSITION_REVIEW_CORRECT,
        "alert_uuids": f"{alert1.uuid},{alert2.uuid}",
    })

    assert response.status_code == 302
    assert "manage" in response.location

    db = get_db()
    for alert in [alert1, alert2]:
        db.refresh(alert)
        assert alert.disposition_review == DISPOSITION_REVIEW_CORRECT

    with web_client.session_transaction() as sess:
        assert "checked" not in sess


@pytest.mark.integration
def test_review_disposition_permission_denied(app):
    """Test that a user without the alert:review permission gets a 403."""
    limited = add_user("limited_reviewer", "limited@test.com", "Limited", "password123")
    # grant an unrelated permission but NOT alert:review
    add_user_permission(limited.id, "alert", "read")

    try:
        alert = insert_alert()
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, 1)

        with app.test_client() as client:
            client.post(url_for("auth.login"), data={
                "username": "limited_reviewer",
                "password": "password123",
            })
            response = client.post(url_for("analysis.review_disposition"), data={
                "review_result": DISPOSITION_REVIEW_CORRECT,
                "alert_uuid": alert.uuid,
            })

        assert response.status_code == 403

        db = get_db()
        db.refresh(alert)
        assert alert.disposition_review == DISPOSITION_REVIEW_UNREVIEWED

    finally:
        delete_user("limited_reviewer")
