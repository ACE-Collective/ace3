from datetime import datetime, timedelta
import hashlib
import logging
import pytest
import uuid

from saq.configuration.config import get_config
from saq.constants import (
    ANALYSIS_MODE_DISPOSITIONED,
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_IGNORE,
    DISPOSITION_REVIEW_CORRECT,
    DISPOSITION_REVIEW_INCORRECT,
    DISPOSITION_REVIEW_UNREVIEWED,
    DISPOSITION_WEAPONIZATION,
    REVIEW_COMMENT_PREFIX,
)
from saq.database.model import Alert, Comment, Observable, ObservableMapping, Workload
from saq.database.pool import get_db
from saq.database.util.alert import ALERT, get_alert_by_uuid, set_dispositions, set_disposition_reviews
from saq.database.util.user_management import add_user, delete_user
from saq.disposition import get_malicious_dispositions
from saq.permissions.user import add_user_permission
from tests.saq.helpers import create_root_analysis, insert_alert


@pytest.mark.integration
def test_ALERT_function():
    """Test the ALERT function converts RootAnalysis to Alert and inserts into database."""
    # Create a root analysis
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid)
    root.initialize_storage()
    root.save()
    
    # Convert to Alert using ALERT function
    alert = ALERT(root)
    
    # Verify alert was created and has database properties
    assert alert is not None
    assert isinstance(alert, Alert)
    assert alert.id is not None
    assert alert.uuid == root_uuid
    assert alert.storage_dir == root.storage_dir
    assert alert.tool == root.tool
    assert alert.alert_type == root.alert_type
    assert alert.description == root.description
    
    # Verify alert exists in database
    db = get_db()
    db_alert = db.query(Alert).filter(Alert.uuid == root_uuid).first()
    assert db_alert is not None
    assert db_alert.id == alert.id


@pytest.mark.integration
def test_get_alert_by_uuid_existing():
    """Test getting an existing alert by UUID."""
    # Create and insert an alert
    alert = insert_alert()
    alert_uuid = alert.uuid
    
    # Get alert by UUID
    retrieved_alert = get_alert_by_uuid(alert_uuid)
    
    # Verify correct alert was retrieved
    assert retrieved_alert is not None
    assert retrieved_alert.uuid == alert_uuid
    assert retrieved_alert.id == alert.id


@pytest.mark.integration
def test_get_alert_by_uuid_nonexistent():
    """Test getting a non-existent alert by UUID returns None."""
    nonexistent_uuid = str(uuid.uuid4())
    
    # Try to get non-existent alert
    alert = get_alert_by_uuid(nonexistent_uuid)
    
    # Should return None
    assert alert is None


@pytest.mark.integration
def test_set_dispositions_basic():
    """Test basic disposition setting functionality."""
    # Create test user
    user = add_user("testuser_disp", "testuser_disp@test.com", "Test User", "password123")
    add_user_permission(user.id, "*", "*")
    
    try:
        # Create test alert
        alert = insert_alert()

        # Set disposition
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, user.id)

        # Verify disposition was set
        db = get_db()
        db.refresh(alert)

        assert alert.disposition == DISPOSITION_FALSE_POSITIVE
        assert alert.disposition_user_id == user.id
        assert alert.disposition_time is not None
        assert alert.owner_id == user.id  # Should be set if was null
        assert alert.owner_time is not None
        
    finally:
        delete_user("testuser_disp")


@pytest.mark.integration
def test_set_dispositions_with_comment():
    """Test setting disposition with user comment."""
    user = add_user("testuser_comment", "testuser_comment@test.com", "Test User", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = insert_alert()
        comment_text = "This is a test disposition comment"
        
        # Set disposition with comment
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, user.id, comment_text)
        
        # Verify disposition was set
        db = get_db()
        db.refresh(alert)
        assert alert.disposition == DISPOSITION_FALSE_POSITIVE
        
        # Verify comment was added
        comment = db.query(Comment).filter(
            Comment.uuid == alert.uuid,
            Comment.user_id == user.id,
            Comment.comment == comment_text
        ).first()
        
        assert comment is not None
        assert comment.comment == comment_text
        
    finally:
        delete_user("testuser_comment")


@pytest.mark.integration
def test_set_dispositions_multiple_alerts():
    """Test setting disposition for multiple alerts at once."""
    user = add_user("testuser_multi", "testuser_multi@test.com", "Test User", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        # Create multiple alerts
        alert1 = insert_alert()
        alert2 = insert_alert()
        alert3 = insert_alert()
        
        alert_uuids = [alert1.uuid, alert2.uuid, alert3.uuid]
        
        # Set disposition for all alerts
        set_dispositions(alert_uuids, DISPOSITION_FALSE_POSITIVE, user.id, "Bulk disposition")
        
        # Verify all alerts were updated
        db = get_db()
        db.refresh(alert1)
        db.refresh(alert2)
        db.refresh(alert3)
        updated_alerts = [alert1, alert2, alert3]
        
        for alert in updated_alerts:
            assert alert.disposition == DISPOSITION_FALSE_POSITIVE
            assert alert.disposition_user_id == user.id
            assert alert.disposition_time is not None
        
        # Verify comments were added to all alerts
        comments = db.query(Comment).filter(
            Comment.uuid.in_(alert_uuids),
            Comment.comment == "Bulk disposition"
        ).all()
        assert len(comments) == 3
        
    finally:
        delete_user("testuser_multi")


@pytest.mark.integration
def test_set_dispositions_malicious_leaves_observable_expiration_alone():
    """Dispositioning malicious no longer rewrites observables.expires_on.

    It used to call refresh_observable_expires_on(), which pushed that column forward for every
    observable in the alert. Nothing read it except the detection cache, and detection expiration
    now lives in observable_detections.expires_on where only an analyst sets it -- silently
    extending an analyst's chosen expiration as a side effect of triage would be wrong.
    """
    get_config().observable_expiration_mappings["fqdn"] = "01:00:00:00"

    user = add_user("testuser_mal", "testuser_mal@test.com", "Test User", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = insert_alert()

        db = get_db()
        original_expires_on = datetime(2030, 1, 1, 0, 0, 0)
        observable = Observable(
            type="fqdn",
            value=b"malicious.example.com",
            sha256=b"test_hash_6" * 2,
            expires_on=original_expires_on,
        )
        db.add(observable)
        db.commit()

        db.add(ObservableMapping(observable_id=observable.id, alert_id=alert.id))
        db.commit()

        malicious_disposition = next(iter(get_malicious_dispositions()))
        set_dispositions([alert.uuid], malicious_disposition, user.id)

        db.refresh(alert)
        assert alert.disposition == malicious_disposition

        db.refresh(observable)
        assert observable.expires_on == original_expires_on

    finally:
        delete_user("testuser_mal")


@pytest.mark.integration
def test_set_dispositions_ignore_no_workload():
    """Test that IGNORE disposition doesn't add to workload."""
    user = add_user("testuser_ignore", "testuser_ignore@test.com", "Test User", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = insert_alert()
        
        # Set IGNORE disposition
        set_dispositions([alert.uuid], DISPOSITION_IGNORE, user.id)
        
        # Verify disposition was set
        db = get_db()
        db.refresh(alert)
        alert = db.query(Alert).filter(Alert.id == alert.id).first()
        assert alert.disposition == DISPOSITION_IGNORE
        
        # Verify no workload entry was created for DISPOSITIONED analysis
        workload_entry = db.query(Workload).filter(
            Workload.uuid == alert.uuid,
            Workload.analysis_mode == ANALYSIS_MODE_DISPOSITIONED
        ).first()
        
        assert workload_entry is None
        
    finally:
        delete_user("testuser_ignore")


@pytest.mark.integration
def test_set_dispositions_non_ignore_adds_workload():
    """Test that non-IGNORE dispositions add alert back to workload."""
    user = add_user("testuser_workload", "testuser_workload@test.com", "Test User", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = insert_alert()
        
        # Set non-IGNORE disposition
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, user.id)
        
        # Verify workload entry was created
        db = get_db()
        workload_entry = db.query(Workload).filter(
            Workload.uuid == alert.uuid,
            Workload.analysis_mode == ANALYSIS_MODE_DISPOSITIONED
        ).first()
        
        assert workload_entry is not None
        assert workload_entry.uuid == alert.uuid
        assert workload_entry.analysis_mode == ANALYSIS_MODE_DISPOSITIONED
        
    finally:
        delete_user("testuser_workload")


@pytest.mark.integration
def test_set_dispositions_preserves_existing_owner():
    """Test that existing owner is preserved when setting disposition."""
    original_user = add_user("original_owner", "original@test.com", "Original Owner", "password123")
    new_user = add_user("new_disposer", "new@test.com", "New Disposer", "password123")
    add_user_permission(original_user.id, "*", "*")
    add_user_permission(new_user.id, "*", "*")

    try:
        alert = insert_alert()
        
        # Set initial owner
        db = get_db()
        alert_obj = db.query(Alert).filter(Alert.id == alert.id).first()
        alert_obj.owner_id = original_user.id
        alert_obj.owner_time = datetime.utcnow()
        db.commit()
        
        # Set disposition with different user
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, new_user.id)
        
        # Verify owner remained the same, but disposer is different
        alert_obj = db.refresh(alert_obj)
        alert_obj = db.query(Alert).filter(Alert.id == alert.id).first()
        assert alert_obj.owner_id == original_user.id  # Should remain original
        assert alert_obj.disposition_user_id == new_user.id  # Should be new user
        
    finally:
        delete_user("original_owner")
        delete_user("new_disposer")


@pytest.mark.integration
def test_set_dispositions_already_dispositioned():
    """Test setting disposition on already dispositioned alert."""
    user = add_user("testuser_redispo", "testuser_redispo@test.com", "Test User", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = insert_alert()
        
        # Set initial disposition
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, user.id)
        
        # Try to set same disposition again (should not change anything)
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, user.id)

        # Should still work but might not update if already set to same value
        db = get_db()
        db.refresh(alert)
        assert alert.disposition == DISPOSITION_FALSE_POSITIVE

    finally:
        delete_user("testuser_redispo")


@pytest.mark.integration
def test_set_disposition_reviews_correct():
    """Test recording a review that finds the disposition correct."""
    analyst = add_user("review_analyst", "review_analyst@test.com", "Analyst", "password123")
    reviewer = add_user("review_reviewer", "review_reviewer@test.com", "Reviewer", "password123")
    add_user_permission(analyst.id, "*", "*")
    add_user_permission(reviewer.id, "*", "*")

    try:
        alert = insert_alert()

        # the analyst dispositions the alert
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, analyst.id)

        # the reviewer confirms the disposition is correct
        set_disposition_reviews([alert.uuid], DISPOSITION_REVIEW_CORRECT, reviewer.id, review_comment="looks good")

        db = get_db()
        db.refresh(alert)

        # the review is recorded but the disposition is untouched
        assert alert.disposition_review == DISPOSITION_REVIEW_CORRECT
        assert alert.review_user_id == reviewer.id
        assert alert.review_time is not None
        assert alert.disposition == DISPOSITION_FALSE_POSITIVE
        assert alert.disposition_user_id == analyst.id
        assert alert.incorrect_disposition is None

        # a prefixed review comment was added
        comment = db.query(Comment).filter(
            Comment.uuid == alert.uuid,
            Comment.user_id == reviewer.id,
        ).first()
        assert comment is not None
        assert comment.comment == f"{REVIEW_COMMENT_PREFIX}looks good"

    finally:
        delete_user("review_analyst")
        delete_user("review_reviewer")


@pytest.mark.integration
def test_set_disposition_reviews_incorrect_preserves_original_and_corrects():
    """Test recording a review that finds the disposition incorrect and corrects it."""
    analyst = add_user("review_analyst2", "review_analyst2@test.com", "Analyst", "password123")
    reviewer = add_user("review_reviewer2", "review_reviewer2@test.com", "Reviewer", "password123")
    add_user_permission(analyst.id, "*", "*")
    add_user_permission(reviewer.id, "*", "*")

    try:
        alert = insert_alert()

        # the analyst dispositions the alert (incorrectly)
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, analyst.id)
        db = get_db()
        db.refresh(alert)
        original_disposition_time = alert.disposition_time

        # the reviewer corrects the disposition
        set_disposition_reviews(
            [alert.uuid], DISPOSITION_REVIEW_INCORRECT, reviewer.id,
            corrected_disposition=DISPOSITION_WEAPONIZATION, review_comment="actually malicious")

        db.refresh(alert)

        # the original (incorrect) disposition is preserved
        assert alert.incorrect_disposition == DISPOSITION_FALSE_POSITIVE
        assert alert.incorrect_disposition_user_id == analyst.id
        assert alert.incorrect_disposition_time == original_disposition_time

        # the disposition is corrected and attributed to the reviewer
        assert alert.disposition == DISPOSITION_WEAPONIZATION
        assert alert.disposition_user_id == reviewer.id

        # the review is recorded
        assert alert.disposition_review == DISPOSITION_REVIEW_INCORRECT
        assert alert.review_user_id == reviewer.id
        assert alert.review_time is not None

        # a prefixed review comment was added
        comment = db.query(Comment).filter(
            Comment.uuid == alert.uuid,
            Comment.comment == f"{REVIEW_COMMENT_PREFIX}actually malicious",
        ).first()
        assert comment is not None

        # the corrected (non-IGNORE) disposition re-inserts the alert into the workload
        workload_entry = db.query(Workload).filter(
            Workload.uuid == alert.uuid,
            Workload.analysis_mode == ANALYSIS_MODE_DISPOSITIONED,
        ).first()
        assert workload_entry is not None

    finally:
        delete_user("review_analyst2")
        delete_user("review_reviewer2")


@pytest.mark.integration
def test_set_disposition_reviews_default_unreviewed():
    """Test that a freshly dispositioned alert starts out unreviewed."""
    user = add_user("review_default", "review_default@test.com", "Analyst", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = insert_alert()
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, user.id)

        db = get_db()
        db.refresh(alert)
        assert alert.disposition_review == DISPOSITION_REVIEW_UNREVIEWED
        assert alert.review_user_id is None
        assert alert.review_time is None
        assert alert.incorrect_disposition is None

    finally:
        delete_user("review_default")

#
# Disposition audit logging
#
# Alerts dispositioned IGNORE are eventually deleted outright, so these log
# lines are the only lasting record of what was ignored. The fields ride in
# extra={} rather than the message text (see saq/logging.py), so the assertions
# below read LogRecord attributes.
#

DISPOSITION_LOG_FIELDS = (
    "alert_uuid", "alert_description", "old_disposition", "new_disposition",
    "disposition_user", "disposition_comment", "alert_type", "alert_tool",
    "alert_tool_instance", "alert_queue", "alert_company", "alert_owner",
    "alert_insert_date", "alert_event_time",
)


def _audit_records(caplog, event):
    return [r for r in caplog.records if r.getMessage() == event]


def _titled_alert(description):
    """An alert with a known title, which is the whole point of these lines."""
    alert = insert_alert()
    alert.description = description
    get_db().commit()
    return alert


@pytest.mark.integration
def test_set_dispositions_logs_alert_title(caplog):
    """The title is what an analyst searches by once the alert is deleted."""
    user = add_user("disp_log_title", "disp_log_title@test.com", "Analyst", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = _titled_alert("Phish Reported - Invoice Due")

        with caplog.at_level(logging.INFO):
            set_dispositions([alert.uuid], DISPOSITION_IGNORE, user.id, "not a real phish")

        records = _audit_records(caplog, "AUDIT: alert dispositioned")
        assert len(records) == 1
        record = records[0]
        assert record.alert_uuid == alert.uuid
        assert record.alert_description == "Phish Reported - Invoice Due"
        assert record.new_disposition == DISPOSITION_IGNORE
        assert record.disposition_user == "disp_log_title"
        assert record.disposition_comment == "not a real phish"

    finally:
        delete_user("disp_log_title")


@pytest.mark.integration
def test_set_dispositions_logs_all_fields(caplog):
    """Anything missing from this line is unrecoverable once the alert is gone."""
    user = add_user("disp_log_fields", "disp_log_fields@test.com", "Analyst", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = _titled_alert("Suspicious Login")

        with caplog.at_level(logging.INFO):
            set_dispositions([alert.uuid], DISPOSITION_IGNORE, user.id)

        record = _audit_records(caplog, "AUDIT: alert dispositioned")[0]
        for field in DISPOSITION_LOG_FIELDS:
            assert hasattr(record, field), f"disposition log line missing field {field!r}"

    finally:
        delete_user("disp_log_fields")


@pytest.mark.integration
def test_set_dispositions_logs_previous_disposition(caplog):
    """The outgoing disposition is overwritten in place, so it has to be
    captured before the UPDATE or it is lost."""
    user = add_user("disp_log_prev", "disp_log_prev@test.com", "Analyst", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = _titled_alert("Malicious URL")
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, user.id)

        # that first call logged too; only the second one is under test
        caplog.clear()
        with caplog.at_level(logging.INFO):
            set_dispositions([alert.uuid], DISPOSITION_IGNORE, user.id)

        record = _audit_records(caplog, "AUDIT: alert dispositioned")[0]
        assert record.old_disposition == DISPOSITION_FALSE_POSITIVE
        assert record.new_disposition == DISPOSITION_IGNORE

    finally:
        delete_user("disp_log_prev")


@pytest.mark.integration
def test_set_dispositions_logs_one_line_per_alert(caplog):
    """A bulk disposition must not collapse into a single line -- each alert
    needs its own title attached to its own uuid."""
    user = add_user("disp_log_bulk", "disp_log_bulk@test.com", "Analyst", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        titles = {}
        for index in range(3):
            alert = _titled_alert(f"Bulk Alert {index}")
            titles[alert.uuid] = f"Bulk Alert {index}"

        with caplog.at_level(logging.INFO):
            set_dispositions(list(titles), DISPOSITION_IGNORE, user.id)

        records = _audit_records(caplog, "AUDIT: alert dispositioned")
        assert len(records) == 3
        assert {r.alert_uuid: r.alert_description for r in records} == titles

    finally:
        delete_user("disp_log_bulk")


@pytest.mark.integration
def test_set_dispositions_no_log_when_disposition_unchanged(caplog):
    """The UPDATE skips alerts already at the target disposition, so logging
    one would report an event that never happened."""
    user = add_user("disp_log_noop", "disp_log_noop@test.com", "Analyst", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = _titled_alert("Already Ignored")
        set_dispositions([alert.uuid], DISPOSITION_IGNORE, user.id)

        # that first call logged too; only the second one is under test
        caplog.clear()
        with caplog.at_level(logging.INFO):
            set_dispositions([alert.uuid], DISPOSITION_IGNORE, user.id)

        assert _audit_records(caplog, "AUDIT: alert dispositioned") == []

    finally:
        delete_user("disp_log_noop")


@pytest.mark.integration
def test_set_disposition_reviews_incorrect_logs_correction(caplog):
    """An INCORRECT review can correct an alert to IGNORE, which deletes it
    just as a direct disposition would."""
    analyst = add_user("rev_log_analyst", "rev_log_analyst@test.com", "Analyst", "password123")
    reviewer = add_user("rev_log_reviewer", "rev_log_reviewer@test.com", "Reviewer", "password123")
    add_user_permission(analyst.id, "*", "*")
    add_user_permission(reviewer.id, "*", "*")

    try:
        alert = _titled_alert("Credential Harvester")
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, analyst.id)

        with caplog.at_level(logging.INFO):
            set_disposition_reviews(
                [alert.uuid], DISPOSITION_REVIEW_INCORRECT, reviewer.id,
                corrected_disposition=DISPOSITION_IGNORE, review_comment="should have been ignored")

        records = _audit_records(caplog, "AUDIT: alert disposition reviewed")
        assert len(records) == 1
        record = records[0]
        assert record.alert_description == "Credential Harvester"
        assert record.review_result == DISPOSITION_REVIEW_INCORRECT
        assert record.old_disposition == DISPOSITION_FALSE_POSITIVE
        assert record.new_disposition == DISPOSITION_IGNORE
        assert record.disposition_user == "rev_log_reviewer"

    finally:
        delete_user("rev_log_analyst")
        delete_user("rev_log_reviewer")


@pytest.mark.integration
def test_set_disposition_reviews_correct_logs_unchanged_disposition(caplog):
    """A CORRECT review confirms rather than changes the disposition, so old
    and new match -- but the review is still an event worth recording."""
    analyst = add_user("rev_ok_analyst", "rev_ok_analyst@test.com", "Analyst", "password123")
    reviewer = add_user("rev_ok_reviewer", "rev_ok_reviewer@test.com", "Reviewer", "password123")
    add_user_permission(analyst.id, "*", "*")
    add_user_permission(reviewer.id, "*", "*")

    try:
        alert = _titled_alert("Beaconing Host")
        set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, analyst.id)

        with caplog.at_level(logging.INFO):
            set_disposition_reviews(
                [alert.uuid], DISPOSITION_REVIEW_CORRECT, reviewer.id, review_comment="agreed")

        record = _audit_records(caplog, "AUDIT: alert disposition reviewed")[0]
        assert record.alert_description == "Beaconing Host"
        assert record.review_result == DISPOSITION_REVIEW_CORRECT
        assert record.old_disposition == DISPOSITION_FALSE_POSITIVE
        assert record.new_disposition == DISPOSITION_FALSE_POSITIVE

    finally:
        delete_user("rev_ok_analyst")
        delete_user("rev_ok_reviewer")
