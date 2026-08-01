import pytest
from flask import url_for
from unittest.mock import patch, MagicMock

from saq.constants import DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE, VALID_DISPOSITIONS
from saq.database.model import Alert, Comment, Workload
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, delete_user
from tests.saq.helpers import insert_alert


@pytest.mark.integration
def test_set_disposition_single_alert_success(web_client):
    """Test successfully setting disposition for a single alert from analysis page."""
    # Create test alert
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "comment": "Test disposition comment",
        "alert_uuid": alert.uuid
    })
    
    # Should redirect to analysis.index
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Verify disposition was set in database
    db = get_db()
    db.refresh(alert)
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE
    assert alert.disposition_user_id is not None
    assert alert.disposition_time is not None
    
    # Verify comment was added
    comment = db.query(Comment).filter(
        Comment.uuid == alert.uuid,
        Comment.comment == "Test disposition comment"
    ).first()
    assert comment is not None


@pytest.mark.integration
def test_set_disposition_multiple_alerts_success(web_client):
    """Test successfully setting disposition for multiple alerts from manage page."""
    # Create test alerts
    alert1 = insert_alert()
    alert2 = insert_alert()
    alert3 = insert_alert()
    alert_uuids = f"{alert1.uuid},{alert2.uuid},{alert3.uuid}"
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "comment": "Bulk disposition test",
        "alert_uuids": alert_uuids
    })
    
    # Should redirect to analysis.manage
    assert response.status_code == 302
    assert "manage" in response.location
    
    # Verify all alerts have disposition set
    db = get_db()
    for alert in [alert1, alert2, alert3]:
        db.refresh(alert)
        assert alert.disposition == DISPOSITION_FALSE_POSITIVE
        assert alert.disposition_user_id is not None
        assert alert.disposition_time is not None
    
    # Verify comments were added to all alerts
    comments = db.query(Comment).filter(
        Comment.uuid.in_([alert1.uuid, alert2.uuid, alert3.uuid]),
        Comment.comment == "Bulk disposition test"
    ).all()
    assert len(comments) == 3


@pytest.mark.integration
def test_set_disposition_invalid_disposition(web_client):
    """Test setting an invalid disposition value."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": "INVALID_DISPOSITION",
        "alert_uuid": alert.uuid
    })
    
    # Should redirect to analysis.index with flash message
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Verify disposition was NOT set
    db = get_db()
    db.refresh(alert)
    assert alert.disposition != "INVALID_DISPOSITION"


@pytest.mark.integration
def test_set_disposition_no_uuids_provided(web_client):
    """Test setting disposition without providing any alert UUIDs."""
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "comment": "No UUIDs test"
    })
    
    # Should redirect to analysis.index with error message
    assert response.status_code == 302
    assert "analysis" in response.location


@pytest.mark.integration
def test_set_disposition_empty_comment_stripped(web_client):
    """Test that empty/whitespace comments are stripped properly."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "comment": "   \n\t  ",  # Only whitespace
        "alert_uuid": alert.uuid
    })
    
    assert response.status_code == 302
    
    # Verify disposition was set
    db = get_db()
    db.refresh(alert)
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE
    
    # Verify no comment was added (empty after stripping)
    comment = db.query(Comment).filter(Comment.uuid == alert.uuid).first()
    assert comment is None


@pytest.mark.integration
def test_set_disposition_ignore_no_workload(web_client):
    """Test that IGNORE disposition doesn't add alert back to workload."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_IGNORE,
        "alert_uuid": alert.uuid
    })
    
    assert response.status_code == 302
    
    # Verify disposition was set
    db = get_db()
    db.refresh(alert)
    assert alert.disposition == DISPOSITION_IGNORE
    
    # Verify no workload entry was created
    workload_entry = db.query(Workload).filter(
        Workload.uuid == alert.uuid
    ).first()
    assert workload_entry is None


@pytest.mark.integration
def test_set_disposition_non_ignore_adds_workload(web_client):
    """Test that non-IGNORE dispositions add alert back to workload."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "alert_uuid": alert.uuid
    })
    
    assert response.status_code == 302
    
    # Verify disposition was set
    db = get_db()
    db.refresh(alert)
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE
    
    # Verify workload entry was created
    workload_entry = db.query(Workload).filter(
        Workload.uuid == alert.uuid
    ).first()
    assert workload_entry is not None


@pytest.mark.integration
def test_set_disposition_with_long_comment(web_client):
    """Test setting disposition with a long comment."""
    alert = insert_alert()
    long_comment = "This is a very long comment " * 50  # Create long comment
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "comment": long_comment,
        "alert_uuid": alert.uuid
    })
    
    assert response.status_code == 302
    
    # Verify comment was added correctly
    db = get_db()
    comment = db.query(Comment).filter(Comment.uuid == alert.uuid).first()
    assert comment is not None
    assert comment.comment == long_comment.strip()


@pytest.mark.integration
def test_set_disposition_session_cleanup_on_manage(web_client):
    """Test that session 'checked' is cleared when coming from manage page."""
    alert = insert_alert()
    
    # Simulate having checked items in session
    with web_client.session_transaction() as sess:
        sess['checked'] = ['uuid1', 'uuid2', 'uuid3']
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "alert_uuids": alert.uuid
    })
    
    assert response.status_code == 302
    
    # Verify session was cleared
    with web_client.session_transaction() as sess:
        assert 'checked' not in sess


@pytest.mark.integration
def test_set_disposition_session_not_cleared_on_analysis(web_client):
    """Test that session 'checked' is NOT cleared when coming from analysis page."""
    alert = insert_alert()
    
    # Simulate having checked items in session
    with web_client.session_transaction() as sess:
        sess['checked'] = ['uuid1', 'uuid2', 'uuid3']
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "alert_uuid": alert.uuid  # Single alert (analysis page)
    })
    
    assert response.status_code == 302
    
    # Verify session was NOT cleared (analysis page doesn't clear it)
    with web_client.session_transaction() as sess:
        assert 'checked' in sess
        assert sess['checked'] == ['uuid1', 'uuid2', 'uuid3']


@patch('app.analysis.views.edit.disposition.set_dispositions')
def test_set_disposition_database_error_handling(mock_set_dispositions, web_client):
    """Test error handling when database operation fails."""
    # Mock the set_dispositions function to raise an exception
    mock_set_dispositions.side_effect = Exception("Database connection failed")
    
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "alert_uuid": alert.uuid
    })
    
    # Should still redirect but with error flash message
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Verify the function was called
    mock_set_dispositions.assert_called_once()


@pytest.mark.integration
def test_set_disposition_special_characters_in_comment(web_client):
    """Test setting disposition with special characters in comment."""
    alert = insert_alert()
    special_comment = "Test with special chars: <script>alert('xss')</script> & ñoño 中文"
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "comment": special_comment,
        "alert_uuid": alert.uuid
    })
    
    assert response.status_code == 302
    
    # Verify comment was stored correctly
    db = get_db()
    comment = db.query(Comment).filter(Comment.uuid == alert.uuid).first()
    assert comment is not None
    assert comment.comment == special_comment


@pytest.mark.integration
def test_set_disposition_multiple_uuids_with_duplicates(web_client):
    """Test setting disposition with duplicate UUIDs in the list."""
    alert = insert_alert()
    # Include duplicate UUIDs
    alert_uuids = f"{alert.uuid},{alert.uuid},{alert.uuid}"
    
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "alert_uuids": alert_uuids
    })
    
    assert response.status_code == 302
    
    # Verify disposition was set (should handle duplicates gracefully)
    db = get_db()
    db.refresh(alert)
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE


@pytest.mark.integration
def test_set_disposition_empty_uuid_list(web_client):
    """Test setting disposition with empty UUID list."""
    response = web_client.post(url_for("analysis.set_disposition"), data={
        "disposition": DISPOSITION_FALSE_POSITIVE,
        "alert_uuids": ""  # Empty string
    })
    
    # Should redirect with error
    assert response.status_code == 302
    assert "manage" in response.location


@pytest.mark.integration 
def test_set_disposition_all_valid_dispositions(web_client):
    """Test setting each valid disposition type."""
    alerts = [insert_alert() for _ in VALID_DISPOSITIONS]
    
    for i, disposition in enumerate(VALID_DISPOSITIONS):
        alert = alerts[i]
        response = web_client.post(url_for("analysis.set_disposition"), data={
            "disposition": disposition,
            "alert_uuid": alert.uuid
        })
        
        assert response.status_code == 302
        
        # Verify disposition was set correctly
        db = get_db()
        db.refresh(alert)
        assert alert.disposition == disposition


@patch('app.analysis.views.edit.disposition.report_exception')
def test_set_disposition_exception_reporting(mock_report_exception, web_client):
    """Test that exceptions are properly reported."""
    # Mock set_dispositions to raise an exception
    with patch('app.analysis.views.edit.disposition.set_dispositions') as mock_set_dispositions:
        mock_set_dispositions.side_effect = Exception("Test exception")
        
        alert = insert_alert()
        response = web_client.post(url_for("analysis.set_disposition"), data={
            "disposition": DISPOSITION_FALSE_POSITIVE,
            "alert_uuid": alert.uuid
        })
        
        assert response.status_code == 302
        mock_report_exception.assert_called_once()


@pytest.mark.integration
def test_set_disposition_audit_logging(web_client, caplog):
    """Test that disposition changes are properly audit logged."""
    alert = insert_alert()
    
    with caplog.at_level('INFO'):
        response = web_client.post(url_for("analysis.set_disposition"), data={
            "disposition": DISPOSITION_FALSE_POSITIVE,
            "comment": "Audit test comment",
            "alert_uuid": alert.uuid
        })
    
    assert response.status_code == 302
    
    # the batch line covers the whole request and is what existing Splunk
    # searches match on, so its wording must not drift
    batch_logs = [
        record for record in caplog.records
        if record.message.startswith('AUDIT: user ')
    ]
    assert len(batch_logs) == 1

    audit_log = batch_logs[0]
    assert DISPOSITION_FALSE_POSITIVE in audit_log.message
    assert alert.uuid in audit_log.message
    assert "Audit test comment" in audit_log.message

    # the per-alert line carries the fields in extra={}; it is the only record
    # that survives once an IGNORE'd alert is deleted
    per_alert_logs = [
        record for record in caplog.records
        if record.message == 'AUDIT: alert dispositioned'
    ]
    assert len(per_alert_logs) == 1
    assert per_alert_logs[0].alert_uuid == alert.uuid
    assert per_alert_logs[0].new_disposition == DISPOSITION_FALSE_POSITIVE
    assert per_alert_logs[0].disposition_comment == "Audit test comment"