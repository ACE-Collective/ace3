import logging
from flask import url_for
import pytest

from saq.database.model import Alert, Comment
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, delete_user
from tests.saq.helpers import insert_alert


@pytest.mark.integration
def test_add_comment_success(web_client):
    """Test successfully adding a comment to an alert."""
    # Create mock alert UUID
    alert_uuid = "test-uuid-123"
    
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "This is a test comment",
        "uuids": alert_uuid,
        "redirect": "index"
    })
    
    # Should redirect to analysis.index
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Verify comment was added to database
    db = get_db()
    comment = db.query(Comment).filter(Comment.uuid == alert_uuid).first()
    assert comment is not None
    assert comment.comment == "This is a test comment"
    
    # Cleanup
    db.delete(comment)
    db.commit()


@pytest.mark.integration
def test_add_comment_multiple_uuids(web_client):
    """Test adding a comment to multiple alerts."""
    alert_uuids = ["test-uuid-1", "test-uuid-2", "test-uuid-3"]
    
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "Multi-alert comment",
        "uuids": ",".join(alert_uuids),
        "redirect": "index"
    })
    
    assert response.status_code == 302
    
    # Verify comments were added for all UUIDs
    db = get_db()
    comments = db.query(Comment).filter(Comment.uuid.in_(alert_uuids)).all()
    assert len(comments) == 3
    
    for comment in comments:
        assert comment.comment == "Multi-alert comment"
        assert comment.uuid in alert_uuids
    
    # Cleanup
    for comment in comments:
        db.delete(comment)
    db.commit()


@pytest.mark.integration
def test_add_comment_empty_comment(web_client):
    """Test adding an empty comment should fail."""
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "   ",  # Only whitespace
        "uuids": "test-uuid",
        "redirect": "index"
    })
    
    assert response.status_code == 302
    
    # Verify no comment was added
    db = get_db()
    comment = db.query(Comment).filter(Comment.uuid == "test-uuid").first()
    assert comment is None


@pytest.mark.integration
def test_add_comment_missing_form_fields(web_client):
    """Test adding comment with missing required form fields."""
    # Missing comment field
    response = web_client.post(url_for("analysis.add_comment"), data={
        "uuids": "test-uuid",
        "redirect": "index"
    })
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Missing uuids field
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "test comment",
        "redirect": "index"
    })
    assert response.status_code == 302
    
    # Missing redirect field
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "test comment",
        "uuids": "test-uuid"
    })
    assert response.status_code == 302


@pytest.mark.integration
def test_add_comment_invalid_redirect(web_client):
    """Test adding comment with invalid redirect value."""
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "test comment",
        "uuids": "test-uuid",
        "redirect": "invalid_redirect_value"
    })
    
    # Should still redirect (defaults to analysis.index)
    assert response.status_code == 302
    assert "analysis" in response.location


@pytest.mark.integration
def test_add_comment_manage_redirect(web_client):
    """Test adding comment with manage redirect sets session."""
    alert_uuid = "test-uuid-manage"
    
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "manage redirect test",
        "uuids": alert_uuid,
        "redirect": "manage"
    })
    
    assert response.status_code == 302
    
    # Cleanup the comment
    db = get_db()
    comment = db.query(Comment).filter(Comment.uuid == alert_uuid).first()
    if comment:
        db.delete(comment)
        db.commit()


@pytest.mark.integration
def test_delete_comment_success(web_client):
    """Test successfully deleting a comment."""
    # First add a comment
    alert_uuid = "test-delete-uuid"
    
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "Comment to delete",
        "uuids": alert_uuid,
        "redirect": "index"
    })
    
    # Get the comment ID
    db = get_db()
    comment = db.query(Comment).filter(Comment.uuid == alert_uuid).first()
    assert comment is not None
    comment_id = comment.comment_id
    
    # Now delete the comment
    response = web_client.post(url_for("analysis.delete_comment"), data={
        "comment_id": str(comment_id),
        "direct": alert_uuid
    })
    
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Verify comment was deleted
    deleted_comment = db.query(Comment).filter(Comment.comment_id == comment_id).first()
    assert deleted_comment is None


@pytest.mark.integration
def test_delete_comment_missing_comment_id(web_client):
    """Test deleting comment without comment_id."""
    response = web_client.post(url_for("analysis.delete_comment"), data={
        "direct": "test-uuid"
    })
    
    assert response.status_code == 302
    assert "analysis" in response.location


@pytest.mark.integration
def test_delete_comment_nonexistent_comment(web_client):
    """Test deleting a non-existent comment."""
    response = web_client.post(url_for("analysis.delete_comment"), data={
        "comment_id": "999999",  # Non-existent ID
        "direct": "test-uuid"
    })
    
    # should redirect with a flash message
    assert response.status_code in [302, 404, 500]

@pytest.fixture
def other_user():
    """Fixture to create another user for testing comment deletion."""
    user = add_user(
        username="jane",
        email="jane@localhost",
        display_name="Jane Doe",
        password="password123")

    yield user

    delete_user(user.username)

@pytest.mark.integration
def test_delete_comment_wrong_user(web_client, analyst, other_user):
    """Test deleting a comment that belongs to another user."""
    # Add a comment first
    alert_uuid = "test-wrong-user-uuid"
    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "Another user's comment",
        "uuids": alert_uuid,
        "redirect": "index"
    })
    
    # Get the comment
    db = get_db()
    comment = db.query(Comment).filter(Comment.uuid == alert_uuid).first()
    assert comment is not None
    comment_id = comment.comment_id

    comment.user_id = other_user.id  # Set to another user
    db.commit()  # Save the change to simulate another user owning the comment

    response = web_client.post(url_for("analysis.delete_comment"), data={
        "comment_id": str(comment_id),
        "direct": alert_uuid
    })
    
    # should redirect with an error message
    assert response.status_code == 302

    db.delete(comment)  # Cleanup
    db.commit()


@pytest.mark.integration
def test_comment_add_and_delete_rotate_alert_version(web_client):
    """Adding and deleting a comment each rotate the alert's version token."""
    alert = insert_alert()
    before = alert.version

    def db_version():
        return get_db().query(Alert.version).filter(Alert.uuid == alert.uuid).scalar()

    response = web_client.post(url_for("analysis.add_comment"), data={
        "comment": "versioned comment",
        "uuids": alert.uuid,
        "redirect": "index"
    })
    assert response.status_code == 302
    after_add = db_version()
    assert after_add != before

    comment = get_db().query(Comment).filter(Comment.uuid == alert.uuid).first()
    response = web_client.post(url_for("analysis.delete_comment"), data={
        "comment_id": comment.comment_id,
        "direct": alert.uuid,
    })
    assert response.status_code == 302
    assert get_db().query(Comment).filter(Comment.comment_id == comment.comment_id).first() is None
    assert db_version() != after_add
