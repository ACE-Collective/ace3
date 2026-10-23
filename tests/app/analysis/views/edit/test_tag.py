import logging
import uuid

from flask import url_for
import pytest

from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock, release_lock
from saq.gui.alert import GUIAlert
from tests.saq.helpers import insert_alert


@pytest.mark.integration
def test_add_tag_success(web_client):
    """Test successfully adding a tag to an alert."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.add_tag"), data={
        "tag": "malware",
        "uuids": str(alert.uuid),
        "redirect": "analysis"
    })
    
    # Should redirect
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Verify tag was added
    db = get_db()
    gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
    gui_alert.load()
    assert gui_alert.root_analysis.has_tag("malware")


@pytest.mark.integration
def test_add_tag_multiple_tags(web_client):
    """Test adding multiple tags to an alert."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.add_tag"), data={
        "tag": "malware phishing suspicious",
        "uuids": str(alert.uuid),
        "redirect": "analysis"
    })
    
    assert response.status_code == 302
    
    # Verify all tags were added
    db = get_db()
    gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
    gui_alert.load()
    assert gui_alert.root_analysis.has_tag("malware")
    assert gui_alert.root_analysis.has_tag("phishing")
    assert gui_alert.root_analysis.has_tag("suspicious")


@pytest.mark.integration
def test_add_tag_multiple_uuids(web_client):
    """Test adding tags to multiple alerts."""
    # Create multiple alerts
    alerts = [insert_alert() for _ in range(3)]
    alert_uuids = [str(alert.uuid) for alert in alerts]
    
    response = web_client.post(url_for("analysis.add_tag"), data={
        "tag": "bulk_tag",
        "uuids": ",".join(alert_uuids),
        "redirect": "analysis"
    })
    
    assert response.status_code == 302
    
    # Verify tag was added to all alerts
    db = get_db()
    for alert_uuid in alert_uuids:
        gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
        gui_alert.load()
        assert gui_alert.root_analysis.has_tag("bulk_tag")


@pytest.mark.integration
def test_add_tag_empty_tag(web_client):
    """Test adding empty tag should fail."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.add_tag"), data={
        "tag": "   ",  # Only whitespace
        "uuids": str(alert.uuid),
        "redirect": "analysis"
    })
    
    assert response.status_code == 302
    
    # Verify no tag was added
    db = get_db()
    gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
    gui_alert.load()
    assert len(gui_alert.root_analysis.tags) == 0


@pytest.mark.integration
def test_add_tag_missing_form_fields(web_client):
    """Test adding tag with missing required form fields."""
    # Missing tag field
    response = web_client.post(url_for("analysis.add_tag"), data={
        "uuids": "test-uuid",
        "redirect": "analysis"
    })
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Missing uuids field
    response = web_client.post(url_for("analysis.add_tag"), data={
        "tag": "test_tag",
        "redirect": "analysis"
    })
    assert response.status_code == 302
    
    # Missing redirect field
    response = web_client.post(url_for("analysis.add_tag"), data={
        "tag": "test_tag",
        "uuids": "test-uuid"
    })
    assert response.status_code == 302


@pytest.mark.integration
def test_add_tag_invalid_redirect(web_client):
    """Test adding tag with invalid redirect value."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.add_tag"), data={
        "tag": "test_tag",
        "uuids": str(alert.uuid),
        "redirect": "invalid_redirect_value"
    })
    
    # Should still redirect (defaults to analysis.index)
    assert response.status_code == 302
    assert "analysis" in response.location


@pytest.mark.integration
def test_add_tag_manage_redirect(web_client):
    """Test adding tag with manage redirect sets session."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.add_tag"), data={
        "tag": "manage_tag",
        "uuids": str(alert.uuid),
        "redirect": "management"
    })
    
    assert response.status_code == 302


@pytest.mark.integration
def test_remove_tag_success(web_client):
    """Test successfully removing a tag from an alert."""
    alert = insert_alert()
    
    # First add a tag
    db = get_db()
    gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
    gui_alert.load()
    gui_alert.root_analysis.add_tag("remove_me")
    gui_alert.sync()
    db.commit()
    
    # Now remove the tag
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "remove_me",
        "uuids": str(alert.uuid),
        "redirect": "analysis"
    })
    
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Verify tag was removed
    gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
    gui_alert.load()
    assert not gui_alert.root_analysis.has_tag("remove_me")


@pytest.mark.integration
def test_remove_tag_multiple_tags(web_client):
    """Test removing multiple tags from an alert."""
    alert = insert_alert()
    
    # First add multiple tags
    db = get_db()
    gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
    gui_alert.load()
    gui_alert.root_analysis.add_tag("tag1")
    gui_alert.root_analysis.add_tag("tag2")
    gui_alert.root_analysis.add_tag("keep_me")
    gui_alert.sync()
    db.commit()
    
    # Remove multiple tags
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "tag1 tag2",
        "uuids": str(alert.uuid),
        "redirect": "analysis"
    })
    
    assert response.status_code == 302
    
    # Verify specified tags were removed but keep_me remains
    gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
    gui_alert.load()
    assert not gui_alert.root_analysis.has_tag("tag1")
    assert not gui_alert.root_analysis.has_tag("tag2")
    assert gui_alert.root_analysis.has_tag("keep_me")


@pytest.mark.integration
def test_remove_tag_multiple_uuids(web_client):
    """Test removing tags from multiple alerts."""
    # Create multiple alerts
    alerts = [insert_alert() for _ in range(3)]
    alert_uuids = [str(alert.uuid) for alert in alerts]
    
    # Add tags to all alerts
    db = get_db()
    for alert in alerts:
        gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
        gui_alert.load()
        gui_alert.root_analysis.add_tag("remove_bulk")
        gui_alert.sync()
    db.commit()
    
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "remove_bulk",
        "uuids": ",".join(alert_uuids),
        "redirect": "analysis"
    })
    
    assert response.status_code == 302
    
    # Verify tag was removed from all alerts
    for alert_uuid in alert_uuids:
        gui_alert = db.query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
        gui_alert.load()
        assert not gui_alert.root_analysis.has_tag("remove_bulk")


@pytest.mark.integration
def test_remove_tag_empty_tag(web_client):
    """Test removing empty tag should fail."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "   ",  # Only whitespace
        "uuids": str(alert.uuid),
        "redirect": "analysis"
    })
    
    assert response.status_code == 302


@pytest.mark.integration
def test_remove_tag_missing_form_fields(web_client):
    """Test removing tag with missing required form fields."""
    # Missing tag field
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "uuids": "test-uuid",
        "redirect": "analysis"
    })
    assert response.status_code == 302
    assert "analysis" in response.location
    
    # Missing uuids field
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "test_tag",
        "redirect": "analysis"
    })
    assert response.status_code == 302
    
    # Missing redirect field
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "test_tag",
        "uuids": "test-uuid"
    })
    assert response.status_code == 302


@pytest.mark.integration
def test_remove_tag_invalid_redirect(web_client):
    """Test removing tag with invalid redirect value."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "test_tag",
        "uuids": str(alert.uuid),
        "redirect": "invalid_redirect_value"
    })
    
    # Should still redirect (defaults to analysis.index)
    assert response.status_code == 302
    assert "analysis" in response.location


@pytest.mark.integration
def test_remove_tag_manage_redirect(web_client):
    """Test removing tag with manage redirect sets session."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "manage_tag",
        "uuids": str(alert.uuid),
        "redirect": "management"
    })
    
    assert response.status_code == 302


@pytest.mark.integration
def test_remove_tag_nonexistent_tag(web_client):
    """Test removing a tag that doesn't exist on the alert."""
    alert = insert_alert()
    
    response = web_client.post(url_for("analysis.remove_tag"), data={
        "tag": "nonexistent_tag",
        "uuids": str(alert.uuid),
        "redirect": "analysis"
    })
    
    # Should handle gracefully and redirect
    assert response.status_code == 302
    assert "analysis" in response.location

def _has_tag(alert, tag: str) -> bool:
    gui_alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert.uuid).one()
    gui_alert.load()
    return gui_alert.root_analysis.has_tag(tag)


def _flashes(web_client) -> list[str]:
    with web_client.session_transaction() as sess:
        return [message for _category, message in sess.get("_flashes", [])]


@pytest.mark.integration
@pytest.mark.parametrize("endpoint", ["analysis.add_tag", "analysis.remove_tag"])
def test_tag_change_skips_an_alert_that_no_longer_exists(web_client, endpoint):
    """A manage page selection can name an alert deleted since the page was loaded."""
    alert = insert_alert()
    if endpoint == "analysis.remove_tag":
        web_client.post(url_for("analysis.add_tag"), data={"tag": "malware", "uuids": alert.uuid, "redirect": "management"})
        assert _has_tag(alert, "malware")

    response = web_client.post(url_for(endpoint), data={
        "tag": "malware", "uuids": f"{uuid.uuid4()},{alert.uuid}", "redirect": "management"})

    assert response.status_code == 302
    assert _has_tag(alert, "malware") is (endpoint == "analysis.add_tag")


@pytest.mark.integration
@pytest.mark.parametrize("endpoint", ["analysis.add_tag", "analysis.remove_tag"])
def test_tag_change_skips_an_alert_being_analyzed(web_client, endpoint):
    alert = insert_alert()
    engine_lock = str(uuid.uuid4())
    assert acquire_lock(alert.uuid, engine_lock)
    try:
        web_client.post(url_for(endpoint), data={"tag": "malware", "uuids": alert.uuid, "redirect": "analysis"})
    finally:
        release_lock(alert.uuid, engine_lock)

    assert _flashes(web_client) == ["unable to modify alert: alert is currently being analyzed"]
    assert not _has_tag(alert, "malware")


@pytest.mark.integration
@pytest.mark.parametrize("endpoint,message", [
    ("analysis.add_tag", "unable to add tag to"),
    ("analysis.remove_tag", "unable to remove tag from"),
])
def test_tag_change_failure_is_logged_with_its_traceback(web_client, monkeypatch, caplog, endpoint, message):
    alert = insert_alert()

    def broken_sync(self):
        raise RuntimeError("the database went away")

    monkeypatch.setattr("saq.gui.alert.GUIAlert.sync", broken_sync)

    with caplog.at_level(logging.ERROR):
        web_client.post(url_for(endpoint), data={"tag": "malware", "uuids": alert.uuid, "redirect": "analysis"})

    [record] = [r for r in caplog.records if message in r.getMessage()]
    assert record.exc_info is not None
    assert _flashes(web_client) == ["unable to modify alert: alert is currently being analyzed"]
    # the lock was released on the way out
    lock = str(uuid.uuid4())
    assert acquire_lock(alert.uuid, lock)
    release_lock(alert.uuid, lock)


@pytest.mark.integration
def test_remove_tag_audit_names_every_tag(web_client, caplog):
    alert = insert_alert()

    with caplog.at_level(logging.INFO):
        web_client.post(url_for("analysis.remove_tag"), data={
            "tag": "malware phish", "uuids": alert.uuid, "redirect": "analysis"})

    [record] = [r for r in caplog.records if r.getMessage().startswith("AUDIT: ") and "removed tags" in r.getMessage()]
    assert "['malware', 'phish']" in record.getMessage()
    assert alert.uuid in record.getMessage()
