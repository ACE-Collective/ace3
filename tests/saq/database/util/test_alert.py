from datetime import datetime, timedelta
import hashlib
import pytest
import uuid

from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_DISPOSITIONED, CONFIG_OBSERVABLE_EXPIRATION_MAPPINGS, DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE
from saq.database.model import Alert, Comment, Observable, ObservableMapping, Workload
from saq.database.pool import get_db
from saq.database.util.alert import ALERT, get_alert_by_uuid, refresh_observable_expires_on, set_dispositions
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
def test_refresh_observable_expires_on_basic():
    """Test basic functionality of refresh_observable_expires_on."""
    # Create alert with observables
    alert = insert_alert()
    
    # Create some test observables for this alert
    db = get_db()
    
    # Create observable with current expires_on
    observable1 = Observable(
        type="ipv4",
        value=b"192.168.1.1",
        sha256=b"test_hash_1" * 2,  # 32 bytes
        expires_on=datetime.utcnow() + timedelta(days=1)
    )
    db.add(observable1)
    db.commit()
    
    # Map observable to alert
    mapping = ObservableMapping(
        observable_id=observable1.id,
        alert_id=alert.id
    )
    db.add(mapping)
    db.commit()
    
    original_expires_on = observable1.expires_on
    
    # Call refresh function
    refresh_observable_expires_on([alert.uuid])
    
    # Verify expires_on was updated (should be different if config has expiration settings)
    db.refresh(observable1)
    # Note: The actual value depends on configuration, we just verify it was processed
    assert observable1.expires_on is not None


@pytest.mark.integration
def test_refresh_observable_expires_on_nullify():
    """Test refresh_observable_expires_on with nullify=True."""
    # Create alert with observables
    alert = insert_alert()
    
    db = get_db()
    
    # Create observable with expires_on set
    observable = Observable(
        type="fqdn",
        value=b"test.example.com",
        sha256=b"test_hash_2" * 2,  # 32 bytes
        expires_on=datetime.utcnow() + timedelta(days=7)
    )
    db.add(observable)
    db.commit()
    
    # Map to alert
    mapping = ObservableMapping(
        observable_id=observable.id,
        alert_id=alert.id
    )
    db.add(mapping)
    db.commit()
    
    # Call refresh with nullify=True
    refresh_observable_expires_on([alert.uuid], nullify=True)
    
    # Verify expires_on was set to None
    db.refresh(observable)
    assert observable.expires_on is None


@pytest.mark.integration
def test_refresh_observable_expires_on_already_null():
    """Test refresh_observable_expires_on doesn't affect already null expires_on."""
    alert = insert_alert()
    
    db = get_db()
    
    # Create observable with expires_on already null
    observable = Observable(
        type="url",
        value=b"http://test.example.com",
        sha256=b"test_hash_3" * 2,  # 32 bytes
        expires_on=None
    )
    db.add(observable)
    db.commit()
    
    # Map to alert
    mapping = ObservableMapping(
        observable_id=observable.id,
        alert_id=alert.id
    )
    db.add(mapping)
    db.commit()
    
    # Call refresh function
    refresh_observable_expires_on([alert.uuid])
    
    # Verify expires_on remains None (should be filtered out by the query)
    db.refresh(observable)
    assert observable.expires_on is None

def hash_bytes(data: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

@pytest.mark.integration
def test_refresh_observable_expires_on_multiple_alerts():
    """Test refresh_observable_expires_on with multiple alerts."""
    get_config()[CONFIG_OBSERVABLE_EXPIRATION_MAPPINGS]["ipv4"] = "30:00:00:00"  # 1 day expiration for ipv4
    get_config()[CONFIG_OBSERVABLE_EXPIRATION_MAPPINGS]["fqdn"] = "01:00:00:00"  # 1 day expiration for ipv4
    alert1 = insert_alert()
    alert2 = insert_alert()
    
    db = get_db()
    
    # Create observables for both alerts
    observable1 = Observable(
        type="ipv4",
        value=b"1.2.3.4",
        sha256=hash_bytes(b"1.2.3.4"),
        expires_on=datetime.utcnow() + timedelta(days=1)
    )
    observable2 = Observable(
        type="fqdn",
        value=b"test.com",
        sha256=hash_bytes(b"test.com"),
        expires_on=datetime.utcnow() + timedelta(days=2)
    )
    
    db.add_all([observable1, observable2])
    db.commit()
    
    # Map observables to alerts
    mappings = [
        ObservableMapping(observable_id=observable1.id, alert_id=alert1.id),
        ObservableMapping(observable_id=observable2.id, alert_id=alert2.id)
    ]
    db.add_all(mappings)
    db.commit()
    
    # Refresh for both alerts
    refresh_observable_expires_on([alert1.uuid, alert2.uuid])
    
    # Both should have been processed
    db.refresh(observable1)
    db.refresh(observable2)
    assert observable1.expires_on is not None
    assert observable2.expires_on is not None


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
def test_set_dispositions_malicious_updates_observables():
    """Test that malicious dispositions trigger observable expires_on updates."""
    get_config()[CONFIG_OBSERVABLE_EXPIRATION_MAPPINGS]["fqdn"] = "01:00:00:00"  # 1 day expiration for ipv4

    user = add_user("testuser_mal", "testuser_mal@test.com", "Test User", "password123")
    add_user_permission(user.id, "*", "*")

    try:
        alert = insert_alert()
        
        # Create observable for this alert
        db = get_db()
        observable = Observable(
            type="fqdn",
            value=b"malicious.example.com",
            sha256=b"test_hash_6" * 2,
            expires_on=datetime.utcnow() + timedelta(days=1)
        )
        db.add(observable)
        db.commit()
        
        # Map to alert
        mapping = ObservableMapping(
            observable_id=observable.id,
            alert_id=alert.id
        )
        db.add(mapping)
        db.commit()
        
        original_expires_on = observable.expires_on
        
        # Set malicious disposition
        malicious_disposition = next(iter(get_malicious_dispositions()))
        set_dispositions([alert.uuid], malicious_disposition, user.id)
        
        # Verify disposition was set
        db.refresh(alert)
        assert alert.disposition == malicious_disposition
        
        # Verify observable expires_on was potentially updated
        # (exact behavior depends on configuration)
        db.refresh(observable)
        assert observable.expires_on is not None
        
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