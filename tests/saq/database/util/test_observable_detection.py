import pytest
from datetime import datetime

from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.database.model import Observable as DBObservable, User
from saq.database.pool import get_db
from saq.database.util.observable_detection import (
    enable_observable_detection,
    disable_observable_detection,
    get_all_observable_detections,
    get_observable_detections,
    _match_observable,
    ObservableDetection
)
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission


@pytest.fixture
def test_user() -> User:
    """Create a test user for observable detection tests."""
    username = "detection_test_user"
    email = "detection_test@example.com"
    display_name = "Detection Test User"
    password = "testpass123"
    
    user = add_user(username, email, display_name, password)
    add_user_permission(user.id, "*", "*")
    yield user
    
    # Cleanup
    try:
        delete_user(username)
    except:
        pass


@pytest.fixture
def test_observable():
    """Create a test observable for detection tests."""
    observable = Observable(type="ipv4", value="192.168.1.1")
    return observable


@pytest.fixture
def test_observables():
    """Create multiple test observables for detection tests."""
    observables = [
        Observable(type="ipv4", value="192.168.1.1"),
        Observable(type="fqdn", value="example.com"),
        Observable(type="url", value="http://malicious.example.com/path"),
        Observable(type="file", value="malicious.exe")
    ]
    return observables


@pytest.fixture
def test_root_analysis(test_observables):
    """Create a test root analysis with observables."""
    root = RootAnalysis()
    for observable in test_observables:
        root.add_observable(observable)
    return root


def cleanup_test_observables():
    """Clean up any test observables from the database."""
    db = get_db()
    test_values = ["192.168.1.1", "example.com", "http://malicious.example.com/path", "malicious.exe"]
    for observable in db.query(DBObservable).all():
        if observable.display_value in test_values:
            db.delete(observable)
    db.commit()


@pytest.mark.integration
def test_enable_observable_detection_new_observable(test_user, test_observable):
    """Test enabling detection for a new observable that doesn't exist in database."""
    detection_context = "Test detection context"
    
    # Ensure observable doesn't exist
    db = get_db()
    existing = db.query(DBObservable).filter(
        DBObservable.sha256 == test_observable.sha256_bytes,
        DBObservable.type == test_observable.type
    ).first()
    if existing:
        db.delete(existing)
        db.commit()
    
    # Enable detection
    enable_observable_detection(test_observable, test_user.id, detection_context)
    
    # Verify observable was created with detection enabled
    db_observable = db.query(DBObservable).filter(
        DBObservable.sha256 == test_observable.sha256_bytes,
        DBObservable.type == test_observable.type
    ).first()
    
    assert db_observable is not None
    assert db_observable.for_detection is True
    assert db_observable.enabled_by == test_user.id
    assert db_observable.detection_context == detection_context
    assert db_observable.type == test_observable.type
    assert db_observable.value == test_observable.value.encode()
    
    # Cleanup
    db.delete(db_observable)
    db.commit()


@pytest.mark.integration
def test_enable_observable_detection_existing_observable(test_user, test_observable):
    """Test enabling detection for an existing observable in database."""
    detection_context = "Updated detection context"
    
    # Create existing observable with detection disabled
    db = get_db()
    existing = DBObservable(
        type=test_observable.type,
        sha256=test_observable.sha256_bytes,
        value=test_observable.value.encode(),
        for_detection=False,
        enabled_by=None,
        detection_context=None
    )
    db.add(existing)
    db.commit()
    
    # Enable detection
    enable_observable_detection(test_observable, test_user.id, detection_context)
    
    # Verify observable was updated
    db.refresh(existing)
    assert existing.for_detection is True
    assert existing.enabled_by == test_user.id
    assert existing.detection_context == detection_context
    
    # Cleanup
    db.delete(existing)
    db.commit()


@pytest.mark.integration
def test_enable_observable_detection_invalid_user(test_observable):
    """Test enabling detection with an invalid user ID."""
    invalid_user_id = 99999
    detection_context = "Test context"
    
    with pytest.raises(ValueError, match=f"User with id {invalid_user_id} not found"):
        enable_observable_detection(test_observable, invalid_user_id, detection_context)


@pytest.mark.integration
def test_disable_observable_detection_existing(test_user, test_observable):
    """Test disabling detection for an existing observable."""
    detection_context = "Test context"
    
    # First enable detection
    enable_observable_detection(test_observable, test_user.id, detection_context)
    
    # Verify it's enabled
    db = get_db()
    db_observable = db.query(DBObservable).filter(
        DBObservable.sha256 == test_observable.sha256_bytes,
        DBObservable.type == test_observable.type
    ).first()
    assert db_observable.for_detection is True
    
    # Disable detection
    disable_observable_detection(test_observable)
    
    # Verify it's disabled
    db.refresh(db_observable)
    assert db_observable.for_detection is False
    
    # Cleanup
    db.delete(db_observable)
    db.commit()


@pytest.mark.integration
def test_disable_observable_detection_nonexistent(test_observable):
    """Test disabling detection for a non-existent observable."""
    # Ensure observable doesn't exist
    db = get_db()
    existing = db.query(DBObservable).filter(
        DBObservable.sha256 == test_observable.sha256_bytes,
        DBObservable.type == test_observable.type
    ).first()
    if existing:
        db.delete(existing)
        db.commit()
    
    # Should not raise an error
    disable_observable_detection(test_observable)


@pytest.mark.integration
def test_match_observable_success(test_observables):
    """Test _match_observable utility function with successful match."""
    # Create a database observable that matches the first test observable
    test_obs = test_observables[0]
    db_observable = DBObservable(
        type=test_obs.type,
        sha256=test_obs.sha256_bytes,
        value=test_obs.value.encode(),
        for_detection=True
    )
    
    result = _match_observable(test_observables, db_observable)
    assert result is not None
    assert result == test_obs
    assert result.type == db_observable.type
    assert result.sha256_bytes == db_observable.sha256


@pytest.mark.integration
def test_match_observable_no_match(test_observables):
    """Test _match_observable utility function with no match."""
    # Create a database observable that doesn't match any test observables
    db_observable = DBObservable(
        type="ipv4",
        sha256=b"different_hash_12345678901234567890123456789012",
        value=b"10.0.0.1",
        for_detection=True
    )
    
    result = _match_observable(test_observables, db_observable)
    assert result is None


@pytest.mark.integration
def test_get_observable_detections_empty_list():
    """Test get_observable_detections with empty observable list."""
    result = get_observable_detections([])
    assert result == {}


@pytest.mark.integration
def test_get_observable_detections_with_detections(test_user, test_observables):
    """Test get_observable_detections with observables that have detection enabled."""
    # Enable detection for first two observables
    enable_observable_detection(test_observables[0], test_user.id, "Context 1")
    enable_observable_detection(test_observables[1], test_user.id, "Context 2")
    
    # Get detections
    detections = get_observable_detections(test_observables)
    
    # Should have detections for first two observables
    assert len(detections) == 2
    assert test_observables[0].uuid in detections
    assert test_observables[1].uuid in detections
    assert test_observables[2].uuid not in detections
    assert test_observables[3].uuid not in detections
    
    # Verify detection data
    detection1 = detections[test_observables[0].uuid]
    assert isinstance(detection1, ObservableDetection)
    assert detection1.observable_uuid == test_observables[0].uuid
    assert detection1.for_detection is True
    assert detection1.enabled_by == test_user.display_name
    assert detection1.detection_context == "Context 1"
    
    detection2 = detections[test_observables[1].uuid]
    assert detection2.observable_uuid == test_observables[1].uuid
    assert detection2.for_detection is True
    assert detection2.enabled_by == test_user.display_name
    assert detection2.detection_context == "Context 2"
    
    # Cleanup
    cleanup_test_observables()


@pytest.mark.integration
def test_get_observable_detections_no_detections(test_observables):
    """Test get_observable_detections with observables that have no detection enabled."""
    # Ensure no detections exist for test observables
    cleanup_test_observables()
    
    detections = get_observable_detections(test_observables)
    assert detections == {}


@pytest.mark.integration
def test_get_observable_detections_mixed(test_user, test_observables):
    """Test get_observable_detections with mix of enabled/disabled detection."""
    # Clean up first
    cleanup_test_observables()
    
    # Enable detection for some observables
    enable_observable_detection(test_observables[0], test_user.id, "Enabled context")
    enable_observable_detection(test_observables[2], test_user.id, "Another context")
    
    # Disable detection for one that was enabled
    disable_observable_detection(test_observables[2])
    
    detections = get_observable_detections(test_observables)
    
    # Should only have detection for first observable (enabled=True)
    # Second observable has detection disabled, so it should still appear but with for_detection=False
    assert len(detections) == 2
    assert test_observables[0].uuid in detections
    assert test_observables[2].uuid in detections
    
    detection1 = detections[test_observables[0].uuid]
    assert detection1.for_detection is True
    
    detection2 = detections[test_observables[2].uuid]
    assert detection2.for_detection is False
    
    # Cleanup
    cleanup_test_observables()


@pytest.mark.integration
def test_get_all_observable_detections(test_user, test_root_analysis):
    """Test get_all_observable_detections with a root analysis."""
    # Clean up first
    cleanup_test_observables()
    
    # Enable detection for some observables in the root analysis
    observables = test_root_analysis.all_observables
    enable_observable_detection(observables[0], test_user.id, "Root context 1")
    enable_observable_detection(observables[1], test_user.id, "Root context 2")
    
    detections = get_all_observable_detections(test_root_analysis)
    
    # Should have detections for enabled observables
    assert len(detections) >= 2
    assert observables[0].uuid in detections
    assert observables[1].uuid in detections
    
    detection1 = detections[observables[0].uuid]
    assert detection1.for_detection is True
    assert detection1.enabled_by == test_user.display_name
    assert detection1.detection_context == "Root context 1"
    
    # Cleanup
    cleanup_test_observables()


@pytest.mark.integration
def test_observable_detection_dataclass():
    """Test ObservableDetection dataclass functionality."""
    detection = ObservableDetection(
        observable_uuid="test-uuid-123",
        for_detection=True,
        enabled_by="Test User",
        detection_context="Test context"
    )
    
    assert detection.observable_uuid == "test-uuid-123"
    assert detection.for_detection is True
    assert detection.enabled_by == "Test User"
    assert detection.detection_context == "Test context"


@pytest.mark.integration
def test_enable_detection_context_persistence(test_user, test_observable):
    """Test that detection context is properly persisted and retrieved."""
    context = "Malicious IP detected in network traffic analysis, confirmed by threat intel"
    
    # Enable detection with specific context
    enable_observable_detection(test_observable, test_user.id, context)
    
    # Retrieve detection and verify context
    detections = get_observable_detections([test_observable])
    detection = detections[test_observable.uuid]
    
    assert detection.detection_context == context
    
    # Cleanup
    cleanup_test_observables()


@pytest.mark.integration
def test_enable_detection_overwrites_existing(test_user, test_observable):
    """Test that enabling detection overwrites existing detection settings."""
    # Enable detection first time
    enable_observable_detection(test_observable, test_user.id, "Original context")
    
    # Create second user for testing
    user2 = add_user("detection_user2", "user2@test.com", "User 2", "pass123")
    add_user_permission(user2.id, "*", "*")

    try:
        # Enable detection second time with different user and context
        enable_observable_detection(test_observable, user2.id, "Updated context")
        
        # Verify it was updated
        detections = get_observable_detections([test_observable])
        detection = detections[test_observable.uuid]
        
        assert detection.enabled_by == user2.display_name
        assert detection.detection_context == "Updated context"
        
    finally:
        # Cleanup
        delete_user("detection_user2")
        cleanup_test_observables()