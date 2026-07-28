import pytest

from saq.database.pool import get_db, get_db_connection
from saq.database.database_observable import observable_is_set_for_detection, upsert_observable
from saq.database.model import ObservableDetection
from saq.database.util.observable_detection import create_observable_detection
from saq.observables import create_observable


@pytest.fixture(autouse=True)
def clean_detections():
    get_db().query(ObservableDetection).delete()
    get_db().commit()
    yield
    get_db().query(ObservableDetection).delete()
    get_db().commit()


@pytest.mark.integration
def test_observable_is_set_for_detection_true():
    observable = create_observable("ipv4", "192.168.50.1")
    create_observable_detection(observable.type, observable.value, None)

    assert observable_is_set_for_detection(observable) is True


@pytest.mark.integration
def test_observable_is_set_for_detection_not_exists():
    observable = create_observable("ipv4", "192.168.50.2")
    assert observable_is_set_for_detection(observable) is False


@pytest.mark.integration
def test_observable_is_set_for_detection_requires_a_matching_type():
    """The type predicate is load-bearing.

    This used to match on the hash alone, so a value enabled for detection under one type reported
    as enabled for every other type sharing that value -- which showed the wrong action menu in the
    alert view.
    """
    detected = create_observable("fqdn", "shared.example.com")
    create_observable_detection(detected.type, detected.value, None)

    other_type = create_observable("url_domain", "shared.example.com")
    assert other_type is not None
    assert detected.sha256_bytes == other_type.sha256_bytes

    assert observable_is_set_for_detection(detected) is True
    assert observable_is_set_for_detection(other_type) is False


@pytest.mark.integration
def test_observable_is_set_for_detection_with_special_characters():
    for value in [
        "test with spaces",
        "test@with#special$chars%",
        "test\nwith\nnewlines",
        "test\twith\ttabs",
        "test'with'quotes\"and\"double",
    ]:
        observable = create_observable("test", value)
        if observable is None:
            continue

        assert observable_is_set_for_detection(observable) is False
        create_observable_detection(observable.type, observable.value, None)
        assert observable_is_set_for_detection(observable) is True



@pytest.mark.integration
def test_upsert_observable_new():
    """Test upserting a new observable that doesn't exist."""
    observable = create_observable("test", "upsert_test_new")
    assert observable is not None
    
    # Ensure it doesn't exist
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM observables WHERE type = %s AND sha256 = %s", 
                      (observable.type, observable.sha256_bytes))
        result = cursor.fetchone()
        assert result[0] == 0
    
    # Upsert the observable
    obs_id = upsert_observable(observable)
    assert obs_id is not None
    assert isinstance(obs_id, int)
    assert obs_id > 0
    
    # Verify it was inserted
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, type, value, sha256, for_detection FROM observables WHERE id = %s", (obs_id,))
        result = cursor.fetchone()
        assert result is not None
        assert result[0] == obs_id
        assert result[1] == observable.type
        assert result[2].decode("utf-8") == observable.value
        assert result[3] == observable.sha256_bytes


@pytest.mark.integration
def test_upsert_observable_existing():
    """Test upserting an observable that already exists."""
    observable = create_observable("test", "upsert_test_existing")
    assert observable is not None
    
    # First insert manually
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO observables (`type`, `value`, `sha256`, `for_detection`) VALUES (%s, %s, %s, %s)",
                      (observable.type, observable.value, observable.sha256_bytes, True))
        db.commit()
        original_id = cursor.lastrowid
    
    # Upsert the same observable
    obs_id = upsert_observable(observable)
    assert obs_id == original_id
    
    # Verify no duplicate was created
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM observables WHERE type = %s AND sha256 = %s",
                      (observable.type, observable.sha256_bytes))
        result = cursor.fetchone()
        assert result[0] == 1


@pytest.mark.integration
def test_upsert_observable_different_types():
    """Test upserting observables of different types."""
    test_cases = [
        ("ipv4", "192.168.1.100"),
        ("fqdn", "upsert.example.com"),
        ("url", "https://upsert.example.com/path"),
        ("email", "upsert@example.com"),
    ]
    
    for obs_type, value in test_cases:
        observable = create_observable(obs_type, value)
        if observable is None:
            continue
            
        obs_id = upsert_observable(observable)
        assert obs_id is not None
        assert isinstance(obs_id, int)
        assert obs_id > 0
        
        # Verify the observable was stored correctly
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT type, value FROM observables WHERE id = %s", (obs_id,))
            result = cursor.fetchone()
            assert result is not None
            assert result[0] == obs_type
            assert result[1].decode("utf-8") == value


@pytest.mark.integration
def test_upsert_observable_special_characters():
    """Test upserting observables with special characters."""
    test_values = [
        "test with spaces",
        "test@with#special$chars%",
        "test'with'quotes\"and\"double",
        "test\\with\\backslashes",
        "test\nwith\nnewlines",
        "test\twith\ttabs",
    ]
    
    for value in test_values:
        observable = create_observable("test", value)
        if observable is None:
            continue
            
        obs_id = upsert_observable(observable)
        assert obs_id is not None
        assert isinstance(obs_id, int)
        assert obs_id > 0
        
        # Verify the value was stored correctly
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT value FROM observables WHERE id = %s", (obs_id,))
            result = cursor.fetchone()
            assert result is not None
            assert result[0].decode("utf-8") == value

@pytest.mark.integration
def test_upsert_observable_idempotent():
    """Test that upserting the same observable multiple times returns the same ID."""
    observable = create_observable("test", "upsert_idempotent_test")
    assert observable is not None
    
    # Upsert multiple times
    obs_id_1 = upsert_observable(observable)
    obs_id_2 = upsert_observable(observable)
    obs_id_3 = upsert_observable(observable)
    
    # All should return the same ID
    assert obs_id_1 == obs_id_2 == obs_id_3
    
    # Verify only one record exists
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM observables WHERE type = %s AND sha256 = %s",
                      (observable.type, observable.sha256_bytes))
        result = cursor.fetchone()
        assert result[0] == 1


@pytest.mark.integration
def test_upsert_observable_same_value_different_type():
    """Test upserting observables with same value but different types."""
    value = "same_value_test"
    
    # Create observables with same value but different types
    obs1 = create_observable("test", value)
    obs2 = create_observable("fqdn", value)
    
    if obs1 is None or obs2 is None:
        pytest.skip("Could not create required observables")
    
    # They should have different sha256 hashes due to different types
    assert obs1.sha256_bytes != obs2.sha256_bytes
    
    # Upsert both
    obs_id_1 = upsert_observable(obs1)
    obs_id_2 = upsert_observable(obs2)
    
    # Should get different IDs
    assert obs_id_1 != obs_id_2
    
    # Verify both exist in database
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM observables WHERE value = %s", (value,))
        result = cursor.fetchone()
        assert result[0] == 2


@pytest.mark.integration
def test_upsert_observable_race_condition_simulation():
    """Test upsert behavior when race conditions might occur."""
    observable = create_observable("test", "race_condition_test")
    assert observable is not None
    
    # First upsert
    obs_id_1 = upsert_observable(observable)
    assert obs_id_1 is not None
    
    # Simulate what might happen in a race condition by manually inserting
    # the same observable again (this should trigger the IntegrityError path)
    try:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("INSERT INTO observables (`type`, `value`, `sha256`) VALUES (%s, %s, %s)",
                          (observable.type, observable.value, observable.sha256_bytes))
            db.commit()
    except Exception:
        # Expected to fail due to unique constraint
        pass
    
    # Second upsert should still work and return the original ID
    obs_id_2 = upsert_observable(observable)
    assert obs_id_2 == obs_id_1


@pytest.mark.integration
def test_upsert_observable_return_type():
    """Test that upsert_observable returns the correct type."""
    observable = create_observable("test", "return_type_test")
    assert observable is not None
    
    obs_id = upsert_observable(observable)
    
    # Should return an integer
    assert isinstance(obs_id, int)
    assert obs_id > 0
    
    # Should be a valid database ID
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM observables WHERE id = %s", (obs_id,))
        result = cursor.fetchone()
        assert result is not None
        assert result[0] == obs_id
