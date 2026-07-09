import hashlib
from datetime import datetime
from flask import url_for
import pytest
from unittest.mock import Mock, patch

from saq.constants import ACTION_ENABLE_DETECTION
from saq.database.model import Observable
from saq.database.pool import get_db
from saq.gui.alert import GUIAlert


@pytest.fixture
def mock_alert():
    """Create a mock alert for testing."""
    alert = Mock(spec=GUIAlert)
    alert.uuid = "test-alert-uuid"
    alert.description = "Test Alert"
    alert.root_analysis = Mock()
    alert.root_analysis.load = Mock()
    alert.root_analysis.get_observable = Mock()
    return alert


@pytest.fixture
def mock_observable():
    """Create a mock observable for testing."""
    observable = Mock()
    observable.type = "ipv4"
    observable.value = "192.168.1.1"
    observable.sha256_hex = "abcd1234"
    observable.sha256_bytes = bytes.fromhex("abcd1234")
    observable.expires_on = None
    return observable


@pytest.fixture
def db_observable():
    """Create a database observable for testing."""
    # Create a test observable in the database
    test_value = "192.168.1.1"
    test_type = "ipv4"
    test_sha256 = hashlib.sha256(test_value.encode()).digest()
    
    observable = Observable()
    observable.type = test_type
    observable.value = test_value.encode()
    observable.sha256 = test_sha256
    observable.for_detection = False
    
    db = get_db()
    db.add(observable)
    db.commit()
    
    yield observable
    
    # Cleanup
    db.delete(observable)
    db.commit()


@pytest.mark.integration
class TestObservableActionSetForDetection:
    """Tests for observable_action_set_for_detection function."""

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_no_alert(self, mock_get_alert, web_client):
        """Test when no alert is found."""
        mock_get_alert.return_value = None
        
        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })
        
        assert response.status_code == 200
        assert b"Error: unable to find alert" in response.data

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_alert_load_error(self, mock_get_alert, web_client, mock_alert):
        """Test when alert fails to load."""
        mock_alert.root_analysis.load.side_effect = Exception("Load failed")
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })
        
        assert response.status_code == 200
        assert b"unable to load alert" in response.data

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_observable_not_found(self, mock_get_alert, web_client, mock_alert):
        """Test when observable is not found in alert."""
        mock_alert.root_analysis.get_observable.return_value = None
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })
        
        assert response.status_code == 200
        assert b"unable to find observable in alert" in response.data

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_enable_success(self, mock_get_alert, web_client, mock_alert, mock_observable, db_observable):
        """Test successfully enabling detection for an observable."""
        # Set up the mock sha256 to match our test observable
        mock_observable.sha256_hex = db_observable.sha256.hex()
        mock_observable.sha256_bytes = db_observable.sha256
        mock_observable.type = db_observable.type
        
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })
        
        assert response.status_code == 200
        assert b"Observable enabled for detection" in response.data
        
        # Verify the observable was updated in database
        db = get_db()
        updated_observable = db.query(Observable).filter(Observable.id == db_observable.id).first()
        assert updated_observable.for_detection is True
        assert updated_observable.detection_modified_by is not None
        assert "manually enabled in the gui" in updated_observable.detection_context

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_disable_success(self, mock_get_alert, web_client, mock_alert, mock_observable, db_observable):
        """Test successfully disabling detection for an observable."""
        # First enable it
        db_observable.for_detection = True
        db = get_db()
        db.commit()
        
        # Set up the mock sha256 to match our test observable
        mock_observable.sha256_hex = db_observable.sha256.hex()
        mock_observable.sha256_bytes = db_observable.sha256
        mock_observable.type = db_observable.type
        
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': 'disable_detection'
        })
        
        assert response.status_code == 200
        assert b"Observable disabled for detection" in response.data
        
        # Verify the observable was updated in database
        updated_observable = db.query(Observable).filter(Observable.id == db_observable.id).first()
        assert updated_observable.for_detection is False

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_database_error(self, mock_get_alert, web_client, mock_alert, mock_observable):
        """Test database error when updating observable."""
        mock_observable.sha256_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        mock_observable.sha256_bytes = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        mock_observable.type = "ipv4"
        
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })
        
        assert response.status_code == 200
        assert b"Observable enabled for detection" in response.data


@pytest.mark.integration
class TestObservableActionAdjustExpiration:
    """Tests for observable_action_adjust_expiration function."""

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_no_alert(self, mock_get_alert, web_client):
        """Test when no alert is found."""
        mock_get_alert.return_value = None
        
        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid'
        })
        
        assert response.status_code == 200
        assert b"Error: unable to find alert" in response.data

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_alert_load_error(self, mock_get_alert, web_client, mock_alert):
        """Test when alert fails to load."""
        mock_alert.root_analysis.load.side_effect = Exception("Load failed")
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid'
        })
        
        assert response.status_code == 302  # Should redirect on error

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_observable_not_found(self, mock_get_alert, web_client, mock_alert):
        """Test when observable is not found in alert."""
        mock_alert.root_analysis.get_observable.return_value = None
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid'
        })
        
        assert response.status_code == 302  # Should redirect on error

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_set_datetime_success(self, mock_get_alert, web_client, mock_alert, mock_observable):
        """Test successfully setting expiration datetime."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        
        expiration_time = "2024-12-31 23:59:59"
        
        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid',
            'observable_expiration_time': expiration_time
        })
        
        assert response.status_code == 302  # Should redirect on success
        
        # Verify the observable expiration was set
        expected_datetime = datetime.strptime(expiration_time, '%Y-%m-%d %H:%M:%S')
        assert mock_observable.expires_on == expected_datetime

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_never_expire_success(self, mock_get_alert, web_client, mock_alert, mock_observable):
        """Test successfully setting observable to never expire."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid',
            'observable_never_expire': 'on'
        })
        
        assert response.status_code == 302  # Should redirect on success
        
        # Verify the observable expiration was set to None
        assert mock_observable.expires_on is None

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_invalid_datetime_format(self, mock_get_alert, web_client, mock_alert, mock_observable):
        """Test with invalid datetime format."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        
        # The datetime parsing happens before try/catch, so we expect a ValueError
        with pytest.raises(ValueError, match="time data 'invalid-date' does not match format"):
            web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
                'alert_uuid': 'test-uuid',
                'observable_uuid': 'obs-uuid',
                'observable_expiration_time': 'invalid-date'
            })

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_observable_update_error(self, mock_get_alert, web_client, mock_alert, mock_observable):
        """Test error when updating observable expiration."""
        # Configure the observable mock to raise an exception when expires_on is set
        type(mock_observable).expires_on = Mock(side_effect=Exception("Update failed"))
        
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        
        expiration_time = "2024-12-31 23:59:59"
        
        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid',
            'observable_expiration_time': expiration_time
        })
        
        assert response.status_code == 302  # Should redirect on error