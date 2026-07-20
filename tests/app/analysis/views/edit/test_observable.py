import pytest
from unittest.mock import Mock, patch
from flask import url_for
from datetime import datetime

from saq.analysis.root import RootAnalysis
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED
from saq.gui.alert import GUIAlert


@pytest.fixture
def mock_alert():
    """Create a mock GUIAlert for testing."""
    alert = Mock(spec=GUIAlert)
    alert.uuid = "test-alert-uuid"
    alert.description = "Test Alert"
    alert.lock_uuid = None
    alert.load = Mock()
    alert.sync = Mock()
    # a real RootAnalysis (not a Mock) so analysis_mode and state round-trip honestly
    alert.root_analysis = RootAnalysis(uuid="test-root-uuid", analysis_mode=ANALYSIS_MODE_DISPOSITIONED)
    # the observable does not already exist in the alert by default
    alert.root_analysis.get_observable_by_spec = Mock(return_value=None)
    alert.root_analysis.add_observable_by_spec = Mock()
    return alert


@pytest.fixture
def basic_form_data():
    """Basic form data for add_observable requests."""
    return {
        'alert_uuid': 'test-alert-uuid',
        'add_observable_type': 'ipv4',
        'add_observable_value': '192.168.1.1',
        'add_observable_time': ''
    }


@pytest.fixture
def conversation_form_data():
    """Form data for conversation-type observables."""
    return {
        'alert_uuid': 'test-alert-uuid',
        'add_observable_type': 'email_conversation',
        'add_observable_value_A': 'sender@example.com',
        'add_observable_value_B': 'recipient@example.com',
        'add_observable_time': ''
    }


@pytest.mark.integration
class TestAddObservable:
    """Tests for add_observable function."""

    def test_missing_alert_uuid(self, web_client):
        """Test when alert_uuid is missing from form."""
        response = web_client.post(url_for('analysis.add_observable'), data={
            'add_observable_type': 'ipv4',
            'add_observable_value': '192.168.1.1',
            'add_observable_time': ''
        })
        
        assert response.status_code == 302
        # Should redirect to analysis.index due to missing form item

    def test_missing_observable_type(self, web_client):
        """Test when add_observable_type is missing from form."""
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': 'test-uuid',
            'add_observable_value': '192.168.1.1',
            'add_observable_time': ''
        })
        
        assert response.status_code == 302

    def test_missing_observable_value(self, web_client):
        """Test when add_observable_value is missing from form."""
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': 'test-uuid',
            'add_observable_type': 'ipv4',
            'add_observable_time': ''
        })
        
        assert response.status_code == 302

    def test_missing_observable_time(self, web_client):
        """Test when add_observable_time is missing from form."""
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': 'test-uuid',
            'add_observable_type': 'ipv4',
            'add_observable_value': '192.168.1.1'
        })
        
        assert response.status_code == 302

    def test_conversation_type_with_value_a_b(self, web_client):
        """Test that conversation types accept add_observable_value_A and _B instead of add_observable_value."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_alert = Mock(spec=GUIAlert)
            mock_alert.uuid = 'test-uuid'
            mock_alert.lock_uuid = None
            mock_alert.load = Mock()
            mock_alert.sync = Mock()
            mock_alert.root_analysis = RootAnalysis(uuid='test-root-uuid',
                                                   analysis_mode=ANALYSIS_MODE_DISPOSITIONED)
            mock_alert.root_analysis.add_observable_by_spec = Mock()
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'email_conversation',
                'add_observable_value_A': 'sender@example.com',
                'add_observable_value_B': 'recipient@example.com',
                'add_observable_time': ''
            })
            
            assert response.status_code == 302
            # Should redirect to analysis.index with direct parameter

    def test_email_conversation_value_formatting(self, web_client, mock_alert):
        """Test that email conversation values are joined with pipe."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'email_conversation',
                'add_observable_value_A': 'sender@example.com',
                'add_observable_value_B': 'recipient@example.com',
                'add_observable_time': ''
            })
            
            mock_alert.root_analysis.add_observable_by_spec.assert_called_once_with(
                'email_conversation', 'sender@example.com|recipient@example.com', None
            )

    def test_ipv4_conversation_value_formatting(self, web_client, mock_alert):
        """Test that ipv4 conversation values are joined with underscore."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4_conversation',
                'add_observable_value_A': '192.168.1.1',
                'add_observable_value_B': '192.168.1.2',
                'add_observable_time': ''
            })
            
            mock_alert.root_analysis.add_observable_by_spec.assert_called_once_with(
                'ipv4_conversation', '192.168.1.1_192.168.1.2', None
            )

    def test_ipv4_full_conversation_value_formatting(self, web_client, mock_alert):
        """Test that ipv4 full conversation values are joined with colon."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4_full_conversation',
                'add_observable_value_A': '192.168.1.1:8080',
                'add_observable_value_B': '192.168.1.2:80',
                'add_observable_time': ''
            })
            
            mock_alert.root_analysis.add_observable_by_spec.assert_called_once_with(
                'ipv4_full_conversation', '192.168.1.1:8080:192.168.1.2:80', None
            )

    def test_valid_datetime_parsing(self, web_client, mock_alert):
        """Test that valid datetime strings are parsed correctly."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            
            test_time = '2024-01-15 14:30:45'
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4',
                'add_observable_value': '192.168.1.1',
                'add_observable_time': test_time
            })
            
            expected_datetime = datetime.strptime(test_time, '%Y-%m-%d %H:%M:%S')
            mock_alert.root_analysis.add_observable_by_spec.assert_called_once_with(
                'ipv4', '192.168.1.1', expected_datetime
            )

    def test_invalid_datetime_format(self, web_client):
        """Test that invalid datetime format causes flash error and redirect."""
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': 'test-uuid',
            'add_observable_type': 'ipv4',
            'add_observable_value': '192.168.1.1',
            'add_observable_time': 'invalid-date-format'
        })
        
        assert response.status_code == 302

    def test_empty_observable_value(self, web_client):
        """Test that empty observable value causes flash error and redirect."""
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': 'test-uuid',
            'add_observable_type': 'ipv4',
            'add_observable_value': '',
            'add_observable_time': ''
        })
        
        assert response.status_code == 302

    @patch('app.analysis.views.edit.observable.get_db')
    def test_alert_not_found_in_database(self, mock_get_db, web_client):
        """Test when alert cannot be found in database."""
        mock_db = Mock()
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.one.side_effect = Exception("Alert not found")
        
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': 'nonexistent-uuid',
            'add_observable_type': 'ipv4',
            'add_observable_value': '192.168.1.1',
            'add_observable_time': ''
        })
        
        assert response.status_code == 302

    @patch('app.analysis.views.edit.observable.acquire_lock')
    @patch('app.analysis.views.edit.observable.get_db')
    def test_unable_to_acquire_lock(self, mock_get_db, mock_acquire_lock, web_client, mock_alert):
        """Test when unable to acquire lock on alert."""
        mock_db = Mock()
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
        mock_acquire_lock.return_value = False
        
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': 'test-uuid',
            'add_observable_type': 'ipv4',
            'add_observable_value': '192.168.1.1',
            'add_observable_time': ''
        })
        
        assert response.status_code == 302

    def test_alert_load_error(self, web_client, mock_alert):
        """Test when alert.load() raises an exception."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            mock_alert.load.side_effect = Exception("Load failed")
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4',
                'add_observable_value': '192.168.1.1',
                'add_observable_time': ''
            })
            
            assert response.status_code == 302
            mock_release_lock.assert_called_once()

    def test_alert_sync_error(self, web_client, mock_alert):
        """Test when alert.sync() raises an exception."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            mock_alert.sync.side_effect = Exception("Sync failed")
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4',
                'add_observable_value': '192.168.1.1',
                'add_observable_time': ''
            })
            
            assert response.status_code == 302
            mock_release_lock.assert_called_once()

    def test_successful_observable_addition(self, web_client, mock_alert):
        """Test successful addition of an observable."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload, \
             patch('app.analysis.views.edit.observable.uuidlib.uuid4') as mock_uuid4:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            
            # Mock the generated UUID
            mock_uuid = Mock()
            mock_uuid.__str__ = Mock(return_value='test-lock-uuid')
            mock_uuid4.return_value = mock_uuid
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4',
                'add_observable_value': '192.168.1.1',
                'add_observable_time': ''
            })
            
            assert response.status_code == 302
            mock_alert.load.assert_called_once()
            mock_alert.root_analysis.add_observable_by_spec.assert_called_once_with('ipv4', '192.168.1.1', None)
            assert mock_alert.root_analysis.analysis_mode == ANALYSIS_MODE_CORRELATION
            mock_alert.sync.assert_called_once()
            mock_add_workload.assert_called_once_with(mock_alert.root_analysis)
            mock_release_lock.assert_called_once_with('test-alert-uuid', 'test-lock-uuid')

    def test_added_by_stamped_on_new_observable(self, web_client, mock_alert):
        """Test that a newly added observable is stamped with the current user and time."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:

            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True

            mock_observable = Mock()
            mock_alert.root_analysis.add_observable_by_spec.return_value = mock_observable

            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4',
                'add_observable_value': '192.168.1.1',
                'add_observable_time': ''
            })

            assert response.status_code == 302
            # the web_client fixture logs in as user "john"
            assert mock_observable.added_by == 'john'
            assert isinstance(mock_observable.added_time, datetime)

    def test_added_by_not_stamped_on_existing_observable(self, web_client, mock_alert):
        """Test that an observable that already existed in the alert is not stamped."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:

            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True

            mock_observable = Mock()
            mock_observable.added_by = None
            mock_observable.added_time = None
            # the observable already exists in the alert (e.g. added by the engine)
            mock_alert.root_analysis.get_observable_by_spec.return_value = mock_observable
            mock_alert.root_analysis.add_observable_by_spec.return_value = mock_observable

            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4',
                'add_observable_value': '192.168.1.1',
                'add_observable_time': ''
            })

            assert response.status_code == 302
            assert mock_observable.added_by is None
            assert mock_observable.added_time is None

    def test_lock_release_error_handling(self, web_client, mock_alert):
        """Test that lock release errors are handled gracefully."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload, \
             patch('app.analysis.views.edit.observable.uuidlib.uuid4') as mock_uuid4:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            mock_release_lock.side_effect = Exception("Release failed")
            
            # Mock the generated UUID
            mock_uuid = Mock()
            mock_uuid.__str__ = Mock(return_value='test-lock-uuid')
            mock_uuid4.return_value = mock_uuid
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'ipv4',
                'add_observable_value': '192.168.1.1',
                'add_observable_time': ''
            })
            
            # Should still complete successfully despite lock release error
            assert response.status_code == 302
            mock_release_lock.assert_called_once()

    def test_email_delivery_value_formatting(self, web_client, mock_alert):
        """Test that email delivery values are joined with pipe."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'email_delivery',
                'add_observable_value_A': 'sender@example.com',
                'add_observable_value_B': 'recipient@example.com',
                'add_observable_time': ''
            })
            
            mock_alert.root_analysis.add_observable_by_spec.assert_called_once_with(
                'email_delivery', 'sender@example.com|recipient@example.com', None
            )

    def test_regular_observable_type_ignores_value_a_b(self, web_client, mock_alert):
        """Test that regular observable types use add_observable_value, not _A/_B."""
        with patch('app.analysis.views.edit.observable.get_db') as mock_get_db, \
             patch('app.analysis.views.edit.observable.acquire_lock') as mock_acquire_lock, \
             patch('app.analysis.views.edit.observable.release_lock') as mock_release_lock, \
             patch('app.analysis.views.edit.observable.add_workload') as mock_add_workload:
            
            mock_db = Mock()
            mock_get_db.return_value = mock_db
            mock_db.query.return_value.filter.return_value.one.return_value = mock_alert
            mock_acquire_lock.return_value = True
            
            response = web_client.post(url_for('analysis.add_observable'), data={
                'alert_uuid': 'test-uuid',
                'add_observable_type': 'domain',
                'add_observable_value': 'example.com',
                'add_observable_value_A': 'ignored',
                'add_observable_value_B': 'also_ignored',
                'add_observable_time': ''
            })
            
            mock_alert.root_analysis.add_observable_by_spec.assert_called_once_with(
                'domain', 'example.com', None
            )