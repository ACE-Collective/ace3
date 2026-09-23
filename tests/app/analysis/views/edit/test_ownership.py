import pytest
from unittest.mock import Mock, patch
from flask import url_for
from datetime import datetime

from saq.database.model import Alert, User
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, delete_user
from tests.saq.helpers import insert_alert


@pytest.fixture
def mock_db():
    """Create a mock database for testing."""
    db = Mock()
    db.execute = Mock()
    db.commit = Mock()
    db.query = Mock()
    return db


@pytest.fixture
def mock_user():
    """Create a mock user for testing."""
    user = Mock(spec=User)
    user.id = 123
    user.username = "testuser"
    return user


@pytest.mark.integration
class TestAssignOwnership:
    """Tests for assign_ownership function."""

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_no_form_fields(self, mock_get_db, web_client):
        """Test when neither alert_uuid nor alert_uuids is in form."""
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'selected_user_id': '123'
        })
        
        assert response.status_code == 302
        # Should redirect to analysis.index due to missing form fields

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_single_alert_analysis_page(self, mock_get_db, web_client, mock_db, mock_user):
        """Test assigning ownership from analysis page with single alert."""
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuid': 'test-alert-uuid',
            'selected_user_id': '123'
        })
        
        assert response.status_code == 302
        # Should call execute to update the alert
        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()
        
        # Should query for the target user
        mock_db.query.assert_called_with(User)

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_multiple_alerts_management_page(self, mock_get_db, web_client, mock_db, mock_user):
        """Test assigning ownership from management page with multiple alerts."""
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        
        with web_client.session_transaction() as sess:
            # Initialize session to avoid KeyError
            pass
        
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuids': 'uuid1,uuid2,uuid3',
            'selected_user_id': '123'
        })
        
        assert response.status_code == 302
        # Should call execute to update multiple alerts
        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()
        
        # Should query for the target user
        mock_db.query.assert_called_with(User)

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_empty_alert_uuids(self, mock_get_db, web_client, mock_db, mock_user):
        """Test when alert_uuids is empty string."""
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuids': '',
            'selected_user_id': '123'
        })
        
        assert response.status_code == 302
        # The code still calls execute even with empty list (len(['']) = 1)
        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_user_query_exception(self, mock_get_db, web_client, mock_db):
        """Test when user query raises an exception."""
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.side_effect = Exception("User not found")
        
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuid': 'test-alert-uuid',
            'selected_user_id': '123'
        })
        
        assert response.status_code == 302
        # Should still call execute and commit despite user query error
        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_invalid_user_id(self, mock_get_db, web_client, mock_db):
        """Test when selected_user_id is not a valid integer."""
        mock_get_db.return_value = mock_db
        
        # The ValueError happens in the int() conversion in the database update, not in the query
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuid': 'test-alert-uuid',
            'selected_user_id': 'invalid'
        })

        # should fail with a flash message
        assert response.status_code == 302

    @patch('app.analysis.views.edit.ownership.get_db')
    @patch('app.analysis.views.edit.ownership.datetime')
    def test_assign_ownership_datetime_called(self, mock_datetime, mock_get_db, web_client, mock_db, mock_user):
        """Test that datetime.now() is called for owner_time."""
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        mock_now = datetime(2024, 1, 15, 10, 30, 45)
        mock_datetime.now.return_value = mock_now
        
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuid': 'test-alert-uuid',
            'selected_user_id': '123'
        })
        
        assert response.status_code == 302
        mock_datetime.now.assert_called_once()

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_analysis_page_redirect(self, mock_get_db, web_client, mock_db, mock_user):
        """Test that analysis page redirects back to analysis.index with direct parameter."""
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuid': 'test-alert-uuid',
            'selected_user_id': '123'
        })
        
        assert response.status_code == 302
        assert 'direct=test-alert-uuid' in response.location

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_management_page_redirect(self, mock_get_db, web_client, mock_db, mock_user):
        """Test that management page redirects to analysis.manage."""
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        
        response = web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuids': 'uuid1,uuid2',
            'selected_user_id': '123'
        })
        
        assert response.status_code == 302
        assert '/manage' in response.location

    @patch('app.analysis.views.edit.ownership.get_db')
    def test_assign_ownership_session_checked_set(self, mock_get_db, web_client, mock_db, mock_user):
        """Test that session['checked'] is set for management page."""
        mock_get_db.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        
        with web_client.session_transaction() as sess:
            # Ensure session is clean
            sess.pop('checked', None)
        
        web_client.post(url_for('analysis.assign_ownership'), data={
            'alert_uuids': 'uuid1,uuid2,uuid3',
            'selected_user_id': '123'
        })
        
        with web_client.session_transaction() as sess:
            assert 'checked' in sess
            assert sess['checked'] == ['uuid1', 'uuid2', 'uuid3']


@pytest.fixture
def other_analyst():
    """An analyst other than the logged-in one, who owns alerts."""
    user = add_user("jane_owner", "jane_owner@localhost", "Jane", "password")
    yield user
    delete_user("jane_owner")


def _owned_by(alert, user_id):
    db = get_db()
    db.query(Alert).filter(Alert.id == alert.id).update({Alert.owner_id: user_id})
    db.commit()


def _owner_of(alert):
    db = get_db()
    db.expire_all()
    return db.get(Alert, alert.id).owner_id


@pytest.mark.integration
class TestSetOwner:
    """Tests for set_owner function."""

    def test_set_owner_get_request_rejected(self, web_client):
        """set_owner writes to the database, so it is POST-only: a GET must change nothing."""
        alert = insert_alert()

        response = web_client.get(url_for('analysis.set_owner'), query_string={
            'alert_uuids': [alert.uuid]
        })

        assert response.status_code == 405
        assert _owner_of(alert) is None

    def test_set_owner_post_request(self, web_client, analyst):
        alerts = [insert_alert(), insert_alert()]

        response = web_client.post(url_for('analysis.set_owner'), data={
            'alert_uuids': [alert.uuid for alert in alerts]
        })

        assert response.status_code == 204
        assert response.data == b''
        for alert in alerts:
            assert _owner_of(alert) == analyst

    def test_set_owner_session_checked_set(self, web_client):
        """Test that session['checked'] is set correctly."""
        with web_client.session_transaction() as sess:
            sess.pop('checked', None)

        web_client.post(url_for('analysis.set_owner'), data={
            'alert_uuids': ['uuid1', 'uuid2']
        })

        with web_client.session_transaction() as sess:
            assert sess['checked'] == ['uuid1', 'uuid2']

    def test_set_owner_no_alert_uuids_parameter(self, web_client):
        response = web_client.post(url_for('analysis.set_owner'))
        assert response.status_code == 204

    def test_set_owner_leaves_alert_owned_by_another_alone(self, web_client, analyst, other_analyst):
        owned = insert_alert()
        _owned_by(owned, other_analyst.id)
        unowned = insert_alert()

        response = web_client.post(url_for('analysis.set_owner'), data={
            'alert_uuids': [owned.uuid, unowned.uuid]
        })

        assert response.status_code == 204
        assert _owner_of(owned) == other_analyst.id
        assert _owner_of(unowned) == analyst
        with web_client.session_transaction() as sess:
            assert [message for _, message in sess['_flashes']] == [
                "took ownership of 1 alerts; left 1 alert owned by Jane alone"]

    def test_set_owner_takes_confirmed_alert(self, web_client, analyst, other_analyst):
        owned = insert_alert()
        _owned_by(owned, other_analyst.id)

        response = web_client.post(url_for('analysis.set_owner'), data={
            'alert_uuids': [owned.uuid],
            'take_owned': f"{owned.uuid}:{other_analyst.id}",
        })

        assert response.status_code == 204
        assert _owner_of(owned) == analyst
        with web_client.session_transaction() as sess:
            assert '_flashes' not in sess

    def test_set_owner_database_error(self, web_client):
        with patch('app.analysis.views.edit.ownership.take_ownership', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                web_client.post(url_for('analysis.set_owner'), data={
                    'alert_uuids': ['uuid1']
                })
