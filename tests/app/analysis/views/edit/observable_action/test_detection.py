from datetime import datetime
from flask import url_for
import pytest
from unittest.mock import Mock, patch

from saq.constants import ACTION_ENABLE_DETECTION
from saq.database.model import ObservableDetection
from saq.database.pool import get_db
from saq.database.util.observable_detection import create_observable_detection
from saq.gui.alert import GUIAlert
from saq.observables.generator import create_observable


TEST_TYPE = "ipv4"
TEST_VALUE = "192.168.1.1"


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
def observable():
    """A real analysis observable -- the detection helpers key off sha256_bytes, which is
    polymorphic, so a Mock would not exercise the real path."""
    return create_observable(TEST_TYPE, TEST_VALUE)


@pytest.fixture(autouse=True)
def clean_detections():
    get_db().query(ObservableDetection).delete()
    get_db().commit()
    yield
    get_db().query(ObservableDetection).delete()
    get_db().commit()


def _detection():
    return get_db().query(ObservableDetection).filter(
        ObservableDetection.type == TEST_TYPE, ObservableDetection.value == TEST_VALUE).one_or_none()


@pytest.mark.integration
class TestObservableActionSetForDetection:
    """Tests for observable_action_set_for_detection function."""

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_no_alert(self, mock_get_alert, web_client):
        mock_get_alert.return_value = None

        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })

        assert response.status_code == 200
        assert b"unable to find alert" in response.data

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_alert_load_error(self, mock_get_alert, web_client, mock_alert):
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
        mock_alert.root_analysis.get_observable.return_value = None
        mock_get_alert.return_value = mock_alert

        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })

        assert response.status_code == 200
        assert b"unable to find observable in alert" in response.data

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_enable_success(self, mock_get_alert, web_client, mock_alert, observable):
        mock_alert.root_analysis.get_observable.return_value = observable
        mock_get_alert.return_value = mock_alert

        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })

        assert response.status_code == 200
        assert b"Observable enabled for detection" in response.data

        detection = _detection()
        assert detection is not None
        assert detection.value_sha256 == observable.sha256_bytes
        assert detection.modified_by is not None
        assert "manually enabled in the gui" in detection.detection_context

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_enable_does_not_touch_the_observables_index(self, mock_get_alert, web_client, mock_alert, observable):
        """Enabling used to insert an observables row as a side effect of where the flag lived."""
        from saq.database.model import Observable as DBObservable

        mock_alert.root_analysis.get_observable.return_value = observable
        mock_get_alert.return_value = mock_alert

        web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': ACTION_ENABLE_DETECTION
        })

        assert get_db().query(DBObservable).filter(
            DBObservable.sha256 == observable.sha256_bytes).one_or_none() is None

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_set_for_detection_disable_removes_the_detection(self, mock_get_alert, web_client, mock_alert, observable):
        """A row is an active detection, so disabling deletes it."""
        create_observable_detection(TEST_TYPE, TEST_VALUE, None)
        assert _detection() is not None

        mock_alert.root_analysis.get_observable.return_value = observable
        mock_get_alert.return_value = mock_alert

        response = web_client.post(url_for('analysis.observable_action_set_for_detection'), data={
            'observable_uuid': 'test-uuid',
            'action_id': 'disable_detection'
        })

        assert response.status_code == 200
        assert b"Observable disabled for detection" in response.data
        assert _detection() is None


@pytest.mark.integration
class TestObservableActionAdjustExpiration:
    """Tests for observable_action_adjust_expiration function."""

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_no_alert(self, mock_get_alert, web_client):
        mock_get_alert.return_value = None

        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid'
        })

        assert response.status_code == 200
        assert b"Error: unable to find alert" in response.data

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_alert_load_error(self, mock_get_alert, web_client, mock_alert):
        mock_alert.root_analysis.load.side_effect = Exception("Load failed")
        mock_get_alert.return_value = mock_alert

        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid'
        })

        assert response.status_code == 302  # Should redirect on error

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_observable_not_found(self, mock_get_alert, web_client, mock_alert):
        mock_alert.root_analysis.get_observable.return_value = None
        mock_get_alert.return_value = mock_alert

        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid'
        })

        assert response.status_code == 302  # Should redirect on error

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_persists(self, mock_get_alert, web_client, mock_alert, observable):
        """The expiration must actually reach the database.

        This used to assign expires_on on the transient in-memory Observable -- which has no such
        attribute -- and flash success having written nothing.
        """
        create_observable_detection(TEST_TYPE, TEST_VALUE, None)

        mock_alert.root_analysis.get_observable.return_value = observable
        mock_get_alert.return_value = mock_alert

        expiration_time = "2030-12-31 23:59:59"
        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid',
            'observable_expiration_time': expiration_time
        })

        assert response.status_code == 302
        get_db().expire_all()
        assert _detection().expires_on == datetime.strptime(expiration_time, '%Y-%m-%d %H:%M:%S')

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_never_expire_persists(self, mock_get_alert, web_client, mock_alert, observable):
        create_observable_detection(
            TEST_TYPE, TEST_VALUE, None, expires_on=datetime(2030, 1, 1, 0, 0, 0))

        mock_alert.root_analysis.get_observable.return_value = observable
        mock_get_alert.return_value = mock_alert

        response = web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
            'alert_uuid': 'test-uuid',
            'observable_uuid': 'obs-uuid',
            'observable_never_expire': 'on'
        })

        assert response.status_code == 302
        get_db().expire_all()
        assert _detection().expires_on is None

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_without_a_detection_reports_an_error(self, mock_get_alert, web_client, mock_alert, observable):
        """Expiration belongs to a detection, so there must be one to adjust."""
        mock_alert.root_analysis.get_observable.return_value = observable
        mock_get_alert.return_value = mock_alert

        response = web_client.post(
            url_for('analysis.observable_action_adjust_expiration'),
            data={
                'alert_uuid': 'test-uuid',
                'observable_uuid': 'obs-uuid',
                'observable_expiration_time': "2030-12-31 23:59:59",
            },
            follow_redirects=True)

        assert b"not enabled for detection" in response.data

    @patch('app.analysis.views.edit.observable_action.detection.get_current_alert')
    def test_adjust_expiration_invalid_datetime_format(self, mock_get_alert, web_client, mock_alert, observable):
        mock_alert.root_analysis.get_observable.return_value = observable
        mock_get_alert.return_value = mock_alert

        # the datetime parsing happens before the try/except, so this propagates
        with pytest.raises(ValueError, match="time data 'invalid-date' does not match format"):
            web_client.post(url_for('analysis.observable_action_adjust_expiration'), data={
                'alert_uuid': 'test-uuid',
                'observable_uuid': 'obs-uuid',
                'observable_expiration_time': 'invalid-date'
            })
