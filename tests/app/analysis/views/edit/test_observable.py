import logging

import pytest
from unittest.mock import patch
from uuid import uuid4
from flask import url_for
from datetime import datetime

from saq.analysis.root import load_root
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED, DISPOSITION_SIMULATED, STATE_ANALYST_REQUESTED_ANALYSIS
from saq.database.model import Alert, Workload
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.database.util.locking import acquire_lock, release_lock
from saq.gui.alert import GUIAlert
from tests.saq.helpers import audit_actor_of, audit_record


@pytest.fixture
def alert(root_analysis):
    """A real alert in a post-correlation analysis mode."""
    root_analysis.analysis_mode = ANALYSIS_MODE_DISPOSITIONED
    root_analysis.save()
    ALERT(root_analysis)
    return root_analysis


@pytest.fixture
def basic_form_data(alert):
    """Basic form data for add_observable requests."""
    return {
        'alert_uuid': alert.uuid,
        'add_observable_type': 'ipv4',
        'add_observable_value': '192.168.1.1',
        'add_observable_time': ''
    }


def _saved_root(alert):
    return load_root(alert.storage_dir)


def _workload_modes(alert) -> list[str]:
    get_db().expire_all()
    return [w.analysis_mode for w in get_db().query(Workload).filter(Workload.uuid == alert.uuid)]


def _is_unlocked(alert_uuid: str) -> bool:
    lock_uuid = str(uuid4())
    if not acquire_lock(alert_uuid, lock_uuid):
        return False
    release_lock(alert_uuid, lock_uuid)
    return True


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

    def test_conversation_type_with_value_a_b(self, web_client, alert):
        """Test that conversation types accept add_observable_value_A and _B instead of add_observable_value."""
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': alert.uuid,
            'add_observable_type': 'email_conversation',
            'add_observable_value_A': 'sender@example.com',
            'add_observable_value_B': 'recipient@example.com',
            'add_observable_time': ''
        })

        # Should redirect to analysis.index with direct parameter
        assert response.status_code == 302
        assert f'direct={alert.uuid}' in response.location
        assert _saved_root(alert).get_observable_by_type('email_conversation') is not None

    def test_email_conversation_value_formatting(self, web_client, alert):
        """Test that email conversation values are joined with pipe."""
        web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': alert.uuid,
            'add_observable_type': 'email_conversation',
            'add_observable_value_A': 'sender@example.com',
            'add_observable_value_B': 'recipient@example.com',
            'add_observable_time': ''
        })

        observable = _saved_root(alert).get_observable_by_type('email_conversation')
        assert observable.value == 'sender@example.com|recipient@example.com'

    def test_ipv4_conversation_value_formatting(self, web_client, alert):
        """Test that ipv4 conversation values are joined with underscore."""
        web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': alert.uuid,
            'add_observable_type': 'ipv4_conversation',
            'add_observable_value_A': '192.168.1.1',
            'add_observable_value_B': '192.168.1.2',
            'add_observable_time': ''
        })

        observable = _saved_root(alert).get_observable_by_type('ipv4_conversation')
        assert observable.value == '192.168.1.1_192.168.1.2'

    def test_ipv4_full_conversation_value_formatting(self, web_client, alert):
        """Test that ipv4 full conversation values are joined with colon."""
        web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': alert.uuid,
            'add_observable_type': 'ipv4_full_conversation',
            'add_observable_value_A': '192.168.1.1:8080',
            'add_observable_value_B': '192.168.1.2:80',
            'add_observable_time': ''
        })

        observable = _saved_root(alert).get_observable_by_type('ipv4_full_conversation')
        assert observable.value == '192.168.1.1:8080:192.168.1.2:80'

    def test_valid_datetime_parsing(self, web_client, alert):
        """Test that valid datetime strings are parsed correctly."""
        test_time = '2024-01-15 14:30:45'
        web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': alert.uuid,
            'add_observable_type': 'ipv4',
            'add_observable_value': '192.168.1.1',
            'add_observable_time': test_time
        })

        observable = _saved_root(alert).get_observable_by_type('ipv4')
        assert observable.value == '192.168.1.1'
        assert observable.time.replace(tzinfo=None) == datetime.strptime(test_time, '%Y-%m-%d %H:%M:%S')

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

    def test_alert_not_found_in_database(self, web_client):
        """Test when alert cannot be found in database."""
        missing_uuid = str(uuid4())
        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': missing_uuid,
            'add_observable_type': 'ipv4',
            'add_observable_value': '192.168.1.1',
            'add_observable_time': ''
        })

        assert response.status_code == 302
        assert f'direct={missing_uuid}' in response.location
        assert _is_unlocked(missing_uuid)

    def test_frozen_alert_is_not_modified(self, web_client, alert, basic_form_data):
        """An alert with a frozen disposition is neither changed nor queued again."""
        get_db().query(Alert).filter(Alert.uuid == alert.uuid).update({Alert.disposition: DISPOSITION_SIMULATED})
        get_db().commit()

        response = web_client.post(url_for('analysis.add_observable'), data=basic_form_data)

        assert response.status_code == 302
        assert _saved_root(alert).get_observable_by_type('ipv4') is None
        assert _workload_modes(alert) == []

    def test_unable_to_acquire_lock(self, web_client, alert, basic_form_data):
        """Test when unable to acquire lock on alert."""
        other_lock = str(uuid4())
        assert acquire_lock(alert.uuid, other_lock)
        try:
            response = web_client.post(url_for('analysis.add_observable'), data=basic_form_data)
        finally:
            release_lock(alert.uuid, other_lock)

        assert response.status_code == 302
        assert _saved_root(alert).get_observable_by_type('ipv4') is None
        assert _workload_modes(alert) == []

    def test_alert_load_error(self, web_client, alert, basic_form_data):
        """Test when alert.load() raises an exception."""
        with patch.object(GUIAlert, 'load', side_effect=Exception("Load failed")):
            response = web_client.post(url_for('analysis.add_observable'), data=basic_form_data)

        assert response.status_code == 302
        assert _workload_modes(alert) == []
        assert _is_unlocked(alert.uuid)

    def test_alert_sync_error(self, web_client, alert, basic_form_data):
        """Test when alert.sync() raises an exception."""
        with patch.object(GUIAlert, 'sync', side_effect=Exception("Sync failed")):
            response = web_client.post(url_for('analysis.add_observable'), data=basic_form_data)

        assert response.status_code == 302
        assert _saved_root(alert).get_observable_by_type('ipv4') is None
        assert _workload_modes(alert) == []
        assert _is_unlocked(alert.uuid)

    def test_successful_observable_addition(self, web_client, session_actor, alert, basic_form_data, caplog):
        """Test successful addition of an observable."""
        caplog.set_level(logging.INFO)
        response = web_client.post(url_for('analysis.add_observable'), data={
            **basic_form_data,
            'add_observable_directives': 'no_scan, not_a_directive',
        })

        assert response.status_code == 302
        root = _saved_root(alert)
        observable = root.get_observable_by_type('ipv4')
        assert observable.value == '192.168.1.1'
        assert observable.directives == ['no_scan']
        added = audit_record(caplog, "user john added observable (ipv4,192.168.1.1,")
        assert (*audit_actor_of(added), added.alert_uuid, added.observable_type, added.observable_value) == (
            *session_actor, alert.uuid, "ipv4", "192.168.1.1")
        directed = audit_record(caplog, "user john added directives ['no_scan']")
        assert (*audit_actor_of(directed), directed.alert_uuid, directed.observable_uuid, directed.directives) == (
            *session_actor, alert.uuid, observable.uuid, ["no_scan"])
        # switched back into correlation mode and queued for the analysis the analyst asked for
        assert root.analysis_mode == ANALYSIS_MODE_CORRELATION
        assert root.state[STATE_ANALYST_REQUESTED_ANALYSIS] is True
        assert _workload_modes(alert) == [ANALYSIS_MODE_CORRELATION]
        assert _is_unlocked(alert.uuid)

    def test_added_by_stamped_on_new_observable(self, web_client, alert, basic_form_data):
        """Test that a newly added observable is stamped with the current user and time."""
        response = web_client.post(url_for('analysis.add_observable'), data=basic_form_data)

        assert response.status_code == 302
        observable = _saved_root(alert).get_observable_by_type('ipv4')
        # the web_client fixture logs in as user "john"
        assert observable.added_by == 'john'
        assert isinstance(observable.added_time, datetime)

    def test_added_by_not_stamped_on_existing_observable(self, web_client, root_analysis):
        """Test that an observable that already existed in the alert is not stamped."""
        # the observable already exists in the alert (e.g. added by the engine)
        root_analysis.add_observable_by_spec('ipv4', '192.168.1.1')
        root_analysis.save()
        ALERT(root_analysis)

        response = web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': root_analysis.uuid,
            'add_observable_type': 'ipv4',
            'add_observable_value': '192.168.1.1',
            'add_observable_time': ''
        })

        assert response.status_code == 302
        observables = _saved_root(root_analysis).get_observables_by_type('ipv4')
        assert len(observables) == 1
        assert observables[0].added_by is None
        assert observables[0].added_time is None

    def test_lock_release_error_handling(self, web_client, alert, basic_form_data):
        """Test that lock release errors are handled gracefully."""
        with patch('app.analysis.views.edit.observable.release_lock',
                   side_effect=Exception("Release failed")) as mock_release_lock:
            response = web_client.post(url_for('analysis.add_observable'), data=basic_form_data)

        # Should still complete successfully despite lock release error
        assert response.status_code == 302
        mock_release_lock.assert_called_once()
        assert mock_release_lock.call_args.args[0] == alert.uuid
        assert _saved_root(alert).get_observable_by_type('ipv4') is not None
        assert _workload_modes(alert) == [ANALYSIS_MODE_CORRELATION]

    def test_email_delivery_value_formatting(self, web_client, alert):
        """Test that email delivery values are joined with pipe."""
        web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': alert.uuid,
            'add_observable_type': 'email_delivery',
            'add_observable_value_A': '<message-id@example.com>',
            'add_observable_value_B': 'recipient@example.com',
            'add_observable_time': ''
        })

        observable = _saved_root(alert).get_observable_by_type('email_delivery')
        assert observable.value == '<message-id@example.com>|recipient@example.com'

    def test_regular_observable_type_ignores_value_a_b(self, web_client, alert):
        """Test that regular observable types use add_observable_value, not _A/_B."""
        web_client.post(url_for('analysis.add_observable'), data={
            'alert_uuid': alert.uuid,
            'add_observable_type': 'fqdn',
            'add_observable_value': 'example.com',
            'add_observable_value_A': 'ignored',
            'add_observable_value_B': 'also_ignored',
            'add_observable_time': ''
        })

        observables = _saved_root(alert).get_observables_by_type('fqdn')
        assert [o.value for o in observables] == ['example.com']
