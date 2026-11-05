import hashlib
import pytest
from flask import url_for
from saq.database.model import Observable, ObservableMapping
from saq.database.pool import get_db
from saq.gui.alert import GUIAlert


@pytest.mark.integration
class TestObservablesView:
    """Test the observables view function."""

    def test_observables_missing_alert_uuid(self, web_client):
        """Test observables view with missing alert_uuid parameter."""
        response = web_client.get(url_for('analysis.observables'))
        
        # Should redirect to analysis index
        assert response.status_code == 302
        assert response.location.endswith(url_for('analysis.index'))

    def test_observables_invalid_alert_uuid(self, web_client):
        """Test observables view with invalid alert_uuid."""
        response = web_client.get(url_for('analysis.observables', alert_uuid='invalid-uuid'))
        
        # Should redirect to analysis index
        assert response.status_code == 302
        assert response.location.endswith(url_for('analysis.index'))

    def test_observables_valid_alert_no_observables(self, web_client):
        """Test observables view with valid alert but no observables."""
        # Create a test alert
        db = get_db()
        alert = GUIAlert()
        alert.uuid = 'test-alert-uuid'
        alert.storage_dir = '/tmp/test'
        alert.tool = 'test'
        alert.tool_instance = 'test'
        alert.alert_type = 'test'
        alert.description = 'Test alert'
        alert.priority = 1
        alert.disposition = None
        alert.location = 'test'
        alert.insert_date = '2023-01-01 00:00:00'
        
        db.add(alert)
        db.commit()

        response = web_client.get(url_for('analysis.observables', alert_uuid=alert.uuid))
        
        assert response.status_code == 200

    def test_observables_sorting_by_type_and_value(self, web_client):
        """Test that observables are sorted by type and then by value."""
        db = get_db()
        
        # Create a test alert
        alert = GUIAlert()
        alert.uuid = 'test-alert-uuid-3'
        alert.storage_dir = '/tmp/test'
        alert.tool = 'test'
        alert.tool_instance = 'test'
        alert.alert_type = 'test'
        alert.description = 'Test alert'
        alert.priority = 1
        alert.disposition = None
        alert.location = 'test'
        alert.insert_date = '2023-01-01 00:00:00'
        
        db.add(alert)
        db.flush()

        # inserted out of order, both by type and by value within a type
        observables_data = [
            ('ipv4', '192.168.1.2'),
            ('domain', 'zzz.example.com'),
            ('ipv4', '192.168.1.1'),
            ('domain', 'aaa.example.com'),
        ]

        observables = []
        for obs_type, obs_value in observables_data:
            observable = Observable()
            observable.type = obs_type
            observable.value = obs_value.encode('utf-8')
            observable.sha256 = hashlib.sha256(observable.value).digest()
            observables.append(observable)
            db.add(observable)
        
        db.flush()

        # Create observable mappings
        for observable in observables:
            mapping = ObservableMapping()
            mapping.alert_id = alert.id
            mapping.observable_id = observable.id
            db.add(mapping)
        
        db.commit()

        response = web_client.get(url_for('analysis.observables', alert_uuid=alert.uuid))
        
        assert response.status_code == 200
        # the types in order, and each type's values in order
        page = response.get_data(as_text=True)
        expected_order = ['<li>domain</li>', 'aaa.example.com (', 'zzz.example.com (',
                          '<li>ipv4</li>', '192.168.1.1 (', '192.168.1.2 (']
        positions = [page.index(text) for text in expected_order]
        assert positions == sorted(positions)

    def test_observables_count_only_default_queue(self, web_client):
        """The "seen N times" count follows the disposition history rule: only alerts in the
        default queue count, and faqueue alerts never do."""
        db = get_db()

        def _alert(uuid, queue="default", alert_type="test"):
            alert = GUIAlert()
            alert.uuid = uuid
            alert.storage_dir = f'/tmp/{uuid}'
            alert.tool = 'test'
            alert.tool_instance = 'test'
            alert.alert_type = alert_type
            alert.description = 'Test alert'
            alert.priority = 1
            alert.location = 'test'
            alert.insert_date = '2023-01-01 00:00:00'
            alert.queue = queue
            db.add(alert)
            return alert

        viewed = _alert('test-alert-uuid-queue-1')
        alerts = [
            viewed,
            _alert('test-alert-uuid-queue-2'),
            _alert('test-alert-uuid-queue-3', queue='external'),
            _alert('test-alert-uuid-queue-4', alert_type='faqueue'),
        ]
        db.flush()

        observable = Observable()
        observable.type = 'ipv4'
        observable.value = '192.168.1.200'.encode('utf-8')
        observable.sha256 = hashlib.sha256(observable.value).digest()
        db.add(observable)
        db.flush()

        for alert in alerts:
            db.add(ObservableMapping(alert_id=alert.id, observable_id=observable.id))
        db.commit()

        response = web_client.get(url_for('analysis.observables', alert_uuid=viewed.uuid))

        assert response.status_code == 200
        assert '192.168.1.200 (2)' in response.get_data(as_text=True)

    def test_observables_count_zero_when_only_other_queues(self, web_client):
        """An alert outside the default queue still lists its observables, with a count of 0."""
        db = get_db()
        alert = GUIAlert()
        alert.uuid = 'test-alert-uuid-queue-5'
        alert.storage_dir = '/tmp/test-queue-5'
        alert.tool = 'test'
        alert.tool_instance = 'test'
        alert.alert_type = 'test'
        alert.description = 'Test alert'
        alert.priority = 1
        alert.location = 'test'
        alert.insert_date = '2023-01-01 00:00:00'
        alert.queue = 'external'
        db.add(alert)
        db.flush()

        observable = Observable()
        observable.type = 'ipv4'
        observable.value = '192.168.1.201'.encode('utf-8')
        observable.sha256 = hashlib.sha256(observable.value).digest()
        db.add(observable)
        db.flush()
        db.add(ObservableMapping(alert_id=alert.id, observable_id=observable.id))
        db.commit()

        response = web_client.get(url_for('analysis.observables', alert_uuid=alert.uuid))

        assert response.status_code == 200
        assert '192.168.1.201 (0)' in response.get_data(as_text=True)
