import glob
import hashlib
import io
import logging
import os
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
import requests
from flask import url_for

from app.analysis.views.edit.new import SUBMIT_TIMEOUT
from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import F_FILE, F_IPV4, create_file_location
from saq.database.model import Alert, Company, Nodes
from saq.database.pool import get_db
from saq.environment import get_data_dir, get_temp_dir
from saq.util.uuid import get_storage_dir


@pytest.fixture
def target_node():
    """A node that accepts any analysis mode, as the form's target_node_data value."""
    node = Nodes(
        name="new-alert-node",
        location="new-alert-location",
        company_id=get_config().global_settings.company_id,
        last_update=datetime.now(),
        any_mode=True)
    get_db().add(node)
    get_db().commit()
    return f"{node.id},{node.location},{node.company_id}"


def _form(target_node, **fields):
    data = {
        'new_alert_insert_date': '01-01-2024 12:00:00',
        'timezone': 'UTC',
        'new_alert_type': 'manual',
        'new_alert_description': 'Test Alert',
        'new_alert_queue': 'default',
        'target_node_data': target_node,
        'observables_directives_0': 'no_scan',
        'observable_data_sep_0': 'single',
        'submit_type': 'single',
    }
    data.update(fields)
    return data


def _alert_uuid(response) -> str:
    assert response.status_code == 302
    assert 'direct=' in response.location
    return response.location.split('direct=')[1]


def _submitted_root(response):
    return load_root(get_storage_dir(_alert_uuid(response)))


def _alerts() -> list[Alert]:
    get_db().expire_all()
    return get_db().query(Alert).all()


def _leftover_uploads() -> list[str]:
    return glob.glob(os.path.join(get_temp_dir(), '*.upload'))


def _flashes(web_client) -> list[str]:
    with web_client.session_transaction() as session:
        return [message for _category, message in session.get('_flashes', [])]


@pytest.mark.integration
def test_new_alert_observable_get(web_client):
    """Test GET request to new_alert_observable returns template with correct data."""
    response = web_client.get(url_for('analysis.new_alert_observable', index='5'))

    assert response.status_code == 200
    # Template should be returned successfully
    assert response.data is not None


@pytest.mark.integration
def test_new_alert_observable_missing_index(web_client):
    """Test new_alert_observable without index parameter."""
    try:
        response = web_client.get(url_for('analysis.new_alert_observable'))
        # Should return 400 or 500 due to missing required parameter
        assert response.status_code in [400, 500]
    except Exception:
        # URL generation may fail without required parameter
        pass


@pytest.mark.integration
def test_file_route_get(web_client, target_node):
    """Test GET request to file route returns analyze_file template."""
    response = web_client.get(url_for('analysis.file'))

    assert response.status_code == 200
    assert f'value="{target_node}"'.encode() in response.data


@pytest.mark.integration
def test_new_alert_single_observable_success(web_client, mock_api_call, analyst, target_node):
    """Test successful creation of single alert with one observable."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        new_alert_description='Test Alert',
        observables_types_0='ipv4',
        observables_values_0='192.168.1.1'))

    # Should redirect to analysis index with the new alert UUID
    assert 'analysis' in response.location
    root = _submitted_root(response)
    assert root.description == 'Test Alert (192.168.1.1)'
    assert root.tool == 'gui'
    assert root.queue == 'default'
    assert root.details['user'] == 'john'
    assert root.event_time == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

    observable = root.get_observable_by_type(F_IPV4)
    assert observable.value == '192.168.1.1'
    assert observable.has_directive('no_scan')
    assert observable.added_by == 'john'
    assert observable.added_time

    # the analyst who submitted it owns it
    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
    assert alert.owner_id == analyst
    assert alert.owner_time is not None


@pytest.mark.integration
def test_new_alert_multiple_observables_multi_submit(web_client, mock_api_call, analyst, target_node):
    """Test creation of multiple alerts from multi-line observable input."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        new_alert_description='Multi Alert',
        observables_types_0='ipv4',
        observables_values_0='192.168.1.1\n192.168.1.2\n192.168.1.3',
        observable_data_sep_0='multi',
        submit_type='multiple'))

    # one alert per value, each owned by the analyst, and the redirect goes to the last one
    alerts = _alerts()
    assert sorted(alert.description for alert in alerts) == [
        'Multi Alert (192.168.1.1)', 'Multi Alert (192.168.1.2)', 'Multi Alert (192.168.1.3)']
    assert all(alert.owner_id == analyst for alert in alerts)

    root = _submitted_root(response)
    assert root.description == 'Multi Alert (192.168.1.3)'
    assert [o.value for o in root.get_observables_by_type(F_IPV4)] == ['192.168.1.3']


@pytest.mark.integration
def test_new_alert_invalid_timezone(web_client, mock_api_call, target_node):
    """Test new alert creation with invalid timezone."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        timezone='Invalid/Timezone'))

    # Should redirect to manage page due to timezone error
    assert response.status_code == 302
    assert 'manage' in response.location
    assert _alerts() == []


@pytest.mark.integration
def test_new_alert_email_conversation_observable(web_client, mock_api_call, target_node):
    """Test creation of alert with email conversation observable."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        observables_types_0='email_conversation',
        observables_values_0_A='sender@example.com',
        observables_values_0_B='recipient@example.com'))

    root = _submitted_root(response)
    observable = root.get_observable_by_type('email_conversation')
    assert observable.value == 'sender@example.com|recipient@example.com'


@pytest.mark.integration
def test_new_alert_ipv4_conversation_observable(web_client, mock_api_call, target_node):
    """Test creation of alert with IPv4 conversation observable."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        observables_types_0='ipv4_conversation',
        observables_values_0_A='192.168.1.1',
        observables_values_0_B='192.168.1.2'))

    root = _submitted_root(response)
    observable = root.get_observable_by_type('ipv4_conversation')
    assert observable.value == '192.168.1.1_192.168.1.2'


@pytest.mark.integration
def test_new_alert_file_location_observable(web_client, mock_api_call, target_node):
    """Test creation of alert with file location observable."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        observables_types_0='file_location',
        observables_values_0_A='hostname',
        observables_values_0_B='/path/to/file'))

    root = _submitted_root(response)
    observable = root.get_observable_by_type('file_location')
    assert observable.value == create_file_location('hostname', '/path/to/file')


@pytest.mark.integration
def test_new_alert_file_row_without_upload_is_refused(web_client, mock_api_call, target_node, caplog):
    """A file observable posted without a file is refused with a message, not an error report."""
    with caplog.at_level(logging.WARNING):
        response = web_client.post(url_for('analysis.new_alert'), data=_form(
            target_node,
            observables_types_0=F_FILE,
            observables_values_0='/path/to/file'))

    assert response.status_code == 302
    assert 'manage' in response.location
    assert _alerts() == []
    assert _flashes(web_client) == ['no file uploaded for observable 0']
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.mark.integration
@pytest.mark.parametrize('submit_type', ['single', 'multiple'])
def test_new_alert_file_row_without_upload_refuses_every_observable(web_client, mock_api_call, target_node, submit_type):
    """A file row without an upload among other observables refuses the whole submission: a single
    alert is not created without it, no alert is created for the other observables, and the upload
    already saved for an earlier row is removed."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        observables_types_0=F_FILE,
        observables_values_0=(io.BytesIO(b'uploaded content'), 'upload.txt'),
        observables_types_1=F_FILE,
        observables_values_1='not an upload',
        observables_directives_1='',
        observable_data_sep_1='single',
        submit_type=submit_type),
        content_type='multipart/form-data')

    assert response.status_code == 302
    assert 'manage' in response.location
    assert _alerts() == []
    assert _flashes(web_client) == ['no file uploaded for observable 1']
    assert _leftover_uploads() == []


@pytest.mark.integration
def test_new_alert_api_submission_failure(web_client, target_node):
    """Test handling of API submission failure."""
    # Mock API submission to raise exception
    with patch('app.analysis.views.edit.new.ace_api.submit', side_effect=Exception("API submission failed")):
        response = web_client.post(url_for('analysis.new_alert'), data=_form(
            target_node,
            observables_types_0='ipv4',
            observables_values_0='192.168.1.1'))

    # Should redirect to manage page with error
    assert response.status_code == 302
    assert 'manage' in response.location


@pytest.mark.integration
@pytest.mark.parametrize('submit_type', ['single', 'multiple'])
def test_new_alert_submission_timeout_is_reported(web_client, target_node, monkeypatch, caplog, submit_type):
    """A target node that stalls times the submission out instead of holding the GUI worker."""
    post = Mock(side_effect=requests.Timeout("read timed out"))
    # ace_api imports requests when it makes the call
    monkeypatch.setattr("requests.post", post)
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

    with caplog.at_level(logging.ERROR):
        response = web_client.post(url_for('analysis.new_alert'), data=_form(
            target_node,
            observables_types_0='ipv4',
            observables_values_0='192.168.1.1',
            submit_type=submit_type))

    post.assert_called_once()
    assert post.call_args.kwargs['timeout'] == SUBMIT_TIMEOUT
    assert response.status_code == 302
    assert 'manage' in response.location
    assert _flashes(web_client) == ['unable to submit alert: read timed out']
    records = [r for r in caplog.records if r.getMessage().startswith("unable to submit alert")]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None
    write_error_report.assert_called_once()
    assert _alerts() == []


@pytest.mark.integration
def test_new_alert_comma_separated_multi_values(web_client, mock_api_call, target_node):
    """Test parsing of comma-separated multi-value observables."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        new_alert_description='Comma Separated Alert',
        observables_types_0='ipv4',
        observables_values_0='192.168.1.1,192.168.1.2,192.168.1.3',
        observable_data_sep_0='multi'))

    # a single alert carrying all three values
    root = _submitted_root(response)
    assert root.description == 'Comma Separated Alert'
    assert sorted(o.value for o in root.get_observables_by_type(F_IPV4)) == [
        '192.168.1.1', '192.168.1.2', '192.168.1.3']
    assert len(_alerts()) == 1


@pytest.mark.integration
def test_new_alert_observable_with_time(web_client, mock_api_call, target_node):
    """Test creation of observable with specific time."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        timezone='America/New_York',
        observables_types_0='ipv4',
        observables_values_0='192.168.1.1',
        observables_times_0='01-02-2024 14:30:00'))

    # the observable time is read in the submitted timezone
    root = _submitted_root(response)
    observable = root.get_observable_by_type(F_IPV4)
    assert observable.time == datetime(2024, 1, 2, 19, 30, 0, tzinfo=UTC)


@pytest.mark.integration
def test_new_alert_directive_list_parsing(web_client, mock_api_call, target_node):
    """Test parsing of directive lists from form."""
    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        observables_types_0='ipv4',
        observables_values_0='192.168.1.1',
        observables_directives_0='no_scan, archive,'))

    root = _submitted_root(response)
    observable = root.get_observable_by_type(F_IPV4)
    assert sorted(observable.directives) == ['archive', 'no_scan']


@pytest.mark.integration
def test_file_route_lists_nodes_of_every_company(web_client, target_node):
    """The node list on the file page covers every company's nodes."""
    company = Company(name='secondary-company')
    get_db().add(company)
    get_db().flush()
    node = Nodes(name='secondary-node', location='secondary-location', company_id=company.id,
                 last_update=datetime.now(), any_mode=True)
    get_db().add(node)
    get_db().commit()

    response = web_client.get(url_for('analysis.file'))

    assert response.status_code == 200
    assert f'value="{target_node}"'.encode() in response.data
    assert f'value="{node.id},secondary-location,{company.id}"'.encode() in response.data
    assert b'secondary-location (secondary-company)' in response.data


@pytest.mark.integration
def test_new_alert_no_observables(web_client, mock_api_call, analyst, target_node):
    """Test creation of alert with no observables."""
    response = web_client.post(url_for('analysis.new_alert'), data={
        'new_alert_insert_date': '01-01-2024 12:00:00',
        'timezone': 'UTC',
        'new_alert_type': 'manual',
        'new_alert_description': 'No Observable Alert',
        'new_alert_queue': 'default',
        'target_node_data': target_node,
        'submit_type': 'single'
    })

    root = _submitted_root(response)
    assert root.description == 'No Observable Alert'
    assert root.all_observables == []
    assert get_db().query(Alert).filter(Alert.uuid == root.uuid).one().owner_id == analyst


@pytest.mark.integration
def test_new_alert_never_reads_a_server_path(web_client, mock_api_call, target_node, tmp_path):
    """A file observable's value is only ever an upload: a path on this server given in its place
    (as the removed is_local field once allowed) is not opened or attached."""
    server_file = tmp_path / 'secret.txt'
    server_file.write_bytes(b'server file content')

    response = web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        new_alert_description='Server Path Alert',
        observables_types_0=F_FILE,
        observables_values_0=str(server_file),
        is_local='true'))

    # a file row without an upload is refused, and nothing was read from the server path
    assert response.status_code == 302
    assert 'direct=' not in response.location
    assert _flashes(web_client) == ['no file uploaded for observable 0']
    assert get_db().query(Alert).count() == 0
    for dir_path, _, file_names in os.walk(get_data_dir()):
        for file_name in file_names:
            with open(os.path.join(dir_path, file_name), 'rb') as fp:
                assert b'server file content' not in fp.read()


@pytest.mark.integration
def test_new_alert_file_upload_with_actual_file(web_client, mock_api_call, target_node):
    """An uploaded file is submitted as a file observable carrying the form's settings."""
    file_data = b'test file content for upload'

    response = web_client.post(
        url_for('analysis.new_alert'),
        data=_form(
            target_node,
            new_alert_description='Real File Upload Alert',
            observables_types_0=F_FILE,
            observables_values_0=(io.BytesIO(file_data), 'test_upload.txt')),
        content_type='multipart/form-data')

    root = _submitted_root(response)
    assert root.description == 'Real File Upload Alert (test_upload.txt)'
    observable = root.get_observable_by_type(F_FILE)
    assert observable.sha256_hash == hashlib.sha256(file_data).hexdigest()
    assert observable.file_name == 'test_upload.txt'
    with open(observable.full_path, 'rb') as fp:
        assert fp.read() == file_data
    assert observable.has_directive('no_scan')
    assert observable.added_by == 'john'


@pytest.mark.integration
def test_new_alert_file_upload_with_multipart_form(web_client, mock_api_call, target_node):
    """Each alert of a multiple submission carries only its own uploaded file, and the
    temporary upload files are removed afterwards."""
    response = web_client.post(
        url_for('analysis.new_alert'),
        data=_form(
            target_node,
            new_alert_description='Multipart File Upload',
            observables_types_0=F_FILE,
            observables_values_0=(io.BytesIO(b'first upload'), 'first.txt'),
            observables_types_1=F_FILE,
            observables_values_1=(io.BytesIO(b'second upload'), 'second.txt'),
            observables_directives_1='',
            observable_data_sep_1='single',
            submit_type='multiple'),
        content_type='multipart/form-data')

    assert response.status_code == 302
    files_by_alert = {}
    for alert in _alerts():
        root = load_root(get_storage_dir(alert.uuid))
        files_by_alert[root.description] = [o.sha256_hash for o in root.get_observables_by_type(F_FILE)]

    assert files_by_alert == {
        'Multipart File Upload (first.txt)': [hashlib.sha256(b'first upload').hexdigest()],
        'Multipart File Upload (second.txt)': [hashlib.sha256(b'second upload').hexdigest()],
    }
    assert _leftover_uploads() == []

@pytest.mark.integration
def test_new_alert_file_save_failure_is_reported(web_client, mock_api_call, target_node, monkeypatch, caplog):
    """An uploaded file that cannot be saved stops the submission and is reported."""
    def failing_save(self, dst, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("werkzeug.datastructures.FileStorage.save", failing_save)
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

    with caplog.at_level(logging.ERROR):
        response = web_client.post(url_for('analysis.new_alert'), data=_form(
            target_node,
            new_alert_description='File Upload Alert',
            observables_types_0=F_FILE,
            observables_values_0=(io.BytesIO(b'uploaded content'), 'upload.txt')),
            content_type='multipart/form-data')

    assert response.status_code == 302
    assert 'manage' in response.location
    assert _alerts() == []
    assert _leftover_uploads() == []
    records = [r for r in caplog.records if r.getMessage().startswith("unable to save")]
    assert len(records) == 1
    write_error_report.assert_called_once()


def _post_file_alert(web_client, target_node):
    return web_client.post(url_for('analysis.new_alert'), data=_form(
        target_node,
        new_alert_description='File Upload Alert',
        observables_types_0=F_FILE,
        observables_values_0=(io.BytesIO(b'uploaded content'), 'upload.txt')),
        content_type='multipart/form-data')


@pytest.mark.integration
def test_new_alert_temp_file_remove_failure_is_reported(web_client, mock_api_call, target_node, monkeypatch, caplog):
    """An upload left behind in the temp dir is reported with its traceback and path, and the
    alert is still submitted."""
    real_remove = os.remove

    def failing_remove(path, *args, **kwargs):
        if str(path).endswith('.upload'):
            raise PermissionError("permission denied")
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(os, "remove", failing_remove)
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

    with caplog.at_level(logging.ERROR):
        response = _post_file_alert(web_client, target_node)

    monkeypatch.undo()
    leftovers = _leftover_uploads()
    for path in leftovers:
        os.remove(path)

    _alert_uuid(response)
    assert len(leftovers) == 1
    records = [r for r in caplog.records if r.getMessage().startswith("unable to remove")]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info[0] is PermissionError
    assert records[0].path == leftovers[0]
    write_error_report.assert_called_once()


@pytest.mark.integration
def test_new_alert_upload_close_failure_is_reported(web_client, mock_api_call, target_node, monkeypatch, caplog):
    """An upload whose file descriptor cannot be closed is reported with its traceback and file
    name, and the temp file is still removed."""
    class FailingClose(io.BufferedReader):
        def close(self):
            if self.closed:
                return
            super().close()
            raise OSError("bad file descriptor")

    monkeypatch.setattr("app.analysis.views.edit.new.open",
                        lambda path, mode: FailingClose(io.FileIO(path, mode)), raising=False)
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

    with caplog.at_level(logging.ERROR):
        response = _post_file_alert(web_client, target_node)

    _alert_uuid(response)
    assert _leftover_uploads() == []
    records = [r for r in caplog.records if r.getMessage().startswith("unable to close")]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info[0] is OSError
    assert records[0].file_name == 'upload.txt'
    write_error_report.assert_called_once()
