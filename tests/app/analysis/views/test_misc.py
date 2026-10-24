import hashlib
import logging
import os
from io import BytesIO
from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from flask import url_for

from saq.analysis.file_manager.local_file_manager import clean_file_name
from saq.analysis.root import RootAnalysis
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED, STATE_ANALYST_REQUESTED_ANALYSIS
from saq.database.model import Alert, ObservableComment
from saq.database.pool import get_db
from saq.database.util.alert import get_alert_by_uuid
from saq.database.util.locking import acquire_lock, release_lock
from saq.environment import get_temp_dir
from saq.util.filesystem import is_path_under


@pytest.mark.integration
class TestUploadFile:
    """Test the upload_file function in misc.py."""
    
    def test_upload_file_no_file_specified(self, web_client):
        """Test upload_file when no file is specified."""
        data = {
            'comment': 'test comment',
            'alert_uuid': ''
        }
        
        result = web_client.post(url_for('analysis.upload_file'), data=data)
        
        # Should redirect to analysis.file with flash message
        assert result.status_code == 302
        assert result.location == url_for('analysis.file')
    
    def test_upload_file_save_failure_is_reported(self, web_client, monkeypatch, caplog):
        """A file that cannot be saved to the temp dir redirects back and is reported."""
        def failing_save(self, dst, *args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr("werkzeug.datastructures.FileStorage.save", failing_save)
        write_error_report = Mock()
        monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

        data = {
            'file_path': (BytesIO(b'test file content'), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': ''
        }
        with caplog.at_level(logging.ERROR):
            result = web_client.post(url_for('analysis.upload_file'), data=data, content_type='multipart/form-data')

        assert result.status_code == 302
        assert result.location == url_for('analysis.file')
        records = [r for r in caplog.records if r.getMessage().startswith("unable to save file to")]
        assert len(records) == 1
        write_error_report.assert_called_once()

    def test_upload_file_new_alert_success(self, web_client):
        """Test successful file upload creating new alert."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse

        # Create test file
        test_content = b'test file content'
        data = {
            'file_path': (BytesIO(test_content), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': ''
        }
            
        result = web_client.post(url_for('analysis.upload_file'), 
                                data=data, content_type='multipart/form-data')
        
        # Should redirect to analysis.index with new alert UUID
        assert result.status_code == 302
        assert '/analysis' in result.location
        assert 'direct=' in result.location
        
        # Extract the alert UUID from the redirect URL
        parsed_url = urlparse(result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        # Verify the alert was actually created in the database
        alert = get_alert_by_uuid(alert_uuid)
        assert alert is not None
        assert alert.uuid == alert_uuid
        assert alert.alert_type == 'manual_upload'
        assert alert.description == 'Manual File upload test_file.txt'
        assert alert.tool == 'Manual File Upload - test_file.txt'
        
        # Verify the alert can be loaded and contains the uploaded file
        alert.load()  # load() returns None but populates _root_analysis
        root_analysis = alert.root_analysis
        assert root_analysis is not None
        
        # Check that the file observable was added
        file_observables = [obs for obs in root_analysis.observables if obs.type == 'file']
        assert len(file_observables) == 1
        assert file_observables[0].file_name == 'test_file.txt'
        
        # Verify the file was actually saved to disk
        file_observable = file_observables[0]
        assert os.path.exists(file_observable.full_path)
        with open(file_observable.full_path, 'rb') as f:
            assert f.read() == test_content
    
    @pytest.mark.parametrize("path_in_name", [False, True])
    def test_upload_file_name_stays_in_the_files_directory(self, web_client, tmp_path, path_in_name):
        """The client's file name is cleaned by the root's file manager, so it can name a
        subdirectory of the alert's files directory but never a place outside it."""
        # in a directory of its own, so that what the name points at is not the temporary copy
        name = os.path.join(f"escaped-{uuid4().hex}", "escaped.txt")
        client_name = f"../../{name}" if path_in_name else str(tmp_path / name)
        data = {
            'file_path': (BytesIO(b'escaped'), client_name),
            'comment': '',
            'alert_uuid': ''
        }

        result = web_client.post(url_for('analysis.upload_file'), data=data, content_type='multipart/form-data')

        assert result.status_code == 302
        alert = get_alert_by_uuid(parse_qs(urlparse(result.location).query)['direct'][0])
        alert.load()
        (file_observable,) = [o for o in alert.root_analysis.observables if o.type == 'file']
        assert file_observable.file_path == clean_file_name(client_name)
        assert file_observable.file_path.endswith(name)
        assert is_path_under(file_observable.full_path, alert.root_analysis.file_dir)
        assert not (tmp_path / name).parent.exists()
        assert not os.path.exists(os.path.dirname(os.path.join(alert.root_analysis.file_dir, "..", "..", name)))

    def test_upload_file_existing_alert_success(self, web_client):
        """Test successful file upload to existing alert."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        # First create an existing alert
        initial_data = {
            'file_path': (BytesIO(b'initial content'), 'initial_file.txt'),
            'comment': 'initial comment',
            'alert_uuid': ''
        }
        
        initial_result = web_client.post(url_for('analysis.upload_file'), 
                                       data=initial_data, content_type='multipart/form-data')
        
        # Extract the alert UUID from the redirect URL
        parsed_url = urlparse(initial_result.location)
        query_params = parse_qs(parsed_url.query)
        existing_alert_uuid = query_params['direct'][0]
        
        # Now upload to the existing alert
        test_content = b'test file content for existing alert'
        data = {
            'file_path': (BytesIO(test_content), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': existing_alert_uuid
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should redirect to analysis.index
        assert result.status_code == 302
        assert '/analysis' in result.location
        
        # Verify the alert was updated with the new file
        alert = get_alert_by_uuid(existing_alert_uuid)
        assert alert is not None
        alert.load()
        root_analysis = alert.root_analysis
        
        # Should now have 2 file observables
        file_observables = [obs for obs in root_analysis.observables if obs.type == 'file']
        assert len(file_observables) == 2
        
        # Verify both files exist
        file_names = [obs.file_name for obs in file_observables]
        assert 'initial_file.txt' in file_names
        assert 'test_file.txt' in file_names
    
    def test_a_later_upload_by_the_same_name_leaves_an_alert_alone(self, web_client):
        """The alert's copy of an upload is a hardlink to the temporary file it was saved to, so
        that file is the request's own and is gone afterwards."""
        temp_files_before = set(os.listdir(get_temp_dir()))
        alerts = []
        for content in (b'first content', b'second content'):
            data = {'file_path': (BytesIO(content), 'same.txt'), 'comment': '', 'alert_uuid': ''}
            result = web_client.post(url_for('analysis.upload_file'), data=data, content_type='multipart/form-data')
            alert = get_alert_by_uuid(parse_qs(urlparse(result.location).query)['direct'][0])
            alert.load()
            alerts.append(alert)

        for alert, content in zip(alerts, (b'first content', b'second content')):
            (file_observable,) = [o for o in alert.root_analysis.observables if o.type == 'file']
            with open(file_observable.full_path, 'rb') as f:
                assert f.read() == content
        assert not os.path.exists(os.path.join(get_temp_dir(), 'same.txt'))
        assert not [name for name in set(os.listdir(get_temp_dir())) - temp_files_before
                    if os.path.isfile(os.path.join(get_temp_dir(), name))]

    def test_upload_file_existing_alert_same_name_other_content(self, web_client):
        """An alert that already has a file by the uploaded name gets the upload under a name of
        its own, not an observable whose path serves the other file's bytes."""
        initial_data = {
            'file_path': (BytesIO(b'initial content'), 'report.txt'),
            'comment': '',
            'alert_uuid': ''
        }
        initial_result = web_client.post(url_for('analysis.upload_file'), data=initial_data, content_type='multipart/form-data')
        alert_uuid = parse_qs(urlparse(initial_result.location).query)['direct'][0]

        data = {
            'file_path': (BytesIO(b'other content'), 'report.txt'),
            'comment': '',
            'alert_uuid': alert_uuid
        }
        result = web_client.post(url_for('analysis.upload_file'), data=data, content_type='multipart/form-data')

        assert result.status_code == 302
        alert = get_alert_by_uuid(alert_uuid)
        alert.load()
        file_observables = [o for o in alert.root_analysis.observables if o.type == 'file']
        assert sorted(o.file_path for o in file_observables) == ['report.txt', 'report_000.txt']
        for file_observable in file_observables:
            with open(file_observable.full_path, 'rb') as f:
                assert hashlib.sha256(f.read()).hexdigest() == file_observable.value

    def test_upload_file_nonexistent_alert(self, web_client):
        """Test upload_file with non-existent alert UUID."""
        test_content = b'test file content'
        data = {
            'file_path': (BytesIO(test_content), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': 'nonexistent-uuid-12345'
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should redirect to analysis.index when alert doesn't exist
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_upload_file_empty_filename(self, web_client):
        """Test upload_file with empty filename."""
        test_content = b'test file content'
        data = {
            'file_path': (BytesIO(test_content), ''),  # Empty filename
            'comment': 'test comment',
            'alert_uuid': ''
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should redirect to analysis.file when filename is empty
        assert result.status_code == 302
        assert result.location == url_for('analysis.file')
    
    def test_upload_file_large_file(self, web_client):
        """Test upload_file with large file content."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        # Create a larger test file (1MB)
        test_content = b'A' * (1024 * 1024)
        data = {
            'file_path': (BytesIO(test_content), 'large_test_file.txt'),
            'comment': 'large file test comment',
            'alert_uuid': ''
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should successfully handle large file
        assert result.status_code == 302
        assert '/analysis' in result.location
        assert 'direct=' in result.location
        
        # Extract the alert UUID and verify the file was saved
        parsed_url = urlparse(result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        alert = get_alert_by_uuid(alert_uuid)
        assert alert is not None
        alert.load()
        
        file_observables = [obs for obs in alert.root_analysis.observables if obs.type == 'file']
        assert len(file_observables) == 1
        assert file_observables[0].file_name == 'large_test_file.txt'
        
        # Verify the large file was actually saved correctly
        with open(file_observables[0].full_path, 'rb') as f:
            saved_content = f.read()
            assert len(saved_content) == len(test_content)
            assert saved_content == test_content
    
    def test_upload_file_special_characters_filename(self, web_client):
        """Test upload_file with special characters in filename."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        test_content = b'test file content with special chars'
        data = {
            'file_path': (BytesIO(test_content), 'test file with spaces & symbols!@#.txt'),
            'comment': 'special filename test',
            'alert_uuid': ''
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should successfully handle special characters in filename
        assert result.status_code == 302
        assert '/analysis' in result.location
        assert 'direct=' in result.location
        
        # Extract the alert UUID and verify the file was saved
        parsed_url = urlparse(result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        alert = get_alert_by_uuid(alert_uuid)
        assert alert is not None
        alert.load()
        
        file_observables = [obs for obs in alert.root_analysis.observables if obs.type == 'file']
        assert len(file_observables) == 1
        assert file_observables[0].file_name == 'test file with spaces & symbols!@#.txt'
        
        # Verify the file was actually saved
        assert os.path.exists(file_observables[0].full_path)
        with open(file_observables[0].full_path, 'rb') as f:
            assert f.read() == test_content


@pytest.mark.integration  
class TestAnalyzeAlert:
    """Test the analyze_alert function in misc.py."""
    
    def test_analyze_alert_no_alert_uuid(self, web_client):
        """Test analyze_alert when no alert_uuid parameter is provided."""
        # Call analyze_alert without providing alert_uuid form parameter
        result = web_client.post(url_for('analysis.analyze_alert'))
        
        # Should redirect to analysis.index with flash message about missing UUID
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_analyze_alert_with_existing_alert(self, web_client):
        """Test analyze_alert with valid alert_uuid parameter."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        # First create an alert
        test_content = b'test file content'
        data = {
            'file_path': (BytesIO(test_content), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': ''
        }
        
        upload_result = web_client.post(url_for('analysis.upload_file'), 
                                      data=data, content_type='multipart/form-data')
        
        # Extract the alert UUID
        parsed_url = urlparse(upload_result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        # Now analyze the alert by passing the alert_uuid as form parameter
        analyze_data = {'alert_uuid': alert_uuid}
        result = web_client.post(url_for('analysis.analyze_alert'), data=analyze_data)
        
        # Should redirect back to analysis.index with the same alert UUID
        assert result.status_code == 302
        assert '/analysis' in result.location
        assert f'direct={alert_uuid}' in result.location
        
        # Verify the alert still exists and was scheduled for processing
        alert = get_alert_by_uuid(alert_uuid)
        assert alert is not None
    
    def test_analyze_alert_nonexistent_uuid(self, web_client):
        """Test analyze_alert with nonexistent alert_uuid."""
        # Try to analyze an alert with a nonexistent UUID
        analyze_data = {'alert_uuid': 'nonexistent-uuid-12345'}
        result = web_client.post(url_for('analysis.analyze_alert'), data=analyze_data)
        
        # Should redirect to analysis.index with flash message about alert not found
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_analyze_alert_schedule_functionality(self, web_client):
        """Test that analyze_alert properly schedules the alert for reanalysis."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        # Create an alert first
        test_content = b'test file for scheduling'
        data = {
            'file_path': (BytesIO(test_content), 'schedule_test.txt'),
            'comment': 'test scheduling',
            'alert_uuid': ''
        }
        
        upload_result = web_client.post(url_for('analysis.upload_file'), 
                                      data=data, content_type='multipart/form-data')
        
        # Extract alert UUID
        parsed_url = urlparse(upload_result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        # Get the alert before scheduling
        alert_before = get_alert_by_uuid(alert_uuid)
        assert alert_before is not None
        
        # Call analyze_alert with alert_uuid form parameter
        analyze_data = {'alert_uuid': alert_uuid}
        result = web_client.post(url_for('analysis.analyze_alert'), data=analyze_data)
        
        # Should redirect successfully
        assert result.status_code == 302
        assert f'direct={alert_uuid}' in result.location
        
        # Verify the alert still exists after scheduling
        alert_after = get_alert_by_uuid(alert_uuid)
        assert alert_after is not None
        assert alert_after.uuid == alert_uuid


@pytest.mark.unit
class TestMiscHelperFunctions:
    """Test any helper functions or utilities in misc.py if they exist."""
    
    def test_imports_and_module_structure(self):
        """Test that the module imports correctly and has expected structure."""
        import app.analysis.views.misc as misc_module
        
        # Verify expected functions exist
        assert hasattr(misc_module, 'upload_file')
        assert hasattr(misc_module, 'analyze_alert')
        
        # Verify they are callable
        assert callable(misc_module.upload_file)
        assert callable(misc_module.analyze_alert)


@pytest.mark.integration
def test_misc_routes_require_login(app):
    """Test that misc routes require authentication."""
    # Create a client without auto-login
    with app.test_client() as client:
        # Test upload_file requires login
        result = client.post(url_for('analysis.upload_file'))
        assert result.status_code == 302  # Redirect to login
        
        # Test analyze_alert requires login  
        result = client.post(url_for('analysis.analyze_alert'))
        assert result.status_code == 302  # Redirect to login


@pytest.mark.integration
def test_misc_routes_only_accept_post(web_client):
    """Test that misc routes only accept POST methods."""
    # Test upload_file only accepts POST
    result = web_client.get(url_for('analysis.upload_file'))
    assert result.status_code == 405  # Method not allowed
    
    # Test analyze_alert only accepts POST
    result = web_client.get(url_for('analysis.analyze_alert'))  
    assert result.status_code == 405  # Method not allowed


def _upload(web_client, content: bytes, file_name: str, alert_uuid: str = "", comment: str = ""):
    return web_client.post(url_for('analysis.upload_file'), data={
        'file_path': (BytesIO(content), file_name),
        'comment': comment,
        'alert_uuid': alert_uuid,
    }, content_type='multipart/form-data')


def _new_alert_uuid(web_client, comment: str = "") -> str:
    result = _upload(web_client, b'first upload', 'first.txt', comment=comment)
    return parse_qs(urlparse(result.location).query)['direct'][0]


def _file_observable(alert_uuid: str, file_name: str):
    alert = get_alert_by_uuid(alert_uuid)
    alert.load()
    return alert, next(o for o in alert.root_analysis.observables if o.type == 'file' and o.file_name == file_name)


@pytest.mark.integration
class TestUploadFileRecordsTheAnalyst:
    """An uploaded file is the analyst's addition: it says who added it, it is audited, it is
    analyzed, and the form's comment lands on the file."""

    def test_new_alert_upload_is_marked_added_by(self, web_client, caplog):
        caplog.set_level(logging.INFO)
        alert_uuid = _new_alert_uuid(web_client)

        _, file_observable = _file_observable(alert_uuid, 'first.txt')
        assert file_observable.added_by == 'john'
        assert file_observable.added_time is not None
        assert f"AUDIT: user john uploaded file first.txt as new alert {alert_uuid}" in caplog.text

    def test_existing_alert_upload_is_marked_added_by(self, web_client, caplog):
        alert_uuid = _new_alert_uuid(web_client)
        caplog.set_level(logging.INFO)

        result = _upload(web_client, b'uploaded during triage', 'later.txt', alert_uuid=alert_uuid)

        assert result.status_code == 302
        _, file_observable = _file_observable(alert_uuid, 'later.txt')
        assert file_observable.added_by == 'john'
        assert file_observable.added_time is not None
        assert f"AUDIT: user john uploaded file later.txt to alert {alert_uuid}" in caplog.text

    def test_upload_to_dispositioned_alert_is_analyzed_in_correlation(self, web_client):
        alert_uuid = _new_alert_uuid(web_client)
        alert = get_alert_by_uuid(alert_uuid)
        alert.load()
        alert.root_analysis.analysis_mode = ANALYSIS_MODE_DISPOSITIONED
        alert.root_analysis.save()

        _upload(web_client, b'uploaded after disposition', 'later.txt', alert_uuid=alert_uuid)

        alert, _ = _file_observable(alert_uuid, 'later.txt')
        assert alert.root_analysis.analysis_mode == ANALYSIS_MODE_CORRELATION
        assert alert.root_analysis.state.get(STATE_ANALYST_REQUESTED_ANALYSIS) is True

    def test_comment_is_an_observable_comment_on_the_file(self, web_client):
        alert_uuid = _new_alert_uuid(web_client, comment='new alert upload note')
        _upload(web_client, b'uploaded during triage', 'later.txt', alert_uuid=alert_uuid,
                comment='captured from the detonation VM')

        for file_name, text in (('first.txt', 'new alert upload note'), ('later.txt', 'captured from the detonation VM')):
            _, file_observable = _file_observable(alert_uuid, file_name)
            comment = get_db().query(ObservableComment).filter(ObservableComment.comment == text).one()
            assert comment.user.username == 'john'
            assert comment.observable.type == 'file'
            assert comment.observable.value.decode() == file_observable.value

    def test_empty_comment_adds_no_observable_comment(self, web_client):
        alert_uuid = _new_alert_uuid(web_client)
        before = get_db().query(ObservableComment).count()

        _upload(web_client, b'uploaded during triage', 'later.txt', alert_uuid=alert_uuid, comment='  ')

        assert get_db().query(ObservableComment).count() == before

    def test_lock_is_released_when_the_alert_fails_to_load(self, web_client):
        alert_uuid = _new_alert_uuid(web_client)
        os.remove(RootAnalysis(storage_dir=get_alert_by_uuid(alert_uuid).storage_dir).json_path)

        with pytest.raises(FileNotFoundError):
            _upload(web_client, b'uploaded during triage', 'later.txt', alert_uuid=alert_uuid)

        lock_uuid = str(uuid4())
        assert acquire_lock(alert_uuid, lock_uuid)
        release_lock(alert_uuid, lock_uuid)


def _flashes(web_client) -> list[str]:
    with web_client.session_transaction() as sess:
        return [message for _category, message in sess.get("_flashes", [])]


@pytest.mark.integration
class TestUploadFileFailures:
    """The ways an upload to an existing alert can fail, and what each one leaves behind."""

    def test_a_comment_that_cannot_be_saved_keeps_the_upload(self, web_client, monkeypatch, caplog):
        alert_uuid = _new_alert_uuid(web_client)

        def broken(*args, **kwargs):
            raise RuntimeError("the database went away")

        monkeypatch.setattr("app.analysis.views.misc.create_comment", broken)

        with caplog.at_level(logging.ERROR):
            result = _upload(web_client, b'uploaded during triage', 'later.txt', alert_uuid=alert_uuid,
                             comment='captured from the detonation VM')

        assert result.status_code == 302
        assert _flashes(web_client) == ["uploaded the file, but unable to save the comment"]
        [record] = [r for r in caplog.records if "unable to add the upload comment" in r.getMessage()]
        assert alert_uuid in record.getMessage()
        assert record.exc_info is not None
        _, file_observable = _file_observable(alert_uuid, 'later.txt')
        assert file_observable is not None

    def test_an_alert_being_analyzed_is_left_alone(self, web_client):
        alert_uuid = _new_alert_uuid(web_client)
        engine_lock = str(uuid4())
        assert acquire_lock(alert_uuid, engine_lock)
        try:
            result = _upload(web_client, b'uploaded during triage', 'later.txt', alert_uuid=alert_uuid)
        finally:
            release_lock(alert_uuid, engine_lock)

        assert result.status_code == 302
        assert [message for message in _flashes(web_client) if message.startswith("unable to lock alert")]
        alert = get_alert_by_uuid(alert_uuid)
        alert.load()
        assert not [o for o in alert.root_analysis.observables if o.type == 'file' and o.file_name == 'later.txt']

    def test_an_alert_that_will_not_load_is_reported(self, web_client, monkeypatch):
        alert_uuid = _new_alert_uuid(web_client)
        monkeypatch.setattr(RootAnalysis, "load", lambda self, *args, **kwargs: False)

        result = _upload(web_client, b'uploaded during triage', 'later.txt', alert_uuid=alert_uuid)

        assert result.status_code == 302
        assert [message for message in _flashes(web_client) if message.startswith("unable to load alert")]
        # the lock was released on the way out
        lock_uuid = str(uuid4())
        assert acquire_lock(alert_uuid, lock_uuid)
        release_lock(alert_uuid, lock_uuid)

    def test_a_lock_that_cannot_be_released_is_reported(self, web_client, monkeypatch):
        alert_uuid = _new_alert_uuid(web_client)
        released = []

        def release_but_fail(uuid, lock_uuid):
            released.append(release_lock(uuid, lock_uuid))
            return False

        monkeypatch.setattr("app.analysis.views.misc.release_lock", release_but_fail)

        result = _upload(web_client, b'uploaded during triage', 'later.txt', alert_uuid=alert_uuid)

        assert result.status_code == 302
        assert [message for message in _flashes(web_client) if message.startswith("unable to release lock for alert")]
        assert released == [True]
