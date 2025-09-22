import pytest
from flask import url_for, session
from io import BytesIO
from urllib.parse import parse_qs, urlparse

from saq.database.util.alert import get_alert_by_uuid


@pytest.mark.integration
class TestRedirectTo:
    """Test the redirect_to function in navigation.py."""
    
    def test_redirect_to_missing_alert(self, web_client):
        """Test redirect_to when no current alert is available."""
        # Call redirect_to without setting up a current alert
        result = web_client.post(url_for('analysis.redirect_to'))
        
        # Should redirect to analysis.index with flash message
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_redirect_to_missing_file_uuid(self, web_client):
        """Test redirect_to when file_uuid parameter is missing."""
        # First create an alert to work with
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
        
        # Call redirect_to without file_uuid but with the alert context
        redirect_data = {'direct': alert_uuid, 'target': 'vt'}
        result = web_client.post(url_for('analysis.redirect_to'), data=redirect_data)
        
        # Should return 500 error for missing file_uuid
        assert result.status_code == 500
        assert b'missing file_uuid' in result.data
    
    def test_redirect_to_missing_target(self, web_client):
        """Test redirect_to when target parameter is missing."""
        # First create an alert to work with
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
        
        # Get the alert and find a file observable
        alert = get_alert_by_uuid(alert_uuid)
        alert.load()
        file_observables = [obs for obs in alert.root_analysis.observables if obs.type == 'file']
        assert len(file_observables) > 0
        file_id = file_observables[0].uuid
        
        # Call redirect_to without target parameter
        redirect_data = {'alert_uuid': alert_uuid, 'file_uuid': file_id}
        result = web_client.post(url_for('analysis.redirect_to'), data=redirect_data)
        
        # Should return 500 error for missing target
        assert result.status_code == 500
        assert b'missing target' in result.data
    
    def test_redirect_to_invalid_target(self, web_client):
        """Test redirect_to with invalid target parameter."""
        # First create an alert to work with
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
        
        # Get the alert and find a file observable
        alert = get_alert_by_uuid(alert_uuid)
        alert.load()
        file_observables = [obs for obs in alert.root_analysis.observables if obs.type == 'file']
        assert len(file_observables) > 0
        file_id = file_observables[0].uuid
        
        # Call redirect_to with invalid target
        redirect_data = {'alert_uuid': alert_uuid, 'file_uuid': file_id, 'target': 'invalid_target'}
        result = web_client.post(url_for('analysis.redirect_to'), data=redirect_data)
        
        # Should redirect to analysis.index with flash message about invalid target
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_redirect_to_virustotal_success(self, web_client):
        """Test successful redirect to VirusTotal."""
        # First create an alert to work with
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
        
        # Get the alert and find a file observable
        alert = get_alert_by_uuid(alert_uuid)
        alert.load()
        file_observables = [obs for obs in alert.root_analysis.observables if obs.type == 'file']
        assert len(file_observables) > 0
        file_observable = file_observables[0]
        file_id = file_observable.uuid
        
        # Call redirect_to with valid VirusTotal target
        redirect_data = {'alert_uuid': alert_uuid, 'file_uuid': file_id, 'target': 'vt'}
        result = web_client.post(url_for('analysis.redirect_to'), data=redirect_data)
        
        # Should redirect to VirusTotal with the file's SHA256 hash
        assert result.status_code == 302
        assert result.location.startswith('https://www.virustotal.com/gui/file/')
        assert file_observable.value in result.location
    
    def test_redirect_to_nonexistent_file_id(self, web_client):
        """Test redirect_to with non-existent file ID."""
        # First create an alert to work with
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
        
        # Call redirect_to with non-existent file ID
        redirect_data = {'alert_uuid': alert_uuid, 'file_uuid': 'nonexistent-id', 'target': 'vt'}
        result = web_client.post(url_for('analysis.redirect_to'), data=redirect_data)
        
        # Should redirect to analysis.index with flash message about missing file observable
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_redirect_to_get_method(self, web_client):
        """Test redirect_to with GET method parameters."""
        # First create an alert to work with
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
        
        # Get the alert and find a file observable
        alert = get_alert_by_uuid(alert_uuid)
        alert.load()
        file_observables = [obs for obs in alert.root_analysis.observables if obs.type == 'file']
        assert len(file_observables) > 0
        file_observable = file_observables[0]
        file_id = file_observable.uuid
        
        # Call redirect_to with GET method
        redirect_url = url_for('analysis.redirect_to', alert_uuid=alert_uuid, file_uuid=file_id, target='vt')
        result = web_client.get(redirect_url)
        
        # Should redirect to VirusTotal with the file's SHA256 hash
        assert result.status_code == 302
        assert result.location.startswith('https://www.virustotal.com/gui/file/')
        assert file_observable.value in result.location


@pytest.mark.integration
class TestSetPageOffset:
    """Test the set_page_offset function in navigation.py."""
    
    def test_set_page_offset_get_method(self, web_client):
        """Test set_page_offset with GET method."""
        # Clear any existing page_offset first
        with web_client.session_transaction() as sess:
            sess.pop('page_offset', None)
        
        # Call set_page_offset with GET method
        result = web_client.get(url_for('analysis.set_page_offset', offset=100))
        
        # Should return empty response with 204 status
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_offset') == 100

    def test_set_page_offset_post_method(self, web_client):
        """Test set_page_offset with POST method."""
        # Clear any existing page_offset first
        with web_client.session_transaction() as sess:
            sess.pop('page_offset', None)
        
        # Call set_page_offset with POST method
        data = {'offset': '250'}
        result = web_client.post(url_for('analysis.set_page_offset'), data=data)
        
        # Should return empty response with 204 status
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_offset') == 250
    
    def test_set_page_offset_session_update(self, web_client):
        """Test that set_page_offset updates the session correctly."""
        with web_client.session_transaction() as sess:
            # Clear any existing page_offset
            sess.pop('page_offset', None)
        
        # Call set_page_offset with POST method
        data = {'offset': '500'}
        result = web_client.post(url_for('analysis.set_page_offset'), data=data)
        
        # Should return 204 and update session
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_offset') == 500
    
    def test_set_page_offset_string_conversion(self, web_client):
        """Test that set_page_offset properly converts string to int."""
        # Clear any existing page_offset first
        with web_client.session_transaction() as sess:
            sess.pop('page_offset', None)
        
        # Call with string value that should be converted to int
        data = {'offset': '999'}
        result = web_client.post(url_for('analysis.set_page_offset'), data=data)
        
        # Should handle string conversion without error
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_offset') == 999
    
    def test_set_page_offset_zero_value(self, web_client):
        """Test set_page_offset with zero value."""
        # Clear any existing page_offset first
        with web_client.session_transaction() as sess:
            sess.pop('page_offset', None)
        
        # Call with zero offset
        result = web_client.get(url_for('analysis.set_page_offset', offset=0))
        
        # Should handle zero value correctly
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_offset') == 0


@pytest.mark.integration
class TestSetPageSize:
    """Test the set_page_size function in navigation.py."""
    
    def test_set_page_size_get_method(self, web_client):
        """Test set_page_size with GET method."""
        # Clear any existing page_size first
        with web_client.session_transaction() as sess:
            sess.pop('page_size', None)
        
        # Call set_page_size with GET method
        result = web_client.get(url_for('analysis.set_page_size', size=50))
        
        # Should return empty response with 204 status
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_size') == 50
    
    def test_set_page_size_post_method(self, web_client):
        """Test set_page_size with POST method."""
        # Clear any existing page_size first
        with web_client.session_transaction() as sess:
            sess.pop('page_size', None)
        
        # Call set_page_size with POST method
        data = {'size': '100'}
        result = web_client.post(url_for('analysis.set_page_size'), data=data)
        
        # Should return empty response with 204 status
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_size') == 100
    
    def test_set_page_size_session_update(self, web_client):
        """Test that set_page_size updates the session correctly."""
        with web_client.session_transaction() as sess:
            # Clear any existing page_size
            sess.pop('page_size', None)
        
        # Call set_page_size with POST method
        data = {'size': '25'}
        result = web_client.post(url_for('analysis.set_page_size'), data=data)
        
        # Should return 204 and update session
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_size') == 25
    
    def test_set_page_size_string_conversion(self, web_client):
        """Test that set_page_size properly converts string to int."""
        # Clear any existing page_size first
        with web_client.session_transaction() as sess:
            sess.pop('page_size', None)
        
        # Call with string value that should be converted to int
        data = {'size': '75'}
        result = web_client.post(url_for('analysis.set_page_size'), data=data)
        
        # Should handle string conversion without error
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_size') == 75
    
    def test_set_page_size_large_value(self, web_client):
        """Test set_page_size with large value."""
        # Clear any existing page_size first
        with web_client.session_transaction() as sess:
            sess.pop('page_size', None)
        
        # Call with large page size
        result = web_client.get(url_for('analysis.set_page_size', size=1000))
        
        # Should handle large value correctly
        assert result.status_code == 204
        assert result.data == b''
        
        # Check that session was updated
        with web_client.session_transaction() as sess:
            assert sess.get('page_size') == 1000


@pytest.mark.integration
def test_navigation_routes_require_login(app):
    """Test that navigation routes require authentication."""
    # Create a client without auto-login
    with app.test_client() as client:
        # Test redirect_to requires login
        result = client.post(url_for('analysis.redirect_to'))
        assert result.status_code == 302  # Redirect to login
        
        result = client.get(url_for('analysis.redirect_to'))
        assert result.status_code == 302  # Redirect to login
        
        # Test set_page_offset requires login
        result = client.post(url_for('analysis.set_page_offset'))
        assert result.status_code == 302  # Redirect to login
        
        result = client.get(url_for('analysis.set_page_offset', offset=100))
        assert result.status_code == 302  # Redirect to login
        
        # Test set_page_size requires login
        result = client.post(url_for('analysis.set_page_size'))
        assert result.status_code == 302  # Redirect to login
        
        result = client.get(url_for('analysis.set_page_size', size=50))
        assert result.status_code == 302  # Redirect to login


@pytest.mark.unit
class TestNavigationModuleStructure:
    """Test the navigation module structure and imports."""
    
    def test_imports_and_module_structure(self):
        """Test that the navigation module imports correctly and has expected structure."""
        import app.analysis.views.navigation as navigation_module
        
        # Verify expected functions exist
        assert hasattr(navigation_module, 'redirect_to')
        assert hasattr(navigation_module, 'set_page_offset')
        assert hasattr(navigation_module, 'set_page_size')
        
        # Verify they are callable
        assert callable(navigation_module.redirect_to)
        assert callable(navigation_module.set_page_offset)
        assert callable(navigation_module.set_page_size)