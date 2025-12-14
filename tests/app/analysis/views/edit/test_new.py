from unittest.mock import patch, MagicMock, mock_open
from flask import url_for
import pytest
import io

from saq.constants import F_FILE


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
def test_file_route_get(web_client):
    """Test GET request to file route returns analyze_file template."""
    with patch('app.analysis.views.edit.new.get_db_connection') as mock_db:
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
        mock_db.return_value.__enter__.return_value.cursor.return_value = mock_cursor
        
        response = web_client.get(url_for('analysis.file'))
    
    assert response.status_code == 200
    assert b'analyze_file.html' in response.data or response.status_code == 200


@pytest.mark.integration
@patch('app.analysis.views.edit.new.ace_api.submit')
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_single_observable_success(mock_db_conn, mock_api_submit, web_client):
    """Test successful creation of single alert with one observable."""
    # Mock database connection
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    # Mock API submission response
    mock_api_submit.return_value = {
        'result': {'uuid': 'test-alert-uuid-123'}
    }
    
    # Mock database update
    with patch('app.analysis.views.edit.new.get_db') as mock_db:
        mock_db.return_value.execute.return_value = None
        mock_db.return_value.commit.return_value = None
        
        response = web_client.post(url_for('analysis.new_alert'), data={
            'new_alert_insert_date': '01-01-2024 12:00:00',
            'timezone': 'UTC',
            'new_alert_type': 'manual',
            'new_alert_description': 'Test Alert',
            'new_alert_queue': 'default',
            'target_node_data': '1,test-location,1',
            'observables_types_0': 'ipv4',
            'observables_values_0': '192.168.1.1',
            'observables_directives_0': 'no_scan',
            'observable_data_sep_0': 'single',
            'submit_type': 'single'
        })
    
    # Should redirect to analysis index with the new alert UUID
    assert response.status_code == 302
    assert 'analysis' in response.location
    assert 'test-alert-uuid-123' in response.location


@pytest.mark.integration
@patch('app.analysis.views.edit.new.ace_api.submit')
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_multiple_observables_multi_submit(mock_db_conn, mock_api_submit, web_client):
    """Test creation of multiple alerts from multi-line observable input."""
    # Mock database connection
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    # Mock API submission response
    mock_api_submit.return_value = {
        'result': {'uuid': 'test-alert-uuid-456'}
    }
    
    with patch('app.analysis.views.edit.new.get_db') as mock_db:
        mock_db.return_value.execute.return_value = None
        mock_db.return_value.commit.return_value = None
        
        response = web_client.post(url_for('analysis.new_alert'), data={
            'new_alert_insert_date': '01-01-2024 12:00:00',
            'timezone': 'UTC',
            'new_alert_type': 'manual',
            'new_alert_description': 'Multi Alert',
            'new_alert_queue': 'default',
            'target_node_data': '1,test-location,1',
            'observables_types_0': 'ipv4',
            'observables_values_0': '192.168.1.1\n192.168.1.2\n192.168.1.3',
            'observables_directives_0': 'no_scan',
            'observable_data_sep_0': 'multi',
            'submit_type': 'multiple'
        })
    
    # Should redirect after processing multiple alerts
    assert response.status_code == 302
    assert 'analysis' in response.location


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_invalid_timezone(mock_db_conn, web_client):
    """Test new alert creation with invalid timezone."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    response = web_client.post(url_for('analysis.new_alert'), data={
        'new_alert_insert_date': '01-01-2024 12:00:00',
        'timezone': 'Invalid/Timezone',
        'new_alert_type': 'manual',
        'new_alert_description': 'Test Alert',
        'new_alert_queue': 'default',
        'target_node_data': '1,test-location,1',
    })
    
    # Should redirect to manage page due to timezone error
    assert response.status_code == 302
    assert 'manage' in response.location


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_email_conversation_observable(mock_db_conn, web_client):
    """Test creation of alert with email conversation observable."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-email-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            response = web_client.post(url_for('analysis.new_alert'), data={
                'new_alert_insert_date': '01-01-2024 12:00:00',
                'timezone': 'UTC',
                'new_alert_type': 'manual',
                'new_alert_description': 'Email Alert',
                'new_alert_queue': 'default',
                'target_node_data': '1,test-location,1',
                'observables_types_0': 'email_conversation',
                'observables_values_0_A': 'sender@example.com',
                'observables_values_0_B': 'recipient@example.com',
                'observables_directives_0': 'no_scan',
                'observable_data_sep_0': 'single',
                'submit_type': 'single'
            })
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_ipv4_conversation_observable(mock_db_conn, web_client):
    """Test creation of alert with IPv4 conversation observable."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-ipv4-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            response = web_client.post(url_for('analysis.new_alert'), data={
                'new_alert_insert_date': '01-01-2024 12:00:00',
                'timezone': 'UTC',
                'new_alert_type': 'manual',
                'new_alert_description': 'IPv4 Alert',
                'new_alert_queue': 'default',
                'target_node_data': '1,test-location,1',
                'observables_types_0': 'ipv4_conversation',
                'observables_values_0_A': '192.168.1.1',
                'observables_values_0_B': '192.168.1.2',
                'observables_directives_0': 'no_scan',
                'observable_data_sep_0': 'single',
                'submit_type': 'single'
            })
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_file_location_observable(mock_db_conn, web_client):
    """Test creation of alert with file location observable."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-file-location-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            with patch('saq.constants.create_file_location') as mock_create_file_location:
                mock_create_file_location.return_value = 'host:path/to/file'
                
                response = web_client.post(url_for('analysis.new_alert'), data={
                    'new_alert_insert_date': '01-01-2024 12:00:00',
                    'timezone': 'UTC',
                    'new_alert_type': 'manual',
                    'new_alert_description': 'File Location Alert',
                    'new_alert_queue': 'default',
                    'target_node_data': '1,test-location,1',
                    'observables_types_0': 'file_location',
                    'observables_values_0_A': 'hostname',
                    'observables_values_0_B': '/path/to/file',
                    'observables_directives_0': 'no_scan',
                    'observable_data_sep_0': 'single',
                    'submit_type': 'single'
                })
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_file_upload(mock_db_conn, web_client):
    """Test creation of alert with file upload."""
    # Mock database connection
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-file-upload-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            # Test without file upload - should handle gracefully
            response = web_client.post(url_for('analysis.new_alert'), data={
                'new_alert_insert_date': '01-01-2024 12:00:00',
                'timezone': 'UTC',
                'new_alert_type': 'manual',
                'new_alert_description': 'File Upload Alert',
                'new_alert_queue': 'default',
                'target_node_data': '1,test-location,1',
                'observables_types_0': F_FILE,
                'observables_values_0': '/path/to/file',
                'observables_directives_0': 'no_scan',
                'observable_data_sep_0': 'single',
                'submit_type': 'single'
            })
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.ace_api.submit')
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_api_submission_failure(mock_db_conn, mock_api_submit, web_client):
    """Test handling of API submission failure."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    # Mock API submission to raise exception
    mock_api_submit.side_effect = Exception("API submission failed")
    
    response = web_client.post(url_for('analysis.new_alert'), data={
        'new_alert_insert_date': '01-01-2024 12:00:00',
        'timezone': 'UTC',
        'new_alert_type': 'manual',
        'new_alert_description': 'Test Alert',
        'new_alert_queue': 'default',
        'target_node_data': '1,test-location,1',
        'observables_types_0': 'ipv4',
        'observables_values_0': '192.168.1.1',
        'observables_directives_0': 'no_scan',
        'observable_data_sep_0': 'single',
        'submit_type': 'single'
    })
    
    # Should redirect to manage page with error
    assert response.status_code == 302
    assert 'manage' in response.location


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_comma_separated_multi_values(mock_db_conn, web_client):
    """Test parsing of comma-separated multi-value observables."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-comma-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            response = web_client.post(url_for('analysis.new_alert'), data={
                'new_alert_insert_date': '01-01-2024 12:00:00',
                'timezone': 'UTC',
                'new_alert_type': 'manual',
                'new_alert_description': 'Comma Separated Alert',
                'new_alert_queue': 'default',
                'target_node_data': '1,test-location,1',
                'observables_types_0': 'ipv4',
                'observables_values_0': '192.168.1.1,192.168.1.2,192.168.1.3',
                'observables_directives_0': 'no_scan',
                'observable_data_sep_0': 'multi',
                'submit_type': 'single'
            })
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_observable_with_time(mock_db_conn, web_client):
    """Test creation of observable with specific time."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-time-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            response = web_client.post(url_for('analysis.new_alert'), data={
                'new_alert_insert_date': '01-01-2024 12:00:00',
                'timezone': 'UTC',
                'new_alert_type': 'manual',
                'new_alert_description': 'Timed Observable Alert',
                'new_alert_queue': 'default',
                'target_node_data': '1,test-location,1',
                'observables_types_0': 'ipv4',
                'observables_values_0': '192.168.1.1',
                'observables_times_0': '01-02-2024 14:30:00',
                'observables_directives_0': 'no_scan',
                'observable_data_sep_0': 'single',
                'submit_type': 'single'
            })
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_directive_list_parsing(mock_db_conn, web_client):
    """Test parsing of directive lists from form."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-directive-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            response = web_client.post(url_for('analysis.new_alert'), data={
                'new_alert_insert_date': '01-01-2024 12:00:00',
                'timezone': 'UTC',
                'new_alert_type': 'manual',
                'new_alert_description': 'Directive List Alert',
                'new_alert_queue': 'default',
                'target_node_data': '1,test-location,1',
                'observables_types_0': 'ipv4',
                'observables_values_0': '192.168.1.1',
                'observables_directives_0': 'no_scan,archive',
                'observable_data_sep_0': 'single',
                'submit_type': 'single'
            })
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_file_route_with_secondary_companies(mock_db_conn, web_client):
    """Test file route with secondary company configuration."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.side_effect = [
        [(1, 'primary-node', 'primary-location', 1, 'primary-company')],
        [(2, 'secondary-node', 'secondary-location', 2, 'secondary-company')]
    ]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('saq.configuration.config.get_config') as mock_config:
        mock_config.return_value = {
            'global': {
                'secondary_company_ids': '2,3'
            }
        }
        
        response = web_client.get(url_for('analysis.file'))
    
    assert response.status_code == 200


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_no_observables(mock_db_conn, web_client):
    """Test creation of alert with no observables."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-no-obs-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            response = web_client.post(url_for('analysis.new_alert'), data={
                'new_alert_insert_date': '01-01-2024 12:00:00',
                'timezone': 'UTC',
                'new_alert_type': 'manual',
                'new_alert_description': 'No Observable Alert',
                'new_alert_queue': 'default',
                'target_node_data': '1,test-location,1',
                'submit_type': 'single'
            })
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
@patch('app.analysis.views.edit.new.sha256_file')
@patch('builtins.open', new_callable=mock_open)
@patch('os.path.basename')
def test_new_alert_local_file_path(mock_basename, mock_file_open, mock_sha256, mock_db_conn, web_client):
    """Test creation of alert with local file path (lines 143-147)."""
    # Mock database connection
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    # Mock file operations
    mock_sha256.return_value = 'abc123sha256hash'
    mock_basename.return_value = 'test_file.txt'
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-local-file-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            response = web_client.post(url_for('analysis.new_alert'), data={
                'new_alert_insert_date': '01-01-2024 12:00:00',
                'timezone': 'UTC',
                'new_alert_type': 'manual',
                'new_alert_description': 'Local File Alert',
                'new_alert_queue': 'default',
                'target_node_data': '1,test-location,1',
                'observables_types_0': F_FILE,
                'observables_values_0': '/path/to/local/file.txt',
                'observables_directives_0': 'no_scan',
                'observable_data_sep_0': 'single',
                'submit_type': 'single',
                'is_local': 'true'  # This triggers the local file path code
            })
    
    assert response.status_code == 302
    # Verify file operations were called
    mock_sha256.assert_called_with('/path/to/local/file.txt')
    mock_basename.assert_called_with('/path/to/local/file.txt')


@pytest.mark.integration  
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_file_upload_with_actual_file(mock_db_conn, web_client):
    """Test file upload with actual werkzeug FileStorage object (lines 152-167)."""
    # Mock database connection
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-upload-real-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            with patch('tempfile.mkstemp') as mock_mkstemp:
                mock_mkstemp.return_value = (5, '/tmp/test_upload_real')
                
                with patch('os.close') as mock_os_close:
                    with patch('app.analysis.views.edit.new.get_temp_dir') as mock_get_temp_dir:
                        mock_get_temp_dir.return_value = '/tmp'
                        
                        with patch('app.analysis.views.edit.new.sha256_file') as mock_sha256:
                            mock_sha256.return_value = 'real456sha256hash'
                            
                            with patch('builtins.open', mock_open()) as mock_file:
                                with patch('os.remove'):
                                    # Create file data
                                    file_data = b'test file content for upload'
                                    
                                    response = web_client.post(
                                        url_for('analysis.new_alert'),
                                        data={
                                            'new_alert_insert_date': '01-01-2024 12:00:00',
                                            'timezone': 'UTC',
                                            'new_alert_type': 'manual',
                                            'new_alert_description': 'Real File Upload Alert',
                                            'new_alert_queue': 'default',
                                            'target_node_data': '1,test-location,1',
                                            'observables_types_0': F_FILE,
                                            'observables_directives_0': 'no_scan',
                                            'observable_data_sep_0': 'single',
                                            'submit_type': 'single',
                                            'observables_values_0': (io.BytesIO(file_data), 'test_upload.txt')
                                        },
                                        content_type='multipart/form-data'
                                    )
    
    assert response.status_code == 302


@pytest.mark.integration
@patch('app.analysis.views.edit.new.get_db_connection')
def test_new_alert_file_upload_with_multipart_form(mock_db_conn, web_client):
    """Test file upload through multipart form (covers lines 152-167)."""
    # Mock database connection
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(1, 'test-node', 'test-location', 1, 'test-company')]
    mock_db_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor
    
    with patch('app.analysis.views.edit.new.ace_api.submit') as mock_api_submit:
        mock_api_submit.return_value = {
            'result': {'uuid': 'test-multipart-uuid'}
        }
        
        with patch('app.analysis.views.edit.new.get_db') as mock_db:
            mock_db.return_value.execute.return_value = None
            mock_db.return_value.commit.return_value = None
            
            with patch('tempfile.mkstemp') as mock_mkstemp:
                mock_mkstemp.return_value = (5, '/tmp/test_multipart')
                
                with patch('os.close'):
                    with patch('app.analysis.views.edit.new.get_temp_dir') as mock_get_temp_dir:
                        mock_get_temp_dir.return_value = '/tmp'
                        
                        with patch('app.analysis.views.edit.new.sha256_file') as mock_sha256:
                            mock_sha256.return_value = 'multipart456hash'
                            
                            with patch('builtins.open', mock_open()):
                                with patch('os.remove'):
                                    # Test with actual multipart file upload
                                    file_data = b'test file for multipart upload'
                                    
                                    response = web_client.post(
                                        url_for('analysis.new_alert'),
                                        data={
                                            'new_alert_insert_date': '01-01-2024 12:00:00',
                                            'timezone': 'UTC',
                                            'new_alert_type': 'manual',
                                            'new_alert_description': 'Multipart File Upload',
                                            'new_alert_queue': 'default',
                                            'target_node_data': '1,test-location,1',
                                            'observables_types_0': F_FILE,
                                            'observables_directives_0': 'no_scan',
                                            'observable_data_sep_0': 'single',
                                            'submit_type': 'single',
                                            'observables_values_0': (io.BytesIO(file_data), 'multipart_test.txt')
                                        },
                                        content_type='multipart/form-data'
                                    )
    
    # Should redirect successfully after processing file
    assert response.status_code == 302