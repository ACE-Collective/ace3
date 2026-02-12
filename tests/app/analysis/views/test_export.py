from unittest.mock import patch
from uuid import uuid4

import pytest
from flask import url_for

from saq.configuration import get_config
from saq.constants import F_TEST
from saq.database.model import Alert, Comment
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.environment import get_global_runtime_settings
from saq.observables.testing import TestObservable
from saq.util.time import local_time


@pytest.mark.integration
def test_download_json_no_alert(web_client):
    """Test download_json when no alert is loaded."""
    result = web_client.get(url_for("analysis.download_json"))
    assert result.status_code == 200
    assert result.data == b'{}'


@pytest.mark.integration 
def test_download_json_with_alert(web_client, root_analysis):
    """Test download_json with a valid alert."""
    # Create test observable 
    test_observable = root_analysis.add_observable_by_spec(F_TEST, "test_value")
    assert isinstance(test_observable, TestObservable)

    # Save and create alert
    root_analysis.save()
    alert = ALERT(root_analysis)
    assert isinstance(alert, Alert)

    result = web_client.get(url_for("analysis.download_json"), 
                          query_string={'direct': alert.uuid})
    assert result.status_code == 200
    assert result.mimetype == 'application/json'
    
    data = result.get_json()
    assert 'nodes' in data
    assert 'edges' in data
    # Should have at least the root analysis node and the observable node
    assert len(data['nodes']) >= 2


@pytest.mark.integration
def test_download_json_load_error(web_client, root_analysis):
    """Test download_json when alert fails to load."""
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    # Remove alert storage to cause load error
    import shutil
    shutil.rmtree(alert.storage_dir)

    result = web_client.get(url_for("analysis.download_json"),
                          query_string={'direct': alert.uuid})
    assert result.status_code == 200
    assert result.data == b'{}'


@pytest.mark.integration
def test_export_alerts_to_csv_no_filters(web_client):
    """Test export_alerts_to_csv with no session filters."""
    result = web_client.get(url_for("analysis.export_alerts_to_csv"))
    assert result.status_code == 200
    assert result.headers['Content-Type'] == 'text/csv'
    assert 'export.csv' in result.headers['Content-Disposition']


@pytest.mark.integration  
def test_export_alerts_to_csv_with_alerts(web_client, root_analysis):
    """Test export_alerts_to_csv with actual alerts in database."""
    root_analysis.event_time = local_time()
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    # Add a comment to test comments column
    comment = Comment(uuid=alert.uuid, comment="Test comment", user_id=get_global_runtime_settings().automation_user_id)
    get_db().add(comment)
    get_db().commit()

    # Initialize session filters
    with web_client.session_transaction() as sess:
        sess['filters'] = []

    result = web_client.get(url_for("analysis.export_alerts_to_csv"))
    assert result.status_code == 200
    assert result.headers['Content-Type'] == 'text/csv'
    
    csv_content = result.get_data(as_text=True)
    assert 'Event Time' in csv_content
    assert 'Alert Time' in csv_content
    assert 'Description' in csv_content
    assert str(alert.uuid) in csv_content


@pytest.mark.integration
def test_download_file_no_alert(web_client):
    """Test download_file when no alert is loaded."""
    result = web_client.get(url_for("analysis.download_file"))
    assert result.status_code == 302
    assert url_for('analysis.index') in result.location


@pytest.mark.integration
def test_download_file_missing_params(web_client, root_analysis):
    """Test download_file with missing required parameters."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.download_file"),
                          query_string={'direct': alert.uuid})
    assert result.status_code == 500
    assert b"missing file_uuid" in result.data


@pytest.mark.integration
def test_download_file_missing_mode(web_client, root_analysis):
    """Test download_file with missing mode parameter."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.download_file"),
                          query_string={
                              'direct': alert.uuid,
                              'file_uuid': str(uuid4())
                          })
    assert result.status_code == 500
    assert b"missing mode" in result.data


@pytest.mark.integration
def test_download_file_invalid_uuid(web_client, root_analysis):
    """Test download_file with invalid file UUID."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.download_file"),
                          query_string={
                              'direct': alert.uuid,
                              'file_uuid': str(uuid4()),
                              'mode': 'raw'
                          })
    assert result.status_code == 302
    assert url_for('analysis.index') in result.location


@pytest.mark.integration
def test_download_file_text_mode(web_client, root_analysis, tmpdir):
    """Test download_file in text mode with actual file."""
    # Create a temporary file
    target_path = tmpdir / "test_file.txt"
    target_path.write_text("Test file content.", encoding="utf8")

    # Add file observable
    file_observable = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.download_file"),
                            query_string={
                                'direct': alert.uuid,
                                'file_uuid': file_observable.uuid,
                                'mode': 'text'
                            })
    assert result.status_code == 200
    assert result.headers['Content-Type'] == 'text/plain'
    assert b"Test file content" in result.data


@pytest.mark.integration
def test_download_file_hex_mode(web_client, root_analysis, tmpdir):
    """Test download_file in hex mode."""
    target_path = tmpdir / "test_file.txt"
    target_path.write_text("ABC", encoding="utf8")

    # Add file observable
    file_observable = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.download_file"),
                            query_string={
                                'direct': alert.uuid,
                                'file_uuid': file_observable.uuid,
                                'mode': 'hex'
                            })
    assert result.status_code == 200
    assert result.headers['Content-Type'] == 'text/plain'

@pytest.mark.integration
def test_get_alert_metadata_no_alert(web_client):
    """Test get_alert_metadata when no alert is loaded."""
    result = web_client.get(url_for("analysis.get_alert_metadata"))
    assert result.status_code == 200
    assert result.get_json() == {}


@pytest.mark.integration
def test_get_alert_metadata_with_alert(web_client, root_analysis):
    """Test get_alert_metadata with valid alert."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.get_alert_metadata"),
                          query_string={'direct': alert.uuid})
    assert result.status_code == 200
    assert result.mimetype == 'application/json'
    
    data = result.get_json()
    assert isinstance(data, dict)


@pytest.mark.integration
def test_email_file_no_alert(web_client):
    """Test email_file when no alert is loaded."""
    result = web_client.post(url_for("analysis.email_file"))
    assert result.status_code == 302
    assert url_for('analysis.index') in result.location


@pytest.mark.integration
def test_email_file_missing_observable(web_client, root_analysis):
    """Test email_file with missing file observable."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.post(url_for("analysis.email_file"),
                           data={
                               'direct': alert.uuid,
                               'toemail': 'test@example.com',
                               'file_uuid': str(uuid4()),
                               'emailmessage': 'Test message'
                           })
    assert result.status_code == 302


@pytest.mark.integration
@patch('smtplib.SMTP')
@patch('saq.configuration.config.get_config')
def test_email_file_success(mock_config, mock_smtp, web_client, root_analysis, tmpdir):
    """Test successful email_file operation."""
    # Mock configuration
    mock_config.return_value.get.side_effect = lambda section, key: {
        ('smtp', 'server'): 'localhost',
        ('smtp', 'mail_from'): 'ace@localhost'
    }.get((section, key))

    target_path = tmpdir / "test_file.txt"
    target_path.write_text("Test content", encoding="utf8")
    
    # Add file observable
    file_observable = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.post(url_for("analysis.email_file"),
                            data={
                                'direct': alert.uuid,
                                'toemail': 'test@example.com',
                                'file_uuid': file_observable.uuid,
                                'emailmessage': 'Test message',
                                'subject': 'Test subject'
                            })
    assert result.status_code == 302

@pytest.mark.integration
def test_html_details_no_alert(web_client):
    """Test html_details when no alert is loaded."""
    result = web_client.get(url_for("analysis.html_details"))
    assert result.status_code == 200
    assert b"alert not found" in result.data


@pytest.mark.integration
def test_html_details_missing_field(web_client, root_analysis):
    """Test html_details with missing field parameter."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.html_details"),
                          query_string={'direct': alert.uuid})
    assert result.status_code == 200
    assert b"missing required parameter: field" in result.data


@pytest.mark.integration
def test_html_details_with_field(web_client, root_analysis):
    """Test html_details with valid field parameter."""
    # Add some details to the alert
    root_analysis.details = {'test_field': '<h1>Test HTML</h1>'}
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.html_details"),
                          query_string={
                              'direct': alert.uuid,
                              'field': 'test_field'
                          })
    assert result.status_code == 200
    assert b"<h1>Test HTML</h1>" in result.data