from unittest.mock import patch
from uuid import uuid4

import pytest
from flask import url_for

from saq.configuration import get_config
from saq.database.util.alert import ALERT


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
                              'mode': 'text'
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
    assert result.headers['Content-Type'] == 'text/plain; charset=utf-8'
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
@pytest.mark.parametrize("mode", ["raw", "view", "html"])
def test_download_file_removed_modes(web_client, root_analysis, tmpdir, mode):
    """The modes that served an alert's file as-is are gone: an HTML file from an alert must never
    render on the GUI origin."""
    target_path = tmpdir / "page.html"
    target_path.write_text("<html><body><script>alert(1)</script></body></html>", encoding="utf8")

    file_observable = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.download_file"),
                            query_string={
                                'direct': alert.uuid,
                                'file_uuid': file_observable.uuid,
                                'mode': mode
                            })
    assert result.status_code == 404
    assert b"<script>" not in result.data


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
