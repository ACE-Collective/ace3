from unittest.mock import patch
from uuid import uuid4

import pytest
from flask import url_for

from saq.configuration import get_config
from saq.database.util.alert import ALERT


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
