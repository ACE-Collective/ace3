import pytest

from flask import url_for

from saq.configuration.config import get_config
from saq.constants import DB_EMAIL_ARCHIVE
from saq.database.pool import get_db_connection
from saq.email_archive import archive_email, register_email_archive
from saq.email_archive.types import EmailArchiveTargetType
from saq.environment import get_global_runtime_settings
from saq.util.time import local_time
from tests.saq.helpers import reset_s3_email_archive_bucket

TEST_MESSAGE_ID = "<test-message-id@example.com>"
TEST_REMOTE_MESSAGE_ID = "<remote-message-id@example.com>"
TEST_RECIPIENT = "test@local"

@pytest.fixture(autouse=True, scope="function", params=[EmailArchiveTargetType.LOCAL])
def patch_email_archive_target_type(monkeypatch, request):
    monkeypatch.setattr("saq.email_archive.factory.get_email_archive_type", lambda: request.param)
    return request.param


@pytest.fixture
def archived_email(tmpdir):
    """create an archived email for testing"""
    reset_s3_email_archive_bucket()

    email = tmpdir / "test_email.eml"
    email.write_binary(b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test Email\r\n\r\nTest body")

    return archive_email(str(email), TEST_MESSAGE_ID, [TEST_RECIPIENT], local_time())


@pytest.mark.integration
def test_get_archived_email_success(test_client, archived_email):
    """test successful retrieval of an archived email"""
    result = test_client.get(
        url_for('email.get_archived_email'),
        query_string={'message_id': TEST_MESSAGE_ID},
        headers={'x-ace-auth': get_config().api.api_key},
    )

    assert result.status_code == 200
    assert result.mimetype == "message/rfc822"
    assert len(result.data) > 0
    assert b"From: sender@example.com" in result.data


@pytest.mark.integration
def test_get_archived_email_missing_message_id(test_client):
    """test that missing message_id parameter returns 400"""
    result = test_client.get(
        url_for('email.get_archived_email'),
        headers={'x-ace-auth': get_config().api.api_key},
    )

    assert result.status_code == 400


@pytest.mark.integration
def test_get_archived_email_unknown_message_id(test_client):
    """test that unknown message_id returns 404"""
    result = test_client.get(
        url_for('email.get_archived_email'),
        query_string={'message_id': '<unknown-message-id@example.com>'},
        headers={'x-ace-auth': get_config().api.api_key},
    )

    assert result.status_code == 404


@pytest.mark.integration
def test_get_archived_email_missing_encryption_key(test_client, archived_email):
    """test that missing encryption key returns 500"""
    # temporarily remove the encryption key
    original_key = get_global_runtime_settings().encryption_key
    get_global_runtime_settings().encryption_key = None

    try:
        result = test_client.get(
            url_for('email.get_archived_email'),
            query_string={'message_id': TEST_MESSAGE_ID},
            headers={'x-ace-auth': get_config().api.api_key},
        )

        assert result.status_code == 500
    finally:
        # restore the encryption key
        get_global_runtime_settings().encryption_key = original_key
