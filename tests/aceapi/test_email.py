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

@pytest.fixture(autouse=True, scope="function", params=[EmailArchiveTargetType.S3])
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


@pytest.mark.integration
def test_get_archived_email_remote_server(test_client, tmpdir, patch_email_archive_target_type):
    """test that request is redirected when email is on a remote server"""
    # this test only applies to LOCAL storage since S3 has no concept of server locality
    #if patch_email_archive_target_type == EmailArchiveTargetType.S3:
        #pytest.skip("remote server redirect only applies to LOCAL email archive storage")

    # create and archive an email using the normal archive_email function
    email = tmpdir / "remote_email.eml"
    email.write_binary(b"From: remote@example.com\r\nTo: recipient@example.com\r\nSubject: Remote Email\r\n\r\nRemote body")

    # archive the email normally (this will archive it to the local server)
    archived_result = archive_email(str(email), TEST_REMOTE_MESSAGE_ID, [TEST_RECIPIENT], local_time())

    # now register a remote server in the database
    remote_server = "remote.example.com"
    remote_server_id = register_email_archive(hostname=remote_server)

    # update the archive entry to make it look like it's on the remote server
    # this simulates an email that was archived on a different server
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        # update the archive record to point to the remote server_id
        cursor.execute(
            "UPDATE archive SET server_id = %s WHERE archive_id = %s",
            (remote_server_id, archived_result.archive_id)
        )
        db.commit()

    # now make the API call - it should redirect to the remote server
    result = test_client.get(
        url_for('email.get_archived_email'),
        query_string={'message_id': TEST_REMOTE_MESSAGE_ID},
        headers={'x-ace-auth': get_config().api.api_key},
        follow_redirects=False
    )

    if patch_email_archive_target_type == EmailArchiveTargetType.LOCAL:
        assert result.status_code == 302
        assert result.location == f"https://{remote_server}/api/email/get_archived_email?message_id=%3Cremote-message-id%40example.com%3E"
    else:
        assert result.status_code == 200
        assert result.mimetype == "message/rfc822"
        assert len(result.data) > 0
        assert b"From: remote@example.com" in result.data
