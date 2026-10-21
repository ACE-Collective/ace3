"""Tests for the aceapi_v2 email router.

The archive lives in its own database and on disk, outside the test transaction, so the email is
archived through the real ``archive_email`` path and cleaned up by the function-scoped reset.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.configuration.config import get_config
from saq.email_archive import archive_email
from saq.email_archive.types import EmailArchiveTargetType
from saq.environment import get_global_runtime_settings
from saq.util.time import local_time
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.helpers import reset_s3_email_archive_bucket

pytestmark = pytest.mark.integration

ARCHIVE_PATH = "/email/archive"
TEST_MESSAGE_ID = "<test-message-id@example.com>"
TEST_EMAIL = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test Email\r\n\r\nTest body"


@pytest.fixture(autouse=True)
def local_email_archive(monkeypatch):
    monkeypatch.setattr(get_config().email_archive, "target", EmailArchiveTargetType.LOCAL.value)


@pytest.fixture
def archived_email(tmpdir):
    reset_s3_email_archive_bucket()
    email = tmpdir / "test_email.eml"
    email.write_binary(TEST_EMAIL)
    return archive_email(str(email), TEST_MESSAGE_ID, ["test@local"], local_time())


@pytest.mark.asyncio
async def test_streams_the_decrypted_email(client: AsyncClient, archived_email):
    response = await client.get(ARCHIVE_PATH, params={"message_id": TEST_MESSAGE_ID})

    assert response.status_code == 200
    assert response.headers["content-type"] == "message/rfc822"
    assert response.content == TEST_EMAIL


@pytest.mark.asyncio
async def test_message_id_with_a_slash(client: AsyncClient, tmpdir):
    # the reason message_id is a query parameter rather than a path segment
    message_id = "<abc/def@example.com>"
    email = tmpdir / "slash.eml"
    email.write_binary(TEST_EMAIL)
    archive_email(str(email), message_id, ["test@local"], local_time())

    response = await client.get(ARCHIVE_PATH, params={"message_id": message_id})

    assert response.status_code == 200
    assert response.content == TEST_EMAIL


@pytest.mark.asyncio
async def test_unknown_message_id_is_404(client: AsyncClient):
    response = await client.get(ARCHIVE_PATH, params={"message_id": "<unknown@example.com>"})

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_missing_message_id_is_422(client: AsyncClient):
    response = await client.get(ARCHIVE_PATH)

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_missing_encryption_key_is_500(client: AsyncClient, archived_email, monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)

    response = await client.get(ARCHIVE_PATH, params={"message_id": TEST_MESSAGE_ID})

    assert response.status_code == 500


@pytest.mark.asyncio
async def test_requires_auth(unauth_client: AsyncClient):
    response = await unauth_client.get(ARCHIVE_PATH, params={"message_id": TEST_MESSAGE_ID})

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_requires_email_read(noperm_client: AsyncClient, archived_email):
    response = await noperm_client.get(ARCHIVE_PATH, params={"message_id": TEST_MESSAGE_ID})

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_scoped_key_without_email_read_is_denied(
    _override_db_session, session: AsyncSession, test_user, archived_email
):
    # the same scope the node-to-node automation key ships with
    key = await make_api_key(session, test_user.id, inherit=False, scope=[("alert", "create"), ("engine", "*")])
    async with api_key_client(key) as client:
        response = await client.get(ARCHIVE_PATH, params={"message_id": TEST_MESSAGE_ID})

    assert response.status_code == 403
