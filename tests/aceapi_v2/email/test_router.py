"""Tests for the aceapi_v2 email router.

The archive lives in its own database and CAS pool, outside the test transaction, so the email is
archived through the real ``archive_email`` path and cleaned up by the function-scoped reset.
"""

import glob
import hashlib
import io
import logging
import os
import zipfile
from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.email import service
from aceapi_v2.email.schemas import MAX_MESSAGE_IDS
from saq.cas import IntegrityError
from saq.configuration.config import get_config
from saq.email_archive import archive_email, get_email_archive_pool
from saq.environment import get_global_runtime_settings, get_temp_dir
from saq.util.time import local_time
from tests.aceapi_v2.conftest import api_key_client, make_api_key, open_encrypted_zip
from tests.saq.helpers import audit_actor_of, audit_record

pytestmark = pytest.mark.integration

ARCHIVE_PATH = "/email/archive"
LOOKUP_PATH = "/email/archive/lookup"
DOWNLOAD_PATH = "/email/archive/download"
TEST_MESSAGE_ID = "<test-message-id@example.com>"
TEST_EMAIL = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test Email\r\n\r\nTest body"


@pytest.fixture
def archived_email(tmpdir):
    email = tmpdir / "test_email.eml"
    email.write_binary(TEST_EMAIL)
    return archive_email(str(email), TEST_MESSAGE_ID, local_time())


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
    archive_email(str(email), message_id, local_time())

    response = await client.get(ARCHIVE_PATH, params={"message_id": message_id})

    assert response.status_code == 200
    assert response.content == TEST_EMAIL


@pytest.mark.asyncio
async def test_unknown_message_id_is_404(client: AsyncClient):
    response = await client.get(ARCHIVE_PATH, params={"message_id": "<unknown@example.com>"})

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_an_expired_email_is_404(client: AsyncClient, archived_email):
    # its archive rows outlive it: the pool collected it first
    get_email_archive_pool().purge(archived_email, reason="test", actor="test")

    response = await client.get(ARCHIVE_PATH, params={"message_id": TEST_MESSAGE_ID})

    assert response.status_code == 404


def _corrupt(digest: str) -> None:
    pool = get_email_archive_pool()
    with open(pool.backend.path(pool.key(digest)), "r+b") as fp:
        fp.seek(-1, 2)
        last = fp.read(1)
        fp.seek(-1, 2)
        fp.write(bytes([last[0] ^ 0xFF]))


@pytest.mark.asyncio
async def test_a_corrupt_email_fails_before_the_response_starts(archived_email):
    _corrupt(archived_email)

    # the service, not the client: the test client re-raises an app exception whether it comes before
    # the response starts or in the middle of the body, so only this tells the two apart. Raised here,
    # the router never builds the streaming response, and the request fails with a 500 instead of a
    # 200 whose body stops short
    with pytest.raises(IntegrityError):
        await service.open_archived_email(TEST_MESSAGE_ID)


@pytest.mark.asyncio
async def test_streams_an_email_larger_than_one_chunk(client: AsyncClient, tmpdir):
    content = TEST_EMAIL + b"x" * 100_000
    email = tmpdir / "large.eml"
    email.write_binary(content)
    archive_email(str(email), "<large@example.com>", local_time())

    response = await client.get(ARCHIVE_PATH, params={"message_id": "<large@example.com>"})

    assert response.status_code == 200
    assert response.content == content


@pytest.mark.asyncio
async def test_missing_message_id_is_422(client: AsyncClient):
    response = await client.get(ARCHIVE_PATH)

    assert response.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["by message id", "by sha256", "download"])
async def test_missing_encryption_key_is_500_and_reported(client: AsyncClient, archived_email, monkeypatch, caplog, route):
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)

    if route == "by message id":
        response = await client.get(ARCHIVE_PATH, params={"message_id": TEST_MESSAGE_ID})
    elif route == "by sha256":
        response = await client.get(f"{ARCHIVE_PATH}/{archived_email}")
    else:
        response = await client.post(DOWNLOAD_PATH, json={"message_ids": [TEST_MESSAGE_ID]})

    assert response.status_code == 500
    # with its traceback, so the error report handler writes a report and emits the monitor event
    (record,) = [r for r in caplog.records if r.name == "aceapi_v2.email.router" and r.levelno == logging.CRITICAL]
    assert "no encryption key is configured" in record.getMessage()
    assert record.exc_info and record.exc_info[0] is service.EncryptionKeyMissing


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

        for method, path, kwargs in _new_routes(archived_email):
            response = await client.request(method, path, **kwargs)
            assert response.status_code == 403, path


def _archive(tmpdir, content: bytes, message_id: str, when: datetime) -> str:
    path = tmpdir / hashlib.sha256(content).hexdigest()
    path.write_binary(content)
    return archive_email(str(path), message_id, when)


def _new_routes(sha256: str) -> list[tuple[str, str, dict]]:
    body = {"json": {"message_ids": [TEST_MESSAGE_ID]}}
    return [("POST", LOOKUP_PATH, body), ("GET", f"{ARCHIVE_PATH}/{sha256}", {}), ("POST", DOWNLOAD_PATH, body)]


#
# POST /email/archive/lookup
#

@pytest.mark.asyncio
async def test_lookup_lists_every_copy_of_each_message_id(client: AsyncClient, tmpdir):
    now = local_time().replace(microsecond=0)
    older = _archive(tmpdir, b"journaled copy", "<a@example.com>", now - timedelta(minutes=5))
    newer = _archive(tmpdir, b"a longer resent copy", "<a@example.com>", now)
    other = _archive(tmpdir, b"other", "<b@example.com>", now)
    expired = _archive(tmpdir, b"expired", "<c@example.com>", now)
    get_email_archive_pool().purge(expired, reason="test", actor="test")

    response = await client.post(LOOKUP_PATH, json={"message_ids": [
        "b@example.com", "<unknown@example.com>", "<a@example.com>", "<c@example.com>", "<b@example.com>"]})

    assert response.status_code == 200
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S")
    five_minutes_earlier = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S")
    assert response.json() == {"results": [
        {"index": 0, "message_id": "<b@example.com>", "expired_copies": 0,
         "copies": [{"sha256": other, "archived_at": stamp, "size": 5}]},
        {"index": 1, "message_id": "<unknown@example.com>", "expired_copies": 0, "copies": []},
        {"index": 2, "message_id": "<a@example.com>", "expired_copies": 0,
         "copies": [{"sha256": newer, "archived_at": stamp, "size": 20},
                    {"sha256": older, "archived_at": five_minutes_earlier, "size": 14}]},
        {"index": 3, "message_id": "<c@example.com>", "expired_copies": 1, "copies": []},
        {"index": 4, "message_id": "<b@example.com>", "expired_copies": 0,
         "copies": [{"sha256": other, "archived_at": stamp, "size": 5}]},
    ]}


@pytest.mark.asyncio
@pytest.mark.parametrize("message_ids", [[], ["  "], [f"<{n}@example.com>" for n in range(MAX_MESSAGE_IDS + 1)]])
async def test_lookup_rejects_bad_bodies(client: AsyncClient, message_ids):
    assert (await client.post(LOOKUP_PATH, json={"message_ids": message_ids})).status_code == 422


@pytest.mark.asyncio
async def test_lookup_takes_the_most_message_ids(client: AsyncClient, archived_email):
    message_ids = [f"<{n}@example.com>" for n in range(MAX_MESSAGE_IDS - 1)] + [TEST_MESSAGE_ID]

    response = await client.post(LOOKUP_PATH, json={"message_ids": message_ids})

    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == MAX_MESSAGE_IDS
    assert [copy["sha256"] for copy in results[-1]["copies"]] == [archived_email]


#
# GET /email/archive/{sha256}
#

@pytest.mark.asyncio
async def test_streams_any_copy_by_its_sha256(client: AsyncClient, client_actor, tmpdir, caplog):
    caplog.set_level(logging.INFO)
    now = local_time()
    older = _archive(tmpdir, b"the journaled copy", TEST_MESSAGE_ID, now - timedelta(minutes=5))
    _archive(tmpdir, b"a newer copy", TEST_MESSAGE_ID, now)

    # the older copy, which GET /email/archive?message_id= does not return
    response = await client.get(f"{ARCHIVE_PATH}/{older}")

    assert response.status_code == 200
    assert response.headers["content-type"] == "message/rfc822"
    assert response.headers["content-disposition"] == f'attachment; filename="{older}.eml"'
    assert response.content == b"the journaled copy"
    audit = audit_record(caplog, f"user unittest downloading archived email {older}")
    assert (*audit_actor_of(audit), audit.sha256) == (*client_actor, older)


@pytest.mark.asyncio
async def test_unknown_or_expired_sha256_is_404(client: AsyncClient, archived_email):
    assert (await client.get(f"{ARCHIVE_PATH}/{hashlib.sha256(b'never archived').hexdigest()}")).status_code == 404

    get_email_archive_pool().purge(archived_email, reason="test", actor="test")
    assert (await client.get(f"{ARCHIVE_PATH}/{archived_email}")).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("sha256", ["abc", "A" * 64, "g" * 64])
async def test_malformed_sha256_is_422(client: AsyncClient, sha256):
    assert (await client.get(f"{ARCHIVE_PATH}/{sha256}")).status_code == 422


@pytest.mark.asyncio
async def test_a_corrupt_copy_fails_before_the_response_starts(archived_email):
    _corrupt(archived_email)

    # in the service, for the reason test_a_corrupt_email_fails_before_the_response_starts gives
    with pytest.raises(IntegrityError):
        await service.open_archived_copy(archived_email)


#
# POST /email/archive/download
#

@pytest.mark.asyncio
async def test_download_zips_every_copy_with_a_manifest(client: AsyncClient, client_actor, tmpdir, caplog):
    caplog.set_level(logging.INFO)
    now = local_time().replace(microsecond=0)
    older = _archive(tmpdir, b"journaled copy", "<a@example.com>", now - timedelta(minutes=5))
    newer = _archive(tmpdir, b"a longer resent copy", "<a@example.com>", now)
    other = _archive(tmpdir, b"other", "<b@example.com>", now)
    expired = _archive(tmpdir, b"expired", "<c@example.com>", now)
    get_email_archive_pool().purge(expired, reason="test", actor="test")

    response = await client.post(DOWNLOAD_PATH, json={"message_ids": [
        "a@example.com", "<unknown@example.com>", "<b@example.com>", "<c@example.com>"]})

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert 'filename="archived-emails.zip"' in response.headers["content-disposition"]

    archive, manifest = open_encrypted_zip(response.content)
    stamp = now.replace(tzinfo=None).isoformat()
    assert manifest["emails"] == [
        {"index": 0, "message_id": "<a@example.com>", "copies": [
            {"sha256": newer, "archived_at": stamp, "size": 20, "path": f"0000-_a_example.com_/{newer}.eml"},
            {"sha256": older, "archived_at": (now - timedelta(minutes=5)).replace(tzinfo=None).isoformat(),
             "size": 14, "path": f"0000-_a_example.com_/{older}.eml"}]},
        {"index": 2, "message_id": "<b@example.com>", "copies": [
            {"sha256": other, "archived_at": stamp, "size": 5, "path": f"0002-_b_example.com_/{other}.eml"}]},
    ]
    assert manifest["skipped"] == [
        {"index": 1, "message_id": "<unknown@example.com>", "reason": "not_archived"},
        {"index": 3, "message_id": "<c@example.com>", "reason": "expired"},
    ]
    assert archive.read(f"archived-emails/0000-_a_example.com_/{newer}.eml") == b"a longer resent copy"
    assert archive.read(f"archived-emails/0000-_a_example.com_/{older}.eml") == b"journaled copy"
    assert archive.read(f"archived-emails/0002-_b_example.com_/{other}.eml") == b"other"

    # encrypted: unreadable without the password
    with pytest.raises(RuntimeError):
        zipfile.ZipFile(io.BytesIO(response.content)).read(f"archived-emails/0002-_b_example.com_/{other}.eml")

    audit = audit_record(caplog, "user unittest downloading 3 archived emails of 4 message ids")
    assert (*audit_actor_of(audit), audit.sha256s) == (*client_actor, [newer, older, other])

    # the decrypted emails and the zip were staged on disk; none of it outlives the response
    assert _staged_downloads() == []


def _staged_downloads() -> list[str]:
    return glob.glob(os.path.join(get_temp_dir(), "archived-emails-*"))


@pytest.mark.asyncio
async def test_download_keeps_each_message_id_with_a_slash_apart(client: AsyncClient, tmpdir):
    # a Message-ID may contain "/", and a request may name one twice or two that end alike
    first = _archive(tmpdir, b"first", "<thread/1@example.com>", local_time())
    second = _archive(tmpdir, b"second", "<other/1@example.com>", local_time())

    response = await client.post(DOWNLOAD_PATH, json={"message_ids": [
        "<thread/1@example.com>", "<thread/1@example.com>", "<other/1@example.com>"]})

    assert response.status_code == 200
    archive, manifest = open_encrypted_zip(response.content)
    assert [copy["path"] for email in manifest["emails"] for copy in email["copies"]] == [
        f"0000-_thread_1_example.com_/{first}.eml",
        f"0001-_thread_1_example.com_/{first}.eml",
        f"0002-_other_1_example.com_/{second}.eml",
    ]
    assert archive.read(f"archived-emails/0002-_other_1_example.com_/{second}.eml") == b"second"


@pytest.mark.asyncio
async def test_a_download_that_fails_leaves_nothing_staged(client: AsyncClient, tmpdir):
    _archive(tmpdir, b"intact", "<intact@example.com>", local_time())
    corrupt = _archive(tmpdir, b"corrupted on disk", "<corrupt@example.com>", local_time())
    _corrupt(corrupt)

    # the test client re-raises the app's exception; a real client gets a 500
    with pytest.raises(IntegrityError):
        await client.post(DOWNLOAD_PATH, json={"message_ids": ["<intact@example.com>", "<corrupt@example.com>"]})

    assert _staged_downloads() == []


@pytest.mark.asyncio
async def test_download_skips_an_email_collected_after_the_lookup(client: AsyncClient, tmpdir, monkeypatch):
    kept = _archive(tmpdir, b"kept", "<kept@example.com>", local_time())
    collected = _archive(tmpdir, b"collected", "<collected@example.com>", local_time())
    lookup = service.lookup_archived_emails

    def lookup_then_collect(message_ids):
        results = lookup(message_ids)
        get_email_archive_pool().purge(collected, reason="test", actor="test")
        return results

    monkeypatch.setattr(service, "lookup_archived_emails", lookup_then_collect)
    response = await client.post(DOWNLOAD_PATH, json={"message_ids": ["<kept@example.com>", "<collected@example.com>"]})

    assert response.status_code == 200
    _, manifest = open_encrypted_zip(response.content)
    assert [email["copies"][0]["sha256"] for email in manifest["emails"]] == [kept]
    assert [(skipped["message_id"], skipped["reason"]) for skipped in manifest["skipped"]] == [
        ("<collected@example.com>", "no_longer_stored")]


@pytest.mark.asyncio
async def test_download_limits(client: AsyncClient, tmpdir, monkeypatch):
    _archive(tmpdir, b"first email", "<a@example.com>", local_time())
    _archive(tmpdir, b"second email", "<b@example.com>", local_time())
    body = {"json": {"message_ids": ["<a@example.com>", "<b@example.com>"]}}

    monkeypatch.setattr(get_config().email_archive, "max_bulk_download_files", 1)
    assert (await client.post(DOWNLOAD_PATH, **body)).status_code == 413

    monkeypatch.setattr(get_config().email_archive, "max_bulk_download_files", 2)
    monkeypatch.setattr(get_config().email_archive, "max_bulk_download_bytes", 22)
    assert (await client.post(DOWNLOAD_PATH, **body)).status_code == 413

    monkeypatch.setattr(get_config().email_archive, "max_bulk_download_bytes", 23)
    assert (await client.post(DOWNLOAD_PATH, **body)).status_code == 200


@pytest.mark.asyncio
async def test_download_of_nothing_archived_is_404(client: AsyncClient):
    assert (await client.post(DOWNLOAD_PATH, json={"message_ids": ["<unknown@example.com>"]})).status_code == 404


@pytest.mark.asyncio
async def test_download_rejects_bad_bodies(client: AsyncClient):
    assert (await client.post(DOWNLOAD_PATH, json={"message_ids": []})).status_code == 422


@pytest.mark.asyncio
async def test_new_routes_require_auth(unauth_client: AsyncClient, archived_email):
    for method, path, kwargs in _new_routes(archived_email):
        assert (await unauth_client.request(method, path, **kwargs)).status_code == 401, path


@pytest.mark.asyncio
async def test_new_routes_require_email_read(noperm_client: AsyncClient, archived_email):
    for method, path, kwargs in _new_routes(archived_email):
        assert (await noperm_client.request(method, path, **kwargs)).status_code == 403, path
