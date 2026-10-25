"""EmailArchiveS3 against a fake S3 client: what it uploads, skips, raises and downloads."""

import shutil
from unittest.mock import MagicMock

import pytest

pytest.importorskip("botocore")

import botocore.exceptions

from saq.configuration.config import get_config
from saq.email_archive.s3 import EmailArchiveS3

pytestmark = pytest.mark.unit

TEST_MESSAGE_ID = "<test-message-id>"


def _client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError({"Error": {"Code": code, "Message": code}}, "HeadObject")


@pytest.fixture
def s3_client(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr("saq.storage.s3.get_s3_client", lambda region=None: client)
    monkeypatch.setattr(get_config().email_archive, "s3_bucket", "test-bucket")
    return client


@pytest.fixture
def archive(monkeypatch, tmp_path):
    archive = EmailArchiveS3()
    monkeypatch.setattr(archive, "get_email_archive_dir", lambda: str(tmp_path / "archive"))
    return archive


@pytest.fixture
def email(tmp_path):
    path = tmp_path / "email"
    path.write_bytes(b"test email")
    return str(path)


def test_an_email_s3_does_not_have_is_uploaded(archive, s3_client, email):
    s3_client.head_object.side_effect = _client_error("404")

    sha256_hash = archive.archive_email_file(email, TEST_MESSAGE_ID)

    s3_client.head_object.assert_called_once_with(Bucket="test-bucket", Key=sha256_hash)
    s3_client.upload_file.assert_called_once_with(
        archive.get_archive_path_by_hash(sha256_hash), "test-bucket", sha256_hash,
        ExtraArgs={"Metadata": {"message_id": TEST_MESSAGE_ID}})


def test_an_email_s3_already_has_is_not_uploaded(archive, s3_client, email):
    archive.archive_email_file(email, TEST_MESSAGE_ID)

    s3_client.head_object.assert_called_once()
    s3_client.upload_file.assert_not_called()


def test_an_s3_error_other_than_not_found_is_raised(archive, s3_client, email):
    s3_client.head_object.side_effect = _client_error("403")

    with pytest.raises(botocore.exceptions.ClientError):
        archive.archive_email_file(email, TEST_MESSAGE_ID)

    s3_client.upload_file.assert_not_called()


def test_an_archived_email_missing_locally_is_downloaded(archive, s3_client, email, tmp_path):
    s3_client.head_object.side_effect = _client_error("404")
    sha256_hash = archive.archive_email_file(email, TEST_MESSAGE_ID)
    local_path = archive.get_archive_path_by_hash(sha256_hash)

    # what S3 holds is the encrypted archive file; the node no longer has its copy
    stored = tmp_path / "stored"
    shutil.move(local_path, stored)

    def download_file(bucket, key, path):
        assert (bucket, key) == ("test-bucket", sha256_hash)
        shutil.copyfile(stored, path)

    s3_client.download_file.side_effect = download_file

    assert b"".join(archive.iter_decrypt_email(local_path)) == b"test email"
    s3_client.download_file.assert_called_once()
