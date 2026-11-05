"""Unit tests for S3Storage.

The dev stack has no S3-compatible server, so these patch boto3 at the network boundary: the
client is a mock, and every test checks what S3Storage asks of it and what it makes of the answer.
"""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("boto3")

import botocore.exceptions

from saq.configuration.config import get_config
from saq.storage.error import StorageError
from saq.storage.s3 import S3Storage

pytestmark = pytest.mark.unit


def _client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": code}}, "HeadBucket"
    )


@pytest.fixture
def storage(monkeypatch):
    """An S3Storage whose boto3 client is a mock, with real timeout config."""
    monkeypatch.setattr(get_config(), "s3", None)  # use schema defaults
    with patch("saq.storage.s3.boto3") as mock_boto3:
        mock_boto3.client.return_value = MagicMock()
        instance = S3Storage(
            host="s3.local", port=9000, access_key="key", secret_key="secret"
        )
        instance._mock_boto3 = mock_boto3
        yield instance


class TestS3StorageConstruction:
    def test_client_is_built_bounded(self, storage):
        """S3Storage builds its own client, so it needs the bounds independently of
        get_s3_client()."""
        config = storage._mock_boto3.client.call_args.kwargs["config"]
        assert config.connect_timeout == 10
        assert config.read_timeout == 60
        assert config.retries == {"mode": "standard", "total_max_attempts": 3}

    @pytest.mark.parametrize("access_key, secret_key", [
        (None, None),
        ("key", None),
        (None, "secret"),
    ])
    def test_requires_credentials(self, access_key, secret_key):
        with pytest.raises(ValueError, match="access key and secret key must be provided"):
            S3Storage(host="s3.local", port=9000, access_key=access_key, secret_key=secret_key)


class TestEnsureBucketExistsMemo:
    """head_bucket runs once per bucket per S3Storage instance."""

    def test_each_distinct_bucket_is_checked(self, storage):
        storage.client.head_bucket.return_value = {}

        storage._ensure_bucket_exists("bucket-a")
        storage._ensure_bucket_exists("bucket-b")
        storage._ensure_bucket_exists("bucket-a")

        assert storage.client.head_bucket.call_count == 2

    def test_created_bucket_is_memoized(self, storage):
        storage.client.head_bucket.side_effect = _client_error("404")

        storage._ensure_bucket_exists("brand-new")
        storage._ensure_bucket_exists("brand-new")

        assert storage.client.create_bucket.call_count == 1
        assert storage.client.head_bucket.call_count == 1

    def test_a_403_is_never_memoized(self, storage):
        """A 403 means the bucket may well exist but this credential cannot head_bucket it --
        ordinary under least-privilege IAM. It is not 404/NoSuchBucket so it raises; memoizing it
        either way would make the failure permanent for the life of the process, and memoizing it
        as *success* would be worse still."""
        storage.client.head_bucket.side_effect = _client_error("403")

        for _ in range(3):
            with pytest.raises(StorageError):
                storage._ensure_bucket_exists("forbidden")

        # retried every time, never cached in either direction
        assert storage.client.head_bucket.call_count == 3
        assert "forbidden" not in storage._known_buckets
        storage.client.create_bucket.assert_not_called()


class TestObjectExists:
    """Only "not found" means False; anything else is an error, not a missing object (F-18)."""

    @pytest.mark.parametrize("code", ["404", "NotFound", "NoSuchKey"])
    def test_not_found_is_false(self, storage, code):
        storage.client.head_object.side_effect = _client_error(code)
        assert storage.object_exists("bucket", "key") is False

    def test_found_is_true(self, storage):
        storage.client.head_object.return_value = {}
        assert storage.object_exists("bucket", "key") is True

    def test_other_client_errors_raise(self, storage):
        # every code outside the not-found set takes this branch; a 403 is the one that matters,
        # because the bucket may well hold the object
        storage.client.head_object.side_effect = _client_error("403")
        with pytest.raises(StorageError):
            storage.object_exists("bucket", "key")

    def test_connection_error_raises(self, storage):
        storage.client.head_object.side_effect = botocore.exceptions.EndpointConnectionError(
            endpoint_url="https://s3.local:9000")
        with pytest.raises(StorageError):
            storage.object_exists("bucket", "key")


class TestGetObjectInfo:
    def test_not_found_is_none(self, storage):
        # the same not-found codes as object_exists, whose tests check each one
        storage.client.head_object.side_effect = _client_error("404")
        assert storage.get_object_info("bucket", "key") is None

    def test_found_object_is_described(self, storage):
        when = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        storage.client.head_object.return_value = {
            "ContentLength": 4, "LastModified": when, "ETag": '"abc"', "ContentType": "text/plain",
        }

        assert storage.get_object_info("bucket", "key") == {
            "size": 4, "last_modified": when, "etag": '"abc"', "content_type": "text/plain", "metadata": {},
        }
        storage.client.head_object.assert_called_once_with(Bucket="bucket", Key="key")


class TestUploadDownload:
    def test_upload_returns_the_object_url(self, storage, tmp_path):
        source = tmp_path / "source.txt"
        source.write_text("content")

        url = storage.upload_file(Path(source), "bucket", "dir/file with spaces.txt")

        assert url == "http://s3.local:9000/bucket/dir/file with spaces.txt"
        storage.client.head_bucket.assert_called_once_with(Bucket="bucket")
        storage.client.upload_file.assert_called_once_with(
            str(source), "bucket", "dir/file with spaces.txt", ExtraArgs=None)

    def test_upload_of_a_missing_file(self, storage, tmp_path):
        with pytest.raises(FileNotFoundError, match="source file not found"):
            storage.upload_file(tmp_path / "missing.txt", "bucket", "key")
        storage.client.upload_file.assert_not_called()

    def test_download_creates_the_directory_and_bounds_retries(self, storage, tmp_path):
        target = tmp_path / "nested" / "dir" / "file.txt"

        assert storage.download_file("bucket", "key", target) == str(target)

        assert target.parent.is_dir()
        storage.client.head_object.assert_called_once_with(Bucket="bucket", Key="key")
        args, kwargs = storage.client.download_file.call_args
        assert args == ("bucket", "key", str(target))
        # s3transfer's own retry layer, on top of botocore's
        assert kwargs["Config"].num_download_attempts == 3

    def test_download_of_a_missing_object(self, storage, tmp_path):
        storage.client.head_object.side_effect = _client_error("404")

        with pytest.raises(FileNotFoundError, match="file not found in storage"):
            storage.download_file("bucket", "key", tmp_path / "file.txt")
        storage.client.download_file.assert_not_called()


class TestListingAndDelete:
    def test_recursive_listing_follows_every_page(self, storage):
        storage.client.list_objects_v2.side_effect = [
            {"Contents": [{"Key": "p/a"}], "IsTruncated": True, "NextContinuationToken": "token"},
            {"Contents": [{"Key": "p/b/c"}], "IsTruncated": False},
        ]

        assert storage.list_objects("bucket", prefix="p/") == ["p/a", "p/b/c"]
        assert [c.kwargs for c in storage.client.list_objects_v2.call_args_list] == [
            {"Bucket": "bucket", "Prefix": "p/"},
            {"Bucket": "bucket", "Prefix": "p/", "ContinuationToken": "token"},
        ]

    def test_non_recursive_listing_includes_the_directories(self, storage):
        storage.client.list_objects_v2.return_value = {
            "Contents": [{"Key": "p/a"}], "CommonPrefixes": [{"Prefix": "p/b/"}],
        }

        assert storage.list_objects("bucket", prefix="p/", recursive=False) == ["p/a", "p/b/"]
        assert storage.client.list_objects_v2.call_args.kwargs == {
            "Bucket": "bucket", "Prefix": "p/", "Delimiter": "/"}

    def test_list_buckets(self, storage):
        storage.client.list_buckets.return_value = {"Buckets": [{"Name": "a"}, {"Name": "b"}]}
        assert storage.list_buckets() == ["a", "b"]

    def test_unreachable_endpoint_is_a_storage_error(self, storage):
        storage.client.list_buckets.side_effect = botocore.exceptions.EndpointConnectionError(
            endpoint_url="http://s3.local:9000")
        with pytest.raises(StorageError):
            storage.list_buckets()

    def test_delete_object(self, storage):
        assert storage.delete_object("bucket", "key") is True
        storage.client.delete_object.assert_called_once_with(Bucket="bucket", Key="key")
