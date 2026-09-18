"""Unit tests for S3Storage construction and bucket memoization.

tests/saq/storage/test_s3.py covers S3Storage against a live endpoint, but it is integration-marked
and skips whenever get_config().s3 is None -- which is every shipped config, so it never runs here.
These patch boto3 instead and need no server.
"""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("boto3")

import botocore.exceptions

from saq.storage.s3 import S3Storage

pytestmark = pytest.mark.unit


def _client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": code}}, "HeadBucket"
    )


@pytest.fixture
def storage(monkeypatch):
    """An S3Storage whose boto3 client is a mock, with real timeout config."""
    with patch("saq.storage.s3.boto3") as mock_boto3, \
            patch("saq.storage.s3.get_config") as mock_get_config:
        mock_get_config.return_value.s3 = None  # use schema defaults
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

    def test_requires_credentials(self):
        with pytest.raises(ValueError):
            S3Storage(host="s3.local", port=9000, access_key=None, secret_key=None)


class TestEnsureBucketExistsMemo:
    """head_bucket runs once per bucket per S3Storage instance."""

    def test_head_bucket_runs_once_per_bucket(self, storage):
        storage.client.head_bucket.return_value = {}

        for _ in range(5):
            storage._ensure_bucket_exists("ace-crash-reports")

        assert storage.client.head_bucket.call_count == 1

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
        from saq.storage.error import StorageError

        storage.client.head_bucket.side_effect = _client_error("403")

        for _ in range(3):
            with pytest.raises(StorageError):
                storage._ensure_bucket_exists("forbidden")

        # retried every time, never cached in either direction
        assert storage.client.head_bucket.call_count == 3
        assert "forbidden" not in storage._known_buckets
        storage.client.create_bucket.assert_not_called()
