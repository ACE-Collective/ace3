"""
Tests for S3-compatible storage implementation.

These tests verify the functionality of the S3Storage class by testing actual
S3-compatible storage connections and operations. Each test uses a unique bucket
name to avoid conflicts with the main system which uses 'ace3'.
"""

import os
import pytest
import uuid
from pathlib import Path

pytest.importorskip("boto3")

from saq.configuration.config import get_config
from saq.storage.s3 import S3Storage
from saq.storage.error import StorageError

pytestmark = pytest.mark.integration

@pytest.fixture
def s3_config():
    """Get S3 configuration from the system config."""
    config = get_config().s3
    if config is None:
        pytest.skip("s3 configuration not available")
    return {
        "host": config.host,
        "port": config.port,
        "access_key": config.access_key,
        "secret_key": config.secret_key,
        "secure": False,
        "region": config.region,
    }


@pytest.fixture(autouse=True)
def clean_test_bucket(s3_config):
    """
    Automatically clean the ace3test bucket before and after each test.
    """
    storage = S3Storage(**s3_config)
    test_bucket = "ace3test"

    def cleanup_bucket():
        """Remove all objects from the test bucket."""
        try:
            objects = storage.list_objects(test_bucket, recursive=True)
            for obj in objects:
                try:
                    storage.delete_object(test_bucket, obj)
                except Exception:
                    pass
        except Exception:
            pass

    cleanup_bucket()

    try:
        objects = storage.list_objects(test_bucket, recursive=True)
        if objects:
            pytest.fail(f"ace3test bucket was not empty before test. Found objects: {objects}")
    except Exception:
        pass

    yield

    cleanup_bucket()

    try:
        objects = storage.list_objects(test_bucket, recursive=True)
        if objects:
            pytest.fail(f"ace3test bucket was not cleaned after test. Found objects: {objects}")
    except Exception:
        pass


class TestS3StorageInitialization:
    """Test S3 storage initialization and connection."""

    def test_init_with_explicit_credentials(self, s3_config):
        """Test initialization with explicit credentials."""
        storage = S3Storage(
            host=s3_config["host"],
            port=s3_config["port"],
            access_key=s3_config["access_key"],
            secret_key=s3_config["secret_key"],
            secure=s3_config["secure"]
        )

        assert storage.host == s3_config["host"]
        assert storage.port == s3_config["port"]
        assert storage.access_key == s3_config["access_key"]
        assert storage.secret_key == s3_config["secret_key"]
        assert storage.secure == s3_config["secure"]
        assert storage.endpoint == f"{s3_config['host']}:{s3_config['port']}"
        assert storage.client is not None

    def test_init_with_secure_connection(self, s3_config):
        """Test initialization with secure=True."""
        storage = S3Storage(
            host=s3_config["host"],
            port=s3_config["port"],
            access_key=s3_config["access_key"],
            secret_key=s3_config["secret_key"],
            secure=True
        )

        assert storage.secure is True

    def test_init_missing_credentials_raises_error(self, s3_config):
        """Test that missing credentials raise ValueError."""
        with pytest.raises(ValueError, match="access key and secret key must be provided"):
            S3Storage(host=s3_config["host"], port=s3_config["port"])

        with pytest.raises(ValueError, match="access key and secret key must be provided"):
            S3Storage(host=s3_config["host"], port=s3_config["port"], access_key="test")

        with pytest.raises(ValueError, match="access key and secret key must be provided"):
            S3Storage(host=s3_config["host"], port=s3_config["port"], secret_key="test")

    def test_init_with_custom_config(self, s3_config):
        """Test initialization with custom configuration."""
        custom_config = {"verify": False}
        storage = S3Storage(
            host=s3_config["host"],
            port=s3_config["port"],
            access_key=s3_config["access_key"],
            secret_key=s3_config["secret_key"],
            config=custom_config
        )

        assert storage.client is not None


class TestS3StorageFileOperations:
    """Test file upload and download operations."""

    @pytest.fixture
    def storage(self, s3_config):
        """Create an S3 storage instance for testing."""
        return S3Storage(**s3_config)

    @pytest.fixture
    def test_bucket(self):
        """Use the ace3test bucket for all tests."""
        return "ace3test"

    @pytest.fixture
    def unique_prefix(self):
        """Generate a unique prefix for test objects within the bucket."""
        return f"test-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_file(self, tmpdir):
        """Create a test file for upload/download operations."""
        test_content = "This is test content for S3 storage testing."
        test_file = tmpdir.join("test_file.txt")
        test_file.write(test_content)
        return str(test_file), test_content

    def test_upload_file_success(self, storage, test_bucket, unique_prefix, test_file):
        """Test successful file upload."""
        local_path, expected_content = test_file
        remote_path = f"{unique_prefix}/test_folder/uploaded_file.txt"

        url = storage.upload_file(local_path, test_bucket, remote_path)

        expected_url = f"http://{storage.host}:{storage.port}/{test_bucket}/{remote_path}"
        assert url == expected_url

        assert storage.object_exists(test_bucket, remote_path)

        storage.delete_object(test_bucket, remote_path)

    def test_upload_file_nonexistent_source(self, storage, test_bucket, unique_prefix):
        """Test upload with non-existent source file."""
        with pytest.raises(FileNotFoundError, match="source file not found"):
            storage.upload_file("/nonexistent/file.txt", test_bucket, f"{unique_prefix}/remote.txt")

    def test_download_file_success(self, storage, test_bucket, unique_prefix, test_file, tmpdir):
        """Test successful file download."""
        local_path, expected_content = test_file
        remote_path = f"{unique_prefix}/downloaded_file.txt"
        download_path = str(tmpdir.join("downloaded.txt"))

        storage.upload_file(local_path, test_bucket, remote_path)

        result = storage.download_file(test_bucket, remote_path, download_path)

        assert os.path.exists(download_path)
        with open(download_path, 'r') as f:
            assert f.read() == expected_content

        storage.delete_object(test_bucket, remote_path)

    def test_download_file_nonexistent_remote(self, storage, test_bucket, unique_prefix, tmpdir):
        """Test download with non-existent remote file."""
        download_path = str(tmpdir.join("downloaded.txt"))

        with pytest.raises(FileNotFoundError, match="file not found in storage"):
            storage.download_file(test_bucket, f"{unique_prefix}/nonexistent.txt", download_path)

    def test_download_file_creates_local_directory(self, storage, test_bucket, unique_prefix, test_file, tmpdir):
        """Test that download creates local directory if needed."""
        local_path, _ = test_file
        remote_path = f"{unique_prefix}/test.txt"
        nested_download_path = str(tmpdir.join("nested", "dir", "downloaded.txt"))

        storage.upload_file(local_path, test_bucket, remote_path)

        storage.download_file(test_bucket, remote_path, nested_download_path)

        assert os.path.exists(nested_download_path)

        storage.delete_object(test_bucket, remote_path)

    def test_upload_download_with_pathlib_path(self, storage, test_bucket, unique_prefix, tmpdir):
        """Test upload and download using pathlib.Path objects."""
        test_content = "Testing with pathlib.Path"
        local_path = Path(tmpdir) / "path_test.txt"
        local_path.write_text(test_content)

        remote_path = f"{unique_prefix}/pathlib_test.txt"
        download_path = Path(tmpdir) / "downloaded_pathlib.txt"

        storage.upload_file(local_path, test_bucket, remote_path)

        storage.download_file(test_bucket, remote_path, download_path)

        assert download_path.read_text() == test_content

        storage.delete_object(test_bucket, remote_path)


class TestS3StorageBucketOperations:
    """Test bucket listing and management operations."""

    @pytest.fixture
    def storage(self, s3_config):
        """Create an S3 storage instance for testing."""
        return S3Storage(**s3_config)

    def test_list_buckets(self, storage):
        """Test listing all buckets."""
        buckets = storage.list_buckets()
        assert isinstance(buckets, list)
        assert "ace3test" in buckets

    def test_ensure_bucket_exists_with_existing_bucket(self, storage):
        """Test that _ensure_bucket_exists works with existing bucket."""
        test_bucket = "ace3test"

        buckets = storage.list_buckets()
        assert test_bucket in buckets

        storage._ensure_bucket_exists(test_bucket)

        buckets = storage.list_buckets()
        assert test_bucket in buckets

    def test_ensure_bucket_exists_multiple_calls(self, storage):
        """Test that _ensure_bucket_exists can be called multiple times safely."""
        test_bucket = "ace3test"

        storage._ensure_bucket_exists(test_bucket)
        storage._ensure_bucket_exists(test_bucket)

        buckets = storage.list_buckets()
        assert test_bucket in buckets


class TestS3StorageObjectOperations:
    """Test object listing, existence checking, and metadata operations."""

    @pytest.fixture
    def storage(self, s3_config):
        """Create an S3 storage instance for testing."""
        return S3Storage(**s3_config)

    @pytest.fixture
    def test_bucket(self):
        """Use the ace3test bucket for all tests."""
        return "ace3test"

    @pytest.fixture
    def unique_prefix(self):
        """Generate a unique prefix for test objects within the bucket."""
        return f"test-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_objects(self, storage, test_bucket, unique_prefix, tmpdir):
        """Create test objects in the bucket."""
        objects = []

        for i, name in enumerate(["file1.txt", "folder/file2.txt", "folder/subfolder/file3.txt"]):
            content = f"Test content {i+1}"
            temp_file = tmpdir.join(f"temp_{i}.txt")
            temp_file.write(content)

            remote_name = f"{unique_prefix}/{name}"
            storage.upload_file(str(temp_file), test_bucket, remote_name)
            objects.append(remote_name)

        yield objects

        for obj in objects:
            try:
                storage.delete_object(test_bucket, obj)
            except: # noqa: E722
                pass

    def test_list_objects_recursive(self, storage, test_bucket, unique_prefix, test_objects):
        """Test listing objects recursively."""
        objects = storage.list_objects(test_bucket, prefix=unique_prefix, recursive=True)

        assert isinstance(objects, list)
        assert len(objects) == 3
        assert f"{unique_prefix}/file1.txt" in objects
        assert f"{unique_prefix}/folder/file2.txt" in objects
        assert f"{unique_prefix}/folder/subfolder/file3.txt" in objects

    def test_list_objects_with_prefix(self, storage, test_bucket, unique_prefix, test_objects):
        """Test listing objects with prefix filter."""
        objects = storage.list_objects(test_bucket, prefix=f"{unique_prefix}/folder/")

        assert isinstance(objects, list)
        assert len(objects) == 2
        assert f"{unique_prefix}/folder/file2.txt" in objects
        assert f"{unique_prefix}/folder/subfolder/file3.txt" in objects
        assert f"{unique_prefix}/file1.txt" not in objects

    def test_list_objects_nonrecursive(self, storage, test_bucket, unique_prefix, test_objects):
        """Test listing objects non-recursively."""
        objects = storage.list_objects(test_bucket, prefix=f"{unique_prefix}/", recursive=False)

        assert isinstance(objects, list)
        assert len(objects) == 2
        assert f"{unique_prefix}/folder/" in objects
        assert f"{unique_prefix}/folder/subfolder/file3.txt" not in objects
        assert f"{unique_prefix}/file1.txt" in objects

    def test_object_exists_true(self, storage, test_bucket, unique_prefix, test_objects):
        """Test object_exists returns True for existing object."""
        assert storage.object_exists(test_bucket, f"{unique_prefix}/file1.txt") is True
        assert storage.object_exists(test_bucket, f"{unique_prefix}/folder/file2.txt") is True

    def test_object_exists_false(self, storage, test_bucket, unique_prefix):
        """Test object_exists returns False for non-existing object."""
        assert storage.object_exists(test_bucket, f"{unique_prefix}/nonexistent.txt") is False
        assert storage.object_exists("nonexistent-bucket", "file.txt") is False

    def test_get_object_info_existing(self, storage, test_bucket, unique_prefix, test_objects):
        """Test get_object_info for existing object."""
        info = storage.get_object_info(test_bucket, f"{unique_prefix}/file1.txt")

        assert info is not None
        assert isinstance(info, dict)
        assert "size" in info
        assert "last_modified" in info
        assert "etag" in info
        assert "content_type" in info
        assert "metadata" in info
        assert info["size"] > 0

    def test_get_object_info_nonexistent(self, storage, test_bucket, unique_prefix):
        """Test get_object_info returns None for non-existing object."""
        info = storage.get_object_info(test_bucket, f"{unique_prefix}/nonexistent.txt")
        assert info is None

    def test_delete_object_success(self, storage, test_bucket, unique_prefix, tmpdir):
        """Test successful object deletion."""
        test_file = tmpdir.join("delete_test.txt")
        test_file.write("delete me")
        remote_path = f"{unique_prefix}/delete_test.txt"

        storage.upload_file(str(test_file), test_bucket, remote_path)

        assert storage.object_exists(test_bucket, remote_path) is True

        result = storage.delete_object(test_bucket, remote_path)

        assert result is True
        assert storage.object_exists(test_bucket, remote_path) is False

    def test_delete_object_nonexistent(self, storage, test_bucket, unique_prefix):
        """Test deleting non-existent object."""
        result = storage.delete_object(test_bucket, f"{unique_prefix}/nonexistent.txt")
        assert result is True


class TestS3StorageURLGeneration:
    """Test URL generation functionality."""

    @pytest.fixture
    def storage(self, s3_config):
        """Create an S3 storage instance for testing."""
        return S3Storage(**s3_config)

    @pytest.fixture
    def secure_storage(self, s3_config):
        """Create a secure S3 storage instance for testing."""
        config = s3_config.copy()
        config["secure"] = True
        return S3Storage(**config)

    def test_generate_file_url_http(self, storage, s3_config):
        """Test URL generation for HTTP connection."""
        url = storage._generate_file_url("test-bucket", "path/to/file.txt")
        expected_url = f"http://{s3_config['host']}:{s3_config['port']}/test-bucket/path/to/file.txt"
        assert url == expected_url

    def test_generate_file_url_https(self, secure_storage, s3_config):
        """Test URL generation for HTTPS connection."""
        url = secure_storage._generate_file_url("test-bucket", "path/to/file.txt")
        expected_url = f"https://{s3_config['host']}:{s3_config['port']}/test-bucket/path/to/file.txt"
        assert url == expected_url

    def test_generate_file_url_special_characters(self, storage, s3_config):
        """Test URL generation with special characters."""
        url = storage._generate_file_url("test-bucket", "folder/file with spaces.txt")
        expected_url = f"http://{s3_config['host']}:{s3_config['port']}/test-bucket/folder/file with spaces.txt"
        assert url == expected_url


class TestS3StorageErrorHandling:
    """Test error handling and edge cases."""

    @pytest.mark.skip(reason="too slow to test")
    def test_init_with_invalid_host_raises_storage_error(self):
        """Test that invalid host eventually raises StorageError during operations."""
        storage = S3Storage(
            host="nonexistent-host-12345",
            port=3900,
            access_key="test",
            secret_key="test"
        )
        with pytest.raises(StorageError):
            storage.list_buckets()

    @pytest.mark.skip(reason="too slow to test")
    def test_storage_operations_with_network_error(self, s3_config):
        """Test storage operations when storage is not accessible."""
        storage = S3Storage(
            host="invalid-host-that-does-not-exist",
            port=9999,
            access_key=s3_config["access_key"],
            secret_key=s3_config["secret_key"]
        )

        with pytest.raises(StorageError):
            storage.list_buckets()

class TestS3StorageIntegration:
    """Integration tests that test multiple operations together."""

    @pytest.fixture
    def storage(self, s3_config):
        """Create an S3 storage instance for testing."""
        return S3Storage(**s3_config)

    @pytest.fixture
    def test_bucket(self):
        """Use the ace3test bucket for all tests."""
        return "ace3test"

    @pytest.fixture
    def unique_prefix(self):
        """Generate a unique prefix for test objects within the bucket."""
        return f"test-{uuid.uuid4().hex[:8]}"


    def test_full_lifecycle_workflow(self, storage, test_bucket, unique_prefix, tmpdir):
        """Test a complete workflow: upload, list, download, delete."""
        files_data = [
            ("file1.txt", "Content of file 1"),
            ("folder/file2.txt", "Content of file 2"),
            ("folder/subfolder/file3.txt", "Content of file 3"),
        ]

        local_files = []
        for filename, content in files_data:
            local_file = tmpdir.join(f"local_{filename.replace('/', '_')}")
            local_file.write(content)
            local_files.append((str(local_file), f"{unique_prefix}/{filename}", content))

        try:
            for local_path, remote_path, content in local_files:
                url = storage.upload_file(local_path, test_bucket, remote_path)
                assert url.endswith(f"/{test_bucket}/{remote_path}")

            objects = storage.list_objects(test_bucket, prefix=unique_prefix)
            assert len(objects) == 3
            for _, remote_path, _ in local_files:
                assert remote_path in objects

            for _, remote_path, _ in local_files:
                assert storage.object_exists(test_bucket, remote_path)

            for _, remote_path, content in local_files:
                info = storage.get_object_info(test_bucket, remote_path)
                assert info is not None
                assert info["size"] == len(content.encode('utf-8'))

            for local_path, remote_path, expected_content in local_files:
                download_path = str(tmpdir.join(f"downloaded_{remote_path.replace('/', '_').replace(unique_prefix + '_', '')}"))
                url = storage.download_file(test_bucket, remote_path, download_path)

                assert os.path.exists(download_path)
                with open(download_path, 'r') as f:
                    assert f.read() == expected_content

            for _, remote_path, _ in local_files:
                result = storage.delete_object(test_bucket, remote_path)
                assert result is True
                assert storage.object_exists(test_bucket, remote_path) is False

            objects = storage.list_objects(test_bucket, prefix=unique_prefix)
            assert len(objects) == 0

        except Exception:
            for _, remote_path, _ in local_files:
                try:
                    storage.delete_object(test_bucket, remote_path)
                except: # noqa: E722
                    pass
            raise

    def test_concurrent_operations(self, storage, test_bucket, unique_prefix, tmpdir):
        """Test that multiple operations work correctly in sequence."""
        files_to_upload = []
        for i in range(5):
            content = f"Concurrent test file {i}"
            local_file = tmpdir.join(f"concurrent_{i}.txt")
            local_file.write(content)
            files_to_upload.append((str(local_file), f"{unique_prefix}/concurrent_{i}.txt", content))

        try:
            for local_path, remote_path, _ in files_to_upload:
                storage.upload_file(local_path, test_bucket, remote_path)

            objects = storage.list_objects(test_bucket, prefix=unique_prefix)
            assert len(objects) == 5

            for local_path, remote_path, expected_content in files_to_upload:
                download_path = str(tmpdir.join(f"downloaded_concurrent_{remote_path.replace('/', '_')}"))
                storage.download_file(test_bucket, remote_path, download_path)

                with open(download_path, 'r') as f:
                    assert f.read() == expected_content

        finally:
            for _, remote_path, _ in files_to_upload:
                try:
                    storage.delete_object(test_bucket, remote_path)
                except: # noqa: E722
                    pass
