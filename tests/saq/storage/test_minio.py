"""
Tests for MinIO storage implementation.

These tests verify the functionality of the MinIOStorage class by testing actual
MinIO connections and operations. Each test uses a unique bucket name to avoid
conflicts with the main system which uses 'ace3'.
"""

import os
import pytest
import uuid
from pathlib import Path


from saq.configuration.config import get_config
from saq.storage.minio import MinIOStorage
from saq.storage.error import StorageError

pytestmark = pytest.mark.integration


@pytest.fixture
def minio_config():
    """Get MinIO configuration from the system config."""
    config = get_config()
    minio_section = config["minio"]
    return {
        "host": minio_section.get("host", "minio"),
        "port": int(minio_section.get("port", 9000)),
        "access_key": minio_section.get("access_key", "ace3apitest"), 
        "secret_key": minio_section.get("secret_key", "5ad82077-e6bf-471d-8f44-979c4f541082"),  # hard coded for testing
        "secure": False
    }


@pytest.fixture(autouse=True)
def clean_test_bucket(minio_config):
    """
    Automatically clean the ace3test bucket before and after each test.
    
    This fixture ensures that:
    1. The ace3test bucket is empty before each test starts
    2. The ace3test bucket is empty after each test completes
    3. Tests don't interfere with each other through leftover objects
    """
    # Create storage instance for cleanup
    storage = MinIOStorage(**minio_config)
    test_bucket = "ace3test"
    
    def cleanup_bucket():
        """Remove all objects from the test bucket."""
        try:
            # List all objects in the bucket
            objects = storage.list_objects(test_bucket, recursive=True)
            
            # Delete each object
            for obj in objects:
                try:
                    storage.delete_object(test_bucket, obj)
                except Exception:
                    # Continue cleanup even if individual deletions fail
                    pass
        except Exception:
            # If we can't list or clean, that's okay - the test will fail if needed
            pass
    
    # Clean before test
    cleanup_bucket()
    
    # Verify bucket is empty before test
    try:
        objects = storage.list_objects(test_bucket, recursive=True)
        if objects:
            pytest.fail(f"ace3test bucket was not empty before test. Found objects: {objects}")
    except Exception:
        # If we can't verify, let the test proceed
        pass
    
    # Run the test
    yield
    
    # Clean after test
    cleanup_bucket()
    
    # Verify bucket is empty after test
    try:
        objects = storage.list_objects(test_bucket, recursive=True)
        if objects:
            pytest.fail(f"ace3test bucket was not cleaned after test. Found objects: {objects}")
    except Exception:
        # If we can't verify, that's still a problem but don't fail the test
        pass


class TestMinIOStorageInitialization:
    """Test MinIO storage initialization and connection."""
    
    def test_init_with_explicit_credentials(self, minio_config):
        """Test initialization with explicit credentials."""
        storage = MinIOStorage(
            host=minio_config["host"],
            port=minio_config["port"],
            access_key=minio_config["access_key"],
            secret_key=minio_config["secret_key"],
            secure=minio_config["secure"]
        )
        
        assert storage.host == minio_config["host"]
        assert storage.port == minio_config["port"]
        assert storage.access_key == minio_config["access_key"]
        assert storage.secret_key == minio_config["secret_key"]
        assert storage.secure == minio_config["secure"]
        assert storage.endpoint == f"{minio_config['host']}:{minio_config['port']}"
        assert storage.client is not None
    
    def test_init_with_secure_connection(self, minio_config):
        """Test initialization with secure=True."""
        storage = MinIOStorage(
            host=minio_config["host"],
            port=minio_config["port"],
            access_key=minio_config["access_key"],
            secret_key=minio_config["secret_key"],
            secure=True
        )
        
        assert storage.secure is True
    
    def test_init_missing_credentials_raises_error(self, minio_config):
        """Test that missing credentials raise ValueError."""
        with pytest.raises(ValueError, match="access key and secret key must be provided"):
            MinIOStorage(host=minio_config["host"], port=minio_config["port"])
        
        with pytest.raises(ValueError, match="access key and secret key must be provided"):
            MinIOStorage(host=minio_config["host"], port=minio_config["port"], access_key="test")
        
        with pytest.raises(ValueError, match="access key and secret key must be provided"):
            MinIOStorage(host=minio_config["host"], port=minio_config["port"], secret_key="test")
    
    def test_init_with_custom_config(self, minio_config):
        """Test initialization with custom configuration."""
        custom_config = {"cert_check": False}
        storage = MinIOStorage(
            host=minio_config["host"],
            port=minio_config["port"],
            access_key=minio_config["access_key"],
            secret_key=minio_config["secret_key"],
            config=custom_config
        )
        
        assert storage.client is not None


class TestMinIOStorageFileOperations:
    """Test file upload and download operations."""
    
    @pytest.fixture
    def storage(self, minio_config):
        """Create a MinIO storage instance for testing."""
        return MinIOStorage(**minio_config)
    
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
        test_content = "This is test content for MinIO storage testing."
        test_file = tmpdir.join("test_file.txt")
        test_file.write(test_content)
        return str(test_file), test_content
    
    def test_upload_file_success(self, storage, test_bucket, unique_prefix, test_file):
        """Test successful file upload."""
        local_path, expected_content = test_file
        remote_path = f"{unique_prefix}/test_folder/uploaded_file.txt"
        
        # Upload the file
        url = storage.upload_file(local_path, test_bucket, remote_path)
        
        # Verify URL format  
        expected_url = f"http://{storage.host}:{storage.port}/{test_bucket}/{remote_path}"
        assert url == expected_url
        
        # Verify file exists in storage
        assert storage.object_exists(test_bucket, remote_path)
        
        # Cleanup
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
        
        # First upload the file
        storage.upload_file(local_path, test_bucket, remote_path)
        
        # Download the file
        url = storage.download_file(test_bucket, remote_path, download_path)
        
        # Verify URL format  
        expected_url = f"http://{storage.host}:{storage.port}/{test_bucket}/{remote_path}"
        assert url == expected_url
        
        # Verify downloaded file exists and has correct content
        assert os.path.exists(download_path)
        with open(download_path, 'r') as f:
            assert f.read() == expected_content
        
        # Cleanup
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
        
        # Upload file first
        storage.upload_file(local_path, test_bucket, remote_path)
        
        # Download to nested path (directories don't exist)
        storage.download_file(test_bucket, remote_path, nested_download_path)
        
        # Verify file was downloaded
        assert os.path.exists(nested_download_path)
        
        # Cleanup
        storage.delete_object(test_bucket, remote_path)
    
    def test_upload_download_with_pathlib_path(self, storage, test_bucket, unique_prefix, tmpdir):
        """Test upload and download using pathlib.Path objects."""
        # Create test file using Path
        test_content = "Testing with pathlib.Path"
        local_path = Path(tmpdir) / "path_test.txt"
        local_path.write_text(test_content)
        
        remote_path = f"{unique_prefix}/pathlib_test.txt"
        download_path = Path(tmpdir) / "downloaded_pathlib.txt"
        
        # Upload using Path object
        storage.upload_file(local_path, test_bucket, remote_path)
        
        # Download using Path object
        storage.download_file(test_bucket, remote_path, download_path)
        
        # Verify content
        assert download_path.read_text() == test_content
        
        # Cleanup
        storage.delete_object(test_bucket, remote_path)


class TestMinIOStorageBucketOperations:
    """Test bucket listing and management operations."""
    
    @pytest.fixture
    def storage(self, minio_config):
        """Create a MinIO storage instance for testing."""
        return MinIOStorage(**minio_config)
    
    def test_list_buckets(self, storage):
        """Test listing all buckets."""
        buckets = storage.list_buckets()
        assert isinstance(buckets, list)
        # Should contain at least the ace3test bucket used for testing
        assert "ace3test" in buckets
    
    def test_ensure_bucket_exists_with_existing_bucket(self, storage):
        """Test that _ensure_bucket_exists works with existing bucket."""
        test_bucket = "ace3test"
        
        # Verify bucket exists initially
        buckets = storage.list_buckets()
        assert test_bucket in buckets
        
        # Call _ensure_bucket_exists (should not raise error)
        storage._ensure_bucket_exists(test_bucket)
        
        # Verify bucket still exists
        buckets = storage.list_buckets()
        assert test_bucket in buckets
    
    def test_ensure_bucket_exists_multiple_calls(self, storage):
        """Test that _ensure_bucket_exists can be called multiple times safely."""
        test_bucket = "ace3test"
        
        # Call multiple times - should not raise error
        storage._ensure_bucket_exists(test_bucket)
        storage._ensure_bucket_exists(test_bucket)
        
        # Bucket should still exist
        buckets = storage.list_buckets()
        assert test_bucket in buckets


class TestMinIOStorageObjectOperations:
    """Test object listing, existence checking, and metadata operations."""
    
    @pytest.fixture
    def storage(self, minio_config):
        """Create a MinIO storage instance for testing."""
        return MinIOStorage(**minio_config)
    
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
        
        # Create several test files with unique prefix
        for i, name in enumerate(["file1.txt", "folder/file2.txt", "folder/subfolder/file3.txt"]):
            content = f"Test content {i+1}"
            temp_file = tmpdir.join(f"temp_{i}.txt")
            temp_file.write(content)
            
            remote_name = f"{unique_prefix}/{name}"
            storage.upload_file(str(temp_file), test_bucket, remote_name)
            objects.append(remote_name)
        
        yield objects
        
        # Cleanup
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
        # Upload a test file
        test_file = tmpdir.join("delete_test.txt")
        test_file.write("delete me")
        remote_path = f"{unique_prefix}/delete_test.txt"
        
        storage.upload_file(str(test_file), test_bucket, remote_path)
        
        # Verify it exists
        assert storage.object_exists(test_bucket, remote_path) is True
        
        # Delete it
        result = storage.delete_object(test_bucket, remote_path)
        
        # Verify deletion
        assert result is True
        assert storage.object_exists(test_bucket, remote_path) is False
    
    def test_delete_object_nonexistent(self, storage, test_bucket, unique_prefix):
        """Test deleting non-existent object."""
        # MinIO doesn't raise an error for deleting non-existent objects
        # It just succeeds silently, so this should not raise an exception
        result = storage.delete_object(test_bucket, f"{unique_prefix}/nonexistent.txt")
        assert result is True


class TestMinIOStorageURLGeneration:
    """Test URL generation functionality."""
    
    @pytest.fixture
    def storage(self, minio_config):
        """Create a MinIO storage instance for testing."""
        return MinIOStorage(**minio_config)
    
    @pytest.fixture
    def secure_storage(self, minio_config):
        """Create a secure MinIO storage instance for testing."""
        config = minio_config.copy()
        config["secure"] = True
        return MinIOStorage(**config)
    
    def test_generate_file_url_http(self, storage, minio_config):
        """Test URL generation for HTTP connection."""
        url = storage._generate_file_url("test-bucket", "path/to/file.txt")
        expected_url = f"http://{minio_config['host']}:{minio_config['port']}/test-bucket/path/to/file.txt"
        assert url == expected_url
    
    def test_generate_file_url_https(self, secure_storage, minio_config):
        """Test URL generation for HTTPS connection."""
        url = secure_storage._generate_file_url("test-bucket", "path/to/file.txt")
        expected_url = f"https://{minio_config['host']}:{minio_config['port']}/test-bucket/path/to/file.txt"
        assert url == expected_url
    
    def test_generate_file_url_special_characters(self, storage, minio_config):
        """Test URL generation with special characters."""
        url = storage._generate_file_url("test-bucket", "folder/file with spaces.txt")
        expected_url = f"http://{minio_config['host']}:{minio_config['port']}/test-bucket/folder/file with spaces.txt"
        assert url == expected_url


class TestMinIOStorageErrorHandling:
    """Test error handling and edge cases."""
    
    def test_init_with_invalid_host_raises_storage_error(self):
        """Test that invalid host eventually raises StorageError during operations."""
        storage = MinIOStorage(
            host="nonexistent-host-12345",
            port=9000,
            access_key="test",
            secret_key="test"
        )
        # I don't want to "ping" to test the connection on each instantiation
        # so failure happens on the first operation instead
        with pytest.raises(StorageError):
            storage.list_buckets()
    
    def test_storage_operations_with_network_error(self, minio_config):
        """Test storage operations when MinIO is not accessible."""
        storage = MinIOStorage(
            host="invalid-host-that-does-not-exist",
            port=9999,
            access_key=minio_config["access_key"],
            secret_key=minio_config["secret_key"]
        )
        
        # Operations should raise StorageError due to network issues
        with pytest.raises(StorageError):
            storage.list_buckets()
    
class TestMinIOStorageIntegration:
    """Integration tests that test multiple operations together."""
    
    @pytest.fixture
    def storage(self, minio_config):
        """Create a MinIO storage instance for testing."""
        return MinIOStorage(**minio_config)
    
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
        # Create test files
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
            # 1. Upload all files
            for local_path, remote_path, content in local_files:
                url = storage.upload_file(local_path, test_bucket, remote_path)
                assert url.endswith(f"/{test_bucket}/{remote_path}")
            
            # 2. List all objects with our prefix
            objects = storage.list_objects(test_bucket, prefix=unique_prefix)
            assert len(objects) == 3
            for _, remote_path, _ in local_files:
                assert remote_path in objects
            
            # 3. Check object existence
            for _, remote_path, _ in local_files:
                assert storage.object_exists(test_bucket, remote_path)
            
            # 4. Get object info
            for _, remote_path, content in local_files:
                info = storage.get_object_info(test_bucket, remote_path)
                assert info is not None
                assert info["size"] == len(content.encode('utf-8'))
            
            # 5. Download all files
            for local_path, remote_path, expected_content in local_files:
                download_path = str(tmpdir.join(f"downloaded_{remote_path.replace('/', '_').replace(unique_prefix + '_', '')}"))
                url = storage.download_file(test_bucket, remote_path, download_path)
                
                assert os.path.exists(download_path)
                with open(download_path, 'r') as f:
                    assert f.read() == expected_content
            
            # 6. Delete all objects
            for _, remote_path, _ in local_files:
                result = storage.delete_object(test_bucket, remote_path)
                assert result is True
                assert storage.object_exists(test_bucket, remote_path) is False
            
            # 7. Verify our prefix area is empty
            objects = storage.list_objects(test_bucket, prefix=unique_prefix)
            assert len(objects) == 0
            
        except Exception:
            # Cleanup on failure
            for _, remote_path, _ in local_files:
                try:
                    storage.delete_object(test_bucket, remote_path)
                except: # noqa: E722
                    pass
            raise
    
    def test_concurrent_operations(self, storage, test_bucket, unique_prefix, tmpdir):
        """Test that multiple operations work correctly in sequence."""
        # Create multiple files quickly
        files_to_upload = []
        for i in range(5):
            content = f"Concurrent test file {i}"
            local_file = tmpdir.join(f"concurrent_{i}.txt")
            local_file.write(content)
            files_to_upload.append((str(local_file), f"{unique_prefix}/concurrent_{i}.txt", content))
        
        try:
            # Upload all files
            for local_path, remote_path, _ in files_to_upload:
                storage.upload_file(local_path, test_bucket, remote_path)
            
            # Verify all files exist in our prefix
            objects = storage.list_objects(test_bucket, prefix=unique_prefix)
            assert len(objects) == 5
            
            # Download and verify all files
            for local_path, remote_path, expected_content in files_to_upload:
                download_path = str(tmpdir.join(f"downloaded_concurrent_{remote_path.replace('/', '_')}"))
                storage.download_file(test_bucket, remote_path, download_path)
                
                with open(download_path, 'r') as f:
                    assert f.read() == expected_content
        
        finally:
            # Cleanup
            for _, remote_path, _ in files_to_upload:
                try:
                    storage.delete_object(test_bucket, remote_path)
                except: # noqa: E722
                    pass