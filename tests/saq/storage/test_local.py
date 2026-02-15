"""
Tests for local filesystem storage implementation.
"""

import os
import pytest
from pathlib import Path

from saq.storage.local import LocalStorage
from saq.storage.error import StorageError

pytestmark = pytest.mark.unit


class TestLocalStorageInit:
    """Tests for LocalStorage initialization."""

    def test_creates_base_dir(self, tmpdir):
        base_dir = str(tmpdir.join("storage"))
        storage = LocalStorage(base_dir=base_dir)
        assert os.path.isdir(base_dir)
        assert storage.base_dir == Path(base_dir)

    def test_existing_base_dir(self, tmpdir):
        storage = LocalStorage(base_dir=str(tmpdir))
        assert storage.base_dir == Path(str(tmpdir))


class TestLocalStorageUpload:
    """Tests for file upload operations."""

    @pytest.fixture
    def storage(self, tmpdir):
        return LocalStorage(base_dir=str(tmpdir.join("storage")))

    @pytest.fixture
    def sample_file(self, tmpdir):
        f = tmpdir.join("sample.txt")
        f.write("hello world")
        return str(f)

    def test_upload_file(self, storage, sample_file):
        result = storage.upload_file(sample_file, "test-bucket", "remote/file.txt")
        assert os.path.exists(result)
        with open(result) as f:
            assert f.read() == "hello world"

    def test_upload_creates_bucket_dir(self, storage, sample_file):
        storage.upload_file(sample_file, "new-bucket", "file.txt")
        assert os.path.isdir(storage._bucket_path("new-bucket"))

    def test_upload_creates_nested_path(self, storage, sample_file):
        storage.upload_file(sample_file, "bucket", "a/b/c/file.txt")
        assert os.path.exists(storage._object_path("bucket", "a/b/c/file.txt"))

    def test_upload_nonexistent_file(self, storage):
        with pytest.raises(FileNotFoundError):
            storage.upload_file("/nonexistent/file.txt", "bucket", "remote.txt")

    def test_upload_overwrites_existing(self, storage, sample_file, tmpdir):
        storage.upload_file(sample_file, "bucket", "file.txt")

        new_file = tmpdir.join("new.txt")
        new_file.write("updated content")
        storage.upload_file(str(new_file), "bucket", "file.txt")

        with open(storage._object_path("bucket", "file.txt")) as f:
            assert f.read() == "updated content"


class TestLocalStorageDownload:
    """Tests for file download operations."""

    @pytest.fixture
    def storage(self, tmpdir):
        return LocalStorage(base_dir=str(tmpdir.join("storage")))

    def test_download_file(self, storage, tmpdir):
        # upload first
        src = tmpdir.join("src.txt")
        src.write("download me")
        storage.upload_file(str(src), "bucket", "file.txt")

        # download
        dest = str(tmpdir.join("dest.txt"))
        result = storage.download_file("bucket", "file.txt", dest)
        assert os.path.exists(dest)
        with open(dest) as f:
            assert f.read() == "download me"

    def test_download_nonexistent_file(self, storage, tmpdir):
        dest = str(tmpdir.join("dest.txt"))
        with pytest.raises(FileNotFoundError):
            storage.download_file("bucket", "nonexistent.txt", dest)

    def test_download_creates_parent_dirs(self, storage, tmpdir):
        src = tmpdir.join("src.txt")
        src.write("nested download")
        storage.upload_file(str(src), "bucket", "file.txt")

        dest = str(tmpdir.join("deep", "nested", "dest.txt"))
        storage.download_file("bucket", "file.txt", dest)
        assert os.path.exists(dest)


class TestLocalStorageBuckets:
    """Tests for bucket operations."""

    @pytest.fixture
    def storage(self, tmpdir):
        return LocalStorage(base_dir=str(tmpdir.join("storage")))

    def test_list_buckets_empty(self, storage):
        assert storage.list_buckets() == []

    def test_list_buckets(self, storage, tmpdir):
        src = tmpdir.join("src.txt")
        src.write("data")
        storage.upload_file(str(src), "bucket-a", "file.txt")
        storage.upload_file(str(src), "bucket-b", "file.txt")

        buckets = storage.list_buckets()
        assert sorted(buckets) == ["bucket-a", "bucket-b"]


class TestLocalStorageObjects:
    """Tests for object operations."""

    @pytest.fixture
    def storage(self, tmpdir):
        return LocalStorage(base_dir=str(tmpdir.join("storage")))

    @pytest.fixture
    def populated_storage(self, storage, tmpdir):
        src = tmpdir.join("src.txt")
        src.write("data")
        storage.upload_file(str(src), "bucket", "file1.txt")
        storage.upload_file(str(src), "bucket", "dir/file2.txt")
        storage.upload_file(str(src), "bucket", "dir/sub/file3.txt")
        return storage

    def test_list_objects_recursive(self, populated_storage):
        objects = populated_storage.list_objects("bucket")
        assert sorted(objects) == ["dir/file2.txt", "dir/sub/file3.txt", "file1.txt"]

    def test_list_objects_with_prefix(self, populated_storage):
        objects = populated_storage.list_objects("bucket", prefix="dir")
        assert sorted(objects) == ["dir/file2.txt", "dir/sub/file3.txt"]

    def test_list_objects_nonexistent_bucket(self, storage):
        assert storage.list_objects("nonexistent") == []

    def test_list_objects_non_recursive(self, populated_storage):
        objects = populated_storage.list_objects("bucket", recursive=False)
        assert "file1.txt" in objects
        assert "dir/" in objects

    def test_delete_object(self, populated_storage):
        result = populated_storage.delete_object("bucket", "file1.txt")
        assert result is True
        assert not populated_storage.object_exists("bucket", "file1.txt")

    def test_delete_nonexistent_object(self, storage):
        result = storage.delete_object("bucket", "nonexistent.txt")
        assert result is True

    def test_object_exists(self, populated_storage):
        assert populated_storage.object_exists("bucket", "file1.txt") is True
        assert populated_storage.object_exists("bucket", "nonexistent.txt") is False

    def test_get_object_info(self, populated_storage):
        info = populated_storage.get_object_info("bucket", "file1.txt")
        assert info is not None
        assert info["size"] == 4  # "data"
        assert info["last_modified"] is not None

    def test_get_object_info_nonexistent(self, storage):
        info = storage.get_object_info("bucket", "nonexistent.txt")
        assert info is None


class TestLocalStorageIntegration:
    """Integration workflow tests."""

    def test_upload_download_roundtrip(self, tmpdir):
        storage = LocalStorage(base_dir=str(tmpdir.join("storage")))
        src = tmpdir.join("original.txt")
        src.write("roundtrip content")

        storage.upload_file(str(src), "my-bucket", "remote.txt")

        dest = str(tmpdir.join("downloaded.txt"))
        storage.download_file("my-bucket", "remote.txt", dest)

        with open(dest) as f:
            assert f.read() == "roundtrip content"

    def test_upload_list_delete_workflow(self, tmpdir):
        storage = LocalStorage(base_dir=str(tmpdir.join("storage")))
        src = tmpdir.join("file.txt")
        src.write("workflow test")

        storage.upload_file(str(src), "bucket", "file.txt")
        assert storage.object_exists("bucket", "file.txt")
        assert "file.txt" in storage.list_objects("bucket")

        storage.delete_object("bucket", "file.txt")
        assert not storage.object_exists("bucket", "file.txt")
        assert "file.txt" not in storage.list_objects("bucket")
