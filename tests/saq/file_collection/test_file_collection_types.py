import pytest

from saq.file_collection.types import (
    FileCollectionStatus,
    FileCollectionWorkItem,
    FileCollectorResult,
    FileCollectorStatus,
)


class TestFileCollectorStatus:
    @pytest.mark.unit
    def test_is_final_success(self):
        assert FileCollectorStatus.SUCCESS.is_final is True

    @pytest.mark.unit
    def test_is_final_file_not_found(self):
        assert FileCollectorStatus.FILE_NOT_FOUND.is_final is True

    @pytest.mark.unit
    def test_is_final_failed(self):
        assert FileCollectorStatus.FAILED.is_final is True

    @pytest.mark.unit
    def test_is_final_cancelled(self):
        assert FileCollectorStatus.CANCELLED.is_final is True

    @pytest.mark.unit
    def test_is_final_delayed(self):
        assert FileCollectorStatus.DELAYED.is_final is False

    @pytest.mark.unit
    def test_is_final_host_offline(self):
        assert FileCollectorStatus.HOST_OFFLINE.is_final is False

    @pytest.mark.unit
    def test_is_final_error(self):
        assert FileCollectorStatus.ERROR.is_final is False

    @pytest.mark.unit
    def test_is_retryable_delayed(self):
        assert FileCollectorStatus.DELAYED.is_retryable is True

    @pytest.mark.unit
    def test_is_retryable_host_offline(self):
        assert FileCollectorStatus.HOST_OFFLINE.is_retryable is True

    @pytest.mark.unit
    def test_is_retryable_error(self):
        assert FileCollectorStatus.ERROR.is_retryable is True

    @pytest.mark.unit
    def test_is_retryable_success(self):
        assert FileCollectorStatus.SUCCESS.is_retryable is False

    @pytest.mark.unit
    def test_is_retryable_failed(self):
        assert FileCollectorStatus.FAILED.is_retryable is False

    @pytest.mark.unit
    def test_collection_status_final_returns_completed(self):
        assert FileCollectorStatus.SUCCESS.collection_status == FileCollectionStatus.COMPLETED
        assert FileCollectorStatus.FAILED.collection_status == FileCollectionStatus.COMPLETED
        assert FileCollectorStatus.FILE_NOT_FOUND.collection_status == FileCollectionStatus.COMPLETED
        assert FileCollectorStatus.CANCELLED.collection_status == FileCollectionStatus.COMPLETED

    @pytest.mark.unit
    def test_collection_status_retryable_returns_in_progress(self):
        assert FileCollectorStatus.DELAYED.collection_status == FileCollectionStatus.IN_PROGRESS
        assert FileCollectorStatus.HOST_OFFLINE.collection_status == FileCollectionStatus.IN_PROGRESS
        assert FileCollectorStatus.ERROR.collection_status == FileCollectionStatus.IN_PROGRESS


class TestFileCollectorResult:
    @pytest.mark.unit
    def test_create_success_result(self):
        result = FileCollectorResult(
            status=FileCollectorStatus.SUCCESS,
            message="Successfully collected file",
            collected_file_path="/path/to/file",
            collected_file_sha256="abc123",
        )
        assert result.status == FileCollectorStatus.SUCCESS
        assert result.message == "Successfully collected file"
        assert result.collected_file_path == "/path/to/file"
        assert result.collected_file_sha256 == "abc123"

    @pytest.mark.unit
    def test_create_failure_result(self):
        result = FileCollectorResult(
            status=FileCollectorStatus.HOST_OFFLINE,
            message="Host not found",
        )
        assert result.status == FileCollectorStatus.HOST_OFFLINE
        assert result.message == "Host not found"
        assert result.collected_file_path is None
        assert result.collected_file_sha256 is None

    @pytest.mark.unit
    def test_create_minimal_result(self):
        result = FileCollectorResult(status=FileCollectorStatus.DELAYED)
        assert result.status == FileCollectorStatus.DELAYED
        assert result.message is None
        assert result.collected_file_path is None
        assert result.collected_file_sha256 is None


class TestFileCollectionWorkItem:
    @pytest.mark.unit
    def test_create_work_item(self):
        work_item = FileCollectionWorkItem(
            id=1,
            name="falcon_file_collection",
            type="file_location",
            key="host1@/path/to/file.exe",
            alert_uuid="test-uuid-123",
            storage_dir="/tmp/test",
            retry_count=2,
            max_retries=10,
        )
        assert work_item.id == 1
        assert work_item.name == "falcon_file_collection"
        assert work_item.type == "file_location"
        assert work_item.key == "host1@/path/to/file.exe"
        assert work_item.alert_uuid == "test-uuid-123"
        assert work_item.storage_dir == "/tmp/test"
        assert work_item.retry_count == 2
        assert work_item.max_retries == 10

    @pytest.mark.unit
    def test_create_work_item_defaults(self):
        work_item = FileCollectionWorkItem(
            id=1,
            name="test_collector",
            type="file_location",
            key="host@/file",
        )
        assert work_item.alert_uuid is None
        assert work_item.storage_dir is None
        assert work_item.retry_count == 0
        assert work_item.max_retries == 10
