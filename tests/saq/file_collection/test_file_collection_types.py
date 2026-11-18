import pytest

from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus


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

