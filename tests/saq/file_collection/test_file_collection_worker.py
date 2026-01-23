from unittest.mock import Mock, patch

import pytest

from saq.constants import F_FILE_LOCATION
from saq.database.model import FileCollection, FileCollectionHistory
from saq.database.pool import get_db
from saq.file_collection.database import queue_file_collection
from saq.file_collection.file_collector import FileCollector
from saq.file_collection.types import (
    FileCollectionStatus,
    FileCollectionWorkItem,
    FileCollectorResult,
    FileCollectorStatus,
)
from saq.file_collection.worker import FileCollectionWorker


class MockFileCollectorConfig:
    def __init__(self, name="mock_collector", observable_type=F_FILE_LOCATION, thread_count=1):
        self.name = name
        self.observable_type = observable_type
        self.thread_count = thread_count
        self.display_name = "Mock Collector"
        self.description = "A mock file collector for testing"


class MockFileCollector(FileCollector):
    def __init__(self, config=None, result_to_return=None):
        if config is None:
            config = MockFileCollectorConfig()
        super().__init__(config)
        self.result_to_return = result_to_return or FileCollectorResult(
            status=FileCollectorStatus.SUCCESS,
            message="Mock success",
            collected_file_path="/mock/path",
            collected_file_sha256="mockhash",
        )
        self.collect_calls = []

    def collect(self, target: FileCollectionWorkItem) -> FileCollectorResult:
        self.collect_calls.append(target)
        return self.result_to_return


@pytest.mark.unit
def test_worker_handle_request_validates_name():
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    work_item = FileCollectionWorkItem(
        id=1,
        name="wrong_name",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid",
        storage_dir="/opt/ace/data/test-alert",
    )

    with pytest.raises(ValueError, match="does not match"):
        worker.handle_file_collection_request(work_item)


@pytest.mark.unit
def test_worker_handle_request_queues_work():
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    work_item = FileCollectionWorkItem(
        id=1,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid",
        storage_dir="/opt/ace/data/test-alert",
    )

    worker.handle_file_collection_request(work_item)

    assert worker.work_queue.qsize() == 1
    queued_item = worker.work_queue.get_nowait()
    assert queued_item is work_item


@pytest.mark.integration
def test_worker_collect_success():
    collector = MockFileCollector(
        result_to_return=FileCollectorResult(
            status=FileCollectorStatus.SUCCESS,
            message="Successfully collected",
            collected_file_path="/path/to/file",
            collected_file_sha256="abc123",
        )
    )
    worker = FileCollectionWorker(collector)

    collection_id = queue_file_collection(
        collector_name="mock_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/file",
        alert_uuid="test-alert-uuid-success",
    )

    work_item = FileCollectionWorkItem(
        id=collection_id,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-success",
        storage_dir="/opt/ace/data/test-alert",
        retry_count=0,
        max_retries=10,
    )

    result = worker.collect(work_item)

    assert result.status == FileCollectorStatus.SUCCESS
    assert len(collector.collect_calls) == 1

    # verify database was updated
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.status == FileCollectionStatus.COMPLETED.value
    assert file_collection.result == FileCollectorStatus.SUCCESS.value
    assert file_collection.collected_file_path == "/path/to/file"
    assert file_collection.collected_file_sha256 == "abc123"
    assert file_collection.retry_count == 1

    # verify history was created
    history = (
        get_db()
        .query(FileCollectionHistory)
        .filter(FileCollectionHistory.file_collection_id == collection_id)
        .first()
    )
    assert history is not None
    assert history.result == FileCollectorStatus.SUCCESS.value


@pytest.mark.integration
def test_worker_collect_host_offline_retryable():
    collector = MockFileCollector(
        result_to_return=FileCollectorResult(
            status=FileCollectorStatus.HOST_OFFLINE,
            message="Host not found",
        )
    )
    worker = FileCollectionWorker(collector)

    collection_id = queue_file_collection(
        collector_name="mock_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/file",
        alert_uuid="test-alert-uuid-offline",
        max_retries=10,
    )

    work_item = FileCollectionWorkItem(
        id=collection_id,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-offline",
        storage_dir="/opt/ace/data/test-alert",
        retry_count=0,
        max_retries=10,
    )

    result = worker.collect(work_item)

    assert result.status == FileCollectorStatus.HOST_OFFLINE

    # verify database - should still be IN_PROGRESS since it's retryable
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.status == FileCollectionStatus.IN_PROGRESS.value
    assert file_collection.result == FileCollectorStatus.HOST_OFFLINE.value
    assert file_collection.retry_count == 1


@pytest.mark.integration
def test_worker_collect_exceeds_max_retries():
    collector = MockFileCollector(
        result_to_return=FileCollectorResult(
            status=FileCollectorStatus.HOST_OFFLINE,
            message="Host not found",
        )
    )
    worker = FileCollectionWorker(collector)

    collection_id = queue_file_collection(
        collector_name="mock_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/file",
        alert_uuid="test-alert-uuid-max-retries",
        max_retries=5,
    )

    work_item = FileCollectionWorkItem(
        id=collection_id,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-max-retries",
        storage_dir="/opt/ace/data/test-alert",
        retry_count=4,  # next attempt will be 5th, which equals max
        max_retries=5,
    )

    result = worker.collect(work_item)

    # verify database - should be COMPLETED since max retries reached
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.status == FileCollectionStatus.COMPLETED.value
    assert file_collection.retry_count == 5


@pytest.mark.integration
def test_worker_collect_handles_exception():
    collector = MockFileCollector()
    collector.collect = Mock(side_effect=RuntimeError("Test error"))
    worker = FileCollectionWorker(collector)

    collection_id = queue_file_collection(
        collector_name="mock_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/file",
        alert_uuid="test-alert-uuid-exception",
    )

    work_item = FileCollectionWorkItem(
        id=collection_id,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-exception",
        storage_dir="/opt/ace/data/test-alert",
        retry_count=0,
        max_retries=10,
    )

    result = worker.collect(work_item)

    assert result.status == FileCollectorStatus.ERROR
    assert "RuntimeError" in result.message

    # verify database
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.result == FileCollectorStatus.ERROR.value


@pytest.mark.unit
def test_worker_loop_startup_event():
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    assert not any(e.is_set() for e in worker.startup_events)

    # run single iteration and exit
    worker.shutdown_event.set()
    startup_event = Mock()
    worker.worker_loop(startup_event)

    startup_event.set.assert_called_once()


@pytest.mark.unit
def test_worker_loop_processes_queue():
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    work_item = FileCollectionWorkItem(
        id=999,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid",
        storage_dir="/opt/ace/data/test-alert",
    )

    worker.work_queue.put(work_item)
    worker.shutdown_event.set()

    # mock collect to avoid database operations
    worker.collect = Mock(return_value=FileCollectorResult(status=FileCollectorStatus.SUCCESS))

    startup_event = Mock()
    worker.worker_loop(startup_event)

    worker.collect.assert_called_once_with(work_item)
