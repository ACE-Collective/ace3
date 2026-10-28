import logging
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
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

    worker.handle_request(work_item)

    assert worker.work_queue.qsize() == 1
    assert worker.pending_collection_ids() == {1}
    queued_item = worker.work_queue.get_nowait()
    assert queued_item is work_item



class _SignalingSet(set):
    """The pending ids, with an event set on each discard."""

    def __init__(self):
        super().__init__()
        self.discarded = Event()

    def discard(self, item):
        super().discard(item)
        self.discarded.set()


@pytest.mark.unit
def test_worker_handle_request_releases_id_collected_before_put_returns():
    worker = FileCollectionWorker(MockFileCollector())
    worker.queue_wait_timeout = 0.1
    worker._pending_ids = _SignalingSet()
    collected = Event()
    worker.collect = Mock(side_effect=lambda work_item: collected.set())

    # a worker thread takes the item, collects it and finishes with it before put() returns
    put = worker.work_queue.put
    def _put_then_collect(work_item):
        put(work_item)
        assert collected.wait(5)
        # bounded: the worker thread cannot discard the id while handle_request holds the lock
        worker._pending_ids.discarded.wait(1)

    worker.work_queue.put = _put_then_collect
    thread = Thread(target=worker.worker_loop, args=(Event(),))
    with patch("saq.queue_service.remove_all_sessions"):
        thread.start()
        try:
            worker.handle_request(FileCollectionWorkItem(
                id=7,
                name="mock_collector",
                type=F_FILE_LOCATION,
                key="host@/file",
                alert_uuid="test-alert-uuid",
                storage_dir="/opt/ace/data/test-alert",
            ))
        finally:
            worker.stop()
            thread.join(5)

    assert not thread.is_alive()
    # an id left behind would keep the collection from ever being handed out again
    assert worker.pending_collection_ids() == set()


@pytest.mark.unit
def test_worker_handle_request_rejects_item_for_another_collector():
    worker = FileCollectionWorker(MockFileCollector())

    with pytest.raises(ValueError, match="work item name other does not match worker name mock_collector"):
        worker.handle_request(FileCollectionWorkItem(
            id=1,
            name="other",
            type=F_FILE_LOCATION,
            key="host@/file",
            alert_uuid="test-alert-uuid",
            storage_dir="/opt/ace/data/test-alert",
        ))

    assert worker.pending_collection_ids() == set()
    assert worker.work_queue.empty()

@pytest.mark.integration
def test_worker_loop_releases_pending_id():
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    collection_id = queue_file_collection(
        collector_name="mock_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/file",
        alert_uuid="test-alert-uuid-pending",
    )

    work_item = FileCollectionWorkItem(
        id=collection_id,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-pending",
        storage_dir="/opt/ace/data/test-alert",
    )

    worker.handle_request(work_item)
    assert worker.pending_collection_ids() == {collection_id}

    worker.shutdown_event.set()
    worker.worker_loop(Mock())

    assert len(collector.collect_calls) == 1
    assert worker.pending_collection_ids() == set()


@pytest.mark.integration
def test_worker_collect_skips_completed_record():
    """A queued work item whose record completed in the meantime is not collected again."""
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    collection_id = queue_file_collection(
        collector_name="mock_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/file",
        alert_uuid="test-alert-uuid-completed",
    )

    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.status = FileCollectionStatus.COMPLETED.value
    file_collection.result = FileCollectorStatus.SUCCESS.value
    file_collection.collected_file_path = "/already/collected"
    get_db().add(file_collection)
    get_db().commit()

    work_item = FileCollectionWorkItem(
        id=collection_id,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-completed",
        storage_dir="/opt/ace/data/test-alert",
    )

    assert worker.collect(work_item) is None
    assert collector.collect_calls == []

    # the record is untouched
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.status == FileCollectionStatus.COMPLETED.value
    assert file_collection.collected_file_path == "/already/collected"
    assert file_collection.retry_count == 0
    assert not get_db().query(FileCollectionHistory).filter(
        FileCollectionHistory.file_collection_id == collection_id
    ).count()


@pytest.mark.integration
def test_worker_collect_skips_record_locked_by_someone_else():
    """A work item is not collected if the record has since been locked under a different uuid."""
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    collection_id = queue_file_collection(
        collector_name="mock_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/file",
        alert_uuid="test-alert-uuid-relocked",
    )

    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.lock = "someone-else"
    file_collection.lock_time = datetime.now(UTC)
    file_collection.status = FileCollectionStatus.IN_PROGRESS.value
    get_db().add(file_collection)
    get_db().commit()

    work_item = FileCollectionWorkItem(
        id=collection_id,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-relocked",
        storage_dir="/opt/ace/data/test-alert",
        lock="our-lock",
    )

    assert worker.collect(work_item) is None
    assert collector.collect_calls == []

    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.lock == "someone-else"
    assert file_collection.status == FileCollectionStatus.IN_PROGRESS.value


@pytest.mark.integration
def test_worker_collect_skips_missing_record():
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    work_item = FileCollectionWorkItem(
        id=999999,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-missing",
        storage_dir="/opt/ace/data/test-alert",
    )

    assert worker.collect(work_item) is None
    assert collector.collect_calls == []


@pytest.mark.integration
def test_worker_collect_refreshes_lock_time():
    """When the work item still owns the lock, the lock time is moved to when work starts."""
    collector = MockFileCollector()
    worker = FileCollectionWorker(collector)

    collection_id = queue_file_collection(
        collector_name="mock_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/file",
        alert_uuid="test-alert-uuid-lock-refresh",
    )

    stale_lock_time = datetime.now(UTC) - timedelta(hours=1)
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.lock = "our-lock"
    file_collection.lock_time = stale_lock_time
    file_collection.status = FileCollectionStatus.IN_PROGRESS.value
    get_db().add(file_collection)
    get_db().commit()

    # make the collector observe the lock time as it is while the collection is running
    observed = {}

    def observe(target):
        row = get_db().query(FileCollection).filter(FileCollection.id == target.id).first()
        observed["lock_time"] = row.lock_time
        return FileCollectorResult(status=FileCollectorStatus.SUCCESS, collected_file_path="/path")

    collector.collect = observe

    work_item = FileCollectionWorkItem(
        id=collection_id,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid-lock-refresh",
        storage_dir="/opt/ace/data/test-alert",
        lock="our-lock",
    )

    result = worker.collect(work_item)
    assert result.status == FileCollectorStatus.SUCCESS

    lock_time = observed["lock_time"]
    if lock_time.tzinfo is None:
        lock_time = lock_time.replace(tzinfo=UTC)
    assert lock_time > stale_lock_time + timedelta(minutes=30)

    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.status == FileCollectionStatus.COMPLETED.value
    assert file_collection.lock is None


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
def test_worker_loop_logs_failed_collection_and_releases_pending_id(caplog):
    worker = FileCollectionWorker(MockFileCollector())
    worker.collect = Mock(side_effect=RuntimeError("database gone"))
    worker.handle_request(FileCollectionWorkItem(
        id=7,
        name="mock_collector",
        type=F_FILE_LOCATION,
        key="host@/file",
        alert_uuid="test-alert-uuid",
        storage_dir="/opt/ace/data/test-alert",
    ))

    worker.stop()
    with patch("saq.queue_service.remove_all_sessions"):
        worker.worker_loop(Mock())

    errors = [r for r in caplog.records if r.levelno == logging.ERROR and r.exc_info]
    assert len(errors) == 1
    assert "file collection 7 (mock_collector file_location host@/file)" in errors[0].getMessage()
    assert errors[0].alert_uuid == "test-alert-uuid"
    # a collection that failed is handed out again once it is due
    assert worker.pending_collection_ids() == set()
