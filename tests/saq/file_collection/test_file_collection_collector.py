from datetime import datetime, timedelta, UTC
from uuid import uuid4

import pytest
from sqlalchemy import func

from saq.constants import F_FILE_LOCATION
from saq.database.model import FileCollection
from saq.database.pool import get_db
from saq.file_collection.collector import FileCollectionCollector
from saq.file_collection.database import queue_file_collection
from saq.file_collection.interface import FileCollectionListener
from saq.file_collection.types import FileCollectionStatus, FileCollectionWorkItem, FileCollectorStatus


class TestFileCollectionListener(FileCollectionListener):
    def __init__(self):
        self.collections = []

    def handle_file_collection_request(self, work_item: FileCollectionWorkItem):
        self.collections.append(work_item)


@pytest.mark.integration
def test_collect_work_items_empty():
    collector = FileCollectionCollector()
    assert not collector.collect_work_items()


@pytest.mark.integration
def test_collect_single_work_item(db_alert):
    collector = FileCollectionCollector()
    assert not collector.collect_work_items()

    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=db_alert.uuid,
    )

    # before registering a listener, we should not collect any collections
    assert not collector.collect_work_items()

    # now we register a listener for a different name, so we should (still) not collect
    collector.register_file_collection_listener("other", TestFileCollectionListener())
    assert not collector.collect_work_items()

    # now we register a listener for the same name, so we should collect
    collector.register_file_collection_listener("custom", TestFileCollectionListener())
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == collection_id
    assert tasks[0].storage_dir == db_alert.storage_dir


@pytest.mark.parametrize(
    "status,expected_value",
    [
        (FileCollectionStatus.NEW, True),
        (FileCollectionStatus.IN_PROGRESS, True),
        (FileCollectionStatus.COMPLETED, False),
    ],
)
@pytest.mark.integration
def test_collect_work_item_status(status, expected_value, db_alert):
    collector = FileCollectionCollector()
    collector.register_file_collection_listener("custom", TestFileCollectionListener())

    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=db_alert.uuid,
    )

    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.status = status.value
    get_db().add(file_collection)
    get_db().commit()

    assert bool(collector.collect_work_items()) == expected_value


@pytest.mark.integration
def test_collect_locked_work_item(db_alert):
    collector = FileCollectionCollector()
    collector.register_file_collection_listener("custom", TestFileCollectionListener())

    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=db_alert.uuid,
    )

    # lock the collection
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.lock = str(uuid4())
    file_collection.lock_time = func.NOW()
    get_db().add(file_collection)
    get_db().commit()

    # we should not collect because it is locked
    assert not collector.collect_work_items()

    # set the lock time to zero seconds
    collector.lock_timeout_seconds = 0

    # now we should collect because lock has timed out
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == collection_id


@pytest.mark.integration
def test_collect_delayed_work_item(db_alert):
    collector = FileCollectionCollector()
    collector.register_file_collection_listener("custom", TestFileCollectionListener())

    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=db_alert.uuid,
    )

    # set to in progress and delayed
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.update_time = func.NOW()
    file_collection.status = FileCollectionStatus.IN_PROGRESS.value
    file_collection.result = FileCollectorStatus.DELAYED.value
    get_db().add(file_collection)
    get_db().commit()

    # we should not collect because it is currently delayed
    assert not collector.collect_work_items()

    # set the initial retry delay to zero seconds (exponential backoff)
    collector.initial_retry_delay_seconds = 0

    # now we should collect because delay time has expired
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == collection_id


@pytest.mark.integration
def test_collect_high_retry_count_still_collected(db_alert):
    """Test that high retry counts don't prevent collection - time-based cutoff is used instead."""
    collector = FileCollectionCollector()
    collector.register_file_collection_listener("custom", TestFileCollectionListener())

    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=db_alert.uuid,
        max_retries=5,  # This is no longer enforced
    )

    # set retry_count to a high value
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.retry_count = 100
    get_db().add(file_collection)
    get_db().commit()

    # Should still collect because we use time-based cutoff, not retry count
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == collection_id


@pytest.mark.unit
def test_register_file_collection_listener():
    collector = FileCollectionCollector()
    listener = TestFileCollectionListener()

    collector.register_file_collection_listener("test_name", listener)
    assert "test_name" in collector.listeners
    assert collector.listeners["test_name"] is listener


@pytest.mark.unit
def test_register_file_collection_listener_duplicate():
    collector = FileCollectionCollector()
    listener1 = TestFileCollectionListener()
    listener2 = TestFileCollectionListener()

    collector.register_file_collection_listener("test_name", listener1)

    with pytest.raises(ValueError, match="file collection listener test_name already registered"):
        collector.register_file_collection_listener("test_name", listener2)


@pytest.mark.unit
def test_notify_file_collection_listeners():
    collector = FileCollectionCollector()
    listener = TestFileCollectionListener()

    collector.register_file_collection_listener("test_name", listener)

    work_item = FileCollectionWorkItem(
        id=1,
        name="test_name",
        type=F_FILE_LOCATION,
        key="host@/path/to/file",
        alert_uuid="test-alert-uuid",
        storage_dir="/opt/ace/data/test-alert",
    )

    collector.notify_file_collection_listeners(work_item)

    assert len(listener.collections) == 1
    assert listener.collections[0] is work_item


@pytest.mark.unit
def test_notify_file_collection_listeners_unregistered():
    collector = FileCollectionCollector()

    work_item = FileCollectionWorkItem(
        id=1,
        name="unregistered_name",
        type=F_FILE_LOCATION,
        key="host@/path/to/file",
        alert_uuid="test-alert-uuid",
        storage_dir="/opt/ace/data/test-alert",
    )

    with pytest.raises(ValueError, match="file collector name unregistered_name not registered"):
        collector.notify_file_collection_listeners(work_item)


@pytest.mark.unit
def test_collection_loop_signals_startup():
    collector = FileCollectionCollector()

    assert not collector.collector_startup_event.is_set()

    collector.collect_work_items = lambda: []
    collector.shutdown_event.set()

    collector.collection_loop()

    assert collector.collector_startup_event.is_set()


@pytest.mark.unit
def test_collection_loop_processes_work_items():
    collector = FileCollectionCollector()
    listener = TestFileCollectionListener()
    collector.register_file_collection_listener("test_name", listener)

    work_items = [
        FileCollectionWorkItem(
            id=1,
            name="test_name",
            type=F_FILE_LOCATION,
            key="host@/file1",
            alert_uuid="test-alert-uuid-1",
            storage_dir="/opt/ace/data/test-alert-1",
        ),
        FileCollectionWorkItem(
            id=2,
            name="test_name",
            type=F_FILE_LOCATION,
            key="host@/file2",
            alert_uuid="test-alert-uuid-2",
            storage_dir="/opt/ace/data/test-alert-2",
        ),
    ]

    call_count = [0]

    def mock_collect_work_items():
        call_count[0] += 1
        if call_count[0] == 1:
            return work_items
        return []

    collector.collect_work_items = mock_collect_work_items
    collector.shutdown_event.set()

    collector.collection_loop()

    assert len(listener.collections) == 2
    assert listener.collections[0] is work_items[0]
    assert listener.collections[1] is work_items[1]


@pytest.mark.unit
def test_collection_loop_handles_exceptions():
    collector = FileCollectionCollector()

    call_count = [0]

    def mock_collect_work_items():
        call_count[0] += 1
        if call_count[0] == 1:
            raise RuntimeError("test error")
        return []

    collector.collect_work_items = mock_collect_work_items
    collector.shutdown_event.set()

    # should not raise exception
    collector.collection_loop()

    assert call_count[0] >= 1


#
# Tests for exponential backoff functionality
#
# Note: Tests for calculate_backoff_delay() are in tests/saq/util/test_time.py


@pytest.mark.unit
def test_collector_init_with_exponential_backoff_params():
    """test FileCollectionCollector accepts exponential backoff parameters"""
    collector = FileCollectionCollector(
        lock_timeout_seconds=600,
        initial_retry_delay_seconds=30,
        max_retry_delay_seconds=1800,
        max_collection_time_seconds=86400,
    )

    assert collector.lock_timeout_seconds == 600
    assert collector.initial_retry_delay_seconds == 30
    assert collector.max_retry_delay_seconds == 1800
    assert collector.max_collection_time_seconds == 86400


@pytest.mark.unit
def test_collector_default_exponential_backoff_params():
    """test FileCollectionCollector default exponential backoff parameters"""
    collector = FileCollectionCollector()

    assert collector.initial_retry_delay_seconds == 60
    assert collector.max_retry_delay_seconds == 3600
    assert collector.max_collection_time_seconds == 604800  # 7 days


@pytest.mark.integration
def test_collect_exponential_backoff_respects_retry_count(db_alert):
    """test collect_work_items respects exponential backoff based on retry_count"""
    collector = FileCollectionCollector(
        initial_retry_delay_seconds=60,
        max_retry_delay_seconds=3600,
    )
    collector.register_file_collection_listener("custom", TestFileCollectionListener())

    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=db_alert.uuid,
    )

    # Set to in progress with retry_count=2, should need 240 seconds delay (60 * 2^2)
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.update_time = datetime.now(UTC)
    file_collection.status = FileCollectionStatus.IN_PROGRESS.value
    file_collection.result = FileCollectorStatus.DELAYED.value
    file_collection.retry_count = 2
    get_db().add(file_collection)
    get_db().commit()

    # Should not collect because 240 seconds haven't passed
    assert not collector.collect_work_items()

    # Update the time to simulate 250 seconds in the past
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.update_time = datetime.now(UTC) - timedelta(seconds=250)
    get_db().add(file_collection)
    get_db().commit()

    # Now should collect because 240 second delay has passed
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == collection_id


@pytest.mark.integration
def test_collect_time_based_cutoff(db_alert):
    """test collect_work_items respects max_collection_time_seconds"""
    collector = FileCollectionCollector(
        max_collection_time_seconds=3600,  # 1 hour for testing
    )
    collector.register_file_collection_listener("custom", TestFileCollectionListener())

    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=db_alert.uuid,
    )

    # Set insert_date to 2 hours ago (past the max_collection_time)
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.insert_date = datetime.now(UTC) - timedelta(hours=2)
    get_db().add(file_collection)
    get_db().commit()

    # Should not collect because max collection time has passed
    assert not collector.collect_work_items()

    # Create a new collection that's within the time window
    collection_id2 = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file2",
        alert_uuid=db_alert.uuid,
    )

    # New one should be collected
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == collection_id2
