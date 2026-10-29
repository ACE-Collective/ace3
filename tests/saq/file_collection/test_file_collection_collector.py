from datetime import datetime, timedelta, UTC
import logging
from uuid import uuid4

import pytest
from sqlalchemy import func, text

from saq.constants import F_FILE_LOCATION
from saq.database.model import FileCollection
from saq.database.pool import get_db
from saq.file_collection.collector import FileCollectionCollector
from saq.file_collection.database import queue_file_collection
from saq.file_collection.interface import FileCollectionListener
from saq.file_collection.storage import unattached_storage_dir
from saq.file_collection.types import FileCollectionStatus, FileCollectionWorkItem, FileCollectorStatus


class TestFileCollectionListener(FileCollectionListener):
    __test__ = False

    def __init__(self):
        self.collections = []
        # ids reported as still held; tests call finish() to release them
        self.pending = set()

    def handle_request(self, work_item: FileCollectionWorkItem):
        self.collections.append(work_item)
        self.pending.add(work_item.id)

    def pending_collection_ids(self) -> set[int]:
        return set(self.pending)

    def finish(self, collection_id: int):
        self.pending.discard(collection_id)


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
    collector.register_listener("other", TestFileCollectionListener())
    assert not collector.collect_work_items()

    # now we register a listener for the same name, so we should collect
    collector.register_listener("custom", TestFileCollectionListener())
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == collection_id
    assert tasks[0].storage_dir == db_alert.storage_dir

    # the work item carries the lock that was placed on the record
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert tasks[0].lock is not None
    assert tasks[0].lock == file_collection.lock

    # the lock timestamp must never be ahead of the database clock, or the lock timeout check in
    # collect_work_items() (which compares against NOW()) refuses to reclaim the record
    assert get_db().execute(
        text("SELECT lock_time <= NOW() FROM file_collection WHERE id = :id"),
        {"id": collection_id},
    ).scalar() == 1


@pytest.mark.integration
def test_collect_work_item_without_alert():
    """A collection no alert asked for gets this node's directory for it, not an alert's."""
    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
    )

    collector = FileCollectionCollector()
    collector.register_listener("custom", TestFileCollectionListener())
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].alert_uuid is None
    assert tasks[0].storage_dir == unattached_storage_dir(collection_id)


@pytest.mark.integration
def test_collect_work_item_with_missing_alert(caplog):
    """A collection whose alert is gone is finished as failed instead of handed out, so it is
    neither left locked nor locked again at every lock timeout."""
    alert_uuid = str(uuid4())
    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=alert_uuid,
    )

    collector = FileCollectionCollector()
    listener = TestFileCollectionListener()
    collector.register_listener("custom", listener)
    collector.shutdown_event.set()
    with caplog.at_level(logging.WARNING):
        collector.collection_loop()
        # with no lock timeout, a row left unfinished would be locked again on the next pass
        collector.lock_timeout_seconds = 0
        collector.collection_loop()

    assert not listener.collections
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).one()
    assert file_collection.status == FileCollectionStatus.COMPLETED.value
    assert file_collection.result == FileCollectorStatus.FAILED.value
    assert alert_uuid in file_collection.result_message
    assert file_collection.lock is None
    assert file_collection.update_time is not None

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].file_collection_id == collection_id
    assert warnings[0].alert_uuid == alert_uuid
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.integration
def test_collect_finishes_only_the_collection_whose_alert_is_gone(db_alert):
    """The collections locked in the same pass are still handed out, including one no alert
    asked for, whose alert_uuid is NULL by design."""
    missing_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/missing",
        alert_uuid=str(uuid4()),
    )
    with_alert_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/with_alert",
        alert_uuid=db_alert.uuid,
    )
    without_alert_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/without_alert",
    )

    collector = FileCollectionCollector()
    collector.register_listener("custom", TestFileCollectionListener())
    tasks = {task.id: task for task in collector.collect_work_items()}
    assert sorted(tasks) == sorted([with_alert_id, without_alert_id])
    assert tasks[with_alert_id].storage_dir == db_alert.storage_dir
    assert tasks[without_alert_id].storage_dir == unattached_storage_dir(without_alert_id)

    # discards anything the collector did not commit
    get_db().rollback()
    rows = {
        row.id: row
        for row in get_db().query(FileCollection).filter(
            FileCollection.id.in_([missing_id, with_alert_id, without_alert_id])
        )
    }

    for collection_id in (with_alert_id, without_alert_id):
        assert rows[collection_id].status == FileCollectionStatus.IN_PROGRESS.value
        assert rows[collection_id].result is None
        assert rows[collection_id].lock == tasks[collection_id].lock

    assert rows[missing_id].status == FileCollectionStatus.COMPLETED.value
    assert rows[missing_id].result == FileCollectorStatus.FAILED.value


@pytest.mark.integration
def test_collect_skips_items_held_by_listener(db_alert):
    """A record whose lock has timed out is not handed out again while a listener still holds it."""
    collector = FileCollectionCollector()
    listener = TestFileCollectionListener()
    collector.register_listener("custom", listener)

    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid=db_alert.uuid,
    )

    collector.shutdown_event.set()
    collector.collection_loop()
    assert [w.id for w in listener.collections] == [collection_id]

    # the lock has (effectively) timed out but the listener still holds the item
    collector.lock_timeout_seconds = 0
    assert not collector.collect_work_items()

    # once the listener is done with it the record is eligible again
    listener.finish(collection_id)
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == collection_id


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
    collector.register_listener("custom", TestFileCollectionListener())

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
    collector.register_listener("custom", TestFileCollectionListener())

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
    collector.register_listener("custom", TestFileCollectionListener())

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
    collector.register_listener("custom", TestFileCollectionListener())

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
    collector.register_listener("custom", TestFileCollectionListener())

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
    collector.register_listener("custom", TestFileCollectionListener())

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
