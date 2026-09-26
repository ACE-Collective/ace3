from datetime import datetime, timedelta

import pytest

from saq.constants import F_FILE_LOCATION
from saq.database.model import FileCollection, FileCollectionHistory
from saq.database.pool import get_db
from saq.file_collection.database import (
    cancel_file_collection,
    delete_file_collection,
    get_file_collection,
    get_file_collection_by_observable,
    get_file_collection_history,
    get_pending_file_collection_by_observable,
    queue_file_collection,
    resolve_duplicate_pending_file_collection,
    retry_file_collection,
)
from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus


@pytest.mark.integration
def test_queue_file_collection():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid",
        max_retries=5,
    )

    assert collection_id is not None
    assert collection_id > 0

    # verify record was created
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection is not None
    assert file_collection.name == "test_collector"
    assert file_collection.type == F_FILE_LOCATION
    assert file_collection.key == "host@/path/to/file"
    assert file_collection.alert_uuid == "test-alert-uuid"
    assert file_collection.max_retries == 5
    assert file_collection.status == FileCollectionStatus.NEW.value
    assert file_collection.retry_count == 0


@pytest.mark.unit
def test_queue_file_collection_requires_alert_uuid():
    """Verify that alert_uuid is required."""
    with pytest.raises(ValueError, match="alert_uuid is required"):
        queue_file_collection(
            collector_name="test_collector",
            observable_type=F_FILE_LOCATION,
            observable_value="host@/path/to/file",
            alert_uuid="",
        )

    with pytest.raises(ValueError, match="alert_uuid is required"):
        queue_file_collection(
            collector_name="test_collector",
            observable_type=F_FILE_LOCATION,
            observable_value="host@/path/to/file",
            alert_uuid=None,
        )


@pytest.mark.integration
def test_get_file_collection():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid-2",
    )

    result = get_file_collection(collection_id)

    assert result is not None
    assert result.id == collection_id
    assert result.name == "test_collector"


@pytest.mark.integration
def test_get_file_collection_not_found():
    result = get_file_collection(999999)
    assert result is None


@pytest.mark.integration
def test_get_file_collection_by_observable():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid",
    )

    result = get_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid",
    )

    assert result is not None
    assert result.id == collection_id


@pytest.mark.integration
def test_get_file_collection_by_observable_different_alert():
    """Verify that file collections are correctly filtered by alert_uuid."""
    collection_id1 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/unique/path",
        alert_uuid="alert-uuid-1",
    )

    collection_id2 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/unique/path",
        alert_uuid="alert-uuid-2",
    )

    # Should find the collection for alert-uuid-1
    result = get_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/unique/path",
        alert_uuid="alert-uuid-1",
    )

    assert result is not None
    assert result.id == collection_id1

    # Should find the collection for alert-uuid-2
    result = get_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/unique/path",
        alert_uuid="alert-uuid-2",
    )

    assert result is not None
    assert result.id == collection_id2


@pytest.mark.integration
def test_get_file_collection_by_observable_returns_most_recent():
    # Queue two collections for the same observable
    collection_id1 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/same/path",
        alert_uuid="alert1",
    )

    collection_id2 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/same/path",
        alert_uuid="alert1",
    )

    result = get_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/same/path",
        alert_uuid="alert1",
    )

    # Should return the most recent (highest id)
    assert result.id == collection_id2


@pytest.mark.integration
def test_get_pending_file_collection_by_observable():
    """Verify get_pending_file_collection_by_observable returns pending (non-completed) requests."""
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/pending",
        alert_uuid="test-alert-pending",
    )

    # Should find the NEW collection
    result = get_pending_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/pending",
        alert_uuid="test-alert-pending",
    )

    assert result is not None
    assert result.id == collection_id


@pytest.mark.integration
def test_get_pending_file_collection_by_observable_excludes_completed():
    """Verify get_pending_file_collection_by_observable excludes completed requests."""
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/completed",
        alert_uuid="test-alert-completed",
    )

    # Mark as completed
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.status = FileCollectionStatus.COMPLETED.value
    file_collection.result = FileCollectorStatus.SUCCESS.value
    get_db().add(file_collection)
    get_db().commit()

    # Should NOT find the completed collection
    result = get_pending_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/completed",
        alert_uuid="test-alert-completed",
    )

    assert result is None


@pytest.mark.integration
def test_get_pending_file_collection_by_observable_finds_in_progress():
    """Verify get_pending_file_collection_by_observable finds IN_PROGRESS requests."""
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/inprogress",
        alert_uuid="test-alert-inprogress",
    )

    # Mark as in progress
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.status = FileCollectionStatus.IN_PROGRESS.value
    get_db().add(file_collection)
    get_db().commit()

    # Should find the IN_PROGRESS collection
    result = get_pending_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/inprogress",
        alert_uuid="test-alert-inprogress",
    )

    assert result is not None
    assert result.id == collection_id


@pytest.mark.integration
def test_get_pending_file_collection_by_observable_cross_alert():
    """Verify omitting alert_uuid finds pending requests queued by other alerts."""
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert",
        alert_uuid="alert-uuid-cross-1",
    )

    result = get_pending_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert",
    )

    assert result is not None
    assert result.id == collection_id


@pytest.mark.integration
def test_get_pending_file_collection_by_observable_cross_alert_returns_oldest():
    """Verify the cross-alert lookup returns the oldest pending request so all callers converge."""
    collection_id1 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert_oldest",
        alert_uuid="alert-uuid-oldest-1",
    )

    queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert_oldest",
        alert_uuid="alert-uuid-oldest-2",
    )

    result = get_pending_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert_oldest",
    )

    assert result is not None
    assert result.id == collection_id1


@pytest.mark.integration
def test_get_pending_file_collection_by_observable_cross_alert_excludes_completed():
    """Verify the cross-alert lookup does not return completed requests."""
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert_completed",
        alert_uuid="alert-uuid-cross-completed",
    )

    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.status = FileCollectionStatus.COMPLETED.value
    file_collection.result = FileCollectorStatus.SUCCESS.value
    get_db().add(file_collection)
    get_db().commit()

    result = get_pending_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert_completed",
    )

    assert result is None


@pytest.mark.integration
def test_resolve_duplicate_pending_file_collection_no_duplicate():
    """Verify the request is kept when no older pending request exists."""
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_no_dup",
        alert_uuid="alert-uuid-resolve-1",
    )

    assert resolve_duplicate_pending_file_collection(collection_id) == collection_id
    assert get_file_collection(collection_id) is not None


@pytest.mark.integration
def test_resolve_duplicate_pending_file_collection_attaches_to_older():
    """Verify the newer duplicate request is deleted in favor of the older one."""
    collection_id1 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_dup",
        alert_uuid="alert-uuid-resolve-2",
    )

    collection_id2 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_dup",
        alert_uuid="alert-uuid-resolve-3",
    )

    assert resolve_duplicate_pending_file_collection(collection_id2) == collection_id1
    assert get_file_collection(collection_id2) is None
    assert get_file_collection(collection_id1) is not None


@pytest.mark.integration
def test_resolve_duplicate_pending_file_collection_keeps_locked_row():
    """Verify a duplicate already picked up by the collector loop is kept."""
    collection_id1 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_locked",
        alert_uuid="alert-uuid-resolve-4",
    )

    collection_id2 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_locked",
        alert_uuid="alert-uuid-resolve-5",
    )

    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id2).first()
    file_collection.status = FileCollectionStatus.IN_PROGRESS.value
    file_collection.lock = "test-lock-uuid"
    get_db().add(file_collection)
    get_db().commit()

    assert resolve_duplicate_pending_file_collection(collection_id2) == collection_id2
    assert get_file_collection(collection_id2) is not None
    assert get_file_collection(collection_id1) is not None


@pytest.mark.integration
def test_resolve_duplicate_pending_file_collection_ignores_completed_older():
    """Verify an older completed request does not count as a duplicate."""
    collection_id1 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_completed",
        alert_uuid="alert-uuid-resolve-6",
    )

    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id1).first()
    file_collection.status = FileCollectionStatus.COMPLETED.value
    file_collection.result = FileCollectorStatus.FILE_NOT_FOUND.value
    get_db().add(file_collection)
    get_db().commit()

    collection_id2 = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_completed",
        alert_uuid="alert-uuid-resolve-7",
    )

    assert resolve_duplicate_pending_file_collection(collection_id2) == collection_id2
    assert get_file_collection(collection_id2) is not None


@pytest.mark.integration
def test_cancel_file_collection():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid-cancel",
    )

    result = cancel_file_collection(collection_id)

    assert result is True

    # verify status was updated
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.status == FileCollectionStatus.COMPLETED.value
    assert file_collection.result == FileCollectorStatus.CANCELLED.value


@pytest.mark.integration
def test_cancel_file_collection_already_completed():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid-cancel-completed",
    )

    # set to completed
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.status = FileCollectionStatus.COMPLETED.value
    get_db().add(file_collection)
    get_db().commit()

    result = cancel_file_collection(collection_id)

    # cannot cancel completed collection
    assert result is False


@pytest.mark.integration
def test_cancel_file_collection_not_found():
    result = cancel_file_collection(999999)
    assert result is False


@pytest.mark.integration
def test_retry_file_collection():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid-retry",
    )

    # set to completed with failure
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    file_collection.status = FileCollectionStatus.COMPLETED.value
    file_collection.result = FileCollectorStatus.FAILED.value
    file_collection.retry_count = 5
    get_db().add(file_collection)
    get_db().commit()

    result = retry_file_collection(collection_id)

    assert result is True

    # verify status was reset
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection.status == FileCollectionStatus.NEW.value
    assert file_collection.result is None
    assert file_collection.retry_count == 0
    assert file_collection.lock is None


@pytest.mark.integration
def test_retry_file_collection_not_found():
    result = retry_file_collection(999999)
    assert result is False


@pytest.mark.integration
def test_delete_file_collection():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid-delete",
    )

    # add some history
    history = FileCollectionHistory(
        file_collection_id=collection_id,
        result=FileCollectorStatus.DELAYED.value,
        message="Test message",
        status=FileCollectionStatus.IN_PROGRESS.value,
    )
    get_db().add(history)
    get_db().commit()

    result = delete_file_collection(collection_id)

    assert result is True

    # verify collection was deleted
    file_collection = get_db().query(FileCollection).filter(FileCollection.id == collection_id).first()
    assert file_collection is None

    # verify history was deleted
    history_records = (
        get_db()
        .query(FileCollectionHistory)
        .filter(FileCollectionHistory.file_collection_id == collection_id)
        .all()
    )
    assert len(history_records) == 0


@pytest.mark.integration
def test_delete_file_collection_not_found():
    result = delete_file_collection(999999)
    assert result is False


@pytest.mark.integration
def test_get_file_collection_history():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid-history",
    )

    # add history entries with explicit timestamps to ensure deterministic ordering
    now = datetime.now()
    history1 = FileCollectionHistory(
        file_collection_id=collection_id,
        result=FileCollectorStatus.HOST_OFFLINE.value,
        message="First attempt - host offline",
        status=FileCollectionStatus.IN_PROGRESS.value,
        insert_date=now - timedelta(minutes=5),
    )
    history2 = FileCollectionHistory(
        file_collection_id=collection_id,
        result=FileCollectorStatus.SUCCESS.value,
        message="Second attempt - success",
        status=FileCollectionStatus.COMPLETED.value,
        insert_date=now,
    )
    get_db().add(history1)
    get_db().add(history2)
    get_db().commit()

    history = get_file_collection_history(collection_id)

    assert len(history) == 2
    # should be ordered by insert_date desc (most recent first)
    assert history[0].result == FileCollectorStatus.SUCCESS.value
    assert history[1].result == FileCollectorStatus.HOST_OFFLINE.value
