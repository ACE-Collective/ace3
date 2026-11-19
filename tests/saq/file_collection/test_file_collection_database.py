
import pytest

from saq.constants import F_FILE_LOCATION
from saq.database.model import FileCollection, FileCollectionWaiter
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
    wait_on_file_collection,
)
from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus


def _queue_decoys(observable_value: str, alert_uuid: str):
    """Pending requests that differ from (test_collector, file_location, observable_value) in one of
    the three only, so that a lookup that leaves out one of those filters finds one of them."""
    for name, observable_type, value in [
        ("other_collector", F_FILE_LOCATION, observable_value),
        ("test_collector", "ipv4", observable_value),
        ("test_collector", F_FILE_LOCATION, observable_value + ".other"),
    ]:
        queue_file_collection(collector_name=name, observable_type=observable_type,
                              observable_value=value, alert_uuid=alert_uuid)


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


@pytest.mark.integration
def test_get_file_collection_by_observable():
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
        alert_uuid="test-alert-uuid",
    )
    _queue_decoys("host@/path/to/file", alert_uuid="test-alert-uuid")

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
    _queue_decoys("host@/path/to/pending", alert_uuid="test-alert-pending")

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
def test_resolve_duplicate_pending_file_collection_no_duplicate():
    """Verify the request is kept when no older pending request exists for its observable."""
    _queue_decoys("host@/path/to/resolve_no_dup", alert_uuid="alert-uuid-resolve-0")
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
def test_resolve_duplicate_pending_file_collection_keeps_a_row_already_picked_up():
    """Verify a duplicate the collector loop already picked up is kept. Its lock is gone once an
    attempt has finished and it waits to be tried again, and the worker has recorded history
    against it by then; only its status says it is no longer new."""
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
    file_collection.lock = None
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
def test_get_pending_file_collection_by_observable_cross_alert_skips_alertless():
    """An alert's lookup never converges on a request no alert asked for: its file would be pruned."""
    queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert_alertless",
    )

    assert get_pending_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/cross_alert_alertless",
    ) is None


@pytest.mark.integration
def test_get_pending_file_collection_by_observable_without_alert():
    """with_alert=False finds only the requests no alert asked for."""
    queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/alertless",
        alert_uuid="alert-uuid-alertless-1",
    )
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/alertless",
    )

    result = get_pending_file_collection_by_observable(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/alertless",
        with_alert=False,
    )

    assert result is not None
    assert result.id == collection_id


@pytest.mark.integration
def test_resolve_duplicate_pending_file_collection_keeps_alert_and_alertless_apart():
    """A request with an alert and one without never attach to each other, in either order."""
    alertless_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_kinds",
    )
    alert_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_kinds",
        alert_uuid="alert-uuid-resolve-kinds",
    )
    later_alertless_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_kinds",
    )

    assert resolve_duplicate_pending_file_collection(alert_id) == alert_id
    assert get_file_collection(alert_id) is not None
    # the later alert-less request attaches to the earlier alert-less one, not to the alert's
    assert resolve_duplicate_pending_file_collection(later_alertless_id) == alertless_id
    assert get_file_collection(later_alertless_id) is None


def _waiters(collection_id: int) -> list[str]:
    get_db().expire_all()
    return [waiter.alert_uuid for waiter in get_db().query(FileCollectionWaiter)
            .filter(FileCollectionWaiter.file_collection_id == collection_id)
            .order_by(FileCollectionWaiter.id)]


@pytest.mark.integration
def test_wait_on_file_collection():
    """Each alert is recorded once, in the order they started waiting."""
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/waited_on",
        alert_uuid="alert-uuid-owner",
    )

    wait_on_file_collection(collection_id, "alert-uuid-waiter-1")
    wait_on_file_collection(collection_id, "alert-uuid-waiter-2")
    wait_on_file_collection(collection_id, "alert-uuid-waiter-1")

    assert _waiters(collection_id) == ["alert-uuid-waiter-1", "alert-uuid-waiter-2"]

    # deleting the collection takes its waiters with it
    assert delete_file_collection(collection_id)
    assert _waiters(collection_id) == []


@pytest.mark.integration
def test_wait_on_file_collection_that_no_longer_exists():
    """A collection deleted between the lookup and the wait leaves nothing to record."""
    collection_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/deleted",
        alert_uuid="alert-uuid-owner",
    )
    assert delete_file_collection(collection_id)

    wait_on_file_collection(collection_id, "alert-uuid-waiter")

    assert _waiters(collection_id) == []


@pytest.mark.integration
def test_resolve_duplicate_pending_file_collection_records_the_waiter():
    """The alert whose duplicate is folded into the older request waits on it; a duplicate that is
    kept, and one no alert asked for, record no one."""
    older_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_waiter",
        alert_uuid="alert-uuid-older",
    )
    newer_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_waiter",
        alert_uuid="alert-uuid-newer",
    )
    kept_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_waiter",
        alert_uuid="alert-uuid-kept",
    )
    get_db().query(FileCollection).filter(FileCollection.id == kept_id).update(
        {FileCollection.status: FileCollectionStatus.IN_PROGRESS.value})
    get_db().commit()

    assert resolve_duplicate_pending_file_collection(newer_id) == older_id
    assert resolve_duplicate_pending_file_collection(kept_id) == kept_id
    assert _waiters(older_id) == ["alert-uuid-newer"]
    assert _waiters(kept_id) == []

    alertless_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_waiter_alertless",
    )
    later_alertless_id = queue_file_collection(
        collector_name="test_collector",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/resolve_waiter_alertless",
    )
    assert resolve_duplicate_pending_file_collection(later_alertless_id) == alertless_id
    assert _waiters(alertless_id) == []


@pytest.mark.integration
def test_cancel_file_collection_not_found():
    result = cancel_file_collection(999999)
    assert result is False


@pytest.mark.integration
def test_retry_file_collection_not_found():
    result = retry_file_collection(999999)
    assert result is False


@pytest.mark.integration
def test_delete_file_collection_not_found():
    result = delete_file_collection(999999)
    assert result is False
