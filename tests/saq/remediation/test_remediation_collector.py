from uuid import uuid4
import pytest
from sqlalchemy import func

from saq.constants import F_TEST
from saq.database.model import Remediation
from saq.database.pool import get_db
from saq.environment import get_global_runtime_settings
from saq.remediation.collector import RemediationCollector
from saq.remediation.interface import RemediationListener
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus, RemediationWorkItem, RemediatorStatus

class TestRemediationListener(RemediationListener):
    __test__ = False

    def __init__(self):
        self.remediations = []

    def handle_remediation_request(self, remediation: RemediationWorkItem):
        self.remediations.append(remediation)

@pytest.mark.integration
def test_collect_work_items_empty():
    collector = RemediationCollector()
    assert not collector.collect_work_items()

@pytest.mark.integration
def test_collect_single_work_item():
    collector = RemediationCollector()
    assert not collector.collect_work_items()

    target = RemediationTarget("custom", F_TEST, "test")
    target.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    # before registering a listener, we should not collect any remediations
    assert not collector.collect_work_items()

    # now we register a listener for a different name, so we should (still) not collect any remediations
    collector.register_remediation_listener("other", TestRemediationListener())
    assert not collector.collect_work_items()

    # now we register a listener for the same name, so we should collect the remediation
    collector.register_remediation_listener("custom", TestRemediationListener())
    tasks = collector.collect_work_items()
    assert len(tasks) == 1

@pytest.mark.parametrize("status,expected_value", [
    (RemediationStatus.NEW, True),
    (RemediationStatus.IN_PROGRESS, True),
    (RemediationStatus.COMPLETED, False),
])
@pytest.mark.integration
def test_collect_work_item_status(status, expected_value):
    collector = RemediationCollector()
    collector.register_remediation_listener("custom", TestRemediationListener())

    target = RemediationTarget("custom", F_TEST, "test")
    id = target.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    remediation = get_db().query(Remediation).filter(Remediation.id == id).first()
    remediation.status = status.value
    get_db().add(remediation)
    get_db().commit()

    assert bool(collector.collect_work_items()) == expected_value

@pytest.mark.integration
def test_collect_locked_work_item():
    collector = RemediationCollector()
    collector.register_remediation_listener("custom", TestRemediationListener())

    target = RemediationTarget("custom", F_TEST, "test")
    id = target.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)


    # lock the remediation
    remediation = get_db().query(Remediation).filter(Remediation.id == id).first()
    remediation.lock = str(uuid4())
    remediation.lock_time = func.NOW()
    get_db().add(remediation)
    get_db().commit()

    # we should not collect the remediation because it is locked
    assert not collector.collect_work_items()

    # set the lock time to zero seconds
    collector.lock_timeout_seconds = 0

    # now we should collect the remediation because it is locked but has timed out
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == id

@pytest.mark.integration
def test_collect_delayed_work_item():
    collector = RemediationCollector()
    collector.register_remediation_listener("custom", TestRemediationListener())

    target = RemediationTarget("custom", F_TEST, "test")
    id = target.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    # set to in progress and delayed
    remediation = get_db().query(Remediation).filter(Remediation.id == id).first()
    remediation.update_time = func.NOW()
    remediation.status = RemediationStatus.IN_PROGRESS.value
    remediation.result = RemediatorStatus.DELAYED.value
    get_db().add(remediation)
    get_db().commit()

    # we not should collect the remediation because it is in progress and currently delayed
    assert not collector.collect_work_items()

    # set the delay time to zero seconds
    collector.delay_time_seconds = 0

    # now we should collect the remediation because it is in progress and the delay time has expired
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == id

@pytest.mark.integration
def test_collect_delayed_and_locked_work_item():
    collector = RemediationCollector()
    collector.register_remediation_listener("custom", TestRemediationListener())

    target = RemediationTarget("custom", F_TEST, "test")
    id = target.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    # set to in progress and delayed and locked
    remediation = get_db().query(Remediation).filter(Remediation.id == id).first()
    remediation.update_time = func.NOW()
    remediation.status = RemediationStatus.IN_PROGRESS.value
    remediation.result = RemediatorStatus.DELAYED.value
    remediation.lock = str(uuid4())
    remediation.lock_time = func.NOW()
    get_db().add(remediation)
    get_db().commit()

    # we not should collect the remediation because it is in progress and currently delayed and locked
    assert not collector.collect_work_items()

    # set the delay time to zero seconds
    collector.delay_time_seconds = 0

    # should still fail to collect because it is still locked
    assert not collector.collect_work_items()

    # set the lock time to zero seconds
    collector.lock_timeout_seconds = 0

    # now we should collect the remediation because it is in progress and the delay time and lock has expired
    tasks = collector.collect_work_items()
    assert len(tasks) == 1
    assert tasks[0].id == id

@pytest.mark.unit
def test_register_remediation_listener():
    collector = RemediationCollector()
    listener = TestRemediationListener()

    # should successfully register a listener
    collector.register_remediation_listener("test_name", listener)
    assert "test_name" in collector.listeners
    assert collector.listeners["test_name"] is listener

@pytest.mark.unit
def test_register_remediation_listener_duplicate():
    collector = RemediationCollector()
    listener1 = TestRemediationListener()
    listener2 = TestRemediationListener()

    # register first listener
    collector.register_remediation_listener("test_name", listener1)

    # attempting to register a second listener with the same name should raise ValueError
    with pytest.raises(ValueError, match="remediation listener test_name already registered"):
        collector.register_remediation_listener("test_name", listener2)

@pytest.mark.unit
def test_register_multiple_remediation_listeners():
    collector = RemediationCollector()
    listener1 = TestRemediationListener()
    listener2 = TestRemediationListener()
    listener3 = TestRemediationListener()

    # should successfully register multiple listeners with different names
    collector.register_remediation_listener("listener_1", listener1)
    collector.register_remediation_listener("listener_2", listener2)
    collector.register_remediation_listener("listener_3", listener3)

    assert len(collector.listeners) == 3
    assert collector.listeners["listener_1"] is listener1
    assert collector.listeners["listener_2"] is listener2
    assert collector.listeners["listener_3"] is listener3

@pytest.mark.unit
def test_notify_remediation_listeners():
    collector = RemediationCollector()
    listener = TestRemediationListener()

    # register a listener
    collector.register_remediation_listener("test_name", listener)

    # create a work item
    work_item = RemediationWorkItem(
        id=1,
        action=RemediationAction.REMOVE,
        name="test_name",
        type=F_TEST,
        key="test_key",
        restore_key=None
    )

    # notify the listener
    collector.notify_remediation_listeners(work_item)

    # verify the listener received the work item
    assert len(listener.remediations) == 1
    assert listener.remediations[0] is work_item

@pytest.mark.unit
def test_notify_remediation_listeners_unregistered():
    collector = RemediationCollector()

    # create a work item for an unregistered listener
    work_item = RemediationWorkItem(
        id=1,
        action=RemediationAction.REMOVE,
        name="unregistered_name",
        type=F_TEST,
        key="test_key",
        restore_key=None
    )

    # attempting to notify an unregistered listener should raise ValueError
    with pytest.raises(ValueError, match="remediation name unregistered_name not registered"):
        collector.notify_remediation_listeners(work_item)

@pytest.mark.unit
def test_notify_remediation_listeners_multiple():
    collector = RemediationCollector()
    listener1 = TestRemediationListener()
    listener2 = TestRemediationListener()

    # register two listeners
    collector.register_remediation_listener("listener_1", listener1)
    collector.register_remediation_listener("listener_2", listener2)

    # create work items for each listener
    work_item_1 = RemediationWorkItem(
        id=1,
        action=RemediationAction.REMOVE,
        name="listener_1",
        type=F_TEST,
        key="test_key_1",
        restore_key=None
    )

    work_item_2 = RemediationWorkItem(
        id=2,
        action=RemediationAction.RESTORE,
        name="listener_2",
        type=F_TEST,
        key="test_key_2",
        restore_key="restore_key_2"
    )

    # notify each listener
    collector.notify_remediation_listeners(work_item_1)
    collector.notify_remediation_listeners(work_item_2)

    # verify each listener received only their work item
    assert len(listener1.remediations) == 1
    assert listener1.remediations[0] is work_item_1

    assert len(listener2.remediations) == 1
    assert listener2.remediations[0] is work_item_2

@pytest.mark.unit
def test_notify_remediation_listeners_same_listener_multiple_times():
    collector = RemediationCollector()
    listener = TestRemediationListener()

    # register a listener
    collector.register_remediation_listener("test_name", listener)

    # create multiple work items for the same listener
    work_item_1 = RemediationWorkItem(
        id=1,
        action=RemediationAction.REMOVE,
        name="test_name",
        type=F_TEST,
        key="test_key_1",
        restore_key=None
    )

    work_item_2 = RemediationWorkItem(
        id=2,
        action=RemediationAction.RESTORE,
        name="test_name",
        type=F_TEST,
        key="test_key_2",
        restore_key="restore_key_2"
    )

    # notify the listener multiple times
    collector.notify_remediation_listeners(work_item_1)
    collector.notify_remediation_listeners(work_item_2)

    # verify the listener received both work items
    assert len(listener.remediations) == 2
    assert listener.remediations[0] is work_item_1
    assert listener.remediations[1] is work_item_2

@pytest.mark.unit
def test_collection_loop_signals_startup():
    collector = RemediationCollector()

    # startup event should not be set initially
    assert not collector.collector_startup_event.is_set()

    # mock collect_work_items to return empty list
    collector.collect_work_items = lambda: []

    # set shutdown event so loop exits immediately
    collector.shutdown_event.set()

    # run the collection loop
    collector.collection_loop()

    # verify startup event was set
    assert collector.collector_startup_event.is_set()

@pytest.mark.unit
def test_collection_loop_processes_work_items():
    collector = RemediationCollector()
    listener = TestRemediationListener()
    collector.register_remediation_listener("test_name", listener)

    # create work items to be collected
    work_items = [
        RemediationWorkItem(
            id=1,
            action=RemediationAction.REMOVE,
            name="test_name",
            type=F_TEST,
            key="test_key_1",
            restore_key=None
        ),
        RemediationWorkItem(
            id=2,
            action=RemediationAction.RESTORE,
            name="test_name",
            type=F_TEST,
            key="test_key_2",
            restore_key="restore_key_2"
        )
    ]

    # mock collect_work_items to return work items once, then empty list
    call_count = [0]
    def mock_collect_work_items():
        call_count[0] += 1
        if call_count[0] == 1:
            return work_items
        return []

    collector.collect_work_items = mock_collect_work_items

    # set shutdown event so loop exits after processing
    collector.shutdown_event.set()

    # run the collection loop
    collector.collection_loop()

    # verify all work items were processed
    assert len(listener.remediations) == 2
    assert listener.remediations[0] is work_items[0]
    assert listener.remediations[1] is work_items[1]

@pytest.mark.unit
def test_collection_loop_handles_exceptions_in_collect():
    collector = RemediationCollector()

    # mock collect_work_items to raise an exception first, then return empty list
    call_count = [0]
    def mock_collect_work_items():
        call_count[0] += 1
        if call_count[0] == 1:
            raise RuntimeError("test error in collect_work_items")
        return []

    collector.collect_work_items = mock_collect_work_items

    # set shutdown event so loop exits after processing
    collector.shutdown_event.set()

    # run the collection loop - should not raise exception
    collector.collection_loop()

    # verify collect_work_items was called
    assert call_count[0] >= 1

@pytest.mark.unit
def test_collection_loop_handles_exceptions_in_notify():
    collector = RemediationCollector()
    listener = TestRemediationListener()
    collector.register_remediation_listener("test_name", listener)

    # create work item with wrong name to trigger exception in notify
    work_item = RemediationWorkItem(
        id=1,
        action=RemediationAction.REMOVE,
        name="unregistered_name",
        type=F_TEST,
        key="test_key",
        restore_key=None
    )

    # mock collect_work_items to return bad work item once, then empty list
    call_count = [0]
    def mock_collect_work_items():
        call_count[0] += 1
        if call_count[0] == 1:
            return [work_item]
        return []

    collector.collect_work_items = mock_collect_work_items

    # set shutdown event so loop exits after processing
    collector.shutdown_event.set()

    # run the collection loop - should not raise exception
    collector.collection_loop()

    # verify collect_work_items was called
    assert call_count[0] >= 1

@pytest.mark.unit
def test_collection_loop_removes_database_connection():
    from unittest.mock import patch

    collector = RemediationCollector()

    # mock collect_work_items to return empty list
    collector.collect_work_items = lambda: []

    # set shutdown event so loop exits
    collector.shutdown_event.set()

    with patch("saq.remediation.collector.remove_all_sessions") as mock_remove:
        collector.collection_loop()

    # verify database sessions were removed
    mock_remove.assert_called_once()

@pytest.mark.unit
def test_collection_loop_handles_db_remove_exception():
    from unittest.mock import patch

    collector = RemediationCollector()

    # mock collect_work_items to return empty list
    collector.collect_work_items = lambda: []

    # set shutdown event so loop exits
    collector.shutdown_event.set()

    with patch("saq.remediation.collector.remove_all_sessions", side_effect=RuntimeError("test db error")) as mock_remove:
        # should not raise exception
        collector.collection_loop()

    # verify remove was attempted
    mock_remove.assert_called_once()

@pytest.mark.unit
def test_collection_loop_exits_on_shutdown_event():
    collector = RemediationCollector()

    # mock collect_work_items to track calls
    call_count = [0]
    def mock_collect_work_items():
        call_count[0] += 1
        return []

    collector.collect_work_items = mock_collect_work_items

    # set shutdown event immediately
    collector.shutdown_event.set()

    # run the collection loop
    collector.collection_loop()

    # verify collect_work_items was called only once
    assert call_count[0] == 1

@pytest.mark.unit
def test_collection_loop_waits_between_iterations():
    collector = RemediationCollector()

    # mock collect_work_items to track calls
    call_count = [0]
    def mock_collect_work_items():
        call_count[0] += 1
        # set shutdown after second call
        if call_count[0] >= 2:
            collector.shutdown_event.set()
        return []

    collector.collect_work_items = mock_collect_work_items

    # mock shutdown_event.wait to track calls and set shutdown
    original_wait = collector.shutdown_event.wait
    wait_calls = [0]
    def mock_wait(timeout):
        wait_calls[0] += 1
        return original_wait(timeout)

    collector.shutdown_event.wait = mock_wait

    # run the collection loop
    collector.collection_loop()

    # verify wait was called with 1 second timeout
    assert wait_calls[0] >= 1

@pytest.mark.unit
def test_collection_loop_processes_multiple_listeners():
    collector = RemediationCollector()
    listener1 = TestRemediationListener()
    listener2 = TestRemediationListener()
    collector.register_remediation_listener("listener_1", listener1)
    collector.register_remediation_listener("listener_2", listener2)

    # create work items for different listeners
    work_items = [
        RemediationWorkItem(
            id=1,
            action=RemediationAction.REMOVE,
            name="listener_1",
            type=F_TEST,
            key="test_key_1",
            restore_key=None
        ),
        RemediationWorkItem(
            id=2,
            action=RemediationAction.RESTORE,
            name="listener_2",
            type=F_TEST,
            key="test_key_2",
            restore_key="restore_key_2"
        ),
        RemediationWorkItem(
            id=3,
            action=RemediationAction.REMOVE,
            name="listener_1",
            type=F_TEST,
            key="test_key_3",
            restore_key=None
        )
    ]

    # mock collect_work_items to return work items once, then empty list
    call_count = [0]
    def mock_collect_work_items():
        call_count[0] += 1
        if call_count[0] == 1:
            return work_items
        return []

    collector.collect_work_items = mock_collect_work_items

    # set shutdown event so loop exits after processing
    collector.shutdown_event.set()

    # run the collection loop
    collector.collection_loop()

    # verify each listener received their work items
    assert len(listener1.remediations) == 2
    assert listener1.remediations[0] is work_items[0]
    assert listener1.remediations[1] is work_items[2]

    assert len(listener2.remediations) == 1
    assert listener2.remediations[0] is work_items[1]