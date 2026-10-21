from uuid import uuid4
import pytest
from sqlalchemy import func

from saq.constants import F_TEST
from saq.database.model import Remediation
from saq.database.pool import get_db
from saq.configuration.config import get_config
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
    target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)

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
    id = target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)

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
    id = target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)


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
    id = target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)

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
    id = target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)

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

def _queue(name: str, key: str, action: RemediationAction = RemediationAction.REMOVE, restore_key=None) -> int:
    target = RemediationTarget(name, F_TEST, key)
    return target.queue_remediation(action, get_config().global_settings.automation_user_id, restore_key)

def _counting_collect(collector: RemediationCollector, on_call=None) -> list[int]:
    """Wraps the real collect_work_items to count how often the loop calls it."""
    calls = [0]
    real_collect = collector.collect_work_items

    def collect_work_items():
        calls[0] += 1
        if on_call:
            on_call(calls[0])
        return real_collect()

    collector.collect_work_items = collect_work_items
    return calls

class RaisingRemediationListener(RemediationListener):
    def handle_remediation_request(self, remediation: RemediationWorkItem):
        raise RuntimeError("test error in handle_remediation_request")

@pytest.mark.integration
def test_collection_loop_signals_startup():
    collector = RemediationCollector()

    # startup event should not be set initially
    assert not collector.collector_startup_event.is_set()

    # set shutdown event so loop exits immediately
    collector.shutdown_event.set()

    # run the collection loop
    collector.collection_loop()

    # verify startup event was set
    assert collector.collector_startup_event.is_set()

@pytest.mark.integration
def test_collection_loop_processes_work_items():
    collector = RemediationCollector()
    listener = TestRemediationListener()
    collector.register_remediation_listener("test_name", listener)

    remove_id = _queue("test_name", "test_key_1")
    restore_id = _queue("test_name", "test_key_2", RemediationAction.RESTORE, "restore_key_2")
    # a remediation for a name nobody listens to is left alone
    other_id = _queue("other_name", "test_key_3")

    # set shutdown event so loop exits after processing
    collector.shutdown_event.set()

    # run the collection loop
    collector.collection_loop()

    # verify all work items were processed
    by_id = {item.id: item for item in listener.remediations}
    assert set(by_id) == {remove_id, restore_id}
    assert by_id[remove_id].action == RemediationAction.REMOVE
    assert by_id[remove_id].key == "test_key_1"
    assert by_id[restore_id].action == RemediationAction.RESTORE
    assert by_id[restore_id].restore_key == "restore_key_2"

    # the collected rows are locked and in progress, the other one is untouched
    rows = {r.id: r for r in get_db().query(Remediation).filter(Remediation.id.in_([remove_id, restore_id, other_id]))}
    for id in (remove_id, restore_id):
        assert rows[id].status == RemediationStatus.IN_PROGRESS.value
        assert rows[id].lock is not None
    assert rows[other_id].status == RemediationStatus.NEW.value
    assert rows[other_id].lock is None

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

@pytest.mark.integration
def test_collection_loop_handles_exceptions_in_notify(caplog):
    collector = RemediationCollector()
    collector.register_remediation_listener("test_name", RaisingRemediationListener())
    _queue("test_name", "test_key")

    # set shutdown event so loop exits after processing
    collector.shutdown_event.set()

    # run the collection loop - should not raise exception
    collector.collection_loop()

    errors = [r for r in caplog.records if r.levelname == "ERROR" and "error collecting remediations from database" in r.getMessage()]
    assert len(errors) == 1
    assert errors[0].exc_info is not None

@pytest.mark.integration
def test_collection_loop_removes_database_connection():
    from unittest.mock import patch
    from saq.database.pool import remove_all_sessions

    collector = RemediationCollector()

    # set shutdown event so loop exits
    collector.shutdown_event.set()

    with patch("saq.remediation.collector.remove_all_sessions", wraps=remove_all_sessions) as mock_remove:
        collector.collection_loop()

    # verify database sessions were removed
    mock_remove.assert_called_once()

@pytest.mark.integration
def test_collection_loop_handles_db_remove_exception():
    from unittest.mock import patch

    collector = RemediationCollector()

    # set shutdown event so loop exits
    collector.shutdown_event.set()

    with patch("saq.remediation.collector.remove_all_sessions", side_effect=RuntimeError("test db error")) as mock_remove:
        # should not raise exception
        collector.collection_loop()

    # verify remove was attempted
    mock_remove.assert_called_once()

@pytest.mark.integration
def test_collection_loop_exits_on_shutdown_event():
    collector = RemediationCollector()
    call_count = _counting_collect(collector)

    # set shutdown event immediately
    collector.shutdown_event.set()

    # run the collection loop
    collector.collection_loop()

    # verify collect_work_items was called only once
    assert call_count[0] == 1

@pytest.mark.integration
def test_collection_loop_waits_between_iterations():
    collector = RemediationCollector()

    def _on_call(count: int):
        # set shutdown after second call
        if count >= 2:
            collector.shutdown_event.set()

    call_count = _counting_collect(collector, _on_call)

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
    assert call_count[0] == 2

@pytest.mark.integration
def test_collection_loop_processes_multiple_listeners():
    collector = RemediationCollector()
    listener1 = TestRemediationListener()
    listener2 = TestRemediationListener()
    collector.register_remediation_listener("listener_1", listener1)
    collector.register_remediation_listener("listener_2", listener2)

    id_1 = _queue("listener_1", "test_key_1")
    id_2 = _queue("listener_2", "test_key_2", RemediationAction.RESTORE, "restore_key_2")
    id_3 = _queue("listener_1", "test_key_3")

    # set shutdown event so loop exits after processing
    collector.shutdown_event.set()

    # run the collection loop
    collector.collection_loop()

    # verify each listener received their work items
    assert {item.id for item in listener1.remediations} == {id_1, id_3}
    assert [item.id for item in listener2.remediations] == [id_2]
