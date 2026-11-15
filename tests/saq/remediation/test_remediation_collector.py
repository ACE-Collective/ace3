from uuid import uuid4
import pytest
from sqlalchemy import func
from sqlalchemy.orm import Query

from saq.constants import F_TEST
from saq.database.model import Remediation
from saq.database.pool import get_db
from saq.configuration.config import get_config
from saq.configuration.schema import RemediatorConfig
from saq.remediation.collector import RemediationCollector
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus, RemediationWorkItem, RemediatorResult, RemediatorStatus
from saq.remediation.worker import RemediationWorker
from tests.saq.remediation.test_remediator import TestRemediator

class TestRemediationListener:
    __test__ = False

    def __init__(self):
        self.remediations = []

    def handle_request(self, work_item: RemediationWorkItem):
        self.remediations.append(work_item)

    def pending_ids(self) -> set[int]:
        # done with each item as soon as it has it
        return set()

class CountingRemediator(TestRemediator):
    __test__ = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.removed: list[RemediationWorkItem] = []

    def remove(self, target: RemediationWorkItem) -> RemediatorResult:
        self.removed.append(target)
        return super().remove(target)

@pytest.mark.integration
def test_collect_single_work_item():
    collector = RemediationCollector()
    assert not collector.collect_work_items()

    target = RemediationTarget("custom", F_TEST, "test")
    target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)

    # before registering a listener, we should not collect any remediations
    assert not collector.collect_work_items()

    # now we register a listener for a different name, so we should (still) not collect any remediations
    collector.register_listener("other", TestRemediationListener())
    assert not collector.collect_work_items()

    # now we register a listener for the same name, so we should collect the remediation
    collector.register_listener("custom", TestRemediationListener())
    tasks = collector.collect_work_items()
    assert len(tasks) == 1

@pytest.mark.integration
def test_collect_work_item_status():
    """A completed remediation is not collected again (test_collect_single_work_item collects a new one)."""
    collector = RemediationCollector()
    collector.register_listener("custom", TestRemediationListener())

    target = RemediationTarget("custom", F_TEST, "test")
    id = target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)

    remediation = get_db().query(Remediation).filter(Remediation.id == id).first()
    remediation.status = RemediationStatus.COMPLETED.value
    get_db().add(remediation)
    get_db().commit()

    assert not collector.collect_work_items()

@pytest.mark.integration
def test_collect_locked_work_item():
    collector = RemediationCollector()
    collector.register_listener("custom", TestRemediationListener())

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
    collector.register_listener("custom", TestRemediationListener())

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

def _queue(name: str, key: str, action: RemediationAction = RemediationAction.REMOVE, restore_key=None) -> int:
    target = RemediationTarget(name, F_TEST, key)
    return target.queue_remediation(action, get_config().global_settings.automation_user_id, restore_key)

@pytest.mark.integration
def test_collection_loop_processes_work_items():
    collector = RemediationCollector()
    listener = TestRemediationListener()
    collector.register_listener("test_name", listener)

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

@pytest.mark.integration
def test_collection_loop_processes_multiple_listeners():
    collector = RemediationCollector()
    listener1 = TestRemediationListener()
    listener2 = TestRemediationListener()
    collector.register_listener("listener_1", listener1)
    collector.register_listener("listener_2", listener2)

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

@pytest.mark.integration
def test_collect_skips_remediation_still_queued_after_lock_timeout():
    # the remediator is behind: the row waits in its worker's queue past the lock timeout
    remediator = CountingRemediator(RemediatorConfig(
        name="custom",
        display_name="Custom Remediator",
        description="Custom remediator for testing",
        observable_type=F_TEST,
        python_module="value",
        python_class="value",
    ))
    worker = RemediationWorker(remediator)
    collector = RemediationCollector(lock_timeout_seconds=0)
    collector.register_listener("custom", worker)
    id = _queue("custom", "test")

    collector.start_single_threaded()
    collector.collection_loop()

    assert worker.work_queue.qsize() == 1

    worker.start_single_threaded()

    assert [target.id for target in remediator.removed] == [id]
    # finished, it is not collected again, and a new remediation is
    new_id = _queue("custom", "test_2")
    assert [item.id for item in collector.collect_work_items()] == [new_id]

@pytest.mark.integration
def test_collect_does_not_reopen_remediation_finished_during_collection(monkeypatch):
    class HoldingListener(TestRemediationListener):
        __test__ = False

        def __init__(self):
            super().__init__()
            self.held: set[int] = set()

        def pending_ids(self) -> set[int]:
            return set(self.held)

    listener = HoldingListener()
    collector = RemediationCollector(lock_timeout_seconds=0)
    collector.register_listener("custom", listener)
    id = _queue("custom", "test")
    assert [item.id for item in collector.collect_work_items()] == [id]
    listener.held.add(id)

    # the worker finishes the remediation and lets go of it right after the collector's query has
    # read it unfinished
    query_all = Query.all
    def all_then_finish(query):
        rows = query_all(query)
        if listener.held:
            get_db().execute(Remediation.__table__.update().values(
                status=RemediationStatus.COMPLETED.value, lock=None).where(Remediation.id == id))
            get_db().commit()
            listener.held.clear()
        return rows

    monkeypatch.setattr(Query, "all", all_then_finish)

    assert not collector.collect_work_items()
    get_db().expire_all()
    remediation = get_db().get(Remediation, id)
    assert remediation.status == RemediationStatus.COMPLETED.value
    assert remediation.lock is None
