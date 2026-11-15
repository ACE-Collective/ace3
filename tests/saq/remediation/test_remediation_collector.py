import logging
from uuid import uuid4
import pytest
from sqlalchemy import func

from saq.constants import F_TEST
from saq.database.model import Remediation
from saq.database.pool import get_db
from saq.configuration.config import get_config
from saq.remediation.collector import RemediationCollector
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus, RemediationWorkItem, RemediatorStatus

class TestRemediationListener:
    __test__ = False

    def __init__(self):
        self.remediations = []

    def handle_request(self, work_item: RemediationWorkItem):
        self.remediations.append(work_item)

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


def _lock(remediation_id: int) -> tuple:
    get_db().expire_all()
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).one()
    return remediation.lock, remediation.lock_time


@pytest.mark.integration
def test_release_unlocks_rows_still_holding_the_collectors_lock(caplog):
    collector = RemediationCollector()
    collector.register_listener("custom", TestRemediationListener())
    target = RemediationTarget("custom", F_TEST, "test")
    ids = [target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id) for _ in range(2)]
    work_items = collector.collect_work_items()
    assert sorted(work_item.id for work_item in work_items) == sorted(ids)
    assert all(work_item.lock is not None for work_item in work_items)

    # the second row's lock timed out and another node locked it again
    get_db().execute(Remediation.__table__.update().values(lock="other node").where(Remediation.id == ids[1]))
    get_db().commit()
    caplog.set_level(logging.INFO)

    collector.release(work_items)

    assert _lock(ids[0]) == (None, None)
    assert _lock(ids[1])[0] == "other node"
    records = [r for r in caplog.records if r.levelno == logging.INFO and "released 1 of 2 queued remediation rows" in r.getMessage()]
    assert len(records) == 1
    # the ids go in a field, since a backlog can hold thousands of them
    assert sorted(records[0].row_ids) == sorted(ids)
    # the released row is collected again without waiting out the lock timeout
    assert [work_item.id for work_item in collector.collect_work_items()] == [ids[0]]


@pytest.mark.integration
def test_release_unlocks_rows_of_several_collection_passes(monkeypatch, caplog):
    # several batches per lock too
    monkeypatch.setattr("saq.queue_service.RELEASE_BATCH_SIZE", 1)
    collector = RemediationCollector()
    collector.register_listener("custom", TestRemediationListener())
    target = RemediationTarget("custom", F_TEST, "test")
    automation_user_id = get_config().global_settings.automation_user_id
    # a backlog built over two passes, each of which locks its rows under a lock of its own
    ids = [target.queue_remediation(RemediationAction.REMOVE, automation_user_id) for _ in range(2)]
    first_pass = collector.collect_work_items()
    ids += [target.queue_remediation(RemediationAction.REMOVE, automation_user_id) for _ in range(2)]
    second_pass = collector.collect_work_items()
    assert len(first_pass) == len(second_pass) == 2
    assert first_pass[0].lock != second_pass[0].lock
    caplog.set_level(logging.INFO)

    collector.release(first_pass + second_pass)

    assert [_lock(remediation_id) for remediation_id in ids] == [(None, None)] * 4
    assert any("released 4 of 4 queued remediation rows" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_release_logs_failure_and_leaves_rows_locked(monkeypatch, caplog):
    collector = RemediationCollector()
    collector.register_listener("custom", TestRemediationListener())
    remediation_id = RemediationTarget("custom", F_TEST, "test").queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)
    work_items = collector.collect_work_items()

    class _UnreachableDatabase:
        def execute(self, statement):
            raise RuntimeError("database is gone")

    monkeypatch.setattr("saq.queue_service.get_db", lambda: _UnreachableDatabase())

    collector.release(work_items)

    errors = [r for r in caplog.records if r.levelno == logging.ERROR and r.exc_info]
    assert len(errors) == 1
    assert "unable to release queued remediation rows (0 of 1 released before the failure): database is gone" in errors[0].getMessage()
    assert errors[0].row_ids == [remediation_id]
    assert _lock(remediation_id)[0] == work_items[0].lock


@pytest.mark.integration
def test_release_failure_after_a_batch_says_how_many_were_released(monkeypatch, caplog):
    monkeypatch.setattr("saq.queue_service.RELEASE_BATCH_SIZE", 1)
    collector = RemediationCollector()
    collector.register_listener("custom", TestRemediationListener())
    target = RemediationTarget("custom", F_TEST, "test")
    ids = [target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id) for _ in range(2)]
    work_items = collector.collect_work_items()
    session = get_db()

    class _DatabaseLostAfterOneBatch:
        """The real session for the first batch, then a lost connection."""
        statements = 0

        def execute(self, statement):
            self.statements += 1
            if self.statements > 1:
                raise RuntimeError("database is gone")
            return session.execute(statement)

        def commit(self):
            session.commit()

    database = _DatabaseLostAfterOneBatch()
    monkeypatch.setattr("saq.queue_service.get_db", lambda: database)

    collector.release(work_items)

    errors = [r for r in caplog.records if r.levelno == logging.ERROR and r.exc_info]
    assert len(errors) == 1
    assert "1 of 2 released before the failure" in errors[0].getMessage()
    assert sorted(_lock(remediation_id)[0] is None for remediation_id in ids) == [False, True]


@pytest.mark.integration
def test_release_logs_failed_session_reset(monkeypatch, caplog):
    collector = RemediationCollector()
    collector.register_listener("custom", TestRemediationListener())
    remediation_id = RemediationTarget("custom", F_TEST, "test").queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)
    work_items = collector.collect_work_items()

    def _fail():
        raise RuntimeError("pool gone")

    monkeypatch.setattr("saq.queue_service.remove_all_sessions", _fail)

    collector.release(work_items)

    assert _lock(remediation_id) == (None, None)
    errors = [r for r in caplog.records if r.levelno == logging.ERROR and r.exc_info]
    assert len(errors) == 1
    assert "error removing database connection: pool gone" in errors[0].getMessage()
