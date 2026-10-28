from dataclasses import dataclass
import logging
from threading import Event
from typing import Optional

import pytest

import saq.shutdown
from saq.queue_service import QueueCollector, QueueManager, QueueService, QueueWorker
from tests.saq.helpers import wait_for_condition


@dataclass
class Item:
    id: int
    name: str


class FakeCollector(QueueCollector[Item]):
    label = "fake"

    def __init__(self, batches: Optional[list] = None, **kwargs):
        super().__init__(**kwargs)
        # what each call to collect_work_items returns (or raises), then nothing
        self.batches = list(batches or [])
        self.calls = 0

    def collect_work_items(self) -> list[Item]:
        self.calls += 1
        if not self.batches:
            return []
        batch = self.batches.pop(0)
        if isinstance(batch, Exception):
            raise batch
        return batch

    def build_work_item(self, row) -> Item:
        return row


class FakeWorker(QueueWorker[Item]):
    def __init__(self, name: str = "fake", thread_count: int = 1, fail_ids: tuple = ()):
        super().__init__()
        self._name = name
        self._thread_count = thread_count
        self.fail_ids = fail_ids
        self.processed: list[Item] = []
        self.queue_wait_timeout = 0.1

    @property
    def name(self) -> str:
        return self._name

    @property
    def thread_count(self) -> int:
        return self._thread_count

    def describe(self, work_item: Item) -> str:
        return f"fake item {work_item.id}"

    def log_extra(self, work_item: Item) -> dict:
        return {"alert_uuid": f"uuid-{work_item.id}"}

    def process_one(self, work_item: Item):
        if work_item.id in self.fail_ids:
            raise RuntimeError(f"failed {work_item.id}")
        self.processed.append(work_item)


class FakeManager(QueueManager[FakeWorker]):
    def __init__(self, collector: FakeCollector, workers: list[FakeWorker]):
        super().__init__(collector)
        self.configured_workers = workers

    def create_workers(self) -> list[FakeWorker]:
        return self.configured_workers


class FakeService(QueueService):
    def __init__(self, manager: FakeManager):
        self.fake_manager = manager

    def create_manager(self) -> FakeManager:
        return self.fake_manager


@pytest.fixture
def session_resets(monkeypatch) -> list:
    """Records every remove_all_sessions() call the queue service makes."""
    calls = []
    monkeypatch.setattr("saq.queue_service.remove_all_sessions", lambda: calls.append(True))
    return calls


def _failing_session_reset(monkeypatch):
    def _fail():
        raise RuntimeError("pool gone")

    monkeypatch.setattr("saq.queue_service.remove_all_sessions", _fail)


def _errors_with_traceback(caplog, text: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno == logging.ERROR and r.exc_info and text in r.getMessage()]


#
# collector
#

@pytest.mark.unit
def test_register_listener_rejects_duplicate_name():
    collector = FakeCollector()
    listener = FakeWorker()
    collector.register_listener("fake", listener)
    assert collector.listeners == {"fake": listener}

    with pytest.raises(ValueError, match="fake listener fake already registered"):
        collector.register_listener("fake", FakeWorker())


@pytest.mark.unit
def test_notify_listeners_dispatches_by_name():
    collector = FakeCollector()
    a, b = FakeWorker("a"), FakeWorker("b")
    collector.register_listener("a", a)
    collector.register_listener("b", b)

    collector.notify_listeners(Item(1, "b"))

    assert a.work_queue.empty()
    assert b.work_queue.get_nowait() == Item(1, "b")


@pytest.mark.unit
def test_notify_listeners_rejects_unregistered_name():
    with pytest.raises(ValueError, match="fake name other not registered"):
        FakeCollector().notify_listeners(Item(1, "other"))


@pytest.mark.unit
def test_collection_loop_dispatches_one_pass_when_shutting_down(session_resets):
    collector = FakeCollector([[Item(1, "fake"), Item(2, "fake")], [Item(3, "fake")]])
    worker = FakeWorker()
    collector.register_listener("fake", worker)
    collector.shutdown_event.set()

    collector.collection_loop()

    assert collector.collector_startup_event.is_set()
    assert collector.calls == 1
    assert [worker.work_queue.get_nowait().id for _ in range(2)] == [1, 2]
    assert worker.work_queue.empty()
    assert len(session_resets) == 1


@pytest.mark.unit
def test_collection_loop_logs_collect_failure_and_keeps_going(session_resets, caplog):
    collector = FakeCollector([RuntimeError("database gone"), [Item(1, "fake")]], loop_interval_seconds=0.01)
    worker = FakeWorker()
    collector.register_listener("fake", worker)

    original_collect = collector.collect_work_items

    def collect_then_stop():
        if collector.calls == 1:
            collector.stop()
        return original_collect()

    collector.collect_work_items = collect_then_stop
    collector.collection_loop()

    assert collector.calls == 2
    assert worker.work_queue.get_nowait() == Item(1, "fake")
    assert len(_errors_with_traceback(caplog, "error collecting fake work items from database")) == 1
    # the session is reset after the failed pass too
    assert len(session_resets) == 2


@pytest.mark.unit
def test_collection_loop_logs_dispatch_failure(session_resets, caplog):
    # nobody is registered for the item
    collector = FakeCollector([[Item(1, "unknown")]])
    collector.shutdown_event.set()

    collector.collection_loop()

    errors = _errors_with_traceback(caplog, "error collecting fake work items from database")
    assert len(errors) == 1
    assert "fake name unknown not registered" in errors[0].getMessage()


@pytest.mark.unit
def test_collection_loop_logs_failed_session_reset(monkeypatch, caplog):
    _failing_session_reset(monkeypatch)
    collector = FakeCollector()
    collector.shutdown_event.set()

    collector.collection_loop()

    assert len(_errors_with_traceback(caplog, "error removing database connection")) == 1


@pytest.mark.unit
def test_collector_thread_lifecycle(session_resets):
    collector = FakeCollector(loop_interval_seconds=0.01)
    collector.start()
    try:
        assert collector.wait_for_start(5)
        wait_for_condition(lambda: collector.calls >= 2)
    finally:
        collector.stop()
        collector.wait()

    assert not collector.collector_thread.is_alive()


@pytest.mark.unit
def test_collector_wait_for_start_reports_collector_that_did_not_start(caplog):
    collector = FakeCollector()

    assert not collector.wait_for_start(0.01)
    assert any(r.levelno == logging.ERROR and "fake collector thread did not start" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_collector_start_single_threaded_runs_one_pass(session_resets):
    collector = FakeCollector([[Item(1, "fake")]])
    worker = FakeWorker()
    collector.register_listener("fake", worker)

    collector.start_single_threaded()

    assert collector.calls == 1
    assert worker.work_queue.qsize() == 1
    assert collector.collector_thread is None
    # nothing to join
    collector.wait()


#
# worker
#

@pytest.mark.unit
def test_handle_request_queues_item(caplog):
    worker = FakeWorker()
    caplog.set_level(logging.INFO)

    worker.handle_request(Item(1, "fake"))

    assert worker.work_queue.get_nowait() == Item(1, "fake")
    assert any("received fake item 1" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_handle_request_rejects_item_for_another_worker():
    worker = FakeWorker()

    with pytest.raises(ValueError, match="work item name other does not match worker name fake"):
        worker.handle_request(Item(1, "other"))

    assert worker.work_queue.empty()


@pytest.mark.parametrize("thread_count", [1, 2])
@pytest.mark.unit
def test_worker_thread_lifecycle(session_resets, thread_count):
    worker = FakeWorker(thread_count=thread_count)
    worker.start()
    try:
        assert len(worker.worker_threads) == thread_count
        assert worker.wait_for_start(5)
        assert all(thread.is_alive() for thread in worker.worker_threads)

        worker.handle_request(Item(1, "fake"))
        wait_for_condition(lambda: worker.processed == [Item(1, "fake")])
    finally:
        worker.stop()
        worker.wait()

    assert not any(thread.is_alive() for thread in worker.worker_threads)


@pytest.mark.unit
def test_worker_wait_for_start_reports_thread_that_did_not_start(caplog):
    worker = FakeWorker()
    worker.startup_events.append(Event())

    assert not worker.wait_for_start(0.01)
    assert any(r.levelno == logging.ERROR and "FakeWorker fake thread 0 did not start" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_worker_loop_logs_failed_item_and_resets_session(session_resets, caplog):
    worker = FakeWorker(fail_ids=(1,))
    worker.handle_request(Item(1, "fake"))
    worker.handle_request(Item(2, "fake"))

    # with the shutdown event set, each pass of the loop takes one item and returns
    worker.stop()
    startup_event = Event()
    worker.worker_loop(startup_event)
    worker.worker_loop(Event())

    assert startup_event.is_set()
    assert worker.processed == [Item(2, "fake")]
    errors = _errors_with_traceback(caplog, "error processing fake item 1: failed 1")
    assert len(errors) == 1
    assert errors[0].alert_uuid == "uuid-1"
    # once after each item, failed or not
    assert len(session_resets) == 2



@pytest.mark.unit
def test_worker_loop_logs_failed_item_at_info_during_shutdown(session_resets, monkeypatch, caplog):
    # a peer stopped alongside the service is not a failure to report
    monkeypatch.setattr(saq.shutdown, "is_shutting_down", lambda: True)
    caplog.set_level(logging.INFO)
    worker = FakeWorker(fail_ids=(1,))
    worker.handle_request(Item(1, "fake"))

    worker.stop()
    worker.worker_loop(Event())

    records = [r for r in caplog.records if "error processing fake item 1" in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.INFO
    assert records[0].exc_info is None
    assert records[0].alert_uuid == "uuid-1"

@pytest.mark.unit
def test_worker_loop_without_work_leaves_session_alone(session_resets):
    worker = FakeWorker()
    worker.queue_wait_timeout = 0.01
    worker.stop()

    worker.worker_loop(Event())

    assert session_resets == []


@pytest.mark.unit
def test_worker_loop_logs_failed_session_reset(monkeypatch, caplog):
    _failing_session_reset(monkeypatch)
    worker = FakeWorker()
    worker.handle_request(Item(1, "fake"))
    worker.stop()

    worker.worker_loop(Event())

    assert worker.processed == [Item(1, "fake")]
    assert len(_errors_with_traceback(caplog, "error removing database connection")) == 1


@pytest.mark.unit
def test_worker_start_single_threaded_drains_queue(session_resets):
    worker = FakeWorker()
    for id in range(3):
        worker.handle_request(Item(id, "fake"))

    worker.start_single_threaded()

    assert [item.id for item in worker.processed] == [0, 1, 2]
    assert not worker.worker_threads


@pytest.mark.unit
def test_worker_start_single_threaded_stops_on_shutdown(session_resets, monkeypatch):
    # shutdown is requested (as a signal would) while the first item is being worked
    checks = iter([False])
    monkeypatch.setattr("saq.queue_service.is_shutting_down", lambda: next(checks, True))
    worker = FakeWorker()
    for id in range(3):
        worker.handle_request(Item(id, "fake"))

    worker.start_single_threaded()

    assert [item.id for item in worker.processed] == [0]
    assert worker.work_queue.qsize() == 2


#
# manager and service
#

@pytest.mark.unit
def test_manager_loads_workers_and_registers_them():
    a, b = FakeWorker("a"), FakeWorker("b")
    manager = FakeManager(FakeCollector(), [a, b])

    manager.load_workers()

    assert manager.workers == {"a": a, "b": b}
    assert manager.collector.listeners == {"a": a, "b": b}


@pytest.mark.unit
def test_manager_rejects_duplicate_worker_names():
    manager = FakeManager(FakeCollector(), [FakeWorker("a"), FakeWorker("a")])

    with pytest.raises(ValueError, match="worker a already exists"):
        manager.load_workers()


@pytest.mark.unit
def test_manager_wait_for_start_reports_worker_that_did_not_start(caplog):
    manager = FakeManager(FakeCollector(), [FakeWorker("a")])
    manager.load_workers()
    manager.workers["a"].startup_events.append(Event())

    assert not manager.wait_for_start(0.01)
    assert any(r.levelno == logging.ERROR and "worker a did not start" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_manager_wait_for_start_reports_collector_that_did_not_start(caplog):
    manager = FakeManager(FakeCollector(), [FakeWorker("a")])
    manager.load_workers()

    assert not manager.wait_for_start(0.01)
    assert any(r.levelno == logging.ERROR and "fake collector did not start" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_service_lifecycle(session_resets):
    a, b = FakeWorker("a"), FakeWorker("b")
    collector = FakeCollector([[Item(1, "a"), Item(2, "b")]], loop_interval_seconds=0.01)
    service = FakeService(FakeManager(collector, [a, b]))

    service.start()
    try:
        assert service.wait_for_start(5)
        wait_for_condition(lambda: a.processed == [Item(1, "a")] and b.processed == [Item(2, "b")])
    finally:
        service.stop()
        service.wait()

    assert not collector.collector_thread.is_alive()
    assert not any(thread.is_alive() for worker in (a, b) for thread in worker.worker_threads)


@pytest.mark.unit
def test_service_start_single_threaded_collects_once_and_drains(session_resets):
    a, b = FakeWorker("a"), FakeWorker("b")
    collector = FakeCollector([[Item(1, "a"), Item(2, "b"), Item(3, "a")], [Item(4, "a")]])
    service = FakeService(FakeManager(collector, [a, b]))

    service.start_single_threaded()

    assert collector.calls == 1
    assert [item.id for item in a.processed] == [1, 3]
    assert [item.id for item in b.processed] == [2]
    assert collector.collector_thread is None
    assert not a.worker_threads and not b.worker_threads
    service.wait()
