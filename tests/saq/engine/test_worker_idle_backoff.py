"""Tests for the idle backoff in ``Worker.worker_loop`` (see docs/ENGINE.md §19.3).

``worker_loop`` backs off one second per empty poll, up to ``idle_timeout_max``,
and is supposed to reset that counter as soon as it processes a work item:

    if self.execute(work_item):
        idle_time = 0
        continue

``Worker.execute()`` never returned a truthy value, so both of those lines were
dead: a worker that had been quiet stayed at ``idle_timeout_max`` forever, and
the poll immediately after processing a work item waited the full maximum.

The defect is arithmetic, not integration, so these are unit tests: the loop runs
in-process against a fake workload manager and a mocked orchestrator.
``idle_time`` is a local variable, so it is observed through the durations the
loop passes to ``_immediate_shutdown_event.wait()`` — that list *is* the backoff
curve.

``test_single_shot_processes_exactly_one_work_item`` guards the other side of the
fix: making ``execute()`` truthy naively would let the ``continue`` skip the
``SINGLE_SHOT`` break below it, and single-shot mode (which nearly every module
test uses) would drain the whole queue instead of running one work item.
"""
from unittest.mock import MagicMock, Mock, patch

import pytest

from saq.analysis.root import RootAnalysis
from saq.constants import LockManagerType, WorkloadManagerType
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.enums import EngineExecutionMode
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker


class FakeWorkloadManager:
    """Hands out a scripted sequence of work targets, then nothing forever.

    A ``None`` in ``items`` is an empty poll (the loop idles); anything else is a
    work target. The queue-empty properties reflect what is left, which is what
    ``UNTIL_COMPLETE`` uses to decide it is done.
    """

    def __init__(self, items=None):
        self.items = list(items or [])
        self.get_calls = 0
        self.cleared = []

    def get_next_work_target(self):
        self.get_calls += 1
        return self.items.pop(0) if self.items else None

    @property
    def workload_queue_is_empty(self) -> bool:
        return self.workload_queue_size == 0

    @property
    def delayed_analysis_queue_is_empty(self) -> bool:
        return True

    @property
    def workload_queue_size(self) -> int:
        return len([_ for _ in self.items if _ is not None])

    @property
    def delayed_analysis_queue_size(self) -> int:
        return 0

    def clear_work_target(self, work_item):
        self.cleared.append(work_item)


class FakeShutdownEvent:
    """Stand-in for ``_immediate_shutdown_event`` that records the idle waits.

    ``wait()`` returns True on the ``stop_after_waits``-th call, which breaks the
    loop — that bound also keeps a broken loop from spinning forever.
    """

    def __init__(self, stop_after_waits: int = 1):
        self.waits = []
        self._stop_after_waits = stop_after_waits

    def is_set(self) -> bool:
        return False

    def set(self):
        pass

    def wait(self, timeout=None) -> bool:
        self.waits.append(timeout)
        return len(self.waits) >= self._stop_after_waits


def make_work_item(uuid_value: str = "00000000-0000-0000-0000-000000000001"):
    """A stand-in RootAnalysis work target. ``spec`` keeps the ``isinstance``
    check in ``execute()`` honest without touching the filesystem."""
    work_item = Mock(spec=RootAnalysis)
    work_item.uuid = uuid_value
    work_item.analysis_mode = "test_empty"
    return work_item


@pytest.fixture
def worker() -> Worker:
    """A real Worker with its collaborators replaced.

    ``Worker`` builds its lock manager, workload manager and orchestrator in
    ``__init__`` with no injection point, so they are reassigned afterwards.
    """
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.single_threaded_mode = True
    configuration_manager.config.auto_refresh_frequency = 0

    worker = Worker(
        name="test_worker",
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )

    worker.workload_manager = FakeWorkloadManager()
    worker.lock_manager = MagicMock()
    worker.analysis_orchestrator = MagicMock()
    worker.analysis_orchestrator.orchestrate_analysis.return_value = True

    # a tracking manager that reports no work target keeps _handle_failed_analysis()
    # from trying to recover a root that does not exist
    worker.tracking_message_manager = MagicMock()
    worker.tracking_message_manager.get_current_work_target.return_value = None
    worker.tracking_message_manager.get_current_analysis_module.return_value = None

    return worker


@pytest.fixture(autouse=True)
def mock_worker_environment():
    """No database sessions, and no work directory (so ``execute()`` skips the
    storage relocation branch)."""
    with patch("saq.engine.worker.remove_all_sessions"), patch(
        "saq.engine.worker.get_engine_config"
    ) as mock_get_engine_config:
        mock_get_engine_config.return_value.work_dir = None
        yield


@pytest.mark.unit
def test_execute_returns_true_after_processing(worker):
    """execute() reports that it processed the work item."""
    assert worker.execute(make_work_item()) is True


@pytest.mark.unit
def test_execute_returns_true_when_orchestration_fails(worker):
    """A failed orchestration still consumed a work item, so the loop should not
    back off because of it."""
    worker.analysis_orchestrator.orchestrate_analysis.return_value = False
    assert worker.execute(make_work_item()) is True


@pytest.mark.unit
def test_execute_returns_true_when_orchestration_raises(worker):
    """Same for an exception - it is swallowed and logged inside execute()."""
    worker.analysis_orchestrator.orchestrate_analysis.side_effect = RuntimeError("boom")
    assert worker.execute(make_work_item()) is True


@pytest.mark.unit
def test_execute_returns_false_when_keepalive_fails(worker):
    """Losing the lock means nothing was processed."""
    worker.config.single_threaded_mode = False
    worker.lock_manager.start_keepalive.return_value = False

    assert worker.execute(make_work_item()) is False
    worker.analysis_orchestrator.orchestrate_analysis.assert_not_called()


@pytest.mark.unit
def test_idle_backoff_resets_after_work(worker):
    """Three empty polls back off 1, 2, 3 - then a work item resets the counter
    so the next empty poll waits 1 second again, not 4."""
    worker.workload_manager = FakeWorkloadManager([None, None, None, make_work_item()])
    shutdown_event = FakeShutdownEvent(stop_after_waits=4)
    worker._immediate_shutdown_event = shutdown_event

    worker.worker_loop(EngineExecutionMode.NORMAL)

    assert shutdown_event.waits == [1, 2, 3, 1]
    assert worker.analysis_orchestrator.orchestrate_analysis.call_count == 1


@pytest.mark.unit
def test_idle_backoff_caps_at_idle_timeout_max(worker):
    """Without work the backoff climbs by one second per poll and clamps."""
    worker.idle_timeout_max = 2
    shutdown_event = FakeShutdownEvent(stop_after_waits=4)
    worker._immediate_shutdown_event = shutdown_event

    worker.worker_loop(EngineExecutionMode.NORMAL)

    assert shutdown_event.waits == [1, 2, 2, 2]


@pytest.mark.unit
def test_single_shot_processes_exactly_one_work_item(worker):
    """SINGLE_SHOT means one work item, even with more waiting - the idle reset
    must not skip the single shot check."""
    worker.workload_manager = FakeWorkloadManager([make_work_item(), make_work_item()])
    shutdown_event = FakeShutdownEvent(stop_after_waits=1)
    worker._immediate_shutdown_event = shutdown_event

    worker.worker_loop(EngineExecutionMode.SINGLE_SHOT)

    assert worker.workload_manager.get_calls == 1
    assert worker.analysis_orchestrator.orchestrate_analysis.call_count == 1
    assert shutdown_event.waits == []


@pytest.mark.unit
def test_until_complete_drains_without_idling(worker):
    """UNTIL_COMPLETE processes everything queued and exits on the empty queue
    check at the top of the loop - it never idles."""
    worker.workload_manager = FakeWorkloadManager([make_work_item(), make_work_item()])
    shutdown_event = FakeShutdownEvent(stop_after_waits=1)
    worker._immediate_shutdown_event = shutdown_event

    worker.worker_loop(EngineExecutionMode.UNTIL_COMPLETE)

    assert worker.analysis_orchestrator.orchestrate_analysis.call_count == 2
    assert shutdown_event.waits == []
