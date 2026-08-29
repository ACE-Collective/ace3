"""Tests for the keepalive failure path in ``Worker.execute`` (see docs/ENGINE.md §19.9).

``get_next_work_target()`` claims a work item by inserting a row into ``locks``
before it hands the item back. ``execute()`` then starts the keepalive thread
that holds that claim open -- and it did so *before* the ``try``, so the
``finally`` that gives the claim back never ran on the failure path:

    if not self.lock_manager.start_keepalive(work_item.uuid, ...):
        logging.error("detected lock failure for work item {}".format(work_item))
        self.current_execution_context = None
        return False

The item was never analyzed, so its ``workload`` row correctly survived -- but
so did the ``locks`` row, and ``get_work_target()`` selects on
``locks.uuid IS NULL``. Nothing could pick the item up again until
``lock_timeout_seconds`` expired and the recovery path took it over: a silent
multi-minute stall for a failure the doc describes as transient.

The fix releases the claim (but *not* the workload row -- dropping an item that
was never analyzed would orphan its storage directory) and stops any keepalive
thread leaked by a previous work item, which is the other reason
``start_keepalive`` returns False and which otherwise poisons every subsequent
work item on that worker.

``test_worker_loop_backs_off_after_keepalive_failure`` guards the other side of
the fix: ``worker_loop`` only backed off when *no work was found*, so an item it
could not claim was re-polled with no sleep. The leaked lock used to hide that
(the item became invisible); once the claim is returned correctly, a persistent
failure would hot-spin on the database instead.
"""
import uuid as uuidlib
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import pytest

from saq.analysis.root import RootAnalysis
from saq.constants import LockManagerType, WorkloadManagerType
from saq.database.pool import get_db_connection
from saq.database.util.locking import force_release_lock
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.engine.node_manager.node_manager_factory import create_node_manager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.environment import get_global_runtime_settings
from saq.util.uuid import storage_dir_from_uuid

#
# unit tests
# ----------------------------------------------------------------------------

WORK_ITEM_UUID = "00000000-0000-0000-0000-000000000001"


class FakeWorkloadManager:
    """Hands out a scripted sequence of work targets, then nothing forever.

    Every poll is appended to ``event_log`` so a test can see how the loop
    interleaves polling with backing off.
    """

    def __init__(self, items=None, event_log=None):
        self.items = list(items or [])
        self.get_calls = 0
        self.cleared = []
        self.event_log = event_log if event_log is not None else []

    def get_next_work_target(self):
        self.get_calls += 1
        item = self.items.pop(0) if self.items else None
        self.event_log.append("poll" if item is not None else "poll-empty")
        return item

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
    loop -- that bound also keeps a broken loop from spinning forever.
    """

    def __init__(self, stop_after_waits: int = 1, event_log=None):
        self.waits = []
        self._stop_after_waits = stop_after_waits
        self.event_log = event_log if event_log is not None else []

    def is_set(self) -> bool:
        return False

    def set(self):
        pass

    def wait(self, timeout=None) -> bool:
        self.waits.append(timeout)
        self.event_log.append(f"wait({timeout})")
        return len(self.waits) >= self._stop_after_waits


def make_work_item(uuid_value: str = WORK_ITEM_UUID):
    """A stand-in RootAnalysis work target. ``spec`` keeps the ``isinstance``
    check in ``execute()`` honest without touching the filesystem."""
    work_item = Mock(spec=RootAnalysis)
    work_item.uuid = uuid_value
    work_item.analysis_mode = "test_empty"
    return work_item


def make_delayed_work_item(uuid_value: str = WORK_ITEM_UUID) -> DelayedAnalysisRequest:
    return DelayedAnalysisRequest(
        uuid_value,
        "00000000-0000-0000-0000-0000000000ff",
        "some_analysis_module",
        datetime.now(),
        storage_dir_from_uuid(uuid_value),
        database_id=1,
    )


@pytest.fixture
def worker() -> Worker:
    """A real Worker with its collaborators replaced.

    ``Worker`` builds its lock manager, workload manager and orchestrator in
    ``__init__`` with no injection point, so they are reassigned afterwards.
    ``single_threaded_mode`` is False here because that is the only mode in
    which the keepalive -- and therefore this failure path -- exists at all.
    """
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.single_threaded_mode = False
    configuration_manager.config.auto_refresh_frequency = 0

    worker = Worker(
        name="test_worker",
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )

    worker.workload_manager = FakeWorkloadManager()
    worker.lock_manager = MagicMock()
    worker.lock_manager.start_keepalive.return_value = False
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
def test_keepalive_failure_releases_the_lock(worker):
    """The claim taken by get_next_work_target() goes back immediately."""
    work_item = make_work_item()

    assert worker.execute(work_item) is False

    worker.lock_manager.release_lock.assert_called_once()
    assert worker.lock_manager.release_lock.call_args.args[0] == work_item.uuid


@pytest.mark.unit
def test_keepalive_failure_leaves_the_work_item_in_the_workload(worker):
    """We never analyzed it, so the workload row has to stay -- releasing the
    lock is what makes it available again, not deleting it."""
    assert worker.execute(make_work_item()) is False

    assert worker.workload_manager.cleared == []


@pytest.mark.unit
def test_keepalive_failure_stops_a_leaked_keepalive(worker):
    """A keepalive thread left behind by a previous work item is the other
    reason start_keepalive fails; clearing it lets the next item start one."""
    assert worker.execute(make_work_item()) is False

    worker.lock_manager.stop_keepalive.assert_called_once()


@pytest.mark.unit
def test_keepalive_failure_does_not_analyze(worker):
    """Losing the lock means nothing was processed."""
    assert worker.execute(make_work_item()) is False

    worker.analysis_orchestrator.orchestrate_analysis.assert_not_called()


@pytest.mark.unit
def test_keepalive_failure_releases_lock_for_delayed_analysis_request(worker):
    """Delayed analysis requests are claimed the same way and must be returned
    the same way."""
    work_item = make_delayed_work_item()

    assert worker.execute(work_item) is False

    worker.lock_manager.release_lock.assert_called_once()
    assert worker.lock_manager.release_lock.call_args.args[0] == work_item.uuid
    assert worker.workload_manager.cleared == []


@pytest.mark.unit
def test_successful_keepalive_clears_the_work_target(worker):
    """The normal path is unchanged: the finally still does the cleanup, and the
    lock is released through clear_work_target rather than directly."""
    worker.lock_manager.start_keepalive.return_value = True
    work_item = make_work_item()

    assert worker.execute(work_item) is True

    worker.analysis_orchestrator.orchestrate_analysis.assert_called_once()
    worker.lock_manager.stop_keepalive.assert_called_once()
    worker.lock_manager.release_lock.assert_not_called()
    assert worker.workload_manager.cleared == [work_item]


@pytest.mark.unit
def test_worker_loop_backs_off_after_keepalive_failure(worker):
    """A work item we could not claim backs off exactly like an empty poll.

    Without this the loop re-polls immediately, and since the fix above makes
    the item selectable again the very next query, a persistent keepalive
    failure becomes a hot spin on the database.
    """
    event_log = []
    worker.workload_manager = FakeWorkloadManager(
        [make_work_item(), make_work_item(), make_work_item()], event_log=event_log
    )
    shutdown_event = FakeShutdownEvent(stop_after_waits=3, event_log=event_log)
    worker._immediate_shutdown_event = shutdown_event

    worker.worker_loop(EngineExecutionMode.NORMAL)

    # one wait per unclaimable item, with the backoff climbing as it does when
    # there is no work at all
    assert event_log == ["poll", "wait(1)", "poll", "wait(2)", "poll", "wait(3)"]
    assert worker.workload_manager.get_calls == 3


#
# integration tests
# ----------------------------------------------------------------------------


def local_node_id() -> int:
    return get_global_runtime_settings().saq_node_id


def insert_workload(uuid: str, analysis_mode: str) -> None:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            """INSERT INTO workload ( uuid, node_id, analysis_mode, company_id, storage_dir, insert_date )
               VALUES ( %s, %s, %s, %s, %s, NOW() )""",
            (uuid, local_node_id(), analysis_mode, get_global_runtime_settings().company_id,
             storage_dir_from_uuid(uuid)),
        )
        db.commit()


def lock_row(uuid: str):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT lock_uuid FROM locks WHERE uuid = %s", (uuid,))
        return cursor.fetchone()


def workload_row(uuid: str):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM workload WHERE uuid = %s", (uuid,))
        return cursor.fetchone()


def delete_workload(uuid: str) -> None:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM workload WHERE uuid = %s", (uuid,))
        db.commit()


@pytest.fixture
def claimed_work_item():
    """A real workload row, claimed through the real database workload manager.

    Yields ``(worker, uuid, work_item)`` with the ``locks`` row already in place
    -- exactly the state ``execute()`` is entered in.
    """
    configuration_manager = ConfigurationManager(EngineConfiguration())
    node_manager = create_node_manager(configuration_manager)
    node_manager.initialize_node()

    worker = Worker(
        name="test_keepalive_failure",
        configuration_manager=configuration_manager,
        node_manager=node_manager,
    )

    analysis_mode = configuration_manager.config.local_analysis_modes[0]
    _uuid = str(uuidlib.uuid4())
    insert_workload(_uuid, analysis_mode)

    try:
        work_item = worker.workload_manager.get_next_work_target()
        assert work_item is not None and work_item.uuid == _uuid
        # the claim is in place before execute() is ever called
        assert lock_row(_uuid) is not None

        yield worker, _uuid, work_item
    finally:
        force_release_lock(_uuid)
        delete_workload(_uuid)


@pytest.mark.integration
def test_keepalive_failure_releases_the_database_lock(claimed_work_item):
    """The locks row is gone and the workload row is not."""
    worker, _uuid, work_item = claimed_work_item

    with patch.object(worker.lock_manager, "start_keepalive", return_value=False):
        assert worker.execute(work_item) is False

    assert lock_row(_uuid) is None, "the claim was leaked (docs/ENGINE.md §19.9)"
    assert workload_row(_uuid) is not None, "an unanalyzed work item was dropped"


@pytest.mark.integration
def test_work_item_is_reselectable_after_keepalive_failure(claimed_work_item):
    """The actual harm in §19.9: until the claim comes back, get_work_target()
    cannot see the item (it selects on locks.uuid IS NULL), so it stalls until
    lock_timeout_seconds expires."""
    worker, _uuid, work_item = claimed_work_item

    with patch.object(worker.lock_manager, "start_keepalive", return_value=False):
        assert worker.execute(work_item) is False

    again = worker.workload_manager.get_next_work_target()
    assert again is not None, "work item stalled behind its own leaked lock"
    assert again.uuid == _uuid
