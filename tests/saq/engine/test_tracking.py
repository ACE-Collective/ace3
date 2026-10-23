"""Tests for the worker tracking subsystem (ENGINE.md 19.12).

Tracking answers one question: when a worker dies in the middle of a module, which module
was it? Without that answer the replacement worker picks the same work item back up (its
workload row was never deleted), runs the same module, and dies again.

The worker writes the answer to its own file; the manager reads that file only when it needs
it, and promotes it into ``pending/`` when the worker dies. The worker being the thing that
dies is not a reason to keep the state anywhere else -- the file outlives the process.
"""
import json
import logging
import os
import re
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_analysis_module_config
from saq.constants import F_TEST
from saq.database.util.locking import acquire_lock, get_lock_uuid, release_lock
from saq.engine import tracking
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.lock_manager.adapter import LockManagerAdapter
from saq.engine.lock_manager.distributed import DistributedLockManager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.modules.test import BasicTestAnalyzer
from saq.engine.tracking import (
    NullTrackingWriter,
    TrackingReader,
    TrackingRecord,
    TrackingWriter,
    clear_all_tracking,
    get_pending_dir,
    get_pending_tracking_path,
    get_tracking_dir,
    get_worker_tracking_path,
)


ROOT_UUID = "11111111-1111-1111-1111-111111111111"
OTHER_ROOT_UUID = "22222222-2222-2222-2222-222222222222"

MODULE_PATH = "saq.modules.test:BasicTestAnalysis"


def _target(uuid=ROOT_UUID, storage_dir="/data/root"):
    target = Mock(spec=RootAnalysis)
    target.uuid = uuid
    target.storage_dir = storage_dir
    return target


def _module(maximum_analysis_time=60):
    module = MagicMock()
    module.maximum_analysis_time = maximum_analysis_time
    return module


def _observable(uuid="obs-1", type="test", value="test_1"):
    observable = MagicMock()
    observable.uuid = uuid
    observable.type = type
    observable.value = value
    return observable


def _basic_test_module() -> BasicTestAnalyzer:
    return BasicTestAnalyzer(get_analysis_module_config("basic_test"))


def _track(writer, module_path=MODULE_PATH, maximum_analysis_time=60):
    with patch("saq.engine.tracking.MODULE_PATH", return_value=module_path):
        writer.track_current_analysis_module(_module(maximum_analysis_time), _observable())


@pytest.fixture
def writer():
    """A real writer against this node's real tracking directory.

    ``clear_all_tracking()`` runs per test (tests/conftest.py), so each of these starts empty.
    """
    return TrackingWriter("any-0")


@pytest.fixture
def reader():
    return TrackingReader()


#
# the record itself
#

@pytest.mark.unit
def test_record_round_trips_through_json():
    record = TrackingRecord(
        root_uuid=ROOT_UUID,
        storage_dir="/data/root",
        worker_name="any-0",
        module_path=MODULE_PATH,
        observable_type="test",
        observable_value="test_1",
        maximum_analysis_time=60,
        module_start_monotonic=1234.5,
    )

    restored = TrackingRecord.from_dict(json.loads(json.dumps(record.to_dict())))
    assert restored == record
    # the deadline is derived, not stored, and is directly comparable to time.monotonic()
    assert restored.module_deadline == 1294.5


@pytest.mark.unit
def test_from_dict_ignores_unknown_keys():
    """A snapshot written by another build must not break a load."""
    record = TrackingRecord.from_dict({
        "root_uuid": ROOT_UUID,
        "storage_dir": "/data/root",
        "worker_name": "any-0",
        "something_from_the_future": True,
    })

    assert record.root_uuid == ROOT_UUID
    assert not record.has_module


@pytest.mark.unit
def test_deadline_is_none_without_a_module_or_a_limit():
    record = TrackingRecord(root_uuid=ROOT_UUID, storage_dir="/data/root", worker_name="any-0")
    assert record.module_deadline is None

    record.module_start_monotonic = time.monotonic()
    assert record.module_deadline is None, "no maximum_analysis_time means no deadline"


#
# what the worker writes
#

@pytest.mark.unit
def test_tracking_a_target_writes_the_worker_file(writer, reader):
    writer.track_current_work_target(_target())

    record = reader.read_worker_record("any-0")
    assert record.root_uuid == ROOT_UUID
    assert record.storage_dir == "/data/root"
    assert record.worker_name == "any-0"
    assert record.pid == os.getpid()
    assert not record.has_module


@pytest.mark.unit
def test_the_workers_lock_uuid_survives_into_the_pending_record(writer, reader):
    """Recovery may release the dead worker's lock and no other, so the record has to say which
    lock that was."""
    writer.track_current_work_target(_target(), lock_uuid="dead-lock-uuid")
    _track(writer)

    pending = reader.recover_pending_failures()
    assert [r.lock_uuid for r in pending] == ["dead-lock-uuid"]


@pytest.mark.unit
def test_tracking_a_module_records_the_observable(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)

    record = reader.read_worker_record("any-0")
    assert record.module_path == MODULE_PATH
    # carried alongside the uuid because set_analysis_failed keys on type:value, and because
    # the observable may never have reached storage
    assert (record.observable_type, record.observable_value) == ("test", "test_1")
    assert record.observable_uuid == "obs-1"
    assert record.module_start_monotonic is not None


@pytest.mark.unit
def test_a_new_target_clears_stale_module_state(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)
    writer.track_current_work_target(_target(uuid=OTHER_ROOT_UUID))

    record = reader.read_worker_record("any-0")
    assert record.root_uuid == OTHER_ROOT_UUID
    assert not record.has_module


@pytest.mark.unit
def test_clearing_the_module_leaves_the_target(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)
    writer.clear_module_tracking()

    record = reader.read_worker_record("any-0")
    assert record.root_uuid == ROOT_UUID
    assert not record.has_module
    assert record.module_deadline is None


@pytest.mark.unit
def test_clearing_the_target_removes_the_file(writer, reader):
    writer.track_current_work_target(_target())
    writer.clear_target_tracking()

    assert reader.read_worker_record("any-0") is None
    assert not os.path.exists(get_worker_tracking_path("any-0"))


@pytest.mark.unit
def test_module_tracking_without_a_target_is_ignored(writer, reader):
    _track(writer)
    assert reader.read_worker_record("any-0") is None


@pytest.mark.unit
def test_the_write_is_atomic(writer):
    """tmp + rename, so a reader never sees a torn record and no .tmp is left behind."""
    writer.track_current_work_target(_target())
    _track(writer)

    assert os.path.exists(get_worker_tracking_path("any-0"))
    assert not os.path.exists(f"{get_worker_tracking_path('any-0')}.tmp")


@pytest.mark.unit
def test_the_null_writer_writes_nothing(reader):
    """Single threaded mode has no manager to read this, so it must not pay for it."""
    writer = NullTrackingWriter("any-0")
    writer.track_current_work_target(_target())
    _track(writer)

    assert reader.read_worker_record("any-0") is None
    assert not os.path.exists(get_worker_tracking_path("any-0"))


#
# what the manager reads
#

@pytest.mark.unit
def test_a_missing_file_reads_as_nothing_tracked(reader):
    assert reader.read_worker_record("never-existed") is None


@pytest.mark.unit
def test_a_corrupt_file_reads_as_nothing_tracked(writer, reader):
    writer.track_current_work_target(_target())
    with open(get_worker_tracking_path("any-0"), "w") as fp:
        fp.write('{"root_uuid": "11111111')

    # deliberately "nothing was tracked" rather than a plausible looking half record
    assert reader.read_worker_record("any-0") is None


@pytest.mark.unit
def test_timeout_is_computed_from_monotonic_time(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer, maximum_analysis_time=60)

    record = reader.read_worker_record("any-0")
    assert time.monotonic() < record.module_deadline

    # stamp the module start 61 seconds in the past
    with patch("saq.engine.tracking.time.monotonic", return_value=time.monotonic() - 61):
        _track(writer, maximum_analysis_time=60)

    assert time.monotonic() >= reader.read_worker_record("any-0").module_deadline


#
# failure attribution
#

@pytest.mark.unit
def test_claiming_a_failure_promotes_it_to_pending(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)

    record = reader.claim_failure("any-0")
    assert record.module_path == MODULE_PATH
    assert record.pending_failure

    # the worker file is gone so the replacement (which reuses the name) starts clean, but
    # the failure survives in its own file
    assert not os.path.exists(get_worker_tracking_path("any-0"))
    assert os.path.exists(get_pending_tracking_path(ROOT_UUID))


@pytest.mark.unit
def test_a_worker_that_died_between_modules_has_nothing_to_attribute(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)
    writer.clear_module_tracking()

    assert reader.claim_failure("any-0") is None
    assert not os.path.exists(get_worker_tracking_path("any-0"))
    assert os.listdir(get_pending_dir()) == []


@pytest.mark.unit
def test_a_worker_with_no_file_has_nothing_to_attribute(reader):
    assert reader.claim_failure("any-0") is None


@pytest.mark.unit
def test_a_pending_failure_survives_until_acknowledged(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)
    reader.claim_failure("any-0")

    # a replacement that dies before it applies the record leaves it for the next one
    assert [r.root_uuid for r in reader.recover_pending_failures()] == [ROOT_UUID]

    writer.resolve_pending_failure(ROOT_UUID)
    assert reader.recover_pending_failures() == []


@pytest.mark.unit
def test_reclaiming_the_same_root_does_not_wipe_the_pending_failure(writer, reader):
    """The replacement normally re-claims the very root that killed its predecessor.

    The failure lives in its own file keyed on root_uuid, so the new work target -- which is
    the same root, written by a worker reusing the same name -- cannot overwrite it. That is
    exactly the crash loop this subsystem exists to prevent.
    """
    writer.track_current_work_target(_target())
    _track(writer, module_path="saq.modules.test:Killer")
    reader.claim_failure("any-0")

    replacement = TrackingWriter("any-0")
    replacement.track_current_work_target(_target())
    _track(replacement, module_path="saq.modules.test:Innocent")

    with open(get_pending_tracking_path(ROOT_UUID)) as fp:
        assert json.load(fp)["module_path"] == "saq.modules.test:Killer"

    # and the live worker is tracked independently of it
    assert reader.read_worker_record("any-0").module_path == "saq.modules.test:Innocent"


@pytest.mark.unit
def test_a_replacement_on_a_different_root_leaves_the_failure_alone(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer, module_path="saq.modules.test:Killer")
    reader.claim_failure("any-0")

    replacement = TrackingWriter("any-0")
    replacement.track_current_work_target(_target(uuid=OTHER_ROOT_UUID))

    assert os.path.exists(get_pending_tracking_path(ROOT_UUID))
    assert reader.read_worker_record("any-0").root_uuid == OTHER_ROOT_UUID


#
# startup recovery
#

@pytest.mark.unit
def test_startup_promotes_a_leftover_worker_file(writer, reader):
    """A record still naming a module was never cleared by its owner, so it is unresolved."""
    writer.track_current_work_target(_target())
    _track(writer)

    pending = reader.recover_pending_failures()
    assert [r.root_uuid for r in pending] == [ROOT_UUID]
    assert pending[0].pending_failure
    assert not os.path.exists(get_worker_tracking_path("any-0"))


@pytest.mark.unit
def test_startup_does_not_resurrect_a_cleanly_finished_root(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)
    writer.clear_module_tracking()
    writer.clear_target_tracking()

    assert reader.recover_pending_failures() == []


@pytest.mark.unit
def test_startup_discards_a_worker_file_with_no_module(writer, reader):
    """Nothing to attribute, and keeping it would leave an entry nobody ever clears."""
    writer.track_current_work_target(_target())

    assert reader.recover_pending_failures() == []
    assert not os.path.exists(get_worker_tracking_path("any-0"))


@pytest.mark.unit
def test_a_corrupt_pending_file_is_skipped(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)
    reader.claim_failure("any-0")

    with open(get_pending_tracking_path(ROOT_UUID), "w") as fp:
        fp.write("}{ not json")

    assert reader.recover_pending_failures() == []


@pytest.mark.unit
def test_tracking_is_scoped_to_the_node():
    """Two engines sharing a data directory must not collide."""
    from saq.environment import get_global_runtime_settings

    settings = get_global_runtime_settings()
    original = settings.saq_node
    try:
        settings.saq_node = "node-a"
        TrackingWriter("any-0").track_current_work_target(_target())
        node_a_dir = get_tracking_dir()

        settings.saq_node = "node-b"
        node_b_dir = get_tracking_dir()

        assert node_a_dir != node_b_dir
        assert TrackingReader().read_worker_record("any-0") is None
    finally:
        settings.saq_node = original


@pytest.mark.unit
def test_clear_all_tracking_removes_every_node(writer):
    writer.track_current_work_target(_target())
    assert os.path.exists(get_worker_tracking_path("any-0"))

    clear_all_tracking()
    assert not os.path.exists(get_tracking_dir())


@pytest.mark.unit
def test_startup_dispatch_survives_a_shrunken_pool():
    """A record recovered at startup is handed to *a* worker, not to the worker named in it.

    Matching on worker name would strand every record whose worker no longer exists, which
    is exactly what happens when analysis_pools or pool_size_limit shrinks between runs.
    The record is self describing (root_uuid + storage_dir), so any worker can apply it.
    """
    from saq.engine.enums import EngineExecutionMode, EngineType
    from saq.engine.worker_manager import WorkerManager
    from tests.saq.engine.test_worker_restart_execution_mode import FakeWorker

    # a previous, larger run left a record behind for a worker that no longer exists
    previous = TrackingWriter("correlation-7")
    previous.track_current_work_target(_target())
    _track(previous)

    configuration_manager = ConfigurationManager(EngineConfiguration(
        engine_type=EngineType.LOCAL,
        analysis_pools={"correlation": 2},
        pool_size_limit=2,
        single_threaded_mode=False,
    ))

    with patch("saq.engine.worker_manager.Worker", FakeWorker):
        manager = WorkerManager(configuration_manager, Mock(spec=NodeManagerInterface))
        manager.initialize_workers()
        manager.start_workers(execution_mode=EngineExecutionMode.NORMAL)

        dispatched = [
            record
            for worker in manager.workers
            for record in worker.pending_failures
            if record is not None
        ]
        assert len(dispatched) == 1
        assert dispatched[0].root_uuid == ROOT_UUID
        # none of the live workers is named correlation-7
        assert "correlation-7" not in {worker.name for worker in manager.workers}


@pytest.mark.integration
def test_recovered_record_lands_on_the_right_root(root_analysis):
    """End to end for a full engine restart: the worker died without ever resolving a
    failure, the next manager reads it off disk, and the module that killed the worker is
    recorded against the root it was actually analyzing."""
    from saq.constants import F_TEST
    from saq.modules.test import BasicTestAnalysis
    from saq.util.uuid import get_storage_dir

    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()

    # a worker was analyzing this root with this module when everything died
    dying = TrackingWriter("correlation-0")
    dying.track_current_work_target(root_analysis)
    dying.track_current_analysis_module(_basic_test_module(), observable)

    # a fresh manager comes up and reads what the old one left behind
    pending = TrackingReader().recover_pending_failures()
    assert len(pending) == 1
    assert pending[0].root_uuid == root_analysis.uuid

    assert _recovering_worker()._handle_failed_analysis(pending[0])

    reloaded = RootAnalysis(storage_dir=get_storage_dir(root_analysis.uuid))
    reloaded.load()
    assert reloaded.is_analysis_failed(
        BasicTestAnalysis, reloaded.get_observable(observable.uuid)
    ), "the failure was not recorded against the root named in the recovered record"

    # and the worker acknowledged it, so the next restart will not replay it
    assert TrackingReader().recover_pending_failures() == []
    assert get_lock_uuid(root_analysis.uuid) is None, "recovery did not release its own lock"


@pytest.mark.integration
def test_killed_report_collects_the_dead_workers_hang_dump(root_analysis):
    """The pre-kill thread dump the dead worker left in hang_stacks/<node>/<pid>.txt ends up in
    the killed report as thread_stacks.txt, and the source file is removed once it has."""
    from saq.constants import F_TEST
    from saq.crash_report import (
        CRASH_TYPE_KILLED,
        THREAD_STACKS_FILE,
        find_crash_report_dir,
        get_hang_stacks_path,
        read_crash_report,
    )

    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()

    dying = TrackingWriter("correlation-0")
    dying.track_current_work_target(root_analysis)
    dying.track_current_analysis_module(_basic_test_module(), observable)

    pending = TrackingReader().recover_pending_failures()
    assert len(pending) == 1
    assert pending[0].pid is not None

    # what faulthandler's dump_traceback_later left behind in the dying worker
    stacks = (
        "Timeout (0:00:55)!\n"
        "Thread 0x00007f0000000001 [python] (most recent call first):\n"
        '  File "/opt/ace/saq/modules/test.py", line 170 in execute_analysis_worker_gil_hang\n'
    )
    hang_path = get_hang_stacks_path(pending[0].pid)
    os.makedirs(os.path.dirname(hang_path), exist_ok=True)
    with open(hang_path, "w") as fp:
        fp.write(stacks)

    assert _recovering_worker()._handle_failed_analysis(pending[0])

    # the killed report's id rides in the failure message: "process died unexpectedly (crash_id <id>)"
    reloaded = RootAnalysis(storage_dir=root_analysis.storage_dir)
    reloaded.load()
    message = reloaded.get_analysis_failed_message(MODULE_PATH, reloaded.get_observable(observable.uuid))
    match = re.search(r"\(crash_id ([0-9a-f-]{36})\)", message or "")
    assert match, f"no crash id in the failure message {message!r}"

    report = read_crash_report(match.group(1))
    assert report["crash_type"] == CRASH_TYPE_KILLED

    crash_dir = find_crash_report_dir(match.group(1))
    with open(os.path.join(crash_dir, THREAD_STACKS_FILE)) as fp:
        assert fp.read() == stacks

    assert not os.path.exists(hang_path)
    assert get_lock_uuid(root_analysis.uuid) is None, "recovery did not release its own lock"


@pytest.mark.integration
def test_a_failure_for_a_deleted_root_is_resolved_not_replayed(root_analysis):
    """A root that no longer exists can never be attributed, so the record must not be
    immortal -- otherwise it is handed to a worker again at every engine start, forever."""

    dying = TrackingWriter("correlation-0")
    dying.track_current_work_target(_target(uuid=root_analysis.uuid, storage_dir="/does/not/exist"))
    _track(dying)

    pending = TrackingReader().recover_pending_failures()
    assert len(pending) == 1

    assert _recovering_worker()._handle_failed_analysis(pending[0])

    assert TrackingReader().recover_pending_failures() == []


#
# recovery and the root's lock
#

DEAD_LOCK_UUID = "33333333-3333-3333-3333-333333333333"
LIVE_LOCK_UUID = "44444444-4444-4444-4444-444444444444"


def _recovering_worker() -> Worker:
    """A replacement worker using real database locks, like a distributed engine."""
    worker = Worker(
        name="correlation-0",
        configuration_manager=ConfigurationManager(EngineConfiguration()),
        node_manager=Mock(spec=NodeManagerInterface),
    )
    worker.lock_manager = LockManagerAdapter(lock_manager=DistributedLockManager(lock_owner="recovering"))
    return worker


def _pending_failure_for(root_analysis, lock_uuid) -> tuple[TrackingRecord, object]:
    """Saves root_analysis with one observable and leaves a pending failure for it, as a worker
    killed while analyzing that observable under lock_uuid would."""
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()

    dying = TrackingWriter("correlation-0")
    dying.track_current_work_target(root_analysis, lock_uuid=lock_uuid)
    dying.track_current_analysis_module(_basic_test_module(), observable)

    pending = TrackingReader().recover_pending_failures()
    assert len(pending) == 1
    return pending[0], observable


def _is_marked_failed(root_analysis, observable) -> bool:
    reloaded = RootAnalysis(storage_dir=root_analysis.storage_dir)
    reloaded.load()
    return reloaded.get_analysis_failed_message(MODULE_PATH, reloaded.get_observable(observable.uuid)) is not None


@pytest.mark.integration
def test_recovery_never_releases_a_live_workers_lock(root_analysis):
    """Regression: the replacement released whatever lock the root had, which was a live worker
    analyzing it. A third worker then took the root, found no outstanding work when it finished,
    and deleted the storage directory while the live worker was still using it."""
    record, observable = _pending_failure_for(root_analysis, DEAD_LOCK_UUID)

    # the dead worker's lock is already gone and a live worker has the root
    assert acquire_lock(root_analysis.uuid, LIVE_LOCK_UUID, lock_owner="live")

    worker = _recovering_worker()
    assert not worker._handle_failed_analysis(record), "recovery must defer, not wait, while the root is locked"

    assert get_lock_uuid(root_analysis.uuid) == LIVE_LOCK_UUID
    assert not _is_marked_failed(root_analysis, observable), "the root was modified without its lock"
    assert len(TrackingReader().recover_pending_failures()) == 1, "an unrecorded failure was acknowledged"

    # once the live worker is done, the retry between work items records it
    assert release_lock(root_analysis.uuid, LIVE_LOCK_UUID)
    assert worker._handle_failed_analysis(record)

    assert _is_marked_failed(root_analysis, observable)
    assert TrackingReader().recover_pending_failures() == []
    assert get_lock_uuid(root_analysis.uuid) is None, "recovery did not release its own lock"


@pytest.mark.integration
def test_recovery_releases_the_dead_workers_lock(root_analysis):
    record, observable = _pending_failure_for(root_analysis, DEAD_LOCK_UUID)

    # SIGKILL left the dead worker's lock behind
    assert acquire_lock(root_analysis.uuid, DEAD_LOCK_UUID, lock_owner="dead")

    assert _recovering_worker()._handle_failed_analysis(record)

    assert _is_marked_failed(root_analysis, observable)
    assert TrackingReader().recover_pending_failures() == []
    assert get_lock_uuid(root_analysis.uuid) is None


@pytest.mark.integration
def test_a_record_without_a_lock_uuid_releases_nothing(root_analysis):
    """Records written before the lock was tracked cannot say which lock was the dead worker's,
    so recovery must not guess."""
    record, observable = _pending_failure_for(root_analysis, None)
    assert acquire_lock(root_analysis.uuid, LIVE_LOCK_UUID, lock_owner="live")

    assert not _recovering_worker()._handle_failed_analysis(record)

    assert get_lock_uuid(root_analysis.uuid) == LIVE_LOCK_UUID
    assert not _is_marked_failed(root_analysis, observable)


#
# failures: the writer swallows them, the reader keeps what it could not promote
#

def _failing_pending_writes(monkeypatch):
    """Makes every write into the pending directory fail; worker files still write."""
    real_write_atomic = tracking._write_atomic

    def _write_atomic(path, payload):
        if path.startswith(get_pending_dir()):
            raise OSError(f"no space left on device: {path}")
        real_write_atomic(path, payload)

    monkeypatch.setattr(tracking, "_write_atomic", _write_atomic)


@pytest.mark.unit
def test_a_write_recreates_a_tracking_directory_that_went_away(writer, reader):
    clear_all_tracking()

    writer.track_current_work_target(_target())

    assert reader.read_worker_record("any-0").root_uuid == ROOT_UUID


@pytest.mark.unit
def test_a_failed_write_never_reaches_the_worker(writer, monkeypatch, caplog):
    def _write_atomic(path, payload):
        raise OSError("read-only file system")

    monkeypatch.setattr(tracking, "_write_atomic", _write_atomic)

    with caplog.at_level(logging.DEBUG):
        writer.track_current_work_target(_target())
        _track(writer)

    assert not os.path.exists(get_worker_tracking_path("any-0"))
    assert "unable to write tracking for any-0" in caplog.text


@pytest.mark.unit
def test_a_writer_without_a_tracking_directory_does_nothing(monkeypatch, reader):
    def _makedirs(path, exist_ok=False):
        raise PermissionError(f"permission denied: {path}")

    monkeypatch.setattr(tracking.os, "makedirs", _makedirs)
    writer = TrackingWriter("any-0")
    monkeypatch.undo()

    assert writer.path is None
    writer.track_current_work_target(_target())
    _track(writer)
    writer.clear_target_tracking()
    assert reader.read_worker_record("any-0") is None


@pytest.mark.unit
def test_a_failed_clear_never_reaches_the_worker(writer, caplog):
    # a directory where the file should be cannot be removed with os.remove
    os.makedirs(get_worker_tracking_path("any-0"))

    with caplog.at_level(logging.DEBUG):
        writer.clear_target_tracking()

    assert writer.record is None
    assert "unable to clear tracking for any-0" in caplog.text


@pytest.mark.unit
def test_resolving_a_failure_twice_is_harmless(writer, reader):
    writer.track_current_work_target(_target())
    _track(writer)
    reader.claim_failure("any-0")

    writer.resolve_pending_failure(ROOT_UUID)
    writer.resolve_pending_failure(ROOT_UUID)

    assert reader.recover_pending_failures() == []


@pytest.mark.unit
def test_a_failed_promotion_is_logged_and_recovered_at_startup(writer, reader, monkeypatch, caplog):
    writer.track_current_work_target(_target())
    _track(writer)
    _failing_pending_writes(monkeypatch)

    with caplog.at_level(logging.ERROR):
        assert reader.claim_failure("any-0") is None

    record = next(r for r in caplog.records if "unable to record pending failure" in r.getMessage())
    assert record.levelno == logging.ERROR
    assert record.exc_info is not None
    assert record.worker_name == "any-0"
    assert record.root_uuid == ROOT_UUID
    # the worker file is the only copy of the attribution, so it stays
    assert os.path.exists(get_worker_tracking_path("any-0"))

    monkeypatch.undo()
    assert [r.root_uuid for r in reader.recover_pending_failures()] == [ROOT_UUID]


@pytest.mark.unit
def test_a_failed_startup_promotion_keeps_the_worker_file(writer, reader, monkeypatch, caplog):
    writer.track_current_work_target(_target())
    _track(writer)
    _failing_pending_writes(monkeypatch)

    with caplog.at_level(logging.ERROR):
        assert reader.recover_pending_failures() == []

    record = next(r for r in caplog.records if "unable to recover pending failure" in r.getMessage())
    assert record.levelno == logging.ERROR
    assert record.exc_info is not None
    assert record.root_uuid == ROOT_UUID
    assert os.path.exists(get_worker_tracking_path("any-0"))


@pytest.mark.unit
def test_startup_without_a_tracking_directory_recovers_nothing(reader, monkeypatch, caplog):
    def _makedirs(path, exist_ok=False):
        raise PermissionError(f"permission denied: {path}")

    monkeypatch.setattr(tracking.os, "makedirs", _makedirs)

    with caplog.at_level(logging.WARNING):
        assert reader.recover_pending_failures() == []

    assert "unable to create tracking directory" in caplog.text


@pytest.mark.unit
def test_record_str_names_the_module_only_when_there_is_one():
    record = TrackingRecord(root_uuid=ROOT_UUID, storage_dir="/data/root", worker_name="any-0")
    assert str(record) == f"TrackingRecord(root={ROOT_UUID} worker=any-0)"

    record.module_path = MODULE_PATH
    record.observable_type, record.observable_value = "test", "test_1"
    assert str(record) == f"TrackingRecord(root={ROOT_UUID} worker=any-0 module={MODULE_PATH} observable=test:test_1)"
