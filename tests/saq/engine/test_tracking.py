"""Tests for the worker tracking subsystem (ENGINE.md 19.12).

Tracking answers one question: when a worker dies in the middle of a module, which module
was it? Without that answer the replacement worker picks the same work item back up (its
workload row was never deleted), runs the same module, and dies again.

The worker writes the answer to its own file; the manager reads that file only when it needs
it, and promotes it into ``pending/`` when the worker dies. The worker being the thing that
dies is not a reason to keep the state anywhere else -- the file outlives the process.
"""
import json
import os
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from saq.analysis.root import RootAnalysis
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
    from saq.constants import LockManagerType, WorkloadManagerType
    from saq.engine.configuration_manager import ConfigurationManager
    from saq.engine.enums import EngineExecutionMode
    from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
    from saq.engine.worker_manager import WorkerManager
    from tests.saq.engine.test_worker_restart_execution_mode import FakeWorker

    # a previous, larger run left a record behind for a worker that no longer exists
    previous = TrackingWriter("correlation-7")
    previous.track_current_work_target(_target())
    _track(previous)

    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.single_threaded_mode = False
    configuration_manager.config.analysis_pools = {"correlation": 2}
    configuration_manager.config.pool_size_limit = None
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.auto_refresh_frequency = 0

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
    from saq.engine.configuration_manager import ConfigurationManager
    from saq.engine.engine_configuration import EngineConfiguration
    from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
    from saq.engine.worker import Worker
    from saq.modules.test import BasicTestAnalysis
    from saq.util.uuid import get_storage_dir

    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()

    # a worker was analyzing this root with this module when everything died
    dying = TrackingWriter("correlation-0")
    dying.track_current_work_target(root_analysis)
    with patch("saq.engine.tracking.MODULE_PATH", return_value="saq.modules.test:BasicTestAnalysis"):
        dying.track_current_analysis_module(_module(), observable)

    # a fresh manager comes up and reads what the old one left behind
    pending = TrackingReader().recover_pending_failures()
    assert len(pending) == 1
    assert pending[0].root_uuid == root_analysis.uuid

    configuration_manager = ConfigurationManager(EngineConfiguration())
    worker = Worker(
        name="correlation-0",
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )
    worker.lock_manager = MagicMock()

    worker._handle_failed_analysis(pending[0])

    reloaded = RootAnalysis(storage_dir=get_storage_dir(root_analysis.uuid))
    reloaded.load()
    assert reloaded.is_analysis_failed(
        BasicTestAnalysis, reloaded.get_observable(observable.uuid)
    ), "the failure was not recorded against the root named in the recovered record"

    # and the worker acknowledged it, so the next restart will not replay it
    assert TrackingReader().recover_pending_failures() == []


@pytest.mark.integration
def test_a_failure_for_a_deleted_root_is_resolved_not_replayed(root_analysis):
    """A root that no longer exists can never be attributed, so the record must not be
    immortal -- otherwise it is handed to a worker again at every engine start, forever."""
    from saq.engine.configuration_manager import ConfigurationManager
    from saq.engine.engine_configuration import EngineConfiguration
    from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
    from saq.engine.worker import Worker

    dying = TrackingWriter("correlation-0")
    dying.track_current_work_target(_target(uuid=root_analysis.uuid, storage_dir="/does/not/exist"))
    _track(dying)

    pending = TrackingReader().recover_pending_failures()
    assert len(pending) == 1

    worker = Worker(
        name="correlation-0",
        configuration_manager=ConfigurationManager(EngineConfiguration()),
        node_manager=Mock(spec=NodeManagerInterface),
    )
    worker.lock_manager = MagicMock()
    worker._handle_failed_analysis(pending[0])

    assert TrackingReader().recover_pending_failures() == []
