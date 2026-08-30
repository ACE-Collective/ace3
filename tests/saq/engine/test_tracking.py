"""Tests for the worker tracking subsystem (ENGINE.md 19.12).

Tracking answers one question: when a worker dies in the middle of a module, which module
was it? Without that answer the replacement worker picks the same work item back up (its
workload row was never deleted), runs the same module, and dies again.

The old implementation kept the answer in two unlocked pickle files per worker, written
non-atomically and read with a bare ``except`` that made a torn read indistinguishable from
"nothing was being tracked". It now lives in the manager process -- the one process
guaranteed to outlive the worker -- with a checksummed snapshot so it also outlives a
restart of the manager itself.
"""
import json
import os
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from saq.analysis.root import RootAnalysis
from saq.engine.tracking import (
    MSG_CLEAR_MODULE,
    MSG_CLEAR_TARGET,
    MSG_FAILURE_RESOLVED,
    MSG_TRACK_MODULE,
    MSG_TRACK_TARGET,
    LocalTrackingClient,
    PipeTrackingClient,
    TrackingRecord,
    TrackingServer,
    clear_all_tracking,
    get_tracking_snapshot_path,
)


ROOT_UUID = "11111111-1111-1111-1111-111111111111"
OTHER_ROOT_UUID = "22222222-2222-2222-2222-222222222222"


def _server(tmp_path, persist=True) -> TrackingServer:
    return TrackingServer(snapshot_path=str(tmp_path / "node.json"), persist=persist)


def _track_target(server, worker_name="any-0", root_uuid=ROOT_UUID, storage_dir="/data/root"):
    server.handle_message({
        "type": MSG_TRACK_TARGET,
        "worker_name": worker_name,
        "root_uuid": root_uuid,
        "storage_dir": storage_dir,
        "pid": 4242,
    })


def _track_module(server, worker_name="any-0", module_path="saq.modules.test:BasicTestAnalysis",
                  maximum_analysis_time=60):
    server.handle_message({
        "type": MSG_TRACK_MODULE,
        "worker_name": worker_name,
        "module_path": module_path,
        "observable_uuid": "obs-1",
        "observable_type": "test",
        "observable_value": "test_1",
        "maximum_analysis_time": maximum_analysis_time,
    })


#
# the record itself
#

@pytest.mark.unit
def test_record_round_trips_without_the_monotonic_deadline(tmp_path):
    """module_deadline is a monotonic reading, which is meaningless in another process."""
    record = TrackingRecord(
        root_uuid=ROOT_UUID, storage_dir="/data/root", worker_name="any-0",
        module_path="mod", module_deadline=time.monotonic(),
    )

    as_dict = record.to_dict()
    assert "module_deadline" not in as_dict

    restored = TrackingRecord.from_dict(as_dict)
    assert restored.root_uuid == ROOT_UUID
    assert restored.module_path == "mod"
    assert restored.module_deadline is None


@pytest.mark.unit
def test_from_dict_ignores_unknown_keys():
    """A snapshot written by an older or newer build must not blow up the load."""
    restored = TrackingRecord.from_dict({
        "root_uuid": ROOT_UUID, "storage_dir": "/x", "worker_name": "any-0",
        "some_field_we_do_not_have": True,
    })
    assert restored.root_uuid == ROOT_UUID


#
# state transitions
#

@pytest.mark.unit
def test_tracking_a_target_then_a_module(tmp_path):
    server = _server(tmp_path)
    _track_target(server)

    record = server.get_active_record("any-0")
    assert record is not None
    assert record.root_uuid == ROOT_UUID
    assert not record.has_module

    _track_module(server)
    record = server.get_active_record("any-0")
    assert record.has_module
    assert record.observable_type == "test"
    assert record.observable_value == "test_1"


@pytest.mark.unit
def test_clear_module_leaves_the_target(tmp_path):
    server = _server(tmp_path)
    _track_target(server)
    _track_module(server)

    server.handle_message({"type": MSG_CLEAR_MODULE, "worker_name": "any-0"})

    record = server.get_active_record("any-0")
    assert record is not None
    assert not record.has_module
    assert record.module_deadline is None


@pytest.mark.unit
def test_clear_target_removes_the_record(tmp_path):
    server = _server(tmp_path)
    _track_target(server)
    server.handle_message({"type": MSG_CLEAR_TARGET, "worker_name": "any-0"})
    assert server.get_active_record("any-0") is None


@pytest.mark.unit
def test_tracking_a_module_with_no_target_is_ignored(tmp_path):
    server = _server(tmp_path)
    _track_module(server)
    assert server.get_active_record("any-0") is None


#
# timeouts
#

@pytest.mark.unit
def test_timeout_is_computed_from_monotonic_time(tmp_path):
    """Both ends of the comparison are taken in this process, so a wall clock step or a DST
    shift -- which the old cross-process datetime.now() comparison was exposed to -- cannot
    make a module look timed out or hide one that is."""
    server = _server(tmp_path)
    _track_target(server)

    with patch("saq.engine.tracking.time.monotonic", return_value=1000.0):
        _track_module(server, maximum_analysis_time=60)

    with patch("saq.engine.tracking.time.monotonic", return_value=1059.0):
        assert server.is_timed_out("any-0") is False

    with patch("saq.engine.tracking.time.monotonic", return_value=1060.0):
        assert server.is_timed_out("any-0") is True


@pytest.mark.unit
def test_not_timed_out_with_no_module(tmp_path):
    server = _server(tmp_path)
    _track_target(server)
    assert server.is_timed_out("any-0") is False


@pytest.mark.unit
def test_not_timed_out_for_an_unknown_worker(tmp_path):
    server = _server(tmp_path)
    assert server.is_timed_out("nobody") is False


#
# failure handoff
#

@pytest.mark.unit
def test_pending_failure_survives_until_acknowledged(tmp_path):
    """The old code cleared tracking in a finally regardless of outcome, so a replacement
    that died during recovery lost the attribution. The record now stays until the worker
    says it applied it."""
    server = _server(tmp_path)
    _track_target(server)
    _track_module(server)

    record = server.mark_pending_failure("any-0")
    assert record is not None
    assert record.pending_failure
    assert record.root_uuid == ROOT_UUID

    # still there -- nobody has acknowledged it
    assert [r.root_uuid for r in server.pending_failures()] == [ROOT_UUID]

    server.handle_message({
        "type": MSG_FAILURE_RESOLVED, "worker_name": "any-0", "root_uuid": ROOT_UUID,
    })
    assert server.pending_failures() == []


@pytest.mark.unit
def test_a_worker_that_died_between_modules_has_nothing_to_attribute(tmp_path):
    server = _server(tmp_path)
    _track_target(server)

    assert server.mark_pending_failure("any-0") is None
    assert server.pending_failures() == []


@pytest.mark.unit
def test_reclaiming_the_same_root_does_not_wipe_the_pending_failure(tmp_path):
    """The normal case after a crash: the replacement worker picks the very work item that
    killed its predecessor back up (the workload row was never deleted). If the pending
    failure shared a map with in-flight work, that re-claim would overwrite it and the
    module would be free to kill the worker again."""
    server = _server(tmp_path)
    _track_target(server, root_uuid=ROOT_UUID)
    _track_module(server, module_path="saq.modules.test:Killer")
    server.mark_pending_failure("any-0")

    # the replacement comes up and re-claims the same root
    _track_target(server, worker_name="any-0", root_uuid=ROOT_UUID)

    pending = server.pending_failures()
    assert len(pending) == 1
    assert pending[0].root_uuid == ROOT_UUID
    assert pending[0].module_path == "saq.modules.test:Killer"

    # and it survives a manager restart in that state
    assert [r.module_path for r in _server(tmp_path).load_snapshot()] == [
        "saq.modules.test:Killer"
    ]


@pytest.mark.unit
def test_replacement_worker_does_not_disturb_the_pending_record(tmp_path):
    """Records are keyed by root_uuid, not by worker name. The replacement reuses the name,
    so if the key were the worker its first work item would overwrite the failure we still
    owe somebody."""
    server = _server(tmp_path)
    _track_target(server, root_uuid=ROOT_UUID)
    _track_module(server)
    server.mark_pending_failure("any-0")

    # the replacement comes up under the same name and takes a different root
    _track_target(server, worker_name="any-0", root_uuid=OTHER_ROOT_UUID)

    assert server.get_active_record("any-0").root_uuid == OTHER_ROOT_UUID
    assert [r.root_uuid for r in server.pending_failures()] == [ROOT_UUID]


#
# the snapshot
#

@pytest.mark.unit
def test_snapshot_round_trips_a_pending_record(tmp_path):
    """This is the full-manager-restart path: the manager itself dies before the
    replacement resolves the record, and the next one picks it up off disk."""
    server = _server(tmp_path)
    _track_target(server, storage_dir="/data/root")
    _track_module(server, module_path="saq.modules.test:BasicTestAnalysis")

    # a brand new server, as though the engine had been restarted
    restarted = _server(tmp_path)
    pending = restarted.load_snapshot()

    assert len(pending) == 1
    assert pending[0].root_uuid == ROOT_UUID
    assert pending[0].storage_dir == "/data/root"
    assert pending[0].module_path == "saq.modules.test:BasicTestAnalysis"
    assert pending[0].observable_value == "test_1"
    # a record still naming a module was never cleared, so it is unresolved by definition
    assert pending[0].pending_failure


@pytest.mark.unit
def test_snapshot_does_not_resurrect_a_cleanly_finished_root(tmp_path):
    server = _server(tmp_path)
    _track_target(server)
    _track_module(server)
    server.handle_message({"type": MSG_CLEAR_MODULE, "worker_name": "any-0"})
    server.handle_message({"type": MSG_CLEAR_TARGET, "worker_name": "any-0"})

    assert _server(tmp_path).load_snapshot() == []


@pytest.mark.unit
def test_corrupt_snapshot_reads_as_empty(tmp_path):
    """The atomic rename covers a crash; the checksum covers what it cannot, which is a
    power loss that lands the directory entry but not the data blocks. Either way a bad
    file has to read as 'nothing was tracked' deliberately, rather than as garbage."""
    server = _server(tmp_path)
    _track_target(server)
    _track_module(server)

    snapshot_path = tmp_path / "node.json"
    digest, _, payload = snapshot_path.read_bytes().partition(b"\n")
    tampered = json.loads(payload)
    tampered[0]["module_path"] = "saq.modules.evil:NotWhatWeWrote"
    # same (stale) digest, different payload
    snapshot_path.write_bytes(digest + b"\n" + json.dumps(tampered).encode())

    assert _server(tmp_path).load_snapshot() == []


@pytest.mark.unit
def test_truncated_snapshot_reads_as_empty(tmp_path):
    server = _server(tmp_path)
    _track_target(server)
    _track_module(server)

    snapshot_path = tmp_path / "node.json"
    content = snapshot_path.read_bytes()
    snapshot_path.write_bytes(content[: len(content) // 2])

    assert _server(tmp_path).load_snapshot() == []


@pytest.mark.unit
def test_missing_snapshot_reads_as_empty(tmp_path):
    assert _server(tmp_path).load_snapshot() == []


@pytest.mark.unit
def test_snapshot_is_written_atomically(tmp_path):
    """No .tmp file is left behind for a reader to trip over."""
    server = _server(tmp_path)
    _track_target(server)
    assert os.path.exists(tmp_path / "node.json")
    assert not os.path.exists(tmp_path / "node.json.tmp")


#
# transport
#

@pytest.mark.unit
def test_pipe_client_delivers_to_the_server(tmp_path):
    server = _server(tmp_path)
    client = server.create_pipe_client("any-0")
    server.open_pipe(client)

    root = Mock(spec=RootAnalysis)
    root.uuid = ROOT_UUID
    root.storage_dir = "/data/root"
    client.track_current_work_target(root)

    # drain the one message by hand rather than racing the reader thread
    connection = server._connections["any-0"]
    assert connection.poll(5)
    server._read_one("any-0", connection)

    assert server.get_active_record("any-0").root_uuid == ROOT_UUID


@pytest.mark.unit
def test_a_truncated_frame_does_not_corrupt_state(tmp_path):
    """Connection.send/recv is length prefixed, so a worker killed mid-write surfaces as a
    read error rather than as a plausible-looking half record. The old pickle files could
    not tell that apart from 'nothing is being tracked'."""
    server = _server(tmp_path)
    client = server.create_pipe_client("any-0")
    server.open_pipe(client)

    _track_target(server)
    assert server.get_active_record("any-0") is not None

    # write a frame header promising more bytes than we send, then close
    connection = server._connections["any-0"]
    os.write(client.connection.fileno(), b"\x00\x00\x10\x00partial")
    client.close()

    server._read_one("any-0", connection)

    # the state we already had is untouched, and the bad connection is dropped
    assert server.get_active_record("any-0").root_uuid == ROOT_UUID
    assert "any-0" not in server._connections


@pytest.mark.unit
def test_eof_drops_the_connection(tmp_path):
    server = _server(tmp_path)
    client = server.create_pipe_client("any-0")
    server.open_pipe(client)
    connection = server._connections["any-0"]

    client.close()
    server._read_one("any-0", connection)

    assert "any-0" not in server._connections


@pytest.mark.unit
def test_sending_after_close_is_silent(tmp_path):
    """A worker whose manager went away must not fail its analysis over it."""
    server = _server(tmp_path)
    client = server.create_pipe_client("any-0")
    server.open_pipe(client)
    client.close()

    root = Mock(spec=RootAnalysis)
    root.uuid = ROOT_UUID
    root.storage_dir = "/data/root"
    client.track_current_work_target(root)  # must not raise


@pytest.mark.unit
def test_local_client_reports_straight_into_the_server(tmp_path):
    """Single threaded mode has no manager/worker split at all."""
    server = _server(tmp_path)
    client = LocalTrackingClient("worker-1", server)

    root = Mock(spec=RootAnalysis)
    root.uuid = ROOT_UUID
    root.storage_dir = "/data/root"
    client.track_current_work_target(root)

    assert server.get_active_record("worker-1").root_uuid == ROOT_UUID


@pytest.mark.unit
def test_clear_all_tracking_removes_the_snapshot():
    server = TrackingServer(snapshot_path=get_tracking_snapshot_path())
    _track_target(server)
    assert os.path.exists(get_tracking_snapshot_path())

    clear_all_tracking()
    assert not os.path.exists(get_tracking_snapshot_path())


#
# the two paths the file-based design could never cover
#

@pytest.mark.unit
def test_startup_dispatch_survives_a_shrunken_pool(configuration_manager_for_dispatch=None):
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
    previous = TrackingServer(snapshot_path=get_tracking_snapshot_path())
    _track_target(previous, worker_name="correlation-7")
    _track_module(previous, worker_name="correlation-7")

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
        try:
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
        finally:
            manager.tracking_server.stop()
            # this test deliberately writes to the real node snapshot path, and start_workers
            # leaves the record pending (nobody acked it). don't leave that for the next test.
            clear_all_tracking()


@pytest.mark.integration
def test_recovered_record_lands_on_the_right_root(root_analysis):
    """End to end for a full engine restart: the manager dies without ever acknowledging a
    failure, the next one reads it off disk, and the module that killed the worker is
    recorded against the root it was actually analyzing."""
    from unittest.mock import MagicMock as _MagicMock

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
    dying = TrackingServer(snapshot_path=get_tracking_snapshot_path())
    dying.handle_message({
        "type": MSG_TRACK_TARGET,
        "worker_name": "correlation-0",
        "root_uuid": root_analysis.uuid,
        "storage_dir": root_analysis.storage_dir,
        "pid": 4242,
    })
    dying.handle_message({
        "type": MSG_TRACK_MODULE,
        "worker_name": "correlation-0",
        "module_path": "saq.modules.test:BasicTestAnalysis",
        "observable_uuid": observable.uuid,
        "observable_type": observable.type,
        "observable_value": observable.value,
        "maximum_analysis_time": 60,
    })

    # a fresh manager comes up and reads what the old one left behind
    restarted = TrackingServer(snapshot_path=get_tracking_snapshot_path())
    pending = restarted.load_snapshot()
    assert len(pending) == 1
    assert pending[0].root_uuid == root_analysis.uuid

    configuration_manager = ConfigurationManager(EngineConfiguration())
    worker = Worker(
        name="correlation-0",
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )
    # a real replacement worker is a forked child reporting back over a pipe; here it runs
    # in the same process as the manager, so it talks to the server directly
    worker.tracking_server = restarted
    worker.tracking_message_manager = restarted.create_local_client("correlation-0")
    worker.lock_manager = _MagicMock()

    worker._handle_failed_analysis(pending[0])

    reloaded = RootAnalysis(storage_dir=get_storage_dir(root_analysis.uuid))
    reloaded.load()
    assert reloaded.is_analysis_failed(
        BasicTestAnalysis, reloaded.get_observable(observable.uuid)
    ), "the failure was not recorded against the root named in the recovered record"

    # and the worker acknowledged it, so the next restart will not replay it
    assert restarted.pending_failures() == []
