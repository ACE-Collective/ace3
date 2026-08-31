"""Tracking of what each worker process is currently analyzing.

The engine has to survive a worker dying in the middle of a module -- either by the
``AnalysisModuleMonitor``'s ``os._exit(1)`` or the ``WorkerManager``'s ``SIGKILL``. When
that happens the replacement worker must know *which* module killed its predecessor, or it
will pick the same work item back up, run the same module and die again, forever.

Workers are clients that report over a local pipe to the manager;
the manager runs the server, holds the state in memory, and mirrors it to a small
checksummed file so it also survives a restart of the manager itself.

Records are keyed by ``root_uuid``, not by worker name. The unit of tracking is the analysis
being worked on, not the process working on it -- so a pool that shrinks between restarts
cannot strand a record whose worker no longer exists.
"""

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
import hashlib
import json
import logging
import multiprocessing
import multiprocessing.connection
import os
import threading
import time
from typing import Optional, Union

from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.modules.interfaces import AnalysisModuleInterface

# message types sent from a worker to the tracking server
MSG_TRACK_TARGET = "track_target"
MSG_TRACK_MODULE = "track_module"
MSG_CLEAR_MODULE = "clear_module"
MSG_CLEAR_TARGET = "clear_target"
MSG_FAILURE_RESOLVED = "failure_resolved"

# how long the reader thread blocks waiting for a worker message before it re-reads the
# set of connections it should be watching
_READER_POLL_SECONDS = 0.5


def get_tracking_dir() -> str:
    return os.path.join(get_data_dir(), "var", "tracking")


def get_tracking_snapshot_path() -> str:
    """The snapshot is keyed on the node, not the worker.

    Keying on the worker name (as this subsystem used to) means two engines sharing a data
    directory collide, and it means a record cannot outlive the worker that produced it.
    """
    return os.path.join(get_tracking_dir(), f"{get_global_runtime_settings().saq_node}.json")


@dataclass
class TrackingRecord:
    """What one worker is doing with one root analysis.

    ``observable_type`` and ``observable_value`` are carried alongside the uuid because the
    worker may have died before the observable was ever written to storage, and because
    ``RootAnalysis.set_analysis_failed`` keys on ``type:value`` rather than on the uuid.
    """

    root_uuid: str
    storage_dir: str
    worker_name: str
    pid: Optional[int] = None
    module_path: Optional[str] = None
    observable_uuid: Optional[str] = None
    observable_type: Optional[str] = None
    observable_value: Optional[str] = None
    maximum_analysis_time: Optional[int] = None
    module_start_time: Optional[str] = None
    target_start_time: Optional[str] = None
    pending_failure: bool = False

    # the deadline for the live timeout check, on the monotonic clock. both ends of that
    # comparison are now taken in the manager process, which removes the clock-step and DST
    # hazards of the old design (the child stamped datetime.now(), the parent compared
    # against its own). it is meaningless across processes, so it is never persisted.
    module_deadline: Optional[float] = field(default=None, compare=False, repr=False)

    def to_dict(self) -> dict:
        result = asdict(self)
        del result["module_deadline"]
        return result

    @classmethod
    def from_dict(cls, value: dict) -> "TrackingRecord":
        known = {f.name for f in fields(cls)} - {"module_deadline"}
        return cls(**{k: v for k, v in value.items() if k in known})

    @property
    def has_module(self) -> bool:
        return self.module_path is not None

    def clear_module(self):
        self.module_path = None
        self.observable_uuid = None
        self.observable_type = None
        self.observable_value = None
        self.maximum_analysis_time = None
        self.module_start_time = None
        self.module_deadline = None

    def __str__(self):
        if self.has_module:
            return (
                f"TrackingRecord(root={self.root_uuid} worker={self.worker_name} "
                f"module={self.module_path} observable={self.observable_type}:{self.observable_value})"
            )
        return f"TrackingRecord(root={self.root_uuid} worker={self.worker_name})"


#
# client side -- runs inside the worker process
#

class TrackingClient:
    """The worker-facing half. Reports state changes; never reads any.

    Reporting must never be able to break analysis, so every send failure is swallowed. A
    BrokenPipeError here just means the manager went away, which is not the worker's
    problem to solve.
    """

    def __init__(self, worker_name: str):
        self.worker_name = worker_name

    def _send(self, message: dict):
        raise NotImplementedError()

    def track_current_work_target(self, target: Union[RootAnalysis, DelayedAnalysisRequest]):
        assert isinstance(target, (RootAnalysis, DelayedAnalysisRequest))
        self._send({
            "type": MSG_TRACK_TARGET,
            "worker_name": self.worker_name,
            "root_uuid": target.uuid,
            "storage_dir": target.storage_dir,
            "pid": os.getpid(),
        })

    def clear_target_tracking(self):
        self._send({"type": MSG_CLEAR_TARGET, "worker_name": self.worker_name})

    def track_current_analysis_module(self, module: AnalysisModuleInterface, observable: Observable):
        self._send({
            "type": MSG_TRACK_MODULE,
            "worker_name": self.worker_name,
            "module_path": MODULE_PATH(module),
            "observable_uuid": observable.uuid,
            "observable_type": observable.type,
            "observable_value": observable.value,
            "maximum_analysis_time": module.maximum_analysis_time,
        })

    def clear_module_tracking(self):
        self._send({"type": MSG_CLEAR_MODULE, "worker_name": self.worker_name})

    def report_failure_resolved(self, root_uuid: str):
        """Acknowledges that a pending failure record has been applied to its root.

        The server only drops the record when this arrives, so a replacement worker that
        itself dies mid-recovery leaves the attribution in place for the next one.
        """
        self._send({
            "type": MSG_FAILURE_RESOLVED,
            "worker_name": self.worker_name,
            "root_uuid": root_uuid,
        })


# every pipe client in this process that currently holds an open write end. workers are
# forked, so a child can inherit an open copy of another worker's write end -- which would
# keep the manager's matching read end from ever reaching EOF after that worker dies.
# worker_loop closes them (see close_inherited_clients). entries are added when a pipe is
# opened and dropped when it is closed, so this stays bounded over the life of the engine.
_pipe_clients: list["PipeTrackingClient"] = []


def close_inherited_clients(keep: Optional[TrackingClient] = None):
    """Closes every pipe client in this process except ``keep``.

    Called at the top of a forked worker so the only write end it holds open is its own.
    """
    for client in list(_pipe_clients):
        if client is not keep:
            client.close()


class PipeTrackingClient(TrackingClient):
    """Reports over a one-way pipe to the manager process.

    The pipe itself is opened by the server immediately before the worker is forked and the
    parent's copy of the write end is dropped immediately after, so the same client object
    survives a worker being restarted in place (see WorkerManager.restart_workers).
    """

    def __init__(self, worker_name: str, connection=None):
        super().__init__(worker_name)
        self.connection = connection

    def _send(self, message: dict):
        if self.connection is None:
            return

        try:
            self.connection.send(message)
        except Exception as e:
            logging.debug("unable to send tracking message from %s: %s", self.worker_name, e)

    def close(self):
        """Drops this process's copy of the write end."""
        if self.connection is None:
            return

        try:
            self.connection.close()
        except Exception:
            pass
        finally:
            self.connection = None
            try:
                _pipe_clients.remove(self)
            except ValueError:
                pass


class LocalTrackingClient(TrackingClient):
    """Reports straight into an in-process server.

    Used by single threaded mode, where there is no manager/worker split at all.
    """

    def __init__(self, worker_name: str, server: "TrackingServer"):
        super().__init__(worker_name)
        self.server = server

    def _send(self, message: dict):
        try:
            self.server.handle_message(message)
        except Exception as e:
            logging.debug("unable to record tracking message from %s: %s", self.worker_name, e)


#
# server side -- runs inside the manager process
#

class TrackingServer:
    """Owns every tracking record for this node.

    All state changes funnel through ``handle_message`` -- from the reader thread for forked
    workers, or directly for single threaded mode -- so there is exactly one writer and no
    locking design is needed beyond guarding the dicts themselves.
    """

    def __init__(self, snapshot_path: Optional[str] = None, persist: bool = True):
        self.snapshot_path = snapshot_path
        self.persist = persist

        self._lock = threading.RLock()

        # root_uuid -> TrackingRecord, for work currently in flight
        self._records: dict[str, TrackingRecord] = {}
        # root_uuid -> TrackingRecord, for failures owed to somebody. kept in its own map
        # rather than a flag on _records because the replacement worker normally re-claims
        # the very root that killed its predecessor: sharing one map would let that new
        # work target overwrite the failure before anyone had applied it
        self._pending: dict[str, TrackingRecord] = {}
        # worker_name -> root_uuid of the record that worker is actively working on
        self._active: dict[str, str] = {}
        # worker_name -> the read end of that worker's pipe
        self._connections: dict[str, "multiprocessing.connection.Connection"] = {}

        self._reader_thread: Optional[threading.Thread] = None
        self._shutdown = threading.Event()

    #
    # worker registration
    #

    def create_pipe_client(self, worker_name: str) -> PipeTrackingClient:
        """Returns the client half for a worker. The pipe is opened later, by open_pipe.

        A pipe per worker rather than one shared queue: a process killed while holding a
        multiprocessing.Queue's internal write lock can wedge every other writer, and
        workers dying by SIGKILL is the entire premise of this subsystem. Separate pipes
        have no shared lock, so one worker's death cannot corrupt another's channel.
        """
        return PipeTrackingClient(worker_name)

    def open_pipe(self, client: PipeTrackingClient):
        """Opens a fresh pipe for ``client``, replacing any previous one.

        Called immediately before the worker is forked rather than when it is constructed,
        so that (a) a worker restarted in place gets a working channel again, and (b) the
        only write end alive in the parent at fork time is the one belonging to the worker
        being forked -- a sibling's inherited copy would keep the manager from ever seeing
        EOF on that sibling.
        """
        with self._lock:
            client.close()
            self._close_connection(client.worker_name)
            reader, writer = multiprocessing.Pipe(duplex=False)
            self._connections[client.worker_name] = reader
            client.connection = writer
            _pipe_clients.append(client)

    def create_local_client(self, worker_name: str) -> LocalTrackingClient:
        return LocalTrackingClient(worker_name, self)

    def _close_connection(self, worker_name: str):
        connection = self._connections.pop(worker_name, None)
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    #
    # reader thread
    #

    def start(self):
        if self._reader_thread is not None:
            return

        self._shutdown.clear()
        self._reader_thread = threading.Thread(
            target=self._reader_loop, name="TrackingServer", daemon=True
        )
        self._reader_thread.start()

    def _stop_reader(self):
        self._shutdown.set()
        if self._reader_thread is not None:
            self._reader_thread.join(5)
            self._reader_thread = None

    def stop(self):
        self._stop_reader()

        with self._lock:
            for worker_name in list(self._connections):
                self._close_connection(worker_name)

    @contextmanager
    def forking(self):
        """Wraps a fork so the child is never born into a multi-threaded parent.

        A child forked from a process with a live reader thread inherits every lock that
        thread happened to be holding -- including the logging module's -- with no thread
        alive to release them, which is a classic way to deadlock a child on its first log
        call. Since worker restarts happen exactly when something has already gone wrong,
        that is the worst possible place for it.

        Stopping the reader costs at most one poll interval and only buffers messages in the
        pipes meanwhile, which is what pipes are for.
        """
        was_running = self._reader_thread is not None
        if was_running:
            self._stop_reader()

        try:
            yield
        finally:
            if was_running:
                self.start()

    def _reader_loop(self):
        # drained from a dedicated thread rather than the one second controller tick: a
        # worker running many fast cache-hit modules can emit hundreds of small messages a
        # second, and its send() must never block on the analysis critical path
        while not self._shutdown.is_set():
            with self._lock:
                connections = list(self._connections.items())

            if not connections:
                self._shutdown.wait(_READER_POLL_SECONDS)
                continue

            try:
                ready = multiprocessing.connection.wait(
                    [connection for _, connection in connections],
                    timeout=_READER_POLL_SECONDS,
                )
            except Exception as e:
                logging.debug("tracking server wait failed: %s", e)
                self._shutdown.wait(_READER_POLL_SECONDS)
                continue

            for connection in ready:
                worker_name = next(
                    (name for name, c in connections if c is connection), None
                )
                self._read_one(worker_name, connection)

    def _read_one(self, worker_name: Optional[str], connection):
        try:
            message = connection.recv()
        except EOFError:
            # every write end is closed, so the worker is gone. Connection.send/recv are
            # length prefixed, so a worker killed mid-write lands here rather than handing
            # us a silently truncated record -- which is exactly what the old pickle-file
            # implementation could not distinguish from "nothing was being tracked"
            if worker_name is not None:
                logging.debug("tracking connection for %s closed", worker_name)
                with self._lock:
                    self._close_connection(worker_name)
            return
        except Exception as e:
            logging.warning("unable to read tracking message from %s: %s", worker_name, e)
            if worker_name is not None:
                with self._lock:
                    self._close_connection(worker_name)
            return

        try:
            self.handle_message(message)
        except Exception as e:
            logging.warning("unable to handle tracking message %s: %s", message, e)

    #
    # state
    #

    def handle_message(self, message: dict):
        message_type = message.get("type")
        worker_name = message.get("worker_name")

        with self._lock:
            if message_type == MSG_TRACK_TARGET:
                # a new target implies a new analysis, so any module state is stale
                record = TrackingRecord(
                    root_uuid=message["root_uuid"],
                    storage_dir=message["storage_dir"],
                    worker_name=worker_name,
                    pid=message.get("pid"),
                    target_start_time=datetime.now().isoformat(),
                )
                self._records[record.root_uuid] = record
                self._active[worker_name] = record.root_uuid

            elif message_type == MSG_TRACK_MODULE:
                record = self._active_record(worker_name)
                if record is None:
                    logging.debug("module tracking for %s with no work target", worker_name)
                    return
                record.module_path = message["module_path"]
                record.observable_uuid = message.get("observable_uuid")
                record.observable_type = message.get("observable_type")
                record.observable_value = message.get("observable_value")
                record.maximum_analysis_time = message.get("maximum_analysis_time")
                record.module_start_time = datetime.now().isoformat()
                if record.maximum_analysis_time is not None:
                    record.module_deadline = time.monotonic() + record.maximum_analysis_time

            elif message_type == MSG_CLEAR_MODULE:
                record = self._active_record(worker_name)
                if record is not None:
                    record.clear_module()

            elif message_type == MSG_CLEAR_TARGET:
                root_uuid = self._active.pop(worker_name, None)
                if root_uuid is not None:
                    self._records.pop(root_uuid, None)

            elif message_type == MSG_FAILURE_RESOLVED:
                # only now is it safe to forget the failure
                self._pending.pop(message["root_uuid"], None)

            else:
                logging.warning("unknown tracking message type %s", message_type)
                return

            self._save_snapshot()

    def _active_record(self, worker_name: Optional[str]) -> Optional[TrackingRecord]:
        root_uuid = self._active.get(worker_name)
        if root_uuid is None:
            return None
        return self._records.get(root_uuid)

    def get_active_record(self, worker_name: str) -> Optional[TrackingRecord]:
        with self._lock:
            return self._active_record(worker_name)

    def is_timed_out(self, worker_name: str) -> bool:
        """True when the module this worker is running has exceeded its maximum analysis time."""
        with self._lock:
            record = self._active_record(worker_name)
            if record is None or record.module_deadline is None:
                return False

            return time.monotonic() >= record.module_deadline

    def mark_pending_failure(self, worker_name: str) -> Optional[TrackingRecord]:
        """Moves the record for a worker that just died into the pending map, and returns it.

        It stays there until somebody acknowledges having applied it, and it is out of the
        in-flight map immediately so neither the replacement worker (which reuses the name)
        nor a re-claim of the same root can overwrite it.
        """
        with self._lock:
            record = self._active_record(worker_name)
            self._active.pop(worker_name, None)
            self._close_connection(worker_name)

            if record is None:
                return None

            self._records.pop(record.root_uuid, None)

            if not record.has_module:
                # the worker exited cleanly between modules; there is nothing to attribute
                self._save_snapshot()
                return None

            record.pending_failure = True
            self._pending[record.root_uuid] = record
            self._save_snapshot()
            return record

    def pending_failures(self) -> list[TrackingRecord]:
        with self._lock:
            return list(self._pending.values())

    def clear_all(self):
        with self._lock:
            self._records.clear()
            self._pending.clear()
            self._active.clear()
            self._save_snapshot()

    #
    # snapshot
    #

    def _save_snapshot(self):
        """Mirrors the whole store to disk.

        Called on every state change rather than coalescing: the store is one small record
        per in-flight root, the write happens on the reader thread (well off the analysis
        critical path), and coalescing would risk dropping exactly the record we need.

        Deliberately not fsync'd. A power loss can lose the last record, which is
        acceptable -- the node is restarting in that case anyway, and lock expiry recovery
        still frees the work item. We lose only the attribution.
        """
        if not self.persist or not self.snapshot_path:
            return

        try:
            payload = json.dumps(
                [
                    record.to_dict()
                    for record in list(self._records.values()) + list(self._pending.values())
                ],
                sort_keys=True,
            ).encode()
            digest = hashlib.sha256(payload).hexdigest()

            os.makedirs(os.path.dirname(self.snapshot_path), exist_ok=True)
            temp_path = f"{self.snapshot_path}.tmp"
            with open(temp_path, "wb") as fp:
                fp.write(digest.encode())
                fp.write(b"\n")
                fp.write(payload)

            os.replace(temp_path, self.snapshot_path)
        except Exception as e:
            logging.warning("unable to write tracking snapshot to %s: %s", self.snapshot_path, e)

    def load_snapshot(self) -> list[TrackingRecord]:
        """Reads records left behind by a previous incarnation of the manager.

        The atomic rename makes the file all-or-nothing against a crash; the checksum covers
        what the rename cannot, which is a power loss that lands the directory entry but not
        the data blocks. A file that does not verify reads as "nothing was being tracked" --
        the same answer the old implementation gave, but reached deliberately rather than by
        swallowing an exception from a torn read.
        """
        if not self.snapshot_path or not os.path.exists(self.snapshot_path):
            return []

        try:
            with open(self.snapshot_path, "rb") as fp:
                content = fp.read()

            digest, _, payload = content.partition(b"\n")
            if hashlib.sha256(payload).hexdigest() != digest.decode().strip():
                logging.error(
                    "tracking snapshot %s failed its checksum - discarding", self.snapshot_path
                )
                return []

            records = [TrackingRecord.from_dict(value) for value in json.loads(payload)]
        except Exception as e:
            logging.error("unable to read tracking snapshot %s: %s", self.snapshot_path, e)
            return []

        # anything still carrying a module was never cleared by the worker that owned it, so
        # by definition it is unresolved. a record without one belonged to a worker that died
        # between modules -- there is nothing to attribute, and keeping it would leave an
        # entry nothing will ever clear (the worker that owned it is gone, so it will never
        # send the clear_target that would remove it)
        recovered = [record for record in records if record.has_module]
        for record in recovered:
            record.pending_failure = True

        with self._lock:
            for record in recovered:
                self._pending[record.root_uuid] = record
            self._save_snapshot()

        return recovered


def clear_all_tracking():
    """Removes this node's tracking snapshot. Used by the test suite between runs."""
    snapshot_path = get_tracking_snapshot_path()
    for path in (snapshot_path, f"{snapshot_path}.tmp"):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            logging.debug("unable to remove tracking file %s: %s", path, e)
