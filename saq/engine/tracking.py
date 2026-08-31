"""Tracking of what each worker process is currently analyzing.

The engine has to survive a worker dying in the middle of a module -- either by the
``AnalysisModuleMonitor``'s ``os._exit(1)`` or the ``WorkerManager``'s ``SIGKILL``. When
that happens the replacement worker must know *which* module killed its predecessor, or it
will pick the same work item back up, run the same module and die again, forever.

The worker writes its own recovery point to a small file and the manager reads it only when
it needs it -- once per worker per supervision tick, and again when that worker dies. The
worker being the thing that dies is not an argument for keeping the state elsewhere: the
file outlives the process that wrote it, which is the entire point.

Layout, under ``<data_dir>/var/tracking/<node>/``::

    worker-<worker_name>.json     what that worker is doing right now
    pending/<root_uuid>.json      a failure the manager owes somebody

Every write goes to a ``.tmp`` sibling and is then ``os.replace``d, so a reader sees either
the whole old file or the whole new one and never a torn record. Nothing is fsync'd: a power
loss costs only the attribution, on a node that is restarting anyway.

Pending failures live in their own directory rather than as a flag on the in-flight record.
The replacement worker normally re-claims the very root that killed its predecessor, and
sharing one file would let that new work target overwrite the failure before anyone applied
it -- which is exactly the crash loop this subsystem exists to prevent. Their names are keyed
on ``root_uuid`` rather than worker name so a pool that shrank between restarts cannot strand
one.
"""

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import glob
import json
import logging
import os
import shutil
import time
from typing import Optional, Union

from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.modules.interfaces import AnalysisModuleInterface


def get_tracking_root_dir() -> str:
    """The directory every node's tracking state lives under."""
    return os.path.join(get_data_dir(), "var", "tracking")


def get_tracking_dir() -> str:
    """This node's tracking directory.

    Keyed on the node rather than on the worker name (as this subsystem used to be) so two
    engines sharing a data directory cannot collide with each other.
    """
    return os.path.join(get_tracking_root_dir(), str(get_global_runtime_settings().saq_node))


def get_pending_dir() -> str:
    return os.path.join(get_tracking_dir(), "pending")


def get_worker_tracking_path(worker_name: str) -> str:
    return os.path.join(get_tracking_dir(), f"worker-{worker_name}.json")


def get_pending_tracking_path(root_uuid: str) -> str:
    return os.path.join(get_pending_dir(), f"{root_uuid}.json")


def clear_all_tracking():
    """Removes every node's tracking state. Used by the test suite between runs."""
    tracking_dir = get_tracking_root_dir()
    if os.path.exists(tracking_dir):
        shutil.rmtree(tracking_dir, ignore_errors=True)


def _write_atomic(path: str, payload: str):
    """Writes ``payload`` to ``path`` all-or-nothing.

    The temp file is a sibling so the rename stays on the same filesystem, which is what
    makes it atomic against a concurrent reader.

    The directory is created once by whoever owns the path rather than on every write -- this
    runs twice per module invocation -- so the makedirs here is only the recovery path for a
    directory that went away underneath us.
    """
    temp_path = f"{path}.tmp"
    try:
        with open(temp_path, "w") as fp:
            fp.write(payload)
    except FileNotFoundError:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(temp_path, "w") as fp:
            fp.write(payload)

    os.replace(temp_path, path)


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

    # when the module started, on the monotonic clock. CLOCK_MONOTONIC is system wide on
    # linux, so the manager can compare its own reading against this one directly -- which
    # is what makes this immune to the clock steps and DST shifts that a cross process
    # datetime.now() comparison is not. it is only ever read for a live worker on this host,
    # so it never has to survive a reboot
    module_start_monotonic: Optional[float] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "TrackingRecord":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in value.items() if k in known})

    @property
    def has_module(self) -> bool:
        return self.module_path is not None

    @property
    def module_deadline(self) -> Optional[float]:
        """The monotonic time at which this module has run too long, if it has a limit."""
        if self.module_start_monotonic is None or self.maximum_analysis_time is None:
            return None

        return self.module_start_monotonic + self.maximum_analysis_time

    def clear_module(self):
        self.module_path = None
        self.observable_uuid = None
        self.observable_type = None
        self.observable_value = None
        self.maximum_analysis_time = None
        self.module_start_time = None
        self.module_start_monotonic = None

    def __str__(self):
        if self.has_module:
            return (
                f"TrackingRecord(root={self.root_uuid} worker={self.worker_name} "
                f"module={self.module_path} observable={self.observable_type}:{self.observable_value})"
            )
        return f"TrackingRecord(root={self.root_uuid} worker={self.worker_name})"


#
# worker side
#

class TrackingWriter:
    """The worker-facing half. Writes state changes; never reads any.

    Reporting must never be able to break analysis, so every failure here is swallowed and
    logged at debug. A tracking file we could not write costs an attribution, not a work item.
    """

    def __init__(self, worker_name: str):
        self.worker_name = worker_name
        self.path: Optional[str] = None
        self.record: Optional[TrackingRecord] = None

        # resolved once here rather than on every write, which happens twice per module
        # invocation
        try:
            os.makedirs(get_pending_dir(), exist_ok=True)
            self.path = get_worker_tracking_path(worker_name)
        except Exception as e:
            logging.debug("unable to create tracking directory for %s: %s", worker_name, e)

    def _flush(self):
        if self.record is None or self.path is None:
            return

        try:
            _write_atomic(self.path, json.dumps(self.record.to_dict(), sort_keys=True))
        except Exception as e:
            logging.debug("unable to write tracking for %s to %s: %s", self.worker_name, self.path, e)

    def track_current_work_target(self, target: Union[RootAnalysis, DelayedAnalysisRequest]):
        assert isinstance(target, (RootAnalysis, DelayedAnalysisRequest))
        # a new target implies a new analysis, so any module state is stale
        self.record = TrackingRecord(
            root_uuid=target.uuid,
            storage_dir=target.storage_dir,
            worker_name=self.worker_name,
            pid=os.getpid(),
            target_start_time=datetime.now().isoformat(),
        )
        self._flush()

    def clear_target_tracking(self):
        self.record = None
        if self.path is None:
            return

        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.debug("unable to clear tracking for %s: %s", self.worker_name, e)

    def track_current_analysis_module(self, module: AnalysisModuleInterface, observable: Observable):
        if self.record is None:
            logging.debug("module tracking for %s with no work target", self.worker_name)
            return

        self.record.module_path = MODULE_PATH(module)
        self.record.observable_uuid = observable.uuid
        self.record.observable_type = observable.type
        self.record.observable_value = observable.value
        self.record.maximum_analysis_time = module.maximum_analysis_time
        self.record.module_start_time = datetime.now().isoformat()
        self.record.module_start_monotonic = time.monotonic()
        self._flush()

    def clear_module_tracking(self):
        if self.record is None:
            return

        self.record.clear_module()
        self._flush()

    def resolve_pending_failure(self, root_uuid: str):
        """Acknowledges that a pending failure record has been applied to its root.

        Deleting the file is the acknowledgement, and it happens only once the failure has
        actually been recorded -- so a replacement that itself dies mid recovery leaves the
        attribution in place for the next one.
        """
        try:
            os.remove(get_pending_tracking_path(root_uuid))
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.debug("unable to resolve pending failure %s: %s", root_uuid, e)


class NullTrackingWriter(TrackingWriter):
    """Does nothing at all.

    Used when there is no manager process to read what we would write -- single threaded
    mode, where a dead worker is a dead engine and there is nobody left to recover anything.
    """

    def __init__(self, worker_name: str):
        self.worker_name = worker_name
        self.path = None
        self.record = None

    def _flush(self):
        pass

    def track_current_work_target(self, target: Union[RootAnalysis, DelayedAnalysisRequest]):
        pass

    def clear_target_tracking(self):
        pass

    def track_current_analysis_module(self, module: AnalysisModuleInterface, observable: Observable):
        pass

    def clear_module_tracking(self):
        pass

    def resolve_pending_failure(self, root_uuid: str):
        pass


#
# manager side
#

class TrackingReader:
    """Reads what the workers wrote. Holds no state of its own.

    The manager only needs this once per worker per supervision tick and again when a worker
    dies, so there is nothing to gain from caching it and something to lose -- a cache that
    disagrees with the file is a cache that can miss the record we exist to preserve.
    """

    def read_worker_record(self, worker_name: str) -> Optional[TrackingRecord]:
        return self._load(get_worker_tracking_path(worker_name))

    def _load(self, path: str) -> Optional[TrackingRecord]:
        try:
            with open(path, "r") as fp:
                return TrackingRecord.from_dict(json.load(fp))
        except FileNotFoundError:
            return None
        except Exception as e:
            # a file we cannot parse reads as "nothing was tracked" deliberately, rather
            # than by swallowing the exception somewhere further up
            logging.warning("unable to read tracking from %s: %s", path, e)
            return None

    def _promote(self, record: TrackingRecord):
        """Moves a record into the pending directory, where it stays until acknowledged."""
        record.pending_failure = True
        os.makedirs(get_pending_dir(), exist_ok=True)
        _write_atomic(
            get_pending_tracking_path(record.root_uuid),
            json.dumps(record.to_dict(), sort_keys=True),
        )

    def _discard_worker_file(self, worker_name: str):
        try:
            os.remove(get_worker_tracking_path(worker_name))
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.warning("unable to remove tracking for %s: %s", worker_name, e)

    def claim_failure(self, worker_name: str) -> Optional[TrackingRecord]:
        """Promotes what a worker that just died was doing into a pending failure.

        Returns ``None`` when the worker exited cleanly between modules, because there is
        nothing to attribute. The pending file is written before the worker file is removed,
        so a manager that dies in between simply promotes the same root again at startup.
        """
        record = self.read_worker_record(worker_name)
        if record is None or not record.has_module:
            self._discard_worker_file(worker_name)
            return None

        try:
            self._promote(record)
        except Exception as e:
            logging.error("unable to record pending failure for %s: %s", worker_name, e)
            return None

        self._discard_worker_file(worker_name)
        return record

    def recover_pending_failures(self) -> list[TrackingRecord]:
        """Everything left unresolved by a previous incarnation of this manager.

        A worker file that still names a module was never cleared by the worker that owned
        it, so the module in it is what killed that worker and is unresolved by definition.
        """
        try:
            os.makedirs(get_pending_dir(), exist_ok=True)
        except Exception as e:
            logging.warning("unable to create tracking directory: %s", e)
            return []

        for path in glob.glob(os.path.join(get_tracking_dir(), "worker-*.json")):
            record = self._load(path)
            if record is not None and record.has_module:
                try:
                    self._promote(record)
                except Exception as e:
                    logging.error("unable to recover pending failure from %s: %s", path, e)
                    continue

            try:
                os.remove(path)
            except Exception as e:
                logging.warning("unable to remove tracking file %s: %s", path, e)

        results = []
        for path in sorted(glob.glob(os.path.join(get_pending_dir(), "*.json"))):
            record = self._load(path)
            if record is None:
                continue

            record.pending_failure = True
            results.append(record)

        return results
