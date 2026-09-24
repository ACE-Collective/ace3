"""Crash reports for analysis modules that fail, hang, or take their worker down with them.

When an analysis module fails, ACE marks it failed and moves on. A *crash report* is one
self-contained directory per crash, named by an opaque crash id that is logged when the crash
happens. Given the id, an analyst pulls the whole thing over the API
(``GET /api/v2/crashes/{crash_id}/download``).

This module deliberately sits outside ``saq.engine`` so the API can read crash reports
without importing the engine.

Three kinds of crash are recorded, from three different places:

``exception``
    The module raised. Recorded by the engine's per-module exception handler, in the worker
    that ran it, with a full traceback.

``timeout``
    The module blew through ``maximum_analysis_time`` and the in-process watchdog is about to
    ``os._exit(1)``. This is the only report written *from inside the stuck process*, at the
    moment it is stuck -- see ``thread_stacks.txt``.
    It is not indexed inline (see ``record_module_crash``); it is spooled, and the replacement
    worker indexes it moments later -- see ``drain_index_spool``.

``killed``
    The worker manager SIGKILLed the worker. The replacement worker reconstructs what it can
    from the ``TrackingRecord`` the manager handed it, plus the thread stacks the dying process
    dumped shortly before the kill, when that dump landed -- see "hang stack dumps" below.

A module that hangs while holding the GIL (a catastrophic regex inside ``_sre`` is the common
one) starves the watchdog thread, so it never writes its ``timeout`` report. For that case every
engine worker keeps a ``faulthandler.dump_traceback_later`` timer armed around each module
execution. That timer runs in a C thread that does not need the GIL, and it dumps every thread's
stack into ``hang_stacks/<node>/<pid>.txt`` a few seconds before the manager's kill is due. The
replacement worker copies that file into the ``killed`` report.

A hang can legitimately produce both a ``timeout`` and a ``killed`` report -- the in-process
watchdog and the manager race, and whichever loses still has something to say. They are
correlated by ``root_uuid`` + ``module_path``.

**Nothing in here is allowed to raise.** Crash reporting that can break analysis, or that can
keep a wedged process from exiting, is worse than no crash reporting at all. Every public
entry point swallows and logs its own failures, and returns ``None`` rather than propagating.
This is the same contract ``saq.engine.tracking.TrackingWriter`` documents for itself.

Write ordering matters for the same reason: a worker can be SIGKILLed *while writing its own
crash report*. The expensive, kill-prone copies happen first and ``metadata.json`` is written
last, atomically. A directory without ``metadata.json`` is therefore by definition incomplete,
which is what lets a reader distinguish "still being written / killed mid-write" from "done"
without a lock. Partial evidence still beats none, so an incomplete report is still served.
"""

import faulthandler
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import socket
import sys
import tempfile
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

import psutil

from saq.configuration.config import get_config
from saq.constants import F_FILE, HARDCOPY_SUBDIR
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.error.formatter import ExceptionFormatter
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_MODULE_CRASH

CRASH_TYPE_EXCEPTION = "exception"
CRASH_TYPE_TIMEOUT = "timeout"
CRASH_TYPE_KILLED = "killed"

CRASH_TYPES = (CRASH_TYPE_EXCEPTION, CRASH_TYPE_TIMEOUT, CRASH_TYPE_KILLED)

METADATA_FILE = "metadata.json"
STACK_TRACE_FILE = "stack_trace.txt"
THREAD_STACKS_FILE = "thread_stacks.txt"
ROOT_JSON_FILE = "root.json"
FILE_DIR = "file"

# where each engine worker's pre-kill thread dump goes, one file per pid, under a per-node
# directory: a pid only means something on the host that issued it. like the index spool it sits
# under the crash report root but outside every report directory
HANG_STACKS_DIR = "hang_stacks"

# how long before maximum_analysis_time the pre-kill dump fires. it has to land before the
# manager's SIGKILL, which comes at maximum_analysis_time (checked about once a second)
HANG_STACK_MARGIN_SECONDS = 5

# a hang stack file for a dead pid is only pruned once it is this old, so a worker starting up
# cannot delete a file that another replacement worker has yet to collect
HANG_STACKS_PRUNE_MIN_AGE_SECONDS = 600

# the spool of reports that are on disk but not yet in the database index, one empty file per
# crash id. it lives under the crash report root but outside every report directory, so it never
# shows up in a report's file inventory or archive and never touches the report mtime that
# `ace crash prune` ages reports by
INDEX_PENDING_DIR = "index_pending"

# the serialized RootAnalysis inside a storage directory
ROOT_DATA_FILE = "data.json"

# a crash id is an opaque uuid4. it arrives from a URL and is turned into a filesystem path,
# and the resulting directory is served to an analyst as a zip full of live malware, so it is
# validated at every boundary rather than trusted because "it came from our own log".
# \Z rather than $: in python $ also matches just before a trailing newline, so "<uuid>\n"
# would otherwise validate and then be used to build a path
CRASH_ID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")

# reason codes recorded in metadata["omitted"] so a truncated report says so rather than
# looking complete
OMITTED_TOO_LARGE = "exceeds configured size limit"
OMITTED_DISABLED = "disabled by configuration"
OMITTED_NOT_FOUND = "source file not found"
OMITTED_ERROR = "error while copying"


# How many crash reports one module is allowed to produce for one root, per process.
#
# This exists because crash reporting is on by default and copies the file observable. A module
# that raises on every file in a tree with hundreds of extracted attachments would otherwise
# write hundreds of reports, each with its own copy of the bytes -- turning "we captured the
# evidence" into "we filled the disk". The first few reports of a repeating failure say
# everything the tenth would; the count is logged so the suppression is never silent.
#
# Keyed by (root_uuid, module_path) and process-local, which is the right scope: a worker
# processes one root at a time, so this bounds the fan-out within a single unit of work without
# needing shared state.
_report_counts: dict[tuple, int] = {}

# the counter is keyed by root, and a long-lived worker sees unboundedly many roots
_REPORT_COUNTS_MAX_ENTRIES = 1024


def _within_report_limit(root_uuid: Optional[str], module_path: Optional[str], limit: int) -> bool:
    """True if this (root, module) pair has not yet hit its per-process report limit."""
    if not limit or root_uuid is None or module_path is None:
        return True

    if len(_report_counts) > _REPORT_COUNTS_MAX_ENTRIES:
        _report_counts.clear()

    key = (root_uuid, module_path)
    count = _report_counts.get(key, 0) + 1
    _report_counts[key] = count

    if count > limit:
        if count == limit + 1:
            logging.warning(
                "suppressing further crash reports for module %s on root %s "
                "(hit the limit of %s per root); the module is still failing",
                module_path, root_uuid, limit,
            )
        return False

    return True


def is_valid_crash_id(crash_id: Any) -> bool:
    """True if this is a well formed crash id and therefore safe to build a path out of."""
    return isinstance(crash_id, str) and CRASH_ID_PATTERN.match(crash_id) is not None


# how much of an unbounded value (an observable value, an exception message) goes on a log line.
# the full value always reaches metadata.json
LOG_VALUE_MAX_LENGTH = 512


def _truncate(value: Optional[str], max_length: int) -> Optional[str]:
    if value is None or len(value) <= max_length:
        return value

    return f"{value[:max_length]}...[truncated {len(value)} chars]"


@dataclass
class CrashReportMetadata:
    """Everything known about one crash. Serialized to ``metadata.json`` verbatim, and the
    same field set backs the database index row and the API response."""

    crash_id: str
    crash_type: str
    timestamp: str
    node: Optional[str] = None
    hostname: Optional[str] = None
    pid: Optional[int] = None
    worker_name: Optional[str] = None

    module_path: Optional[str] = None
    module_name: Optional[str] = None
    analysis_mode: Optional[str] = None
    maximum_analysis_time: Optional[int] = None
    module_start_time: Optional[str] = None
    elapsed_seconds: Optional[float] = None

    root_uuid: Optional[str] = None
    root_storage_dir: Optional[str] = None
    root_description: Optional[str] = None

    observable_uuid: Optional[str] = None
    observable_type: Optional[str] = None
    observable_value: Optional[str] = None

    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_sha256: Optional[str] = None

    exception_type: Optional[str] = None
    exception_message: Optional[str] = None

    # what this report does *not* contain, and why. an empty list means the report is complete.
    omitted: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "CrashReportMetadata":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in value.items() if k in known})

    def log_fields(self) -> dict:
        """The subset worth putting on a log record as ``extra={}``.

        ACE's rule is that the message text describes the event and ``extra={}`` carries the
        fields (see saq/logging.py); the text formatter renders these as ``key=value`` and the
        fluent formatter promotes them to top level Splunk fields. So ``crash_id=...`` is both
        greppable in saq.log and directly searchable in Splunk, which is the whole point.
        """
        fields = {
            "crash_id": self.crash_id,
            "crash_type": self.crash_type,
            "module_path": self.module_path,
            "module_name": self.module_name,
            "root_uuid": self.root_uuid,
            "analysis_mode": self.analysis_mode,
            "observable_type": self.observable_type,
            # truncated: an observable value is unbounded (a command line, a long url) and this
            # goes on a log line. the full value is in metadata.json, which is the record
            "observable_value": _truncate(self.observable_value, LOG_VALUE_MAX_LENGTH),
            "exception_type": self.exception_type,
            "node": self.node,
            "pid": self.pid,
        }
        # a timeout crash has no exception and the killed path has no module name; emitting them
        # as "=None" is noise in every line that does not have them
        return {key: value for key, value in fields.items() if value is not None}


#
# configuration and paths
#

def get_crash_reporting_config():
    return get_config().crash_reporting


def get_crash_report_root_dir() -> str:
    """The directory all crash reports live under."""
    return os.path.join(get_data_dir(), get_crash_reporting_config().directory)


def get_crash_report_dir(crash_id: str, when: Optional[datetime] = None) -> str:
    """The directory for one crash report.

    Date partitioned so no single directory grows without bound and so retention is a single
    ``find -mtime`` over a fixed depth.
    """
    when = when or datetime.now()
    return os.path.join(
        get_crash_report_root_dir(),
        when.strftime("%Y"),
        when.strftime("%m"),
        when.strftime("%d"),
        crash_id,
    )


def get_index_pending_dir() -> str:
    """The spool of crash ids whose reports still need a database index row."""
    return os.path.join(get_crash_report_root_dir(), INDEX_PENDING_DIR)


def get_hang_stacks_dir() -> str:
    """This node's directory of pre-kill thread dumps."""
    return os.path.join(
        get_crash_report_root_dir(), HANG_STACKS_DIR, str(get_global_runtime_settings().saq_node)
    )


def get_hang_stacks_path(pid: int) -> str:
    """The pre-kill thread dump file of one engine worker process."""
    return os.path.join(get_hang_stacks_dir(), f"{int(pid)}.txt")


def find_crash_report_dir(crash_id: str, report_dir: Optional[str] = None) -> Optional[str]:
    """Resolve a crash id to its directory, or None.

    ``report_dir`` is the path recorded in the database index, relative to the data dir, and is
    used when supplied. The glob fallback exists because the database row is only an index: the
    insert is best effort precisely because a crash is when the database is most likely to be
    unwell, so a report with no row must still be retrievable.
    """
    if not is_valid_crash_id(crash_id):
        return None

    if report_dir:
        candidate = os.path.join(get_data_dir(), report_dir)
        if os.path.isdir(candidate):
            return candidate

    # bounded: the id is the leaf, and the three levels above it are the date
    matches = glob.glob(os.path.join(get_crash_report_root_dir(), "*", "*", "*", crash_id))
    for match in matches:
        if os.path.isdir(match):
            return match

    return None


def _relative_report_dir(crash_dir: str) -> str:
    """The report directory relative to the data dir, which is what the index stores.

    Storing it relative keeps a row valid when the data dir moves, which it does between a
    container and the host.
    """
    try:
        return os.path.relpath(crash_dir, start=get_data_dir())
    except ValueError:
        return crash_dir


#
# writing
#

def _write_atomic(path: str, content: str):
    """Write via a temp sibling and rename, so a reader never sees a half written file."""
    temp_path = f"{path}.tmp"
    with open(temp_path, "w") as fp:
        fp.write(content)

    os.replace(temp_path, path)


def _resolve_file_source(root, observable=None, observable_type=None, observable_value=None) -> Optional[str]:
    """The path to the bytes of the file observable a module crashed on, or None.

    Two lookups, because the obvious one is not always available. A file observable created
    during an analysis pass that was lost to the crash is not in the tree that was last saved
    to disk -- the reference is missing even though the bytes were already written. Since a
    file observable's *value* is its sha256 and the file manager stores content addressed
    copies under ``<storage_dir>/hardcopies/<sha256>``, the bytes are still findable by value
    alone. Without this fallback a crash report for exactly the interesting case -- the module
    died on something it had just extracted -- would silently contain no file.
    """
    # 1. the live observable, when the caller has one
    if observable is not None:
        try:
            full_path = getattr(observable, "full_path", None)
            if full_path and os.path.isfile(full_path):
                return full_path
        except Exception as e:
            logging.debug("unable to resolve full_path for %s: %s", observable, e)

    if root is None or not observable_value:
        return None

    storage_dir = getattr(root, "storage_dir", None)
    if not storage_dir:
        return None

    # 2. the observable as the saved tree knows it
    try:
        found = root.find_observable(
            lambda o: o.type == F_FILE and o.value == observable_value
        )
        if found is not None:
            full_path = getattr(found, "full_path", None)
            if full_path and os.path.isfile(full_path):
                return full_path
    except Exception as e:
        logging.debug("unable to find file observable %s: %s", observable_value, e)

    # 3. the content addressed hardcopy, which survives a tree that never recorded the reference
    if re.match(r"^[0-9a-fA-F]{64}$", observable_value):
        hardcopy = os.path.join(storage_dir, HARDCOPY_SUBDIR, observable_value.lower())
        if _is_contained(hardcopy, storage_dir) and os.path.isfile(hardcopy):
            return hardcopy

    return None


def _is_contained(path: str, parent: str) -> bool:
    """True if ``path`` really resolves to somewhere inside ``parent``.

    Belt to the sha256 regex's braces: an observable value reaches this code from a submission,
    so the path built out of it is never assumed to stay where it was put.
    """
    try:
        real_parent = os.path.realpath(parent)
        real_path = os.path.realpath(path)
        return os.path.commonpath([real_parent, real_path]) == real_parent
    except Exception:
        return False


def _sha256_of(path: str) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fp:
            for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception as e:
        logging.debug("unable to hash %s: %s", path, e)
        return None


def _capture_thread_stacks() -> str:
    """Every thread's stack, for a module that is stuck rather than broken.

    ``faulthandler`` walks threads at the C level, so it works even when the thread we care
    about is blocked in a syscall and will never run Python again -- which is the whole reason
    this is here. It writes to a file descriptor, not a Python stream (a ``StringIO`` makes it
    raise ``io.UnsupportedOperation``), so the dump goes through a real temporary file and is
    read back. The pure Python fallback covers the case where faulthandler fails anyway.
    """
    try:
        with tempfile.TemporaryFile(mode="w+") as fp:
            faulthandler.dump_traceback(file=fp, all_threads=True)
            fp.seek(0)
            captured = fp.read()
            if captured.strip():
                return captured
    except Exception as e:
        logging.debug("faulthandler could not dump tracebacks: %s", e)

    try:
        lines = []
        for thread_id, frame in sys._current_frames().items():
            lines.append(f"\n# thread {thread_id}")
            lines.extend(traceback.format_stack(frame))
        return "".join(lines)
    except Exception as e:
        return f"unable to capture thread stacks: {e}\n"


#
# hang stack dumps
#
# One faulthandler.dump_traceback_later timer per process, so the state is process global. A
# worker runs one module at a time, and arming always cancels the previous timer first.

_hang_stacks_fp = None


def open_hang_stacks_file() -> bool:
    """Open this process's pre-kill dump file. Called once by each engine worker as it starts.

    Append mode on purpose: faulthandler writes through the raw file descriptor, and O_APPEND is
    what makes a write after ``ftruncate`` land at offset 0 instead of past a sparse hole at the
    old offset. Never raises; returns True if the file is open.
    """
    global _hang_stacks_fp
    try:
        close_hang_stacks_file()
        path = get_hang_stacks_path(os.getpid())
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _hang_stacks_fp = open(path, "a")
        os.ftruncate(_hang_stacks_fp.fileno(), 0)
        return True
    except Exception as e:
        logging.warning("unable to open the hang stack dump file: %s", e)
        _hang_stacks_fp = None
        return False


def close_hang_stacks_file():
    """Cancel any armed dump and close this process's dump file. Never raises."""
    global _hang_stacks_fp
    try:
        faulthandler.cancel_dump_traceback_later()
    except Exception as e:
        logging.debug("unable to cancel the hang stack dump: %s", e)

    if _hang_stacks_fp is not None:
        try:
            _hang_stacks_fp.close()
        except Exception as e:
            logging.debug("unable to close the hang stack dump file: %s", e)

        _hang_stacks_fp = None


def _hang_stack_delay(maximum_analysis_time: float) -> float:
    """How long after a module starts the pre-kill dump fires: ``HANG_STACK_MARGIN_SECONDS``
    before the kill, or halfway there when the limit is too short to leave that much room."""
    if maximum_analysis_time > 2 * HANG_STACK_MARGIN_SECONDS:
        return maximum_analysis_time - HANG_STACK_MARGIN_SECONDS

    return maximum_analysis_time / 2


def _truncate_hang_stacks_file():
    if _hang_stacks_fp is not None:
        os.ftruncate(_hang_stacks_fp.fileno(), 0)


def arm_hang_stack_dump(maximum_analysis_time: Optional[float]):
    """Arm the pre-kill thread dump for the module about to run.

    The timer runs in a C thread that does not need the GIL, so it fires even while the module
    holds it -- exactly the case where the Python watchdog thread (``AnalysisModuleMonitor``) is
    starved and writes nothing. The file is truncated first so it only ever holds the dump of
    the current execution. Does nothing when no dump file is open (the single threaded engine,
    which has no manager to kill it) or when the module has no time limit. Never raises.
    """
    if _hang_stacks_fp is None or not maximum_analysis_time or maximum_analysis_time <= 0:
        return

    try:
        faulthandler.cancel_dump_traceback_later()
        _truncate_hang_stacks_file()
        faulthandler.dump_traceback_later(
            _hang_stack_delay(maximum_analysis_time),
            repeat=False,
            file=_hang_stacks_fp,
            exit=False,
        )
    except Exception as e:
        logging.warning("unable to arm the hang stack dump: %s", e)


def cancel_hang_stack_dump():
    """Disarm the pre-kill dump after a module returns. Never raises.

    The file is truncated here too, so a dump from a module that ran long but did finish can
    never be attached to a later, unrelated kill (a memory kill during the next module).
    """
    if _hang_stacks_fp is None:
        return

    try:
        faulthandler.cancel_dump_traceback_later()
        _truncate_hang_stacks_file()
    except Exception as e:
        logging.warning("unable to cancel the hang stack dump: %s", e)


def take_hang_stacks(pid: Optional[int]) -> Optional[str]:
    """The pre-kill thread dump a dead worker left behind, or None. Never raises."""
    if pid is None:
        return None

    try:
        with open(get_hang_stacks_path(pid)) as fp:
            stacks = fp.read()
        return stacks if stacks.strip() else None
    except FileNotFoundError:
        return None
    except Exception as e:
        logging.warning("unable to read the hang stack dump of pid %s: %s", pid, e)
        return None


def discard_hang_stacks(pid: Optional[int]):
    """Delete a dead worker's pre-kill dump file. Missing is fine; never raises."""
    if pid is None:
        return

    try:
        os.unlink(get_hang_stacks_path(pid))
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.warning("unable to remove the hang stack dump of pid %s: %s", pid, e)


def prune_stale_hang_stacks(min_age_seconds: float = HANG_STACKS_PRUNE_MIN_AGE_SECONDS) -> int:
    """Delete this node's dump files whose process is gone. Returns how many. Never raises.

    A file is only removed when its pid no longer exists *and* it has not been written for
    ``min_age_seconds``: when several workers are killed at once, their replacements start in
    some order, and the age guard keeps the first one from deleting a file the others have yet
    to collect.
    """
    removed = 0
    try:
        hang_dir = get_hang_stacks_dir()
        if not os.path.isdir(hang_dir):
            return removed

        cutoff = time.time() - min_age_seconds
        for file_name in os.listdir(hang_dir):
            pid_text, extension = os.path.splitext(file_name)
            if extension != ".txt" or not pid_text.isdigit():
                continue

            path = os.path.join(hang_dir, file_name)
            try:
                if psutil.pid_exists(int(pid_text)) or os.path.getmtime(path) > cutoff:
                    continue
                os.unlink(path)
                removed += 1
            except FileNotFoundError:
                continue
            except Exception as e:
                logging.warning("unable to prune hang stack dump %s: %s", path, e)

    except Exception as e:
        logging.warning("unable to prune hang stack dumps: %s", e)

    return removed


def _format_exception(exception: Optional[BaseException]) -> Optional[str]:
    """The traceback, rendered the way ACE renders error reports.

    ``ExceptionFormatter`` annotates frames with source context, which is the reason to prefer
    it over ``traceback.format_exc()``; it is the same renderer ``report_exception()`` uses, so
    a crash report and an error report for the same failure read identically.
    """
    if exception is None:
        return None

    tb = exception.__traceback__
    try:
        formatter = ExceptionFormatter()
        stack_trace, final_source = formatter.format_traceback(tb)
        return (
            f"EXCEPTION\n{exception}\n\n"
            f"STACK TRACE\n{stack_trace}\n\n"
            f"EXCEPTION SOURCE\n{final_source}\n"
        )
    except Exception as e:
        logging.debug("unable to format traceback with ExceptionFormatter: %s", e)

    try:
        return "".join(traceback.format_exception(type(exception), exception, tb))
    except Exception as e:
        return f"unable to format exception: {e}\n"


def _copy_capped(source: str, dest: str, max_size: int, what: str, omitted: list) -> Optional[int]:
    """Copy ``source`` to ``dest`` unless it is over ``max_size``. Returns the size copied."""
    try:
        size = os.path.getsize(source)
    except OSError as e:
        omitted.append({"what": what, "reason": OMITTED_NOT_FOUND, "detail": str(e)})
        return None

    if max_size and size > max_size:
        omitted.append({
            "what": what,
            "reason": OMITTED_TOO_LARGE,
            "detail": f"{size} bytes exceeds the {max_size} byte limit",
        })
        return None

    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy(source, dest)
        return size
    except Exception as e:
        omitted.append({"what": what, "reason": OMITTED_ERROR, "detail": str(e)})
        return None


def record_module_crash(
    *,
    crash_type: str,
    module_path: Optional[str] = None,
    module_name: Optional[str] = None,
    root=None,
    observable=None,
    observable_type: Optional[str] = None,
    observable_value: Optional[str] = None,
    observable_uuid: Optional[str] = None,
    exception: Optional[BaseException] = None,
    worker_name: Optional[str] = None,
    maximum_analysis_time: Optional[int] = None,
    module_start_time: Optional[str] = None,
    elapsed_seconds: Optional[float] = None,
    include_thread_stacks: bool = False,
    thread_stacks: Optional[str] = None,
    index: bool = True,
    replicate: bool = True,
) -> Optional[str]:
    """Record one analysis module crash. Returns the crash id, or None.

    Never raises. A crash report that can take analysis down with it, or that can stop a wedged
    process from exiting, is worse than no crash report; every failure below is logged and
    swallowed.

    ``include_thread_stacks`` captures this process's threads right now (the watchdog);
    ``thread_stacks`` is stack text captured earlier, by another process (the pre-kill dump a
    ``killed`` report inherits from the worker that died). The first wins if both are given.

    ``index=False`` skips the database write and ``replicate=False`` skips the copy to shared
    storage. Both are used by the in-process watchdog, which is running inside a process whose
    main thread is already wedged and which must reach ``os._exit(1)`` promptly: the database
    write could block, and ``os._exit()`` annihilates the daemon thread replication would use.
    Neither loses the report. Instead of the row, an unindexed report gets an entry in the local
    index spool -- a file create, the same kind of work as writing the report itself -- and a
    healthy process indexes it later (``drain_index_spool``; the replacement worker does it
    within seconds). ``ace crash sync`` replicates it later.
    """
    try:
        config = get_crash_reporting_config()
        if not config.enabled:
            return None

        # the watchdog is exempt: it fires once and then the process exits, and its report is
        # the only record of where a hung module was stuck
        if not include_thread_stacks and not _within_report_limit(
            getattr(root, "uuid", None), module_path, config.max_reports_per_module_per_root
        ):
            return None

        now = datetime.now()
        crash_id = str(uuid.uuid4())
        crash_dir = get_crash_report_dir(crash_id, now)

        # prefer what the caller passed; fall back to the observable it handed us
        if observable is not None:
            observable_type = observable_type or getattr(observable, "type", None)
            observable_value = observable_value or getattr(observable, "value", None)
            observable_uuid = observable_uuid or getattr(observable, "uuid", None)

        metadata = CrashReportMetadata(
            crash_id=crash_id,
            crash_type=crash_type,
            timestamp=now.isoformat(),
            node=get_global_runtime_settings().saq_node,
            hostname=socket.gethostname(),
            pid=os.getpid(),
            worker_name=worker_name,
            module_path=module_path,
            module_name=module_name,
            analysis_mode=getattr(root, "analysis_mode", None),
            maximum_analysis_time=maximum_analysis_time,
            module_start_time=module_start_time,
            elapsed_seconds=elapsed_seconds,
            root_uuid=getattr(root, "uuid", None),
            root_storage_dir=getattr(root, "storage_dir", None),
            root_description=getattr(root, "description", None),
            observable_uuid=observable_uuid,
            observable_type=observable_type,
            observable_value=observable_value,
            exception_type=type(exception).__name__ if exception is not None else None,
            exception_message=str(exception) if exception is not None else None,
        )

        os.makedirs(crash_dir, exist_ok=True)

        # ---- everything below writes into crash_dir, metadata.json strictly last ----

        stack_trace = _format_exception(exception)
        if stack_trace:
            _write_atomic(os.path.join(crash_dir, STACK_TRACE_FILE), stack_trace)

        if include_thread_stacks:
            _write_atomic(os.path.join(crash_dir, THREAD_STACKS_FILE), _capture_thread_stacks())
        elif thread_stacks:
            _write_atomic(os.path.join(crash_dir, THREAD_STACKS_FILE), thread_stacks)
        elif crash_type == CRASH_TYPE_KILLED:
            # a killed report is only stackless when the pre-kill dump never landed (the module
            # was not hung -- a memory kill -- or the dump could not be written); say so
            metadata.omitted.append({
                "what": THREAD_STACKS_FILE,
                "reason": OMITTED_NOT_FOUND,
                "detail": "no pre-kill thread dump was captured",
            })

        _copy_root_json(root, crash_dir, config, metadata.omitted)
        _copy_file_observable(
            root, observable, observable_type, observable_value, crash_dir, config, metadata
        )

        _write_atomic(
            os.path.join(crash_dir, METADATA_FILE),
            json.dumps(metadata.to_dict(), indent=2, sort_keys=True, default=str),
        )

        # the one line an analyst greps for. the message describes the event; the fields ride
        # on extra={} so they are key=value in saq.log and real fields in Splunk
        logging.error("analysis module crash recorded", extra=metadata.log_fields())

        try:
            emit_monitor(MONITOR_MODULE_CRASH, metadata.to_dict())
        except Exception as e:
            logging.debug("unable to emit crash monitor: %s", e)

        # the spool entry is written after metadata.json, so a spooled id always names a
        # complete report. a failed inline insert is spooled too, so a row lost to an unwell
        # database is retried rather than lost
        if not index or not _index_crash_report(metadata, _relative_report_dir(crash_dir)):
            _spool_for_index(crash_id)

        if replicate:
            _replicate_crash_report(crash_dir, crash_id)

        return crash_id

    except Exception as e:
        # the whole point of this handler: reporting a crash must never cause one
        logging.warning("unable to record analysis module crash: %s", e)
        return None


def _copy_root_json(root, crash_dir: str, config, omitted: list):
    """Copy the root's data.json -- the analysis tree, without its files.

    The tree is what says which modules had already run and what they produced, which is most
    of the context for reading a traceback.

    Only ``data.json`` -- never the whole storage directory. The bytes under ``files/`` and
    ``hardcopies/`` are deliberately left behind: copying them means copying every file
    observable in the tree (twice, since a copy does not preserve the hard links between the
    two directories), which is the part that fills disks. The one file that matters, the one
    the module actually died on, is copied separately by ``_copy_file_observable()``.

    Note this does not include the ``.ace/`` subdirectory, where analysis ``details`` payloads
    are stored externally -- so the report carries the shape of what earlier modules produced,
    not their full output.
    """
    if not config.copy_root_json:
        omitted.append({"what": ROOT_JSON_FILE, "reason": OMITTED_DISABLED})
        return

    storage_dir = getattr(root, "storage_dir", None)
    if not storage_dir:
        return

    source = os.path.join(storage_dir, ROOT_DATA_FILE)
    if not os.path.isfile(source):
        omitted.append({"what": ROOT_JSON_FILE, "reason": OMITTED_NOT_FOUND, "detail": source})
        return

    _copy_capped(
        source, os.path.join(crash_dir, ROOT_JSON_FILE),
        config.max_root_json_size, ROOT_JSON_FILE, omitted,
    )


def _copy_file_observable(root, observable, observable_type, observable_value,
                          crash_dir: str, config, metadata: CrashReportMetadata):
    """Copy the bytes of the file observable the module crashed on.

    This is the artifact an analyst actually wants: the thing that was hostile enough to take
    a module down. Each crash gets its own directory, so unlike the mechanisms this replaces
    there is no basename collision between two crashes on the same file name.
    """
    if observable_type != F_FILE:
        return

    if not config.copy_file:
        metadata.omitted.append({"what": FILE_DIR, "reason": OMITTED_DISABLED})
        return

    source = _resolve_file_source(
        root, observable=observable, observable_type=observable_type,
        observable_value=observable_value,
    )
    if source is None:
        metadata.omitted.append({
            "what": FILE_DIR,
            "reason": OMITTED_NOT_FOUND,
            "detail": f"no bytes found for {observable_value}",
        })
        return

    file_name = os.path.basename(source)
    if observable is not None:
        file_name = getattr(observable, "file_name", None) or file_name

    size = _copy_capped(
        source, os.path.join(crash_dir, FILE_DIR, file_name),
        config.max_file_size, FILE_DIR, metadata.omitted,
    )
    if size is None:
        return

    metadata.file_name = file_name
    metadata.file_size = size
    # a file observable's value is already its sha256; only hash when it came from elsewhere
    if observable_value and re.match(r"^[0-9a-fA-F]{64}$", observable_value):
        metadata.file_sha256 = observable_value.lower()
    else:
        metadata.file_sha256 = _sha256_of(source)


def _index_crash_report(metadata: CrashReportMetadata, report_dir: str,
                        insert_date: Optional[datetime] = None) -> bool:
    """Insert the database index row. Best effort, by design. Returns True if the row exists.

    The filesystem is authoritative. A crash is exactly when the database is most likely to be
    unwell -- pool exhaustion and deadlocks are among the things that get reported here -- so a
    failure to index must not lose the report. ``find_crash_report_dir()`` globs when there is
    no row, and the caller spools a report whose insert failed, so the worst case of this
    failing is a report that cannot be *listed* until the spool is drained.

    Idempotent: a row that already exists counts as success, because the spool can be drained
    by more than one process at once. ``insert_date`` is passed when indexing after the fact,
    so the listing (newest first) orders a report by when it crashed, not when it was indexed.
    """
    try:
        # imported here rather than at module level: saq.database pulls in SQLAlchemy and the
        # connection pool, and this module is imported by the engine's crash paths and by the
        # API, neither of which should pay that cost to write or read a file
        from sqlalchemy.exc import IntegrityError

        from saq.database.model import AnalysisModuleCrash
        from saq.database.pool import get_db

        if get_db().query(AnalysisModuleCrash.id).filter(
            AnalysisModuleCrash.uuid == metadata.crash_id
        ).first() is not None:
            return True

        row = AnalysisModuleCrash(
            uuid=metadata.crash_id,
            crash_type=metadata.crash_type,
            node=metadata.node or "unknown",
            report_dir=report_dir,
            module_path=metadata.module_path,
            module_name=metadata.module_name,
            analysis_mode=metadata.analysis_mode,
            root_uuid=metadata.root_uuid,
            observable_uuid=metadata.observable_uuid,
            observable_type=metadata.observable_type,
            observable_value=metadata.observable_value,
            exception_type=metadata.exception_type,
            exception_message=metadata.exception_message,
            has_file=metadata.file_name is not None,
        )
        if insert_date is not None:
            row.insert_date = insert_date

        get_db().add(row)
        try:
            get_db().commit()
        except IntegrityError:
            # another drainer inserted it between our check and our commit
            get_db().rollback()

        return True
    except Exception as e:
        logging.warning("unable to index crash report %s: %s", metadata.crash_id, e)
        try:
            from saq.database.pool import get_db

            get_db().rollback()
        except Exception:
            pass

        return False


def _spool_for_index(crash_id: str):
    """Record that this report still needs an index row. Local disk only; never raises."""
    try:
        spool_dir = get_index_pending_dir()
        os.makedirs(spool_dir, exist_ok=True)
        _write_atomic(os.path.join(spool_dir, crash_id), "")
    except Exception as e:
        logging.warning("unable to spool crash report %s for indexing: %s", crash_id, e)


def remove_from_index_spool(crash_id: str):
    """Drop a crash id from the spool. Missing entries are fine; never raises."""
    if not is_valid_crash_id(crash_id):
        return

    try:
        os.unlink(os.path.join(get_index_pending_dir(), crash_id))
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.warning("unable to remove crash report %s from the index spool: %s", crash_id, e)


def _index_existing_report(crash_id: str, crash_dir: str, report: dict) -> Optional[CrashReportMetadata]:
    """Index a report that is already on disk, stamped with its own crash time."""
    metadata = CrashReportMetadata.from_dict(report)
    insert_date = None
    try:
        insert_date = datetime.fromisoformat(metadata.timestamp)
    except Exception:
        pass

    if not _index_crash_report(metadata, _relative_report_dir(crash_dir), insert_date):
        return None

    return metadata


def index_crash_report(crash_id: str) -> Optional[CrashReportMetadata]:
    """Index one report that is already on disk, after the fact.

    Returns the metadata that was indexed (or was already indexed), or None if the report is
    missing, incomplete, or could not be indexed. Never raises.
    """
    try:
        crash_dir = find_crash_report_dir(crash_id)
        if crash_dir is None:
            return None

        report = read_crash_report(crash_id)
        if report is None or not report.get("complete"):
            return None

        return _index_existing_report(crash_id, crash_dir, report)
    except Exception as e:
        logging.warning("unable to index crash report %s: %s", crash_id, e)
        return None


def drain_index_spool(limit: Optional[int] = None) -> list[CrashReportMetadata]:
    """Index every spooled crash report. Returns the metadata of each one indexed.

    Called by every engine worker as it starts -- which is promptly after a timeout, because the
    watchdog's ``os._exit(1)`` is what gets a replacement worker started -- and by
    ``ace crash index`` as the catch-up sweep. Safe to run in several processes at once: the
    insert is idempotent and a vanished spool entry is someone else's success.

    An entry whose report is gone (pruned) or unreadable is dropped: there is nothing left that
    could ever be indexed. An entry that fails to *index* stays, and the drain stops there: the
    database is unwell, and the next drain will try again.

    Never raises.
    """
    indexed = []
    try:
        spool_dir = get_index_pending_dir()
        if not os.path.isdir(spool_dir):
            return indexed

        # oldest first, so a limited drain works through a backlog in crash order
        entries = []
        for crash_id in os.listdir(spool_dir):
            # skips _write_atomic's .tmp siblings and anything else that is not ours
            if not is_valid_crash_id(crash_id):
                continue
            try:
                entries.append((os.path.getmtime(os.path.join(spool_dir, crash_id)), crash_id))
            except OSError:
                continue

        for _, crash_id in sorted(entries):
            if limit is not None and len(indexed) >= limit:
                break

            crash_dir = find_crash_report_dir(crash_id)
            report = read_crash_report(crash_id) if crash_dir is not None else None
            if report is None or not report.get("complete"):
                remove_from_index_spool(crash_id)
                continue

            metadata = _index_existing_report(crash_id, crash_dir, report)
            if metadata is None:
                logging.warning("unable to index spooled crash report %s; will retry", crash_id)
                break

            remove_from_index_spool(crash_id)
            indexed.append(metadata)

    except Exception as e:
        logging.warning("unable to drain the crash report index spool: %s", e)

    return indexed


def _replicate_crash_report(crash_dir: str, crash_id: str):
    """Copy the report to shared storage so any node can serve it. Best effort, non-blocking.

    Off unless ``crash_reporting.replicate`` is set. The call returns immediately -- the upload
    runs on a daemon thread that is never joined -- because this is the crash path and
    ``saq/storage`` has no timeouts. See saq/crash_replication.py.
    """
    try:
        # imported here rather than at module level: saq.storage pulls in boto3, which is not a
        # core dependency, and this module is on the engine's crash path
        from saq.crash_replication import replicate_async, replication_enabled

        if not replication_enabled():
            return

        replicate_async(crash_dir, crash_id)
    except Exception as e:
        logging.warning("unable to start replication for crash report %s: %s", crash_id, e)


#
# reading
#

def read_crash_report(crash_id: str, report_dir: Optional[str] = None) -> Optional[dict]:
    """The metadata for one crash report, or None if it cannot be found.

    A directory with no ``metadata.json`` is a report that was killed mid write (or is being
    written right now). It is reported as incomplete rather than hidden -- partial evidence is
    still evidence, and "the worker died while writing the report" is itself a finding.
    """
    crash_dir = find_crash_report_dir(crash_id, report_dir)
    if crash_dir is None:
        return None

    metadata_path = os.path.join(crash_dir, METADATA_FILE)
    if not os.path.isfile(metadata_path):
        return {
            "crash_id": crash_id,
            "complete": False,
            "report_dir": _relative_report_dir(crash_dir),
            "files": list_report_files(crash_dir),
        }

    try:
        with open(metadata_path) as fp:
            metadata = json.load(fp)
    except Exception as e:
        logging.warning("unable to read crash report metadata %s: %s", metadata_path, e)
        return None

    metadata["complete"] = True
    metadata["report_dir"] = _relative_report_dir(crash_dir)
    metadata["files"] = list_report_files(crash_dir)
    return metadata


def list_report_files(crash_dir: str) -> list[dict]:
    """Every file in the report, relative to its directory, with sizes."""
    results = []
    try:
        for dirpath, _, file_names in os.walk(crash_dir):
            for file_name in file_names:
                full_path = os.path.join(dirpath, file_name)
                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    continue
                results.append({
                    "path": os.path.relpath(full_path, start=crash_dir),
                    "size": size,
                })
    except Exception as e:
        logging.debug("unable to list crash report files in %s: %s", crash_dir, e)

    return sorted(results, key=lambda _: _["path"])
