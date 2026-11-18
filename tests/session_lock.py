# vim: sw=4:ts=4:et
#
# the ACE test suite runs once at a time per container, and once at a time per checkout
#
# per container: a run under pytest-xdist (pytest -n auto) starts a worker per cpu, and each
# worker loads the whole of ACE, the search model and an engine of its own. two such runs at
# once, from two checkouts (git worktrees run the suite in the same dev container), run the
# container out of memory. so a run first takes an flock on RUN_LOCK_PATH, in the container's
# own /tmp, and a run that finds it taken waits for it, saying whose run it is waiting on. an
# flock and not a marker file: the kernel drops it when its holder dies, so a killed run never
# leaves a lock behind for the next one to trip over.
#
# per checkout: every pytest process owns a slot (tests/unittest_session.py) that decides its
# data directory (under get_data_dir_root()), its API and network semaphore ports, its Qdrant
# collections and its log file; the process deletes and recreates that data directory at
# session start and again before every integration/system test. the slots of a pytest-xdist
# run are distinct, but a second run of the same checkout would reuse them, so two runs at the
# same time destroy each other's state, and (with pytest-randomly shuffling order) the
# resulting failures land somewhere unrelated and look like ordinary test bugs. the container
# lock already keeps a second run of a checkout out of the container, but the checkout is bind
# mounted into every container of the stack, and each has its own /tmp. so once it holds the
# container lock a run creates a marker file in $SAQ_HOME, and a run that finds the marker
# there is refused: either a run of the checkout is going on in another container, or a killed
# run left the marker behind.
#
# the databases are not part of this: every session provisions its own set (see
# tests/unittest_database.py). the marker is still what makes their cleanup safe, though --
# the process that holds it knows, before its own workers start, that every set an earlier
# session recorded belongs to a session that is dead.
#
# the xdist controller, or the only process of a plain run, takes both; its workers ride on them.
#

import datetime
import fcntl
import json
import os
import socket
import sys
import time
from typing import Optional

MARKER_FILENAME = ".pytest-running"
# the container's own /tmp, which every checkout run in it shares
RUN_LOCK_PATH = "/tmp/ace-pytest-run.lock"

# the open lock file of the container's run lock, while this process holds it
_run_lock_fd: Optional[int] = None


class SessionLockError(Exception):
    """Raised when the pytest session marker file already exists."""
    pass


def get_marker_path() -> str:
    """Returns the path to the pytest session marker file.

    This is deliberately outside of the data directories -- they are deleted by
    execute_global_setup() at the start of the very session the marker is guarding."""
    return os.path.join(os.environ.get("SAQ_HOME", os.getcwd()), MARKER_FILENAME)


def acquire_run():
    """Takes the container's run lock, waiting for it if another run holds it, then creates the
    checkout's marker file. Takes both or neither.

    Raises SessionLockError, explaining the run that holds it, if the marker exists."""
    global _run_lock_fd

    fd = wait_for_run_lock()
    try:
        acquire(get_marker_path())
    except BaseException:
        os.close(fd)
        raise

    _run_lock_fd = fd


def release_run():
    """Undoes acquire_run(). Only for the process that acquire_run() succeeded in."""
    global _run_lock_fd

    # the marker first: a run waiting for the lock takes the marker as soon as it has the lock
    release(get_marker_path())
    if _run_lock_fd is not None:
        os.close(_run_lock_fd)
        _run_lock_fd = None


def _open_run_lock() -> tuple[int, bool]:
    """Opens the run lock file, and says whether this process can record itself in it."""
    try:
        fd = os.open(RUN_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o666)
    except PermissionError:
        # created by another user (a run as root, through bin/exec-in-container.sh -u root),
        # whose umask left it read-only to us. a read-only descriptor locks just the same.
        return os.open(RUN_LOCK_PATH, os.O_RDONLY), False

    try:
        # so that a run as another user can record itself in it too; the umask took the bits
        os.fchmod(fd, 0o666)
    except PermissionError:
        # not ours, but writable to us all the same
        pass

    return fd, True


def wait_for_run_lock() -> int:
    """Takes the container's run lock and returns its open lock file, which holds the lock until
    it is closed. If another run holds it, says so on stderr and waits for that run to end."""
    fd, writable = _open_run_lock()
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.stderr.write(describe_run_lock_holder(fd))
            sys.stderr.flush()
            started = time.monotonic()
            # bounded by the run that holds the lock: the kernel drops it when that run exits,
            # however it exits. Ctrl-C ends the wait.
            fcntl.flock(fd, fcntl.LOCK_EX)
            sys.stderr.write(f"the test suite run lock is free after {_format_wait(time.monotonic() - started)}: starting\n")
            sys.stderr.flush()

        if writable:
            # whoever waits next reads who holds the lock from here
            os.ftruncate(fd, 0)
            os.pwrite(fd, json.dumps(_describe_this_run(), indent=4).encode(), 0)
    except BaseException:
        os.close(fd)
        raise

    return fd


def _format_wait(seconds: float) -> str:
    minutes, seconds = divmod(int(seconds), 60)
    return f"{minutes}m{seconds:02d}s" if minutes else f"{seconds}s"


def _describe_this_run() -> dict:
    return {
        "pid": os.getpid(),
        "hostname": socket.gethostname(),
        "started": datetime.datetime.now().isoformat(),
        "argv": sys.argv,
        "checkout": os.environ.get("SAQ_HOME", os.getcwd()),
    }


def _describe_run(record: Optional[dict]) -> list[str]:
    if record is None:
        return ["    (who it is could not be read)", ""]

    return [
        f"    pid:      {record.get('pid', 'unknown')}",
        f"    hostname: {record.get('hostname', 'unknown')}",
        f"    started:  {record.get('started', 'unknown')}",
        f"    checkout: {record.get('checkout', 'unknown')}",
        f"    command:  {' '.join(record.get('argv') or []) or 'unknown'}",
        "",
    ]


def describe_run_lock_holder(fd: int) -> str:
    """Returns what a run waiting for the run lock tells the user."""
    try:
        record = _parse_record(os.pread(fd, 65536, 0))
    except OSError:
        # only what the message says about the holder: the wait goes ahead without it
        record = None

    lines = [
        "",
        "waiting for the test suite run that is going on in this container to finish:",
        "",
    ]
    lines += _describe_run(record)
    lines += [
        "one run at a time per container: two runs' xdist workers run it out of memory.",
        f"this run starts when that one ends (the lock is {RUN_LOCK_PATH}). Ctrl-C stops waiting.",
        "",
    ]
    return "\n".join(lines)


def _parse_record(data: bytes) -> Optional[dict]:
    """Returns a run's record as a dict, or None. A run can be SIGKILLed part way through
    writing one, so anything here can fail."""
    try:
        result = json.loads(data)
    except ValueError:
        # a partial or empty record: the caller says the holder could not be read
        return None

    if not isinstance(result, dict):
        return None

    return result


def acquire(path: Optional[str] = None) -> bool:
    """Atomically creates the session marker file, recording who created it.

    Returns True if the marker was created. Raises SessionLockError (carrying the full
    explanation intended for the user) if the marker already exists."""

    if path is None:
        path = get_marker_path()

    try:
        # O_EXCL makes this a single atomic check-and-create, so two sessions starting at the
        # same instant cannot both think they won
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        raise SessionLockError(describe_holder(path))

    with os.fdopen(fd, "w") as fp:
        json.dump(_describe_this_run(), fp, indent=4)

    return True


def release(path: Optional[str] = None):
    """Removes the session marker file. Does nothing if it is already gone."""

    if path is None:
        path = get_marker_path()

    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _read_marker(path: str) -> Optional[dict]:
    """Returns the contents of the marker file as a dict, or None if it cannot be read."""

    try:
        with open(path, "rb") as fp:
            return _parse_record(fp.read())
    except OSError:
        # describe_holder() says the marker could not be read
        return None


def _is_pytest_still_running(marker: dict) -> Optional[bool]:
    """Returns True if the process that wrote the marker is still running pytest, False if it
    is definitely gone, or None if we cannot tell.

    We can only tell on the host that wrote the marker: the repository is bind mounted into
    every container, so the marker may well have been written somewhere else."""

    pid = marker.get("pid")
    hostname = marker.get("hostname")

    if not isinstance(pid, int) or hostname != socket.gethostname():
        return None

    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fp:
            cmdline = fp.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return False
    except OSError:
        return None

    # the pid may have been recycled by something that is not pytest at all
    return "pytest" in cmdline


def describe_holder(path: str) -> str:
    """Returns the explanation shown to the user when the marker file blocks a run."""

    marker = _read_marker(path)

    lines = [
        "",
        "another pytest session appears to be running (or to have crashed)",
        "",
        f"the ACE test suite marker file exists: {path}",
        "",
        "the test suite is not safe to run more than once at a time in one checkout -- each",
        "run deletes and recreates the checkout's per-slot data directories and writes its",
        "per-slot Qdrant collections, so concurrent runs corrupt each other. (a single run may",
        "use pytest-xdist: pytest -n auto. a run in this container would have waited for the",
        "other instead, so this marker is another container's, or a killed run's)",
        "",
    ]

    if marker is None:
        lines += [
            "the marker file could not be read, so it is not possible to say whether a run is",
            "still in progress or the file was left behind by a run that did not exit cleanly.",
            "",
        ]
    else:
        lines += _describe_run(marker)

        running = _is_pytest_still_running(marker)
        if running is True:
            lines += [
                "that process is still running. wait for it to finish before starting another run.",
                "",
            ]
        elif running is False:
            lines += [
                "that process is no longer running, so this marker was left behind by a run that",
                "did not exit cleanly (killed, or the container went away). it is safe to remove.",
                "",
            ]
        else:
            lines += [
                "it is not possible to tell from here whether that process is still running (it was",
                "started on a different host or container). either a run is still in progress, or the",
                "marker was left behind by a run that did not exit cleanly.",
                "",
            ]

    lines += [
        "once you are sure no test suite is running, remove the marker file:",
        "",
        f"    rm {path}",
        "",
    ]

    return "\n".join(lines)
