# vim: sw=4:ts=4:et
#
# the ACE test suite is not safe to run more than once at a time in one checkout
#
# every pytest process owns a slot (tests/unittest_session.py) that decides its data directory
# (under get_data_dir_root()), its API and network semaphore ports, its Qdrant collections and
# its log file; the process deletes and recreates that data directory at session start and
# again before every integration/system test. the slots of a pytest-xdist run are distinct, but
# a second run of the same checkout would reuse them, so two runs at the same time destroy each
# other's state, and (with pytest-randomly shuffling order) the resulting failures land
# somewhere unrelated and look like ordinary test bugs.
#
# so a run takes a marker file in $SAQ_HOME on the way in and drops it on the way out: the
# xdist controller, or the only process of a plain run. while that file exists no other run of
# the checkout is allowed to start, from any container the checkout is bind mounted into.
#
# runs of different checkouts (git worktrees run the suite in the same dev container) may run
# side by side. the data directory, the log file and the Qdrant collections are named after the
# checkout; the ports, which are the container's, come from a port block the run claims here.
#
# the databases are not part of this: every session provisions its own set (see
# tests/unittest_database.py). the marker is still what makes their cleanup safe, though --
# the process that holds it knows, before its own workers start, that every set an earlier
# session recorded belongs to a session that is dead.
#

import datetime
import fcntl
import json
import os
import socket
import sys
from typing import Optional

from tests import unittest_session

MARKER_FILENAME = ".pytest-running"
# the container's own /tmp, which every checkout run in it shares, as the ports are
PORT_BLOCK_LOCK_PATH_FORMAT = "/tmp/ace-pytest-ports-{}.lock"

# the open lock file of the port block this process claimed for its run
_port_block_fd: Optional[int] = None


class SessionLockError(Exception):
    """Raised when the pytest session marker file already exists."""
    pass


def get_marker_path() -> str:
    """Returns the path to the pytest session marker file.

    This is deliberately outside of the data directories -- they are deleted by
    execute_global_setup() at the start of the very session the marker is guarding."""
    return os.path.join(os.environ.get("SAQ_HOME", os.getcwd()), MARKER_FILENAME)


def acquire_run():
    """Creates the checkout's marker file and claims a port block for the run, or does neither.

    Raises SessionLockError, explaining the run that holds it, if the marker exists, or if every
    port block is taken."""
    global _port_block_fd

    path = get_marker_path()
    acquire(path)
    try:
        block, _port_block_fd = claim_port_block()
    except SessionLockError:
        release(path)
        raise

    # the xdist workers, which start after pytest_configure, inherit it
    os.environ[unittest_session.PORT_BLOCK_ENV_VAR] = str(block)


def release_run():
    """Undoes acquire_run(). Only for the process that acquire_run() succeeded in."""
    global _port_block_fd

    release(get_marker_path())
    if _port_block_fd is not None:
        os.close(_port_block_fd)
        _port_block_fd = None

    os.environ.pop(unittest_session.PORT_BLOCK_ENV_VAR, None)


def claim_port_block() -> tuple[int, int]:
    """Locks the first free port block, trying the checkout's own block first, and returns the
    block and the open lock file, which holds the block until it is closed.

    An flock and not a marker file: the kernel drops it when its holder dies, so a run that was
    killed never keeps a block. Starting at the checkout's block keeps each checkout on its own
    ports unless two checkouts' hashes pick the same block, and then the second takes the next.

    Block 0 is never claimed: it has the ports of a checkout whose suite predates port blocks,
    which knows nothing of these locks."""
    blocks = unittest_session.PORT_BLOCK_COUNT - 1
    first = int(unittest_session.get_checkout_hash(), 16) % blocks
    for offset in range(blocks):
        block = 1 + (first + offset) % blocks
        fd = os.open(PORT_BLOCK_LOCK_PATH_FORMAT.format(block), os.O_RDONLY | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # another run holds this block
            os.close(fd)
            continue

        return block, fd

    raise SessionLockError(
        f"\nevery one of the {blocks} test suite port blocks is held by a "
        f"running test suite ({PORT_BLOCK_LOCK_PATH_FORMAT.format('*')}): wait for one of them to finish\n")


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
        json.dump({
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "started": datetime.datetime.now().isoformat(),
            "argv": sys.argv,
            "checkout": os.environ.get("SAQ_HOME", os.getcwd()),
        }, fp, indent=4)

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
    """Returns the contents of the marker file as a dict, or None if it cannot be read.

    A session can be SIGKILLed part way through writing the marker, so anything here can fail."""

    try:
        with open(path, "r") as fp:
            result = json.load(fp)
    except (OSError, ValueError):
        return None

    if not isinstance(result, dict):
        return None

    return result


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
        "use pytest-xdist: pytest -n auto, and other checkouts may run at the same time)",
        "",
    ]

    if marker is None:
        lines += [
            "the marker file could not be read, so it is not possible to say whether a run is",
            "still in progress or the file was left behind by a run that did not exit cleanly.",
            "",
        ]
    else:
        lines += [
            f"    pid:      {marker.get('pid', 'unknown')}",
            f"    hostname: {marker.get('hostname', 'unknown')}",
            f"    started:  {marker.get('started', 'unknown')}",
            f"    checkout: {marker.get('checkout', 'unknown')}",
            f"    command:  {' '.join(marker.get('argv') or []) or 'unknown'}",
            "",
        ]

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
