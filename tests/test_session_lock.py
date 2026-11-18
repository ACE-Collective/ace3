"""One run of the test suite at a time per container and per checkout (tests/session_lock.py)."""

import fcntl
import os
import select
import signal
import subprocess
import sys
import time

import pytest

from tests import session_lock

# the checkout the suite is running from, which SAQ_HOME no longer names once a test changes it
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(session_lock.__file__)))

# a run in a process of its own: it takes its run, says so and holds it until its stdin closes
# or it is killed
_RUN = """
import sys
from tests import session_lock
session_lock.RUN_LOCK_PATH = sys.argv[1]
session_lock.acquire_run()
print("started", flush=True)
sys.stdin.read()
session_lock.release_run()
"""


@pytest.fixture
def checkouts(tmp_path, monkeypatch) -> dict[str, str]:
    """Two checkouts in one container, with a run lock of their own: the running suite holds the
    real one, and its process's hold on it is put back afterwards."""
    monkeypatch.setattr(session_lock, "RUN_LOCK_PATH", str(tmp_path / "run.lock"))
    monkeypatch.setattr(session_lock, "_run_lock_fd", None)
    result = {}
    for name in ("main", "worktree"):
        result[name] = str(tmp_path / name)
        os.mkdir(result[name])

    return result


@pytest.fixture
def runs():
    """Starts runs in processes of their own, and kills any a failed test left running."""
    started = []

    def start(checkout: str) -> subprocess.Popen:
        process = subprocess.Popen(
            [sys.executable, "-c", _RUN, session_lock.RUN_LOCK_PATH],
            cwd=_PROJECT_ROOT, env={**os.environ, "SAQ_HOME": checkout},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        started.append(process)
        return process

    yield start

    for process in started:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=30)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def _read_until(stream, text: str, timeout: float = 30) -> str:
    """Reads a run's stdout or stderr until text turns up in it, and returns what it read."""
    data = b""
    deadline = time.monotonic() + timeout
    while text.encode() not in data:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f"{text!r} never came: {data!r}"
        ready, _, _ = select.select([stream], [], [], remaining)
        if ready:
            chunk = os.read(stream.fileno(), 65536)
            assert chunk, f"the run's output ended before {text!r} came: {data!r}"
            data += chunk

    return data.decode()


def _stop(process: subprocess.Popen) -> int:
    process.stdin.close()
    return process.wait(timeout=30)


def _is_run_lock_free() -> bool:
    fd = os.open(session_lock.RUN_LOCK_PATH, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)

    return True


@pytest.mark.unit
@pytest.mark.parametrize("second_checkout", ["worktree", "main"])
def test_a_second_run_in_the_container_waits_for_the_first(checkouts, runs, second_checkout):
    """Another checkout's run, or another run of the same checkout: either waits its turn."""
    first = runs(checkouts["main"])
    _read_until(first.stdout, "started")

    second = runs(checkouts[second_checkout])
    waiting = _read_until(second.stderr, "Ctrl-C stops waiting")
    assert f"pid:      {first.pid}" in waiting
    assert f"checkout: {checkouts['main']}" in waiting
    assert session_lock.RUN_LOCK_PATH in waiting
    # it is still waiting, and has not taken the checkout's marker
    assert second.poll() is None
    if second_checkout == "worktree":
        assert not os.path.exists(os.path.join(checkouts["worktree"], session_lock.MARKER_FILENAME))

    assert _stop(first) == 0
    _read_until(second.stdout, "started")
    assert "the test suite run lock is free after" in _read_until(second.stderr, ": starting")
    assert os.path.exists(os.path.join(checkouts[second_checkout], session_lock.MARKER_FILENAME))

    assert _stop(second) == 0
    for checkout in checkouts.values():
        assert not os.path.exists(os.path.join(checkout, session_lock.MARKER_FILENAME))
    assert _is_run_lock_free()


@pytest.mark.unit
def test_a_run_of_a_checkout_running_in_another_container_is_refused(checkouts, monkeypatch):
    """The same checkout running in another container, which has a run lock of its own: the
    refused run lets go of this container's lock."""
    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    session_lock.acquire(session_lock.get_marker_path())

    with pytest.raises(session_lock.SessionLockError) as error:
        session_lock.acquire_run()

    assert session_lock.get_marker_path() in str(error.value)
    assert session_lock._run_lock_fd is None
    assert _is_run_lock_free()
    # the other run's marker is still its own
    assert os.path.exists(session_lock.get_marker_path())


@pytest.mark.unit
def test_a_killed_run_leaves_the_lock_free_and_its_marker_behind(checkouts, runs, monkeypatch, capfd):
    """No lock to clear by hand: the kernel drops a dead process's flock. The checkout's marker
    is left, and refuses the checkout's next run until it is removed."""
    killed = runs(checkouts["main"])
    _read_until(killed.stdout, "started")
    killed.send_signal(signal.SIGKILL)
    killed.wait(timeout=30)

    # another checkout's run starts at once
    monkeypatch.setenv("SAQ_HOME", checkouts["worktree"])
    session_lock.acquire_run()
    session_lock.release_run()
    assert "waiting for" not in capfd.readouterr().err

    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    with pytest.raises(session_lock.SessionLockError) as error:
        session_lock.acquire_run()

    assert "that process is no longer running" in str(error.value)
    assert f"rm {session_lock.get_marker_path()}" in str(error.value)
    assert _is_run_lock_free()


@pytest.mark.unit
@pytest.mark.skipif(os.geteuid() == 0, reason="root can write a read-only file")
def test_a_read_only_lock_file_still_locks(checkouts, runs, monkeypatch):
    """A lock file created by a run as another user, which this user cannot write to."""
    with open(session_lock.RUN_LOCK_PATH, "w"):
        pass
    os.chmod(session_lock.RUN_LOCK_PATH, 0o444)

    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    session_lock.acquire_run()
    try:
        waiting_run = runs(checkouts["worktree"])
        waiting = _read_until(waiting_run.stderr, "Ctrl-C stops waiting")
    finally:
        session_lock.release_run()

    # this run could not record itself in the lock file
    assert "(who it is could not be read)" in waiting
    _read_until(waiting_run.stdout, "started")
    assert _stop(waiting_run) == 0


@pytest.mark.unit
@pytest.mark.parametrize("record", [b"", b'{"pid": 12', b"[1, 2]"])
def test_a_waiting_run_is_told_when_the_holder_cannot_be_read(tmp_path, record):
    """The holder was killed while it wrote its record, or has not written it yet."""
    path = tmp_path / "run.lock"
    path.write_bytes(record)
    fd = os.open(path, os.O_RDONLY)
    try:
        message = session_lock.describe_run_lock_holder(fd)
    finally:
        os.close(fd)

    assert "(who it is could not be read)" in message
