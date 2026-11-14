"""One run of the test suite at a time per checkout, each on ports of its own (tests/session_lock.py)."""

import glob
import os
import signal
import subprocess
import sys

import pytest

from tests import session_lock, unittest_session

# the checkout the suite is running from, which SAQ_HOME no longer names once a test changes it
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(session_lock.__file__)))

# a run of another checkout in a process of its own: it claims its run, reports its port block
# and holds the run until its stdin closes or it is killed
_RUN_ELSEWHERE = """
import os, sys
from tests import session_lock, unittest_session
session_lock.PORT_BLOCK_LOCK_PATH_FORMAT = sys.argv[1]
session_lock.acquire_run()
print(os.environ[unittest_session.PORT_BLOCK_ENV_VAR], flush=True)
sys.stdin.read()
session_lock.release_run()
"""


@pytest.fixture
def checkouts(tmp_path, monkeypatch) -> dict[str, str]:
    """Two checkouts in one container, with port block locks of their own: the running suite
    holds a real block, and its process's claim and environment are put back afterwards."""
    monkeypatch.setattr(session_lock, "PORT_BLOCK_LOCK_PATH_FORMAT", str(tmp_path / "ports-{}.lock"))
    monkeypatch.setattr(session_lock, "_port_block_fd", None)
    monkeypatch.setenv(unittest_session.PORT_BLOCK_ENV_VAR, "running suite's block")
    result = {}
    for name in ("main", "worktree"):
        result[name] = str(tmp_path / name)
        os.mkdir(result[name])

    return result


def _start_run_elsewhere(checkout: str) -> tuple[subprocess.Popen, int]:
    process = subprocess.Popen(
        [sys.executable, "-c", _RUN_ELSEWHERE, session_lock.PORT_BLOCK_LOCK_PATH_FORMAT],
        cwd=_PROJECT_ROOT, env={**os.environ, "SAQ_HOME": checkout},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    # bounded by the process: it prints its block or exits
    line = process.stdout.readline()
    assert line, f"the run of {checkout} did not start"
    return process, int(line)


def _stop(process: subprocess.Popen):
    process.stdin.close()
    process.wait(timeout=30)
    process.stdout.close()


@pytest.mark.unit
def test_runs_of_two_checkouts_in_one_container_take_different_ports(checkouts, monkeypatch):
    monkeypatch.setenv("SAQ_HOME", checkouts["worktree"])
    other, other_block = _start_run_elsewhere(checkouts["main"])
    try:
        session_lock.acquire_run()
        block = int(os.environ[unittest_session.PORT_BLOCK_ENV_VAR])
        api_port = unittest_session.get_api_port()
        semaphore_port = unittest_session.get_network_semaphore_port()
        session_lock.release_run()
    finally:
        _stop(other)

    assert other.returncode == 0
    assert block != other_block
    monkeypatch.setenv(unittest_session.PORT_BLOCK_ENV_VAR, str(other_block))
    assert unittest_session.get_api_port() != api_port
    assert unittest_session.get_network_semaphore_port() != semaphore_port


@pytest.mark.unit
def test_a_second_run_of_a_checkout_is_refused(checkouts, monkeypatch):
    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    session_lock.acquire_run()
    block = os.environ[unittest_session.PORT_BLOCK_ENV_VAR]

    with pytest.raises(session_lock.SessionLockError) as error:
        session_lock.acquire_run()

    message = str(error.value)
    assert session_lock.get_marker_path() in message
    assert f"checkout: {checkouts['main']}" in message
    # the refused run took nothing of the first run's
    assert os.path.exists(session_lock.get_marker_path())
    assert os.environ[unittest_session.PORT_BLOCK_ENV_VAR] == block

    session_lock.release_run()
    assert not os.path.exists(session_lock.get_marker_path())
    assert unittest_session.PORT_BLOCK_ENV_VAR not in os.environ

    # its block is free again, and the next run starts
    claimed, fd = session_lock.claim_port_block()
    os.close(fd)
    assert str(claimed) == block
    session_lock.acquire_run()
    session_lock.release_run()


@pytest.mark.unit
def test_a_run_refused_by_its_checkout_claims_no_port_block(checkouts, monkeypatch):
    """The same checkout running in another container, which has its own /tmp."""
    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    session_lock.acquire(session_lock.get_marker_path())

    with pytest.raises(session_lock.SessionLockError) as error:
        session_lock.acquire_run()

    assert session_lock.get_marker_path() in str(error.value)
    assert session_lock._port_block_fd is None
    assert os.environ[unittest_session.PORT_BLOCK_ENV_VAR] == "running suite's block"
    assert not glob.glob(session_lock.PORT_BLOCK_LOCK_PATH_FORMAT.format("*"))
    # the other run's marker is still its own
    assert os.path.exists(session_lock.get_marker_path())


@pytest.mark.unit
def test_a_checkout_whose_block_is_taken_takes_another(checkouts, monkeypatch):
    """Two checkouts whose hashes pick the same block."""
    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    first, first_fd = session_lock.claim_port_block()
    second, second_fd = session_lock.claim_port_block()
    os.close(first_fd)
    os.close(second_fd)

    assert second != first
    # block 0 is the ports of a checkout that predates port blocks
    assert 0 not in (first, second)


@pytest.mark.unit
def test_a_run_is_refused_when_every_port_block_is_taken(checkouts, monkeypatch):
    monkeypatch.setattr(unittest_session, "PORT_BLOCK_COUNT", 3)
    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    held = [session_lock.claim_port_block() for _ in range(2)]
    assert sorted(block for block, _ in held) == [1, 2]

    try:
        with pytest.raises(session_lock.SessionLockError) as error:
            session_lock.acquire_run()
    finally:
        for _, fd in held:
            os.close(fd)

    assert "every one of the 2 test suite port blocks is held" in str(error.value)
    assert not os.path.exists(session_lock.get_marker_path())
    assert os.environ[unittest_session.PORT_BLOCK_ENV_VAR] == "running suite's block"


@pytest.mark.unit
def test_the_port_block_of_a_killed_run_is_free(checkouts, monkeypatch):
    """No stale lock to clear by hand: the kernel drops a dead process's flock."""
    killed, killed_block = _start_run_elsewhere(checkouts["main"])
    killed.send_signal(signal.SIGKILL)
    killed.wait(timeout=30)
    killed.stdin.close()
    killed.stdout.close()

    # the killed run left its checkout's marker behind, but not its block
    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    assert os.path.exists(session_lock.get_marker_path())
    block, fd = session_lock.claim_port_block()
    os.close(fd)
    assert block == killed_block
