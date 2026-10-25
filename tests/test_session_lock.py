"""One run of the test suite at a time per checkout and per container (tests/session_lock.py)."""

import os

import pytest

from tests import session_lock


@pytest.fixture
def checkouts(tmp_path, monkeypatch) -> dict[str, str]:
    """Two checkouts in one container, with a host marker of their own: the running suite holds
    the real ones."""
    monkeypatch.setattr(session_lock, "HOST_MARKER_PATH", str(tmp_path / "host-marker"))
    result = {}
    for name in ("main", "worktree"):
        result[name] = str(tmp_path / name)
        os.mkdir(result[name])

    return result


@pytest.mark.unit
def test_a_run_from_another_checkout_in_the_container_is_refused(checkouts, monkeypatch):
    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    session_lock.acquire_run()

    monkeypatch.setenv("SAQ_HOME", checkouts["worktree"])
    with pytest.raises(session_lock.SessionLockError) as error:
        session_lock.acquire_run()

    message = str(error.value)
    assert session_lock.HOST_MARKER_PATH in message
    assert f"checkout: {checkouts['main']}" in message
    assert not os.path.exists(session_lock.get_marker_path())

    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    session_lock.release_run()
    assert not os.path.exists(session_lock.HOST_MARKER_PATH)
    assert not os.path.exists(session_lock.get_marker_path())

    # and the next run starts
    monkeypatch.setenv("SAQ_HOME", checkouts["worktree"])
    session_lock.acquire_run()
    session_lock.release_run()


@pytest.mark.unit
def test_a_run_refused_by_its_checkout_leaves_no_host_marker(checkouts, monkeypatch):
    """The same checkout running in another container, which has its own /tmp."""
    monkeypatch.setenv("SAQ_HOME", checkouts["main"])
    session_lock.acquire(session_lock.get_marker_path())

    with pytest.raises(session_lock.SessionLockError) as error:
        session_lock.acquire_run()

    assert session_lock.get_marker_path() in str(error.value)
    assert not os.path.exists(session_lock.HOST_MARKER_PATH)
    # the other run's marker is still its own
    assert os.path.exists(session_lock.get_marker_path())
