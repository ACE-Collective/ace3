import uuid
import pytest

from saq.database.pool import get_db_connection
from saq.database.util.locking import (
    acquire_lock,
    clear_expired_locks,
    force_release_lock,
    get_expired_locks,
    get_lock_uuid,
    release_lock,
)
from saq.environment import get_global_runtime_settings

@pytest.mark.integration
def test_lock():
    first_lock_uuid = str(uuid.uuid4())
    second_lock_uuid = str(uuid.uuid4())
    target_lock = str(uuid.uuid4())
    assert acquire_lock(target_lock, first_lock_uuid)
    assert not acquire_lock(target_lock, second_lock_uuid)
    assert acquire_lock(target_lock, first_lock_uuid)
    release_lock(target_lock, first_lock_uuid)
    assert acquire_lock(target_lock, second_lock_uuid)
    assert not acquire_lock(target_lock, first_lock_uuid)
    release_lock(target_lock, second_lock_uuid)


@pytest.mark.integration
def test_lock_timeout_no_takeover_by_default(monkeypatch):
    """Even an expired lock cannot be taken over by a different owner unless the caller opts
    into allow_expired_takeover. Workers must never steal expired locks."""
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 0)
    first_lock_uuid = str(uuid.uuid4())
    second_lock_uuid = str(uuid.uuid4())
    target_lock = str(uuid.uuid4())
    assert acquire_lock(target_lock, first_lock_uuid)
    # the lock is instantly expired, but a different owner still may NOT take it over by default
    assert not acquire_lock(target_lock, second_lock_uuid)
    # re-affirming our own lock always works regardless of expiry (this is the keepalive path)
    assert acquire_lock(target_lock, first_lock_uuid)


@pytest.mark.integration
def test_lock_expired_takeover_opt_in(monkeypatch):
    """A recovery path may take over an expired lock held by another owner via
    allow_expired_takeover; a non-expired lock is still protected."""
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 300)
    first_lock_uuid = str(uuid.uuid4())
    second_lock_uuid = str(uuid.uuid4())
    target_lock = str(uuid.uuid4())
    assert acquire_lock(target_lock, first_lock_uuid)
    # not expired -> even with the opt-in, a different owner cannot take it
    assert not acquire_lock(target_lock, second_lock_uuid, allow_expired_takeover=True)
    # now make locks expire immediately -> the opt-in takeover succeeds
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 0)
    assert acquire_lock(target_lock, second_lock_uuid, allow_expired_takeover=True)
    release_lock(target_lock, second_lock_uuid)


@pytest.mark.integration
def test_force_release_lock_ownership_aware():
    """force_release_lock with a lock_uuid only deletes the row when it still matches, so a
    recovery path can never delete a lock a different owner has since taken over."""
    live_lock_uuid = str(uuid.uuid4())
    stale_lock_uuid = str(uuid.uuid4())
    target = str(uuid.uuid4())
    assert acquire_lock(target, live_lock_uuid)
    # trying to force-release a *different* (stale) lock_uuid is a no-op -- the live lock survives
    assert not force_release_lock(target, lock_uuid=stale_lock_uuid)
    assert get_lock_uuid(target) == live_lock_uuid
    # force-releasing the actual lock_uuid works
    assert force_release_lock(target, lock_uuid=live_lock_uuid)
    assert get_lock_uuid(target) is None


@pytest.mark.integration
def test_get_expired_locks_node_scoping(monkeypatch):
    """get_expired_locks can be filtered to a single node so a node recovers only its own work."""
    monkeypatch.setattr(get_global_runtime_settings(), "saq_node_id", 4242)
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 0)
    target = str(uuid.uuid4())
    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(target, lock_uuid)
    # the lock is stamped with our node id and is expired
    rows = get_expired_locks(node_id=4242)
    assert target in [r[0] for r in rows]
    # a different node sees none of our locks
    assert target not in [r[0] for r in get_expired_locks(node_id=9999)]
    force_release_lock(target)

@pytest.mark.integration
def test_clear_expired_locks(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 0)
    # insert a lock that is already expired
    target = str(uuid.uuid4())
    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(target, lock_uuid)
    # this should clear out the lock
    clear_expired_locks()
    # make sure it's gone
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT uuid FROM locks WHERE uuid = %s", (target,))
        assert cursor.fetchone() is None