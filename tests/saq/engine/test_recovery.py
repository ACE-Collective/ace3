import uuid

import pytest

from saq.database.util.locking import acquire_lock, force_release_lock, get_lock_uuid
from saq.engine.recovery import recover_expired_locks, recover_lost_root
from saq.environment import get_global_runtime_settings


@pytest.mark.integration
def test_recover_lost_root_clears_expired_lock(monkeypatch):
    """A lost root (expired lock) is recovered by clearing the stale lock so the still-queued
    workload item becomes claimable again."""
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 0)
    target = str(uuid.uuid4())
    assert acquire_lock(target, str(uuid.uuid4()))  # instantly expired
    assert recover_lost_root(target)
    assert get_lock_uuid(target) is None


@pytest.mark.integration
def test_recover_lost_root_leaves_live_owner(monkeypatch):
    """Recovery must not touch a lock a live owner still holds (not expired)."""
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 300)
    target = str(uuid.uuid4())
    live_lock_uuid = str(uuid.uuid4())
    assert acquire_lock(target, live_lock_uuid)  # fresh, not expired
    assert not recover_lost_root(target)
    assert get_lock_uuid(target) == live_lock_uuid
    force_release_lock(target)


@pytest.mark.integration
def test_recover_expired_locks_node_scoped(monkeypatch):
    """The per-node backstop recovers a node's own expired locks; another node's sweep leaves
    them alone."""
    monkeypatch.setattr(get_global_runtime_settings(), "saq_node_id", 4242)
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 0)
    target = str(uuid.uuid4())
    assert acquire_lock(target, str(uuid.uuid4()))  # stamped node_id=4242, expired

    # a different node's scoped sweep does not recover our lock
    assert recover_expired_locks(node_id=9999) == 0
    assert get_lock_uuid(target) is not None

    # our own node's sweep recovers it
    assert recover_expired_locks(node_id=4242) >= 1
    assert get_lock_uuid(target) is None
