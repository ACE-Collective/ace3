import uuid
import pytest

from saq.constants import G_LOCK_TIMEOUT_SECONDS
from saq.database.pool import get_db_connection
from saq.database.util.locking import acquire_lock, clear_expired_locks, release_lock
from saq.environment import g_obj

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
def test_lock_timeout(monkeypatch):
    monkeypatch.setattr(g_obj(G_LOCK_TIMEOUT_SECONDS), "value", 0)
    first_lock_uuid = str(uuid.uuid4())
    second_lock_uuid = str(uuid.uuid4())
    target_lock = str(uuid.uuid4())
    assert acquire_lock(target_lock, first_lock_uuid)
    assert acquire_lock(target_lock, second_lock_uuid)

@pytest.mark.integration
def test_clear_expired_locks(monkeypatch):
    monkeypatch.setattr(g_obj(G_LOCK_TIMEOUT_SECONDS), "value", 0)
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