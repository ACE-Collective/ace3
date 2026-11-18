import pytest

import saq.local_locking
from saq.local_locking import LocalLockError, lock_local

@pytest.mark.unit
def test_local_lock():
    with lock_local("test"):
        with pytest.raises(LocalLockError):
            with lock_local("test"):
                pass
        
        with lock_local("other"):
            pass
@pytest.mark.unit
def test_a_lock_is_released_when_the_block_raises():
    with pytest.raises(ValueError):
        with lock_local("test"):
            raise ValueError("the work under the lock failed")

    # the email archive treats a lock it cannot take as an email that is already archived
    with lock_local("test"):
        pass

@pytest.mark.unit
def test_an_error_under_the_lock_is_not_a_lock_failure():
    with pytest.raises(OSError) as e:
        with lock_local("test"):
            raise OSError(28, "No space left on device")

    assert not isinstance(e.value, LocalLockError)

@pytest.mark.unit
def test_a_lock_that_cannot_be_created_is_not_a_lock_held_elsewhere(tmp_path, monkeypatch):
    monkeypatch.setattr(saq.local_locking, "get_lock_directory", lambda: str(tmp_path / "missing"))

    with pytest.raises(FileNotFoundError):
        with lock_local("test"):
            pass
