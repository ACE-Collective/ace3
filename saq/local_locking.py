from contextlib import contextmanager
import os

from saq.environment import get_data_dir
from saq.util.hashing import sha256_str

class LocalLockError(Exception):
    pass

def get_lock_directory() -> str:
    return os.path.join(get_data_dir(), "var", "locks")

def get_lock_path(file_path: str):
    return os.path.join(get_lock_directory(), sha256_str(file_path))

@contextmanager
def lock_local(name: str):
    """Obtains an atomic local lock on a given name. For use in with blocks."""
    assert isinstance(name, str)

    lock_dir = f"{get_lock_path(name)}.lock"
    try:
        os.mkdir(lock_dir)
    except FileExistsError as e:
        raise LocalLockError(e) from e

    # released whatever the block does: a lock left behind is held forever
    try:
        yield lock_dir
    finally:
        os.rmdir(lock_dir)
