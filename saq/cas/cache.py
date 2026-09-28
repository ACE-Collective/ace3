"""The node-local read cache (docs/CAS.md, "Read cache").

materialize() and open() need a verified plaintext file on this node. For a plaintext object in a
local backend that is the backend file itself (hardlinked out). For everything else (encrypted
pools, non-local backends) the verified plaintext is produced once into this bounded directory
and reused: <root>/<pool>/<digest>. Eviction is by mtime (oldest first) once the directory is
over budget, and a hit refreshes the mtime, so it behaves as an LRU.

The size accounting is a walk of the directory, which stats every entry. It does not run on every
fill: a process checks the budget on its first fill and then once it has filled another
1/_CHECK_DIVISOR of max_bytes, so the cache can run over budget by up to that much per process
between checks. (Walking on every fill was measured at ~290 ms per fill at the default 10 GiB of
~300 KiB entries with 8 concurrent readers, a hundred times the decrypt it followed.)

Evicting a file that another process has open is safe on POSIX (the inode outlives the name), and
a hardlinked materialize() destination survives eviction for the same reason. A path is not safe:
the entry can go between get_or_fill() returning it and the caller using it, which is why readers
use open_or_fill(), which hands out an open file.
"""

import fcntl
import logging
import os
import shutil
import tempfile
import time
from typing import BinaryIO, Callable

from saq.cas import metrics

_FILL_PREFIX = ".fill-"
_LOCK_DIR = ".locks"
# a process walks the directory to check the budget after filling this fraction of max_bytes
_CHECK_DIVISOR = 100
# open_or_fill() refills an entry that was evicted before it could be opened at most this often
_OPEN_ATTEMPTS = 3


class ReadCache:
    def __init__(self, root: str, max_bytes: int):
        self.root = root
        self.max_bytes = max_bytes
        # bytes this process has filled since its last budget check; None forces a check on the
        # first fill, so a short-lived process still checks once
        self._unchecked_bytes: int | None = None

    @property
    def enabled(self) -> bool:
        return self.max_bytes > 0

    def path(self, pool: str, digest: str) -> str:
        return os.path.join(self.root, pool, digest)

    def get_or_fill(self, pool: str, digest: str, fill: Callable[[BinaryIO], None]) -> str:
        """Return the path of the cached plaintext, producing it with fill(fp) on a miss. fill
        writes into a private temp file that only becomes visible under the digest's name after
        fill returns normally; if it raises, nothing is left behind. Two processes filling the
        same digest serialize on a per-digest lock so the work is done once."""
        path = self.path(pool, digest)
        if self._hit(path):
            return path

        pool_dir = os.path.join(self.root, pool)
        os.makedirs(pool_dir, exist_ok=True)
        with self._digest_lock(digest):
            if self._hit(path):
                return path

            fd, temp_path = tempfile.mkstemp(dir=pool_dir, prefix=_FILL_PREFIX)
            try:
                with os.fdopen(fd, "wb") as fp:
                    fill(fp)
                    filled = fp.tell()

                os.replace(temp_path, path)
            except BaseException:
                try:
                    os.unlink(temp_path)
                except FileNotFoundError:
                    pass

                raise

        if self._unchecked_bytes is not None:
            self._unchecked_bytes += filled

        if self._unchecked_bytes is None or self._unchecked_bytes >= self.max_bytes // _CHECK_DIVISOR:
            self._unchecked_bytes = 0
            # timed on its own (as pool/read_cache/evict) because it walks the whole directory
            started = time.perf_counter()
            self._evict_if_needed()
            metrics.record(pool, "read_cache", "evict", time.perf_counter() - started)

        return path

    def open_or_fill(self, pool: str, digest: str, fill: Callable[[BinaryIO], None]) -> BinaryIO:
        """The cached plaintext open for reading, produced with fill(fp) on a miss (see
        get_or_fill). Once open it is safe from eviction; an entry that another process evicts
        between get_or_fill() returning its path and the open is filled again."""
        for attempt in range(_OPEN_ATTEMPTS):
            path = self.get_or_fill(pool, digest, fill)
            try:
                return open(path, "rb")
            except FileNotFoundError:
                if attempt == _OPEN_ATTEMPTS - 1:
                    raise

                logging.debug("cas read cache entry %s was evicted before it could be opened", path)

    def remove(self, pool: str, digest: str) -> None:
        try:
            os.unlink(self.path(pool, digest))
        except FileNotFoundError:
            pass

    def clear(self) -> None:
        if os.path.isdir(self.root):
            shutil.rmtree(self.root)

    def total_bytes(self) -> int:
        return sum(size for _, size, _ in self._entries())

    def usage(self) -> tuple[int, int]:
        """(entries, bytes) currently cached."""
        entries = self._entries()
        return len(entries), sum(size for _, size, _ in entries)

    def _hit(self, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        try:
            os.utime(path)   # LRU: a hit is a use
        except FileNotFoundError:
            return False

        return True

    def _digest_lock(self, digest: str):
        # a per-digest lock file, held for the fill. it is removed afterwards; the only thing a
        # racing process can then do is a redundant fill into its own temp file, never a corrupt one
        lock_dir = os.path.join(self.root, _LOCK_DIR)
        os.makedirs(lock_dir, exist_ok=True)
        lock_path = os.path.join(lock_dir, digest)
        return _FileLock(lock_path, remove=True)

    def _entries(self) -> list[tuple[str, int, float]]:
        entries = []
        if not os.path.isdir(self.root):
            return entries

        for dirpath, dirnames, filenames in os.walk(self.root):
            if os.path.basename(dirpath) == _LOCK_DIR:
                dirnames[:] = []
                continue

            for name in filenames:
                if name.startswith(_FILL_PREFIX):
                    continue

                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full)
                except FileNotFoundError:
                    continue

                entries.append((full, st.st_size, st.st_mtime))

        return entries

    def _evict_if_needed(self) -> int:
        """Remove oldest entries until the directory is within budget. Returns bytes freed. Only
        one process walks and evicts at a time; another that finds the eviction lock taken just
        skips (the holder is already doing the work). The walk happens under the lock, so it is
        never a snapshot from before another process's eviction."""
        lock = _FileLock(os.path.join(self.root, _LOCK_DIR, ".evict"), remove=False, blocking=False)
        if not lock.acquire():
            return 0

        freed = 0
        try:
            entries = self._entries()
            total = sum(size for _, size, _ in entries)
            for path, size, mtime in sorted(entries, key=lambda entry: entry[2]):
                if total <= self.max_bytes:
                    break

                try:
                    # the walk takes a while on a large cache: an entry read since it saw the
                    # entry's mtime is no longer the oldest, so it stays
                    if os.stat(path).st_mtime > mtime:
                        continue

                    os.unlink(path)
                except FileNotFoundError:
                    # removed meanwhile (GC, purge): no longer counts, but this freed nothing
                    total -= size
                    continue

                total -= size
                freed += size
        finally:
            lock.release()

        if freed:
            logging.debug("cas read cache evicted %s bytes from %s", freed, self.root)

        return freed


class _FileLock:
    """flock() on a lock file. Blocking by default; with blocking=False acquire() returns False
    instead of waiting."""

    def __init__(self, path: str, remove: bool, blocking: bool = True):
        self.path = path
        self.remove = remove
        self.blocking = blocking
        self.fd = None

    def acquire(self) -> bool:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            os.close(fd)
            return False

        self.fd = fd
        return True

    def release(self) -> None:
        if self.fd is None:
            return

        if self.remove:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass

        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)
        self.fd = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_):
        self.release()
