"""Content-addressed blob storage for the analysis result cache.

The BlobStore interface abstracts bulk-content storage from the cache layer so
the local filesystem backend and a pluggable remote backend (a custom class
configured through ``analysis_cache.blob_store``) share the same code paths. See docs/design/analysis_diff_tracking.md §A7 for the full
design.

Two kinds of things live in the blob store:

1. Spilled ``analysis.details`` dicts for cached ModuleExecutionDeltas whose
   details would bloat the DB row.
2. File observable payloads (deferred to Phase 4; not written in Phase 2).

Reference counting is explicit via the ``blob_refs`` table — we never rely on
filesystem link counts, because a remote backend won't have them.
"""

import hashlib
import importlib
import logging
import os
import shutil
import tempfile
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import BinaryIO, Iterable, Iterator, Optional, Type, Union

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.configuration.config import get_config
from saq.configuration.schema import BlobStoreSpec
from saq.constants import DB_ANALYSIS_RESULT_CACHE
from saq.database.model import BlobRef
from saq.database.pool import get_db
from saq.environment import get_base_dir


# Reference kinds stored in the blob_refs table.
REFERRER_KIND_CACHE_ROW = 'cache_row'
REFERRER_KIND_ALERT = 'alert'
REFERRER_KIND_ANALYSIS_DETAILS = 'analysis_details'


class BlobNotFound(Exception):
    pass


# how many sha256 values to fold into a single blob_refs lookup
_MAINTENANCE_BATCH = 500


@dataclass
class GlobalMaintenanceStats:
    """Result of a maintain_global (durable-tier GC) pass."""
    blobs_scanned: int = 0
    blobs_deleted: int = 0
    bytes_reclaimed: int = 0
    skipped_referenced: int = 0
    skipped_within_grace: int = 0
    errors: int = 0


@dataclass
class LocalMaintenanceStats:
    """Result of a maintain_local (node cache eviction) pass."""
    cache_entries_scanned: int = 0
    cache_entries_evicted: int = 0
    bytes_reclaimed: int = 0
    skipped_unflushed: int = 0   # local blob not yet confirmed in the durable tier
    errors: int = 0


@dataclass(frozen=True)
class LocalCacheBudget:
    """Eviction budget for a node's local blob cache tier.

    ``max_bytes`` caps the total cache footprint (oldest-first eviction when
    exceeded); ``max_age`` evicts any blob older than the given age. Either may
    be None to disable that dimension.
    """
    max_bytes: Optional[int] = None
    max_age: Optional[timedelta] = None


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def query_referenced_shas(shas: Iterable[str]) -> set[str]:
    """Return the subset of ``shas`` that have at least one row in blob_refs.

    Used by maintain_global implementations to decide which blobs are still
    referenced. Batched to keep the IN-list bounded.
    """
    shas = list(shas)
    referenced: set[str] = set()
    for i in range(0, len(shas), _MAINTENANCE_BATCH):
        batch = shas[i:i + _MAINTENANCE_BATCH]
        # distinct: blob_refs is append-only-ish (created_at is in the PK), so a
        # sha256 can appear in several rows
        referenced.update(
            get_db(DB_ANALYSIS_RESULT_CACHE).scalars(
                select(BlobRef.sha256).where(BlobRef.sha256.in_(batch)).distinct()
            ).all()
        )
    # release the read transaction so we don't hold it across the delete loop
    get_db(DB_ANALYSIS_RESULT_CACHE).commit()
    return referenced


class BlobStoreConfig(BaseModel):
    """Base Pydantic config for blob store backends.

    Backend implementations subclass this to declare their own config fields and
    return the subclass from BlobStore.get_config_class().
    """


def resolve_blob_store_dir(configured: Optional[str]) -> str:
    """Resolve a configured blob store root directory to an absolute path.

    Absolute paths are used as-is; relative paths resolve against SAQ_HOME; an unset
    value defaults to ``<data_dir>/blob_store``.
    """
    from saq.environment import get_data_dir
    if configured:
        return configured if os.path.isabs(configured) else os.path.join(get_base_dir(), configured)
    return os.path.join(get_data_dir(), 'blob_store')


class BlobStore(ABC):

    @classmethod
    def get_config_class(cls) -> Type[BlobStoreConfig]:
        """Return the Pydantic config class used to validate this backend's config.

        Mirrors AnalysisModule.get_config_class(). Backends with their own config
        fields override this to return their BlobStoreConfig subclass.
        """
        return BlobStoreConfig

    @abstractmethod
    def put(self, data: Union[bytes, BinaryIO]) -> str:
        """Store bytes, return hex sha256."""

    @abstractmethod
    def get(self, sha256: str):
        """Context manager yielding a read stream for the blob.

        Raises BlobNotFound if the blob is missing.
        """

    @abstractmethod
    def exists(self, sha256: str) -> bool:
        ...

    @abstractmethod
    def reference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        """Record that ``referrer`` depends on ``sha256``. Idempotent."""

    @abstractmethod
    def unreference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        """Drop the dependency. Safe to call when the ref doesn't exist."""

    @abstractmethod
    def maintain_global(self, grace_period: timedelta, dry_run: bool = False) -> GlobalMaintenanceStats:
        """Garbage-collect the DURABLE tier.

        Delete blobs that have zero rows in blob_refs and whose durable-tier
        object is older than ``grace_period``. The grace period guards the
        window between blob_store.put() and the blob_refs row being committed.

        MUST run on exactly one node (the primary) — it mutates global durable
        state. When ``dry_run`` is True, count what would be deleted without
        deleting anything.
        """

    @abstractmethod
    def maintain_local(self, budget: LocalCacheBudget, dry_run: bool = False) -> LocalMaintenanceStats:
        """Evict entries from THIS node's local cache tier.

        Safe to run on every analysis node — anything evicted is re-fetchable
        from the durable tier. Backends with no separate cache tier (the pure
        local store) return an empty stats object.
        """

    @abstractmethod
    def materialize(self, sha256: str, dest_path: str) -> None:
        """Make the blob available at a local filesystem path.

        Local backend hardlinks when same-FS, falls back to copy. A remote
        backend downloads to the dest path.
        """


class LocalHardlinkBlobStoreConfig(BlobStoreConfig):
    """Config for the local filesystem blob store backend."""
    root_dir: Optional[str] = None


class LocalHardlinkBlobStore(BlobStore):
    """Local filesystem backend.

    Bytes are stored at ``{root_dir}/<abc>/<def...>`` using a 3-char shard to
    match ACE's existing ``storage_dir_from_uuid`` convention
    (saq/util/uuid.py). Hardlinks are used by ``materialize`` for zero-copy
    access when the destination is on the same filesystem.
    """

    SHARD_LEN = 3

    @classmethod
    def get_config_class(cls) -> Type[BlobStoreConfig]:
        return LocalHardlinkBlobStoreConfig

    def __init__(self, config: LocalHardlinkBlobStoreConfig):
        self.config = config
        self.root_dir = resolve_blob_store_dir(config.root_dir)

    def _path_for(self, sha256: str) -> str:
        if len(sha256) != 64:
            raise ValueError(f"expected 64-char sha256, got {len(sha256)} chars")
        return os.path.join(self.root_dir, sha256[:self.SHARD_LEN], sha256)

    def path_for(self, sha256: str) -> str:
        """Return the on-disk path where the blob is (or would be) stored."""
        return self._path_for(sha256)

    def iter_blobs(self) -> Iterator[tuple[str, str]]:
        """Yield ``(sha256, absolute_path)`` for every blob currently on disk.

        Names that are not a valid sharded sha256 (e.g. tempfiles left by an
        interrupted put()) are skipped.
        """
        if not os.path.isdir(self.root_dir):
            return
        for shard in os.listdir(self.root_dir):
            if len(shard) != self.SHARD_LEN:
                continue
            shard_dir = os.path.join(self.root_dir, shard)
            if not os.path.isdir(shard_dir):
                continue
            for name in os.listdir(shard_dir):
                if len(name) != 64 or not _is_hex(name) or name[:self.SHARD_LEN] != shard:
                    continue
                yield name, os.path.join(shard_dir, name)

    def put(self, data: Union[bytes, BinaryIO]) -> str:
        h = hashlib.sha256()
        if isinstance(data, (bytes, bytearray)):
            h.update(data)
            sha256 = h.hexdigest()
            target = self._path_for(sha256)
            if os.path.exists(target):
                return sha256
            os.makedirs(os.path.dirname(target), exist_ok=True)
            # Atomic write: tempfile in the shard dir, then rename.
            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(target), delete=False
            ) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            os.rename(tmp_path, target)
            return sha256

        # Stream: buffer to a tempfile while hashing, then rename into place.
        os.makedirs(self.root_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=self.root_dir, delete=False
        ) as tmp:
            tmp_path = tmp.name
            while True:
                chunk = data.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                tmp.write(chunk)
        sha256 = h.hexdigest()
        target = self._path_for(sha256)
        if os.path.exists(target):
            os.unlink(tmp_path)
            return sha256
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.rename(tmp_path, target)
        return sha256

    @contextmanager
    def get(self, sha256: str) -> Iterator[BinaryIO]:
        path = self._path_for(sha256)
        if not os.path.exists(path):
            raise BlobNotFound(sha256)
        with open(path, 'rb') as f:
            yield f

    def exists(self, sha256: str) -> bool:
        return os.path.exists(self._path_for(sha256))

    def reference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        stmt = mysql_insert(BlobRef).values(
            sha256=sha256, referrer_kind=referrer_kind, referrer_id=referrer_id,
        ).prefix_with('IGNORE')
        get_db(DB_ANALYSIS_RESULT_CACHE).execute(stmt)
        get_db(DB_ANALYSIS_RESULT_CACHE).commit()

    def unreference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        get_db(DB_ANALYSIS_RESULT_CACHE).execute(
            delete(BlobRef).where(
                BlobRef.sha256 == sha256,
                BlobRef.referrer_kind == referrer_kind,
                BlobRef.referrer_id == referrer_id,
            )
        )
        get_db(DB_ANALYSIS_RESULT_CACHE).commit()

    def maintain_global(self, grace_period: timedelta, dry_run: bool = False) -> GlobalMaintenanceStats:
        # for the local hardlink store the filesystem IS the durable tier, so
        # this is the real GC: walk the shard tree, drop blobs with zero
        # blob_refs rows whose file mtime is older than the grace period.
        stats = GlobalMaintenanceStats()
        cutoff = time.time() - grace_period.total_seconds()
        candidates: list[tuple[str, str, int]] = []  # (sha256, path, size)
        for sha256, path in self.iter_blobs():
            stats.blobs_scanned += 1
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            # a blob freshly put() but not yet referenced has a recent mtime —
            # the grace period keeps us from deleting it before the blob_refs
            # row is committed
            if st.st_mtime > cutoff:
                stats.skipped_within_grace += 1
                continue
            candidates.append((sha256, path, st.st_size))

        for i in range(0, len(candidates), _MAINTENANCE_BATCH):
            batch = candidates[i:i + _MAINTENANCE_BATCH]
            referenced = query_referenced_shas(c[0] for c in batch)
            for sha256, path, size in batch:
                if sha256 in referenced:
                    stats.skipped_referenced += 1
                    continue
                if dry_run:
                    stats.blobs_deleted += 1
                    stats.bytes_reclaimed += size
                    continue
                try:
                    os.unlink(path)
                    stats.blobs_deleted += 1
                    stats.bytes_reclaimed += size
                except FileNotFoundError:
                    pass
                except OSError as e:
                    logging.warning("failed to unlink blob %s: %s", path, e)
                    stats.errors += 1
        return stats

    def maintain_local(self, budget: LocalCacheBudget, dry_run: bool = False) -> LocalMaintenanceStats:
        # the local hardlink store IS the durable tier — there is no separate
        # cache to evict, and removing files here would destroy the only copy
        logging.debug("LocalHardlinkBlobStore.maintain_local is a no-op (store is the durable tier)")
        return LocalMaintenanceStats()

    def materialize(self, sha256: str, dest_path: str) -> None:
        src = self._path_for(sha256)
        if not os.path.exists(src):
            raise BlobNotFound(sha256)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        try:
            os.link(src, dest_path)
        except OSError:
            # Cross-filesystem or hardlinks unsupported — fall back to copy.
            shutil.copyfile(src, dest_path)


_blob_store_singleton: Optional[BlobStore] = None


def _load_blob_store(spec: BlobStoreSpec) -> BlobStore:
    """Load a pluggable blob store backend from its config spec."""
    module = importlib.import_module(spec.python_module)
    cls = getattr(module, spec.python_class)
    config = cls.get_config_class().model_validate(spec.config)
    return cls(config)


def get_blob_store() -> BlobStore:
    """Return the process-wide blob store singleton.

    Lazy-initialized on first call. When ``analysis_cache.blob_store`` is set, the
    configured pluggable backend is loaded; otherwise the local hardlink store is
    used, rooted at ``analysis_cache.blob_store_dir`` (defaulting to
    ``<data_dir>/blob_store``).
    """
    global _blob_store_singleton
    if _blob_store_singleton is None:
        spec = get_config().analysis_cache.blob_store
        if spec is not None:
            _blob_store_singleton = _load_blob_store(spec)
        else:
            configured = get_config().analysis_cache.blob_store_dir
            _blob_store_singleton = LocalHardlinkBlobStore(
                LocalHardlinkBlobStoreConfig(root_dir=configured)
            )
    return _blob_store_singleton


def reset_blob_store_singleton() -> None:
    """Reset the singleton. Used in tests."""
    global _blob_store_singleton
    _blob_store_singleton = None
