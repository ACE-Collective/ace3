"""Tests for LocalHardlinkBlobStore.

maintain_global reads the real blob_refs table; reference/unreference are
also exercised through the cache in test_cache.py.
"""
import hashlib
import io
import os
import time
from datetime import timedelta

import pytest

from saq.analysis.blob_store import (
    BlobNotFound,
    LocalCacheBudget,
    LocalHardlinkBlobStore,
    LocalHardlinkBlobStoreConfig,
)


def _backdate(path, seconds):
    """Set a file's mtime to ``seconds`` in the past."""
    past = time.time() - seconds
    os.utime(path, (past, past))


@pytest.fixture
def blob_store(tmp_path):
    return LocalHardlinkBlobStore(
        LocalHardlinkBlobStoreConfig(root_dir=str(tmp_path / "blob_store"))
    )


class TestPut:

    @pytest.mark.unit
    def test_put_bytes_returns_sha256(self, blob_store):
        data = b"hello world"
        sha = blob_store.put(data)
        assert sha == hashlib.sha256(data).hexdigest()

    @pytest.mark.unit
    def test_put_writes_to_sharded_path(self, blob_store):
        data = b"hello world"
        sha = blob_store.put(data)
        expected = os.path.join(blob_store.root_dir, sha[:3], sha)
        assert os.path.exists(expected)

    @pytest.mark.unit
    def test_put_is_idempotent(self, blob_store):
        data = b"hello world"
        sha1 = blob_store.put(data)
        sha2 = blob_store.put(data)
        assert sha1 == sha2

    @pytest.mark.unit
    def test_put_stream(self, blob_store):
        data = b"x" * (3 * 1024 * 1024)  # > 1 MB, exercises streaming loop
        sha = blob_store.put(io.BytesIO(data))
        assert sha == hashlib.sha256(data).hexdigest()
        assert blob_store.exists(sha)


class TestGetExists:

    @pytest.mark.unit
    def test_get_returns_stored_bytes(self, blob_store):
        data = b"payload"
        sha = blob_store.put(data)
        with blob_store.get(sha) as f:
            assert f.read() == data

    @pytest.mark.unit
    def test_get_missing_raises(self, blob_store):
        with pytest.raises(BlobNotFound):
            with blob_store.get("0" * 64):
                pass

    @pytest.mark.unit
    def test_exists(self, blob_store):
        sha = blob_store.put(b"x")
        assert blob_store.exists(sha)
        assert not blob_store.exists("0" * 64)


class TestMaterialize:

    @pytest.mark.unit
    def test_materialize_hardlinks(self, blob_store, tmp_path):
        data = b"payload"
        sha = blob_store.put(data)
        dest = tmp_path / "materialized" / "file.dat"
        blob_store.materialize(sha, str(dest))
        assert dest.exists()
        assert dest.read_bytes() == data
        # Hardlink check: same inode as the blob store entry
        blob_path = blob_store._path_for(sha)
        assert os.stat(blob_path).st_ino == os.stat(str(dest)).st_ino

    @pytest.mark.unit
    def test_materialize_missing_raises(self, blob_store, tmp_path):
        dest = tmp_path / "out"
        with pytest.raises(BlobNotFound):
            blob_store.materialize("0" * 64, str(dest))


class TestPathValidation:

    @pytest.mark.unit
    def test_path_for_rejects_wrong_length(self, blob_store):
        with pytest.raises(ValueError):
            blob_store._path_for("short")


class TestIterBlobs:

    @pytest.mark.unit
    def test_ignores_non_sha_names(self, blob_store):
        sha = blob_store.put(b"real blob")
        # drop a tempfile-like artifact in the same shard dir
        shard_dir = os.path.dirname(blob_store._path_for(sha))
        with open(os.path.join(shard_dir, "tmpABCD.junk"), "wb") as f:
            f.write(b"junk")
        found = dict(blob_store.iter_blobs())
        assert sha in found
        assert len(found) == 1

    @pytest.mark.unit
    def test_empty_store(self, blob_store):
        assert list(blob_store.iter_blobs()) == []


class TestMaintainGlobal:

    @pytest.mark.integration
    def test_deletes_unreferenced_old_blobs(self, blob_store):
        sha = blob_store.put(b"orphan blob")
        _backdate(blob_store._path_for(sha), 3600)
        stats = blob_store.maintain_global(timedelta(minutes=5))
        assert stats.blobs_deleted == 1
        assert stats.bytes_reclaimed == len(b"orphan blob")
        assert not blob_store.exists(sha)

    @pytest.mark.integration
    def test_keeps_referenced_blobs(self, blob_store):
        sha = blob_store.put(b"referenced blob")
        orphan = blob_store.put(b"orphan blob")
        _backdate(blob_store._path_for(sha), 3600)
        _backdate(blob_store._path_for(orphan), 3600)
        # two referrers of the same blob are two blob_refs rows for one sha256
        blob_store.reference(sha, "test", "referrer-1")
        blob_store.reference(sha, "test", "referrer-2")
        stats = blob_store.maintain_global(timedelta(minutes=5))
        assert stats.blobs_deleted == 1
        assert stats.skipped_referenced == 1
        assert blob_store.exists(sha)
        assert not blob_store.exists(orphan)

    @pytest.mark.integration
    def test_grace_period_protects_fresh_blobs(self, blob_store):
        sha = blob_store.put(b"fresh orphan")  # mtime = now
        stats = blob_store.maintain_global(timedelta(hours=1))
        assert stats.skipped_within_grace == 1
        assert stats.blobs_deleted == 0
        assert blob_store.exists(sha)

    @pytest.mark.integration
    def test_dry_run_does_not_delete(self, blob_store):
        sha = blob_store.put(b"orphan blob")
        _backdate(blob_store._path_for(sha), 3600)
        stats = blob_store.maintain_global(timedelta(minutes=5), dry_run=True)
        assert stats.blobs_deleted == 1
        assert blob_store.exists(sha)


class TestMaintainLocal:

    @pytest.mark.unit
    def test_is_noop_even_with_stale_blobs(self, blob_store):
        # the local hardlink store is the durable tier — nothing is evicted
        sha = blob_store.put(b"data")
        _backdate(blob_store._path_for(sha), 99999)
        stats = blob_store.maintain_local(
            LocalCacheBudget(max_age=timedelta(seconds=1), max_bytes=1)
        )
        assert stats.cache_entries_evicted == 0
        assert blob_store.exists(sha)
