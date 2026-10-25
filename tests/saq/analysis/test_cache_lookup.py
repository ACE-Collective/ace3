"""Integration tests for saq.analysis.cache.get_cached_delta (Phase 3 Step 3.4)."""
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
import zstandard
from sqlalchemy import text

from saq.analysis.blob_store import LocalHardlinkBlobStore, LocalHardlinkBlobStoreConfig
from saq.analysis.cache import (
    generate_cache_key,
    get_cached_delta,
    put_cached_delta,
)
from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)
from saq.configuration.config import get_config
from saq.constants import DB_ANALYSIS_RESULT_CACHE, F_FILE
from saq.database.pool import get_db, get_db_connection


@pytest.fixture
def blob_store(tmp_path):
    return LocalHardlinkBlobStore(
        LocalHardlinkBlobStoreConfig(root_dir=str(tmp_path / "blob_store"))
    )


def _make_module(name=None, ttl=timedelta(hours=1), version=1, extended=None):
    return SimpleNamespace(
        config=SimpleNamespace(name=name or f"mod_{uuid4().hex[:8]}"),
        version=version,
        cache_ttl=ttl,
        extended_version=extended or {},
    )


def _make_observable(o_type="url", value="https://example.com/", time=None):
    return SimpleNamespace(type=o_type, value=value, time=time)


def _make_delta(
    module,
    observable_type="url",
    observable_value="https://example.com/",
    analysis=None,
):
    obs = _make_observable(observable_type, observable_value)
    delta = ModuleExecutionDelta(
        module_path=f"saq.modules.test.{module.config.name}:{module.config.name}Analysis",
        module_instance=None,
        module_version=module.version,
        observable_uuid=str(uuid4()),
        observable_type=observable_type,
        observable_value=observable_value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=42,
        target_observable_diff=ObservableDiff(added_tags=["t1"]),
        new_observables=[],
        root_diff=RootDiff(),
        analysis=analysis,
    )
    delta.cache_key = generate_cache_key(obs, module)
    return delta


def _delete_cache_row(cache_key):
    with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM blob_refs WHERE referrer_id = %s", (cache_key,))
        cursor.execute("DELETE FROM analysis_result_cache WHERE cache_key = %s", (cache_key,))
        db.commit()


def _set_expires_at(cache_key, sql_expr):
    """Force expires_at to a specific SQL expression for testing TTL paths."""
    with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
        cursor = db.cursor()
        cursor.execute(
            f"UPDATE analysis_result_cache SET expires_at = {sql_expr} WHERE cache_key = %s",
            (cache_key,),
        )
        db.commit()


def _write_raw_row(cache_key, module, delta_dict, has_blob_refs=False,
                   expires_sql="DATE_ADD(NOW(), INTERVAL 1 HOUR)"):
    """Insert a raw row bypassing put_cached_delta — for testing legacy
    shapes, corruption paths, and append-only duplicate-key behavior.
    """
    delta_json = json.dumps(delta_dict, sort_keys=True, default=str).encode("utf-8")
    delta_zstd = zstandard.ZstdCompressor(level=3).compress(delta_json)
    with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO analysis_result_cache "
            "(cache_key, module_name, module_version, observable_type, observable_value, "
            f" delta_zstd, delta_uncompressed_size, has_blob_refs, expires_at) "
            f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, {expires_sql})",
            (
                cache_key,
                module.config.name,
                module.version,
                "url",
                "https://example.com/",
                delta_zstd,
                len(delta_json),
                has_blob_refs,
            ),
        )
        db.commit()


def _write_raw_bytes(cache_key, module, delta_zstd):
    """Insert a row whose delta_zstd is exactly ``delta_zstd`` -- for corrupt rows."""
    with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO analysis_result_cache "
            "(cache_key, module_name, module_version, observable_type, observable_value, "
            " delta_zstd, delta_uncompressed_size, has_blob_refs, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL 1 HOUR))",
            (cache_key, module.config.name, module.version, "url", "https://example.com/",
             delta_zstd, len(delta_zstd), False),
        )
        db.commit()


def _kill_cache_session_connection():
    """Kill the MySQL connection the analysis cache session holds, the way a server-side
    wait_timeout or a database failover does."""
    connection_id = get_db(DB_ANALYSIS_RESULT_CACHE).execute(text("SELECT CONNECTION_ID()")).scalar()
    with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
        cursor = db.cursor()
        cursor.execute(f"KILL {int(connection_id)}")


_ANALYSIS = {
    "module_path": "saq.modules.test:Dummy",
    "details": {"foo": "bar"},
    "completed": True,
    "delayed": False,
}


class TestGetCachedDelta:

    @pytest.mark.integration
    def test_module_not_opted_in_returns_non_attempt(self, blob_store):
        """cache_ttl=None: no lookup happens, no miss is counted."""
        module = _make_module(ttl=None)
        obs = _make_observable()
        result = get_cached_delta(obs, module, blob_store)
        assert result.delta is None
        assert result.miss_reason is None  # non-attempt, not a miss

    @pytest.mark.integration
    def test_miss_reports_not_found(self, blob_store):
        """First lookup against an empty cache returns miss_reason='not_found'."""
        module = _make_module()
        obs = _make_observable()
        result = get_cached_delta(obs, module, blob_store)
        assert result.delta is None
        assert result.miss_reason == "not_found"
        assert result.lookup_ms >= 0
        assert result.cache_key_prefix != "n/a"

    @pytest.mark.integration
    def test_hit_round_trips(self, blob_store):
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": {"foo": "bar"},
                "completed": True,
                "delayed": False,
            },
        )
        try:
            assert put_cached_delta(delta, module, blob_store) is not None
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is not None
            assert result.miss_reason is None
            assert result.delta.observable_value == "https://example.com/"
            assert result.delta.target_observable_diff.added_tags == ["t1"]
            assert result.delta.analysis["details"] == {"foo": "bar"}
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_hit_components_decompose_lookup_ms(self, blob_store):
        """lookup_ms is decomposed into db_ms/decode_ms/blob_ms (the timed
        region) plus the separately-measured key_ms. The three in-region
        buckets must never exceed lookup_ms (no double counting; each is a
        floored sub-interval, and the region also holds untimed work), and
        key_ms is measured for every lookup."""
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": {"foo": "bar"},
                "completed": True,
                "delayed": False,
            },
        )
        try:
            assert put_cached_delta(delta, module, blob_store) is not None
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is not None
            for component in (result.key_ms, result.db_ms, result.decode_ms, result.blob_ms):
                assert component >= 0
            assert result.db_ms + result.decode_ms + result.blob_ms <= result.lookup_ms
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_key_ms_measures_extended_version_cost(self, blob_store):
        """key_ms captures generate_cache_key — which probes each module's
        extended_version. A module with a deliberately slow extended_version
        yields key_ms > 0 even on a miss (key computation runs before the
        lookup_ms timer and is reported separately)."""

        class _SlowExtendedVersionModule:
            def __init__(self):
                self.config = SimpleNamespace(name=f"slow_{uuid4().hex[:8]}")
                self.version = 1
                self.cache_ttl = timedelta(hours=1)

            @property
            def extended_version(self):
                time.sleep(0.01)  # 10 ms — dwarfs ms-granularity flooring
                return {"tool": "1.0"}

        result = get_cached_delta(_make_observable(), _SlowExtendedVersionModule(), blob_store)
        assert result.miss_reason == "not_found"
        assert result.key_ms >= 1

    @pytest.mark.integration
    def test_analysis_tags_round_trip(self, blob_store):
        """Tags on the captured analysis dict must survive put → get."""
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": {"foo": "bar"},
                "tags": ["analysis-tag"],
                "completed": True,
                "delayed": False,
            },
        )
        try:
            assert put_cached_delta(delta, module, blob_store) is not None
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is not None
            assert result.delta.analysis["tags"] == ["analysis-tag"]
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_expired_row_excluded(self, blob_store):
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(module, analysis={"module_path": "x", "details": {}})
        try:
            put_cached_delta(delta, module, blob_store)
            _set_expires_at(delta.cache_key, "DATE_SUB(NOW(), INTERVAL 1 HOUR)")
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is None
            assert result.miss_reason == "not_found"
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_legacy_shape_returns_miss(self, blob_store):
        """Step 3.4 legacy guard: rows without `details` in analysis dict
        are pre-Step-3.1 and must be treated as cache miss with reason
        ``legacy_no_details`` so the executor falls through to the live
        run, which overwrites the row.
        """
        module = _make_module()
        obs = _make_observable()
        cache_key = generate_cache_key(obs, module)
        legacy_dict = {
            "module_path": "saq.modules.test.legacy:Legacy",
            "module_version": 1,
            "observable_uuid": str(uuid4()),
            "observable_type": "url",
            "observable_value": "https://example.com/",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": 10,
            "analysis": {
                "module_path": "saq.modules.test:LegacyAnalysis",
                "summary": "old shape",
                "completed": True,
                # NOTE: no "details" key — the legacy bug.
            },
        }
        try:
            _write_raw_row(cache_key, module, legacy_dict)
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is None
            assert result.miss_reason == "legacy_no_details"
        finally:
            _delete_cache_row(cache_key)

    @pytest.mark.integration
    def test_blob_ref_inlined_on_lookup(self, blob_store):
        """When a row has has_blob_refs=True, the lookup must fetch the
        blob and inline it back into ``delta.analysis['details']``.
        """
        module = _make_module()
        obs = _make_observable()
        # 32 KiB triggers the spill path (default threshold = 16 KiB)
        big_details = {"payload": "x" * (32 * 1024)}
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": big_details,
                "completed": True,
            },
        )
        try:
            assert put_cached_delta(delta, module, blob_store) is not None
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is not None
            # Details should be the original dict, not the {"__blob_ref__": ...} pointer.
            assert result.delta.analysis["details"] == big_details
            assert "__blob_ref__" not in result.delta.analysis["details"]
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_blob_missing_returns_miss(self, blob_store, caplog):
        """If the referenced blob has been GC'd, the lookup must treat the
        row as a miss (not silently return a delta with a blob-ref pointer).
        """
        module = _make_module()
        obs = _make_observable()
        big_details = {"payload": "x" * (32 * 1024)}
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": big_details,
                "completed": True,
            },
        )
        try:
            assert put_cached_delta(delta, module, blob_store) is not None

            # Wipe the underlying blob — simulates GC ahead of cache TTL.
            blob_root = blob_store.root_dir
            for dirpath, _dirs, files in os.walk(blob_root):
                for f in files:
                    os.unlink(os.path.join(dirpath, f))

            with caplog.at_level(logging.WARNING):
                result = get_cached_delta(obs, module, blob_store)
            assert result.delta is None
            assert result.miss_reason == "blob_missing"
            # The "missing blob" warning still fires from get_cached_delta
            # so operators have a structured alertable signal independent
            # of the per-(root, module) metric aggregation.
            warns = [r for r in caplog.records if "missing blob" in r.getMessage()]
            assert warns
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_kill_switch_disables_lookup(self, blob_store, monkeypatch):
        """Global ``analysis_cache.enabled`` flag covers reads as well as
        writes — no separate ``reads_enabled`` switch. Disabled = non-attempt
        (miss_reason is None), so this doesn't get counted as a cache miss.
        """
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(
            module,
            analysis={"module_path": "x", "details": {}, "completed": True},
        )
        try:
            put_cached_delta(delta, module, blob_store)
            monkeypatch.setattr(get_config().analysis_cache, "enabled", False)
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is None
            assert result.miss_reason is None
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_returns_freshest_row_when_duplicates(self, blob_store):
        """Append-only: several non-expired rows can share a cache_key; the
        lookup returns the most recently CREATED one — even when an older
        row has a later expires_at. (Ordering by expires_at would let rows
        written under a longer, since-reduced cache_ttl shadow fresher
        data until they expire.)"""
        module = _make_module()
        obs = _make_observable()
        cache_key = generate_cache_key(obs, module)
        stale = _make_delta(
            module, observable_value="https://stale.example/",
            analysis={"module_path": "x", "details": {"v": "stale"}, "completed": True},
        )
        fresh = _make_delta(
            module, observable_value="https://fresh.example/",
            analysis={"module_path": "x", "details": {"v": "fresh"}, "completed": True},
        )
        try:
            # Older row carries the LONGER TTL — written first, so its
            # created_at is earlier but its expires_at is later.
            _write_raw_row(cache_key, module, stale.to_dict(),
                           expires_sql="DATE_ADD(NOW(), INTERVAL 10 HOUR)")
            _write_raw_row(cache_key, module, fresh.to_dict(),
                           expires_sql="DATE_ADD(NOW(), INTERVAL 1 HOUR)")
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is not None
            assert result.delta.analysis["details"]["v"] == "fresh"
        finally:
            _delete_cache_row(cache_key)

    @pytest.mark.integration
    def test_expired_duplicate_ignored_returns_live_row(self, blob_store):
        """An expired row sharing a cache_key with a live row is filtered out
        by the expires_at>NOW() predicate; the lookup returns the live row."""
        module = _make_module()
        obs = _make_observable()
        cache_key = generate_cache_key(obs, module)
        expired = _make_delta(
            module, observable_value="https://expired.example/",
            analysis={"module_path": "x", "details": {"v": "expired"}, "completed": True},
        )
        live = _make_delta(
            module, observable_value="https://live.example/",
            analysis={"module_path": "x", "details": {"v": "live"}, "completed": True},
        )
        try:
            _write_raw_row(cache_key, module, expired.to_dict(),
                           expires_sql="DATE_SUB(NOW(), INTERVAL 1 HOUR)")
            _write_raw_row(cache_key, module, live.to_dict(),
                           expires_sql="DATE_ADD(NOW(), INTERVAL 1 HOUR)")
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is not None
            assert result.delta.analysis["details"]["v"] == "live"
        finally:
            _delete_cache_row(cache_key)


class TestGetCachedDeltaFileObservables:
    """Phase 4: file-bearing rows are only usable when every file blob
    still exists."""

    def _file_delta(self, module, sha, file_path="output.txt"):
        delta = _make_delta(
            module,
            analysis={"module_path": "x", "details": {}, "completed": True},
        )
        delta.new_observables = [
            ObservableSpec(uuid=str(uuid4()), type=F_FILE, value=sha, file_path=file_path),
        ]
        return delta

    @pytest.mark.integration
    def test_file_hit_when_blob_present(self, blob_store):
        module = _make_module()
        obs = _make_observable()
        sha = blob_store.put(b"file content for lookup test")
        delta = self._file_delta(module, sha)
        try:
            _write_raw_row(delta.cache_key, module, delta.to_dict())
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is not None
            assert result.miss_reason is None
            spec = result.delta.new_observables[0]
            assert spec.value == sha
            assert spec.file_path == "output.txt"
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_missing_file_blob_returns_miss(self, blob_store, caplog):
        """GC or a failed remote upload lost the blob — must be a miss
        (live-run fall-through), never an error."""
        module = _make_module()
        obs = _make_observable()
        delta = self._file_delta(module, "1" * 64)  # never stored
        try:
            _write_raw_row(delta.cache_key, module, delta.to_dict())
            with caplog.at_level(logging.WARNING):
                result = get_cached_delta(obs, module, blob_store)
            assert result.delta is None
            assert result.miss_reason == "blob_missing"
            assert any("missing file blob" in r.getMessage() for r in caplog.records)
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_file_spec_without_path_returns_decode_error(self, blob_store):
        module = _make_module()
        obs = _make_observable()
        sha = blob_store.put(b"content")
        delta = self._file_delta(module, sha)
        delta_dict = delta.to_dict()
        del delta_dict["new_observables"][0]["file_path"]
        try:
            _write_raw_row(delta.cache_key, module, delta_dict)
            result = get_cached_delta(obs, module, blob_store)
            assert result.delta is None
            assert result.miss_reason == "decode_error"
        finally:
            _delete_cache_row(delta.cache_key)


class TestGetCachedDeltaFailures:
    """A lookup that fails is a miss: the executor runs the module live."""

    @pytest.mark.integration
    def test_corrupt_row_returns_decode_error(self, blob_store, caplog):
        module = _make_module()
        obs = _make_observable()
        cache_key = generate_cache_key(obs, module)
        try:
            _write_raw_bytes(cache_key, module, b"not zstd at all")
            with caplog.at_level(logging.WARNING):
                result = get_cached_delta(obs, module, blob_store)

            assert result.delta is None
            assert result.miss_reason == "decode_error"
            records = [r for r in caplog.records if r.getMessage() == "failed to decode cached delta"]
            assert len(records) == 1
            assert records[0].module_name == module.config.name
            assert records[0].exc_info is not None
        finally:
            _delete_cache_row(cache_key)

    @pytest.mark.integration
    def test_undeserializable_delta_returns_decode_error(self, blob_store, caplog):
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(module, analysis=_ANALYSIS)
        delta_dict = delta.to_dict()
        delta_dict["new_observables"] = [{"not": "a spec"}]
        try:
            _write_raw_row(delta.cache_key, module, delta_dict)
            with caplog.at_level(logging.WARNING):
                result = get_cached_delta(obs, module, blob_store)

            assert result.delta is None
            assert result.miss_reason == "decode_error"
            assert any(r.getMessage() == "failed to deserialize cached delta" for r in caplog.records)
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_lost_connection_costs_one_miss(self, blob_store, caplog):
        """A lookup on a connection the server dropped fails. The session is rolled back,
        so the lookup after it reconnects instead of failing the same way."""
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(module, analysis=_ANALYSIS)
        try:
            assert put_cached_delta(delta, module, blob_store) is not None
            _kill_cache_session_connection()

            with caplog.at_level(logging.WARNING):
                first = get_cached_delta(obs, module, blob_store)
            assert first.delta is None
            assert first.miss_reason == "decode_error"
            assert any(r.getMessage() == "cache lookup failed" for r in caplog.records)

            second = get_cached_delta(obs, module, blob_store)
            assert second.delta is not None
            assert second.delta.analysis["details"] == {"foo": "bar"}
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_write_after_lost_connection(self, blob_store):
        """The live run that follows a failed lookup gets its result cached."""
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(module, analysis=_ANALYSIS)
        try:
            # opens the session's transaction on a connection that is then lost
            assert get_cached_delta(obs, module, blob_store).miss_reason == "not_found"
            _kill_cache_session_connection()
            assert get_cached_delta(obs, module, blob_store).miss_reason == "decode_error"

            assert put_cached_delta(delta, module, blob_store) is not None
            assert get_cached_delta(obs, module, blob_store).delta is not None
        finally:
            _delete_cache_row(delta.cache_key)
