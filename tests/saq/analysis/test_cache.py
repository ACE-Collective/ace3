"""Integration tests for saq.analysis.cache (put, lookup)."""
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
import zstandard
from PIL import Image

from saq.analysis.blob_store import LocalHardlinkBlobStore, LocalHardlinkBlobStoreConfig
from saq.analysis.cache import (
    apply_delta,
    collect_stats,
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
from saq.analysis.root import RootAnalysis
from saq.analysis.snapshot import ModuleExecutionSnapshot
from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import (
    ANALYSIS_MODULE_QRCODE,
    DB_ANALYSIS_RESULT_CACHE,
    F_FILE,
    AnalysisExecutionResult,
)
from saq.database.pool import get_db_connection
from saq.modules.file_analysis import QRCodeAnalysis, QRCodeAnalyzer
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


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


def _make_delta(
    module,
    observable_type="url",
    observable_value="https://example.com/",
    analysis=None,
    has_removal=False,
    empty=False,
):
    obs = SimpleNamespace(type=observable_type, value=observable_value, time=None)
    if empty:
        target_diff = ObservableDiff()
    else:
        target_diff = ObservableDiff(
            added_tags=["t1"],
            removed_tags=["r1"] if has_removal else [],
        )
    delta = ModuleExecutionDelta(
        module_path=f"saq.modules.test.{module.config.name}:{module.config.name}Analysis",
        module_instance=None,
        module_version=module.version,
        observable_uuid=str(uuid4()),
        observable_type=observable_type,
        observable_value=observable_value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=42,
        target_observable_diff=target_diff,
        new_observables=[],
        root_diff=RootDiff(),
        analysis=analysis,
    )
    delta.cache_key = generate_cache_key(obs, module)
    return delta


def _row_count(cache_key):
    with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM analysis_result_cache WHERE cache_key = %s",
            (cache_key,),
        )
        return cursor.fetchone()[0]


def _blob_ref_count(cache_key):
    with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM blob_refs WHERE referrer_kind = 'cache_row' AND referrer_id = %s",
            (cache_key,),
        )
        return cursor.fetchone()[0]


def _delete_cache_row(cache_key):
    with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM blob_refs WHERE referrer_id = %s", (cache_key,))
        cursor.execute("DELETE FROM analysis_result_cache WHERE cache_key = %s", (cache_key,))
        db.commit()


class TestPutCachedDelta:

    @pytest.mark.integration
    def test_happy_path_writes_row(self, blob_store, caplog):
        module = _make_module()
        delta = _make_delta(module)
        try:
            with caplog.at_level(logging.INFO):
                result = put_cached_delta(delta, module, blob_store)
            assert result is not None
            assert result.op == "insert"
            assert result.uncompressed_bytes > 0
            assert result.compressed_bytes > 0
            assert result.write_ms >= 0
            assert _row_count(delta.cache_key) == 1

            # Verify the payload round-trips through zstd → JSON → from_dict.
            with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
                cursor = db.cursor()
                cursor.execute(
                    "SELECT delta_zstd, delta_uncompressed_size, has_blob_refs "
                    "FROM analysis_result_cache WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                row = cursor.fetchone()
            decompressor = zstandard.ZstdDecompressor()
            dict_back = json.loads(decompressor.decompress(row[0]).decode("utf-8"))
            rebuilt = ModuleExecutionDelta.from_dict(dict_back)
            assert rebuilt.observable_value == delta.observable_value
            assert rebuilt.target_observable_diff.added_tags == ["t1"]
            assert row[1] > 0
            assert row[2] in (0, False)
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_repeat_write_appends_new_row(self, blob_store):
        """The cache is append-only: a second write of the same cache_key
        inserts another row (op is always "insert") rather than upserting."""
        module = _make_module()
        delta = _make_delta(module)
        try:
            first_result = put_cached_delta(delta, module, blob_store)
            assert first_result is not None
            assert first_result.op == "insert"
            assert _row_count(delta.cache_key) == 1

            delta2 = _make_delta(
                module,
                observable_type=delta.observable_type,
                observable_value=delta.observable_value,
            )
            delta2.cache_key = delta.cache_key
            second_result = put_cached_delta(delta2, module, blob_store)
            assert second_result is not None
            assert second_result.op == "insert"
            # append-only — both rows now coexist under the same cache_key
            assert _row_count(delta.cache_key) == 2
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_skips_when_cache_ttl_is_none(self, blob_store):
        module = _make_module(ttl=None)
        delta = _make_delta(module)
        assert put_cached_delta(delta, module, blob_store) is None

    @pytest.mark.integration
    def test_refuses_delta_with_removals(self, blob_store):
        module = _make_module()
        delta = _make_delta(module, has_removal=True)
        assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0

    @pytest.mark.integration
    def test_refuses_empty_delta(self, blob_store):
        """An empty delta has nothing to replay — caching it would write one
        row per observable the module merely looked at. put_cached_delta must
        refuse it, with no row written."""
        module = _make_module()
        delta = _make_delta(module, empty=True)
        assert delta.is_empty
        assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0

    @pytest.mark.integration
    def test_refuses_out_of_scope_relationship(self, blob_store, caplog):
        """A relationship targeting an observable that is neither the
        analyzed observable nor created by this delta depends on tree
        context a replay cannot reproduce — refused at write time."""
        module = _make_module()
        delta = _make_delta(module)
        delta.target_observable_diff.added_relationships = [{
            "type": "is_hash_of",
            "target": "some-other-tree-node-uuid",
            "target_type": "ipv4",
            "target_value": "9.9.9.9",
        }]
        with caplog.at_level(logging.WARNING):
            assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0
        assert any(
            getattr(rec, "refusal_reason", None) == "relationship_out_of_scope"
            for rec in caplog.records
        )

    @pytest.mark.integration
    def test_accepts_in_scope_relationships(self, blob_store):
        """Relationships to the analyzed observable itself or to an
        observable this delta created are within scope and cacheable."""
        module = _make_module()
        delta = _make_delta(module)
        delta.new_observables = [
            ObservableSpec(uuid="child-uuid", type="ipv4", value="1.2.3.4"),
        ]
        delta.target_observable_diff.added_relationships = [
            {"type": "is_hash_of", "target": delta.observable_uuid,
             "target_type": delta.observable_type, "target_value": delta.observable_value},
            {"type": "is_hash_of", "target": "child-uuid",
             "target_type": "ipv4", "target_value": "1.2.3.4"},
        ]
        try:
            assert put_cached_delta(delta, module, blob_store) is not None
            assert _row_count(delta.cache_key) == 1
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_skips_delta_with_delayed_analysis(self, blob_store, caplog):
        """Step 3.2: deltas captured mid-delay must not be cached.

        Replay would mark the analysis completed, lying about state.
        The skip is INFO-level — for delayed-analysis modules this fires
        once per intermediate cycle and is expected behavior.
        """
        module = _make_module()
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": {"x": 1},
                "delayed": True,
                "completed": False,
            },
        )
        with caplog.at_level(logging.INFO):
            assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0
        # the fields live in extra={} only; the formatters surface them as
        # top-level JSON fields (Splunk) or key=value tokens (plain text)
        skip_logs = [r for r in caplog.records if getattr(r, "skip_reason", None) == "still_delayed"]
        assert skip_logs
        assert skip_logs[0].levelno == logging.INFO
        assert skip_logs[0].module_name == module.config.name

    @pytest.mark.integration
    def test_refuses_file_delta_without_root(self, blob_store, caplog):
        """Phase 4: file deltas are cacheable, but only when the caller
        provides the source root (the file bytes live in its file dir).
        A file-bearing delta with root=None is refused."""
        module = _make_module()
        delta = _make_delta(module)
        delta.new_observables = [
            ObservableSpec(
                uuid="00000000-0000-0000-0000-000000000001",
                type=F_FILE,
                value="0" * 64,
                file_path="some/file.txt",
            )
        ]
        with caplog.at_level(logging.WARNING):
            assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0
        warn_logs = [
            r for r in caplog.records
            if getattr(r, "refusal_reason", None) == "file_observables_no_root"
        ]
        assert warn_logs
        assert warn_logs[0].levelno == logging.WARNING
        assert warn_logs[0].module_name == module.config.name

    @pytest.mark.integration
    def test_repeat_write_with_new_version_appends(self, blob_store):
        """A re-analysis at a new module version appends a row; the freshest
        row (the one the lookup path picks) carries the new version."""
        module = _make_module()
        delta = _make_delta(module)
        try:
            put_cached_delta(delta, module, blob_store)
            # second write at version 2 with a longer ttl so its expires_at is
            # unambiguously later than the first row's
            module2 = _make_module(
                name=module.config.name, version=2, ttl=timedelta(hours=2)
            )
            delta2 = _make_delta(
                module2,
                observable_type=delta.observable_type,
                observable_value=delta.observable_value,
            )
            delta2.cache_key = delta.cache_key
            assert put_cached_delta(delta2, module2, blob_store) is not None
            assert _row_count(delta.cache_key) == 2
            # the lookup path reads the freshest (latest expires_at) row
            with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
                cursor = db.cursor()
                cursor.execute(
                    "SELECT module_version FROM analysis_result_cache "
                    "WHERE cache_key = %s ORDER BY expires_at DESC LIMIT 1",
                    (delta.cache_key,),
                )
                assert cursor.fetchone()[0] == 2
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_large_details_spill_to_blob_store(self, blob_store):
        module = _make_module()
        # 32 KiB is 2× the default analysis_cache.details_spill_bytes,
        # so this reliably triggers the blob-store spill path.
        big_details = {"payload": "x" * (32 * 1024)}
        analysis = {
            "type": "saq.modules.test:Dummy",
            "summary": "big",
            "details": big_details,
        }
        delta = _make_delta(module, analysis=analysis)
        try:
            assert put_cached_delta(delta, module, blob_store) is not None
            assert _blob_ref_count(delta.cache_key) == 1

            with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
                cursor = db.cursor()
                cursor.execute(
                    "SELECT delta_zstd, has_blob_refs FROM analysis_result_cache "
                    "WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                row = cursor.fetchone()
            assert row[1] in (1, True)
            decompressor = zstandard.ZstdDecompressor()
            dict_back = json.loads(decompressor.decompress(row[0]).decode("utf-8"))
            # Inline details should be a blob reference now, not the raw dict.
            assert "__blob_ref__" in dict_back["analysis"]["details"]
            sha = dict_back["analysis"]["details"]["__blob_ref__"]
            assert blob_store.exists(sha)
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_refuses_oversized_delta(self, blob_store, monkeypatch):
        # Drop the cap to something tiny so even a small analysis blows it.
        monkeypatch.setattr(
            get_config().analysis_cache, "max_compressed_bytes", 50
        )
        module = _make_module()
        delta = _make_delta(module)
        assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0


def _make_file_root(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path / "root"))
    root.initialize_storage()
    return root


def _add_root_file(root, tmp_path, content=b"phase4 file content", name="output.txt"):
    """Store a real file in the root and return its FileObservable."""
    source = tmp_path / name
    source.write_bytes(content)
    return root.add_file_observable(str(source))


def _make_file_delta(module, file_obs):
    """A delta whose new_observables carries the given file observable."""
    delta = _make_delta(module)
    delta.new_observables = [
        ObservableSpec(
            uuid=file_obs.uuid,
            type=F_FILE,
            value=file_obs.value,
            file_path=file_obs.file_path,
        )
    ]
    return delta


class TestPutCachedDeltaFileObservables:
    """Phase 4 write path: file observable content goes to the blob store."""

    @pytest.mark.integration
    def test_file_delta_writes_row_and_blob(self, blob_store, tmp_path):
        module = _make_module()
        root = _make_file_root(tmp_path)
        file_obs = _add_root_file(root, tmp_path)
        delta = _make_file_delta(module, file_obs)
        try:
            result = put_cached_delta(delta, module, blob_store, root=root)
            assert result is not None
            assert _row_count(delta.cache_key) == 1
            # Content is in the blob store, keyed by the file's sha256.
            assert blob_store.exists(file_obs.value)
            with blob_store.get(file_obs.value) as fp:
                assert fp.read() == b"phase4 file content"
            # One blob_refs row ties the blob to this cache row.
            assert _blob_ref_count(delta.cache_key) == 1
            with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
                cursor = db.cursor()
                cursor.execute(
                    "SELECT has_blob_refs FROM analysis_result_cache WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                assert cursor.fetchone()[0] in (1, True)
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_file_delta_dedupes_existing_blob(self, blob_store, tmp_path):
        """A second write of the same content reuses the existing blob
        (exists() short-circuit) and just adds its own reference."""
        module = _make_module()
        root = _make_file_root(tmp_path)
        file_obs = _add_root_file(root, tmp_path)
        delta = _make_file_delta(module, file_obs)
        try:
            assert put_cached_delta(delta, module, blob_store, root=root) is not None
            assert put_cached_delta(delta, module, blob_store, root=root) is not None
            assert _row_count(delta.cache_key) == 2
            assert blob_store.exists(file_obs.value)
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_refuses_when_backing_file_missing(self, blob_store, tmp_path, caplog):
        module = _make_module()
        root = _make_file_root(tmp_path)
        file_obs = _add_root_file(root, tmp_path)
        delta = _make_file_delta(module, file_obs)
        os.unlink(file_obs.full_path)
        with caplog.at_level(logging.WARNING):
            assert put_cached_delta(delta, module, blob_store, root=root) is None
        assert _row_count(delta.cache_key) == 0
        assert any(getattr(r, "refusal_reason", None) == "file_missing" for r in caplog.records)

    @pytest.mark.integration
    def test_refuses_when_file_too_large(self, blob_store, tmp_path, caplog, monkeypatch):
        monkeypatch.setattr(get_config().analysis_cache, "file_blob_max_bytes", 4)
        module = _make_module()
        root = _make_file_root(tmp_path)
        file_obs = _add_root_file(root, tmp_path)
        delta = _make_file_delta(module, file_obs)
        with caplog.at_level(logging.WARNING):
            assert put_cached_delta(delta, module, blob_store, root=root) is None
        assert _row_count(delta.cache_key) == 0
        assert any(getattr(r, "refusal_reason", None) == "file_too_large" for r in caplog.records)

    @pytest.mark.integration
    def test_does_not_refuse_when_size_cap_disabled(self, blob_store, tmp_path, monkeypatch):
        # a cap of 0 disables the per-file size check entirely
        monkeypatch.setattr(get_config().analysis_cache, "file_blob_max_bytes", 0)
        module = _make_module()
        root = _make_file_root(tmp_path)
        file_obs = _add_root_file(root, tmp_path)
        delta = _make_file_delta(module, file_obs)
        try:
            assert put_cached_delta(delta, module, blob_store, root=root) is not None
            assert _row_count(delta.cache_key) == 1
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_refuses_when_spec_missing_file_path(self, blob_store, tmp_path, caplog):
        module = _make_module()
        root = _make_file_root(tmp_path)
        file_obs = _add_root_file(root, tmp_path)
        delta = _make_file_delta(module, file_obs)
        delta.new_observables[0].file_path = None
        with caplog.at_level(logging.WARNING):
            assert put_cached_delta(delta, module, blob_store, root=root) is None
        assert _row_count(delta.cache_key) == 0
        assert any(getattr(r, "refusal_reason", None) == "file_spec_missing_path" for r in caplog.records)

    @pytest.mark.integration
    def test_refuses_on_hash_mismatch(self, blob_store, tmp_path, caplog):
        """The file changed on disk after the observable hashed it — the
        delta can't be trusted. No row, and the (correctly-keyed) blob the
        put() created is unreferenced."""
        module = _make_module()
        root = _make_file_root(tmp_path)
        file_obs = _add_root_file(root, tmp_path)
        delta = _make_file_delta(module, file_obs)
        # file_dir entries are hardlinks into the hardcopy dir — replace
        # the link rather than writing through it.
        os.unlink(file_obs.full_path)
        with open(file_obs.full_path, "wb") as fp:
            fp.write(b"different bytes than were hashed")
        with caplog.at_level(logging.WARNING):
            assert put_cached_delta(delta, module, blob_store, root=root) is None
        assert _row_count(delta.cache_key) == 0
        assert any(getattr(r, "refusal_reason", None) == "file_hash_mismatch" for r in caplog.records)
        # The expected sha never landed in the store.
        assert not blob_store.exists(file_obs.value)

    @pytest.mark.integration
    def test_size_cap_bailout_unreferences_file_blob(self, blob_store, tmp_path, monkeypatch):
        """If the compressed-delta size cap fires after file blobs were
        referenced, their references are dropped."""
        monkeypatch.setattr(get_config().analysis_cache, "max_compressed_bytes", 50)
        module = _make_module()
        root = _make_file_root(tmp_path)
        file_obs = _add_root_file(root, tmp_path)
        delta = _make_file_delta(module, file_obs)
        assert put_cached_delta(delta, module, blob_store, root=root) is None
        assert _row_count(delta.cache_key) == 0
        assert _blob_ref_count(delta.cache_key) == 0


class TestFileObservableRoundTrip:
    """Phase 4 end-to-end: write a file-bearing delta from one alert,
    look it up, replay onto a *different* alert, and verify byte-identical
    content lands in the target's file dir."""

    @pytest.mark.integration
    def test_write_lookup_replay_onto_fresh_root(self, blob_store, tmp_path):
        module = _make_module()
        content = b"round trip file payload"

        # Source alert: module "produced" a file.
        source_root = _make_file_root(tmp_path)
        file_obs = _add_root_file(source_root, tmp_path, content=content)
        delta = _make_file_delta(module, file_obs)
        delta.new_observables[0].initial_tags = ["extracted"]
        try:
            assert put_cached_delta(delta, module, blob_store, root=source_root) is not None

            # Lookup keyed off a fresh observable with the same identity.
            obs_shim = SimpleNamespace(
                type=delta.observable_type, value=delta.observable_value, time=None,
            )
            lookup = get_cached_delta(obs_shim, module, blob_store)
            assert lookup.delta is not None

            # Replay onto a brand-new alert.
            target_root = RootAnalysis(storage_dir=str(tmp_path / "target_root"))
            target_root.initialize_storage()
            target = target_root.add_observable_by_spec(
                delta.observable_type, delta.observable_value,
            )
            apply_delta(target_root, target, lookup.delta, blob_store=blob_store)

            replayed = [o for o in target_root.all_observables if o.type == F_FILE]
            assert len(replayed) == 1
            assert replayed[0].value == file_obs.value
            assert replayed[0].file_path == file_obs.file_path
            assert "extracted" in replayed[0].tags
            with open(replayed[0].full_path, "rb") as fp:
                assert fp.read() == content
        finally:
            _delete_cache_row(delta.cache_key)


class TestNegativeResultRoundTrip:
    """A module that records a summary-less negative analysis ('scanned,
    found nothing') produces a non-empty, cacheable delta — the mechanism
    that makes QR/OCR negative results skip re-scanning on recurrence."""

    @pytest.mark.integration
    def test_qrcode_negative_write_and_replay(self, blob_store, tmp_path, test_context):
        png_path = tmp_path / "blank.png"
        Image.new("RGB", (64, 64), "white").save(png_path)

        # Live run against a blank image — clean scans, no QR code.
        source_root = create_root_analysis(analysis_mode="test_single")
        source_root.initialize_storage()
        source_obs = source_root.add_file_observable(str(png_path))
        analyzer = QRCodeAnalyzer(
            context=create_test_context(root=source_root),
            config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE),
        )
        analyzer.root = source_root

        before = ModuleExecutionSnapshot.narrow(source_root, source_obs, analyzer)
        result = analyzer.execute_analysis(source_obs)
        after = ModuleExecutionSnapshot.narrow(source_root, source_obs, analyzer)
        assert result == AnalysisExecutionResult.COMPLETED

        delta = ModuleExecutionSnapshot.diff(before, after, analyzer, source_obs)
        # The negative analysis makes the delta non-empty — without it the
        # empty-delta refusal would block the cache write.
        assert not delta.is_empty
        assert delta.analysis is not None
        assert not delta.has_file_observables

        # Cache it. Caching identity comes from a test module shim with a
        # cache_ttl (the unittest YAML doesn't opt qrcode in).
        module = _make_module()
        delta.cache_key = None
        write_result = put_cached_delta(delta, module, blob_store)
        try:
            assert write_result is not None
            assert _row_count(delta.cache_key) == 1

            # Replay onto a fresh root: the negative analysis slot is
            # installed, which is what blocks a re-run of the module.
            target_root = RootAnalysis(storage_dir=str(tmp_path / "target_root"))
            target_root.initialize_storage()
            target_obs = target_root.add_file_observable(str(png_path))
            apply_delta(target_root, target_obs, delta, blob_store=blob_store)

            replayed = target_obs.get_analysis(QRCodeAnalysis)
            assert isinstance(replayed, QRCodeAnalysis)
            assert not replayed.extracted_text
            assert replayed.generate_summary() is None
            assert not replayed.observables
        finally:
            _delete_cache_row(delta.cache_key)


class TestKillSwitch:

    @pytest.mark.integration
    def test_global_kill_switch_blocks_writes(self, blob_store, monkeypatch):
        monkeypatch.setattr(
            get_config().analysis_cache, "enabled", False
        )
        module = _make_module()
        delta = _make_delta(module)
        assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0


class TestMaintainGlobal:

    @pytest.mark.integration
    def test_deletes_orphan_blobs_after_unreference(self, blob_store):
        """maintain_global keeps referenced blobs and reclaims orphans (real blob_refs)."""
        import os
        import time

        module = _make_module()
        # 32 KiB reliably triggers the blob-store spill path
        big_details = {"payload": "x" * (32 * 1024)}
        analysis = {
            "type": "saq.modules.test:Dummy",
            "summary": "big",
            "details": big_details,
        }
        delta = _make_delta(module, analysis=analysis)
        try:
            put_cached_delta(delta, module, blob_store)
            assert _blob_ref_count(delta.cache_key) == 1

            # backdate every blob so the GC grace period doesn't protect them
            for _sha, _path in blob_store.iter_blobs():
                past = time.time() - 3600
                os.utime(_path, (past, past))

            # the blob is still referenced — maintain_global must not delete it
            stats = blob_store.maintain_global(timedelta(minutes=5))
            assert stats.blobs_deleted == 0
            assert stats.skipped_referenced == 1

            # drop the blob_ref — a partition drop reclaims the cache row and
            # its blob_refs together; deleting the row directly stands in here
            with get_db_connection(DB_ANALYSIS_RESULT_CACHE) as db:
                cursor = db.cursor()
                cursor.execute(
                    "DELETE FROM blob_refs WHERE referrer_id = %s",
                    (delta.cache_key,),
                )
                cursor.execute(
                    "DELETE FROM analysis_result_cache WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                db.commit()
            assert _blob_ref_count(delta.cache_key) == 0

            # now the blob is an orphan — maintain_global reclaims it
            stats = blob_store.maintain_global(timedelta(minutes=5))
            assert stats.blobs_deleted == 1
        finally:
            _delete_cache_row(delta.cache_key)


class TestCollectStats:

    @pytest.mark.integration
    def test_stats_reflect_table_state(self, blob_store):
        module = _make_module()
        # 32 KiB is 2× the default analysis_cache.details_spill_bytes,
        # so this reliably triggers the blob-store spill path.
        big_details = {"payload": "x" * (32 * 1024)}
        delta_small = _make_delta(module, observable_value="https://small.example/")
        delta_big = _make_delta(
            module,
            observable_value="https://big.example/",
            analysis={"type": "saq.modules.test:Dummy", "summary": "big", "details": big_details},
        )
        try:
            before = collect_stats()
            put_cached_delta(delta_small, module, blob_store)
            put_cached_delta(delta_big, module, blob_store)
            after = collect_stats()

            # row counts and byte totals come from InnoDB per-partition
            # statistics which only refresh periodically — assert
            # non-regression rather than exact growth
            assert after["total_rows"] >= before["total_rows"]
            assert after["blob_refs_rows"] >= before["blob_refs_rows"]
            assert after["total_on_disk_bytes"] >= before["total_on_disk_bytes"]
        finally:
            _delete_cache_row(delta_small.cache_key)
            _delete_cache_row(delta_big.cache_key)


@pytest.mark.integration
def test_cache_replay_preserves_queue_and_signature():
    """Guards the cache.py replay-fidelity fix: a detection's queue + signature
    fields must survive capture->replay, not silently revert to defaults."""
    from saq.analysis.cache import _apply_root_diff
    from saq.analysis.detection_point import DetectionPoint
    from tests.saq.helpers import create_root_analysis

    # a detection with non-default queue + signature, serialized as the cache stores it
    dp = DetectionPoint("hunt matched", queue="experimental",
                        signature_uuid="sig-xyz", signature_version="deadbeef")
    det_dict = dp.json

    root = create_root_analysis()
    root.initialize_storage()
    diff = RootDiff()
    diff.added_detections = [det_dict]
    _apply_root_diff(root, diff)

    replayed = root.all_detection_points
    assert len(replayed) == 1
    assert replayed[0].queue == "experimental"
    assert replayed[0].signature_uuid == "sig-xyz"
    assert replayed[0].signature_version == "deadbeef"
