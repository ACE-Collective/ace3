"""Unit tests for saq.analysis.cache.apply_delta (Phase 3 Step 3.5)."""
import logging
import os
from datetime import datetime, timezone

import pytest

from saq.analysis.analysis import UnknownAnalysis
from saq.analysis.blob_store import (
    BlobNotFound,
    LocalHardlinkBlobStore,
    LocalHardlinkBlobStoreConfig,
)
from saq.analysis.cache import apply_delta
from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import F_EMAIL_ADDRESS, F_FILE, F_FQDN, F_IP, F_URL, F_USER, R_EXTRACTED_FROM, R_IS_HASH_OF
from saq.modules.rdap import RdapAnalysis


def _make_root(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    return root


def _empty_delta(target_observable, **overrides):
    """Build a minimum-shape delta for the target observable, with
    optional overrides for specific fields under test.
    """
    defaults = dict(
        module_path="saq.modules.test:DummyAnalysis",
        module_instance=None,
        module_version=1,
        observable_uuid=target_observable.uuid,
        observable_type=target_observable.type,
        observable_value=target_observable.value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=42,
        analysis=None,
        target_observable_diff=ObservableDiff(),
        new_observables=[],
        root_diff=RootDiff(),
    )
    defaults.update(overrides)
    return ModuleExecutionDelta(**defaults)


class TestApplyDeltaPrimitives:

    @pytest.mark.unit
    def test_added_tags_applied(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(added_tags=["suspicious", "malware"]),
        )
        apply_delta(root, obs, delta)
        assert "suspicious" in obs.tags
        assert "malware" in obs.tags

    @pytest.mark.unit
    def test_added_detections_applied(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(
                added_detections=[
                    {"description": "yara hit", "details": {"rule": "phish"}},
                ],
            ),
        )
        apply_delta(root, obs, delta)
        assert len(obs.detections) == 1
        assert obs.detections[0].description == "yara hit"
        assert obs.detections[0].details == {"rule": "phish"}

    @pytest.mark.unit
    def test_added_directives_applied(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(added_directives=["sandbox"]),
        )
        apply_delta(root, obs, delta)
        assert obs.has_directive("sandbox")

    @pytest.mark.unit
    def test_added_relationship_resolves_existing_target(self, tmp_path):
        root = _make_root(tmp_path)
        src = root.add_observable_by_spec(F_FQDN, "example.com")
        # Pre-existing target observable in the tree.
        target = root.add_observable_by_spec(F_IP, "1.2.3.4")
        delta = _empty_delta(
            src,
            target_observable_diff=ObservableDiff(
                added_relationships=[{"type": R_IS_HASH_OF, "target": target.uuid}],
            ),
        )
        apply_delta(root, src, delta)
        assert any(
            r.r_type == R_IS_HASH_OF and r.target.uuid == target.uuid
            for r in src.relationships
        )

    @pytest.mark.unit
    def test_relationship_with_missing_target_skipped(self, tmp_path, caplog):
        """Legacy uuid-only relationship dict (no target spec) whose uuid
        isn't in the tree: skipped with a WARNING, never raises."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(
                added_relationships=[{"type": R_IS_HASH_OF, "target": "missing-uuid"}],
            ),
        )
        with caplog.at_level(logging.WARNING):
            apply_delta(root, obs, delta)
        assert not obs.relationships
        assert any("target unresolved" in rec.message for rec in caplog.records)

    @pytest.mark.unit
    def test_relationship_resolved_by_spec_on_fresh_root(self, tmp_path):
        """Cross-root replay: the cached target uuid means nothing on the
        new root, but the (type, value) spec resolves to the observable
        the same delta just created."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            obs,
            observable_uuid="source-obs-uuid",  # captured on a different alert
            new_observables=[
                ObservableSpec(uuid="source-child-uuid", type=F_IP, value="1.2.3.4"),
            ],
            target_observable_diff=ObservableDiff(
                added_relationships=[{
                    "type": R_IS_HASH_OF,
                    "target": "source-child-uuid",
                    "target_type": F_IP,
                    "target_value": "1.2.3.4",
                }],
            ),
        )
        apply_delta(root, obs, delta)

        assert len(obs.relationships) == 1
        resolved = obs.relationships[0].target
        assert resolved.type == F_IP
        assert resolved.value == "1.2.3.4"
        # The replayed child got a fresh uuid — spec resolution, not uuid.
        assert resolved.uuid != "source-child-uuid"

    @pytest.mark.unit
    def test_self_relationship_resolves_despite_time_mismatch(self, tmp_path):
        """A relationship whose target is the analyzed observable itself
        must resolve via the self-target shortcut. The current
        observable carries an event time the source didn't, so a
        (type, value, time) spec lookup would miss — the shortcut on
        delta.observable_uuid is what makes this work."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(
            F_FQDN, "example.com", o_time=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )
        delta = _empty_delta(
            obs,
            observable_uuid="source-obs-uuid",
            target_observable_diff=ObservableDiff(
                added_relationships=[{
                    "type": R_IS_HASH_OF,
                    "target": "source-obs-uuid",
                    "target_type": F_FQDN,
                    "target_value": "example.com",
                }],
            ),
        )
        apply_delta(root, obs, delta)

        assert len(obs.relationships) == 1
        assert obs.relationships[0].target is obs

    @pytest.mark.unit
    def test_excluded_and_limited_dedupe(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(
                added_excluded_analysis=["mod.a:A"],
                added_limited_analysis=["mod.b:B"],
            ),
        )
        apply_delta(root, obs, delta)
        apply_delta(root, obs, delta)  # idempotent re-apply
        assert obs._excluded_analysis == ["mod.a:A"]
        assert obs._limited_analysis == ["mod.b:B"]

    @pytest.mark.unit
    def test_scalar_transitions_applied(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(
                grouping_target=(False, True),
                ignored=(False, True),
            ),
        )
        apply_delta(root, obs, delta)
        assert obs.grouping_target is True
        assert obs._ignored is True


class TestApplyDeltaNewObservables:

    @pytest.mark.unit
    def test_new_observable_spawned_under_root(self, tmp_path):
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        spec = ObservableSpec(
            uuid="11111111-1111-1111-1111-111111111111",
            type=F_URL,
            value="https://example.com/path",
            initial_tags=["from_replay"],
            initial_directives=["sandbox"],
        )
        delta = _empty_delta(target, new_observables=[spec])
        apply_delta(root, target, delta)
        urls = [o for o in root.all_observables if o.type == F_URL]
        assert len(urls) == 1
        assert "from_replay" in urls[0].tags
        assert urls[0].has_directive("sandbox")

    @pytest.mark.unit
    def test_new_observable_carries_excluded_analysis_on_replay(self, tmp_path):
        """Some analysis modules add a child observable and
        immediately call .exclude_analysis(self) on it so the module won't
        recurse. On cache replay that exclusion must be re-applied —
        otherwise the cached module runs against its own children.
        """
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_EMAIL_ADDRESS, "user@company.com")
        spec = ObservableSpec(
            uuid="33333333-3333-3333-3333-333333333333",
            type=F_USER,
            value="Usr123",
            initial_excluded_analysis=["UserLookupAnalyzer"],
            initial_limited_analysis=["LimitedAnalyzer"],
        )
        delta = _empty_delta(target, new_observables=[spec])
        apply_delta(root, target, delta)

        users = [o for o in root.all_observables if o.type == F_USER]
        assert len(users) == 1
        assert "UserLookupAnalyzer" in users[0]._excluded_analysis
        assert "LimitedAnalyzer" in users[0]._limited_analysis

    @pytest.mark.unit
    def test_new_observable_dedup_on_replay(self, tmp_path):
        """Calling apply_delta twice on the same root must NOT spawn a
        second observable — analysis_tree_manager dedupes by
        (type, value, time) and the add_* primitives are idempotent.
        """
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        spec = ObservableSpec(
            uuid="22222222-2222-2222-2222-222222222222",
            type=F_URL,
            value="https://example.com/path",
            initial_tags=["replay"],
        )
        delta = _empty_delta(target, new_observables=[spec])

        apply_delta(root, target, delta)
        apply_delta(root, target, delta)

        urls = [o for o in root.all_observables if o.type == F_URL]
        assert len(urls) == 1
        assert urls[0].tags.count("replay") == 1


class TestApplyDeltaFileObservables:
    """Phase 4: file specs replay by materializing blob content into the
    target root's file dir."""

    def _store(self, tmp_path, content=b"phase4 replay content"):
        store = LocalHardlinkBlobStore(
            LocalHardlinkBlobStoreConfig(root_dir=str(tmp_path / "blob_store"))
        )
        sha = store.put(content)
        return store, sha

    def _file_spec(self, sha, file_path="output.txt", **kwargs):
        return ObservableSpec(
            uuid="44444444-4444-4444-4444-444444444444",
            type=F_FILE,
            value=sha,
            file_path=file_path,
            **kwargs,
        )

    @pytest.mark.unit
    def test_file_materialized_into_target_root(self, tmp_path):
        root = _make_root(tmp_path / "root")
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        store, sha = self._store(tmp_path)
        spec = self._file_spec(sha, volatile=True, initial_tags=["ocr"])
        delta = _empty_delta(target, new_observables=[spec])

        apply_delta(root, target, delta, blob_store=store)

        files = [o for o in root.all_observables if o.type == F_FILE]
        assert len(files) == 1
        file_obs = files[0]
        assert file_obs.value == sha
        assert file_obs.file_path == "output.txt"
        assert file_obs.volatile is True
        assert "ocr" in file_obs.tags
        assert file_obs.exists
        with open(file_obs.full_path, "rb") as fp:
            assert fp.read() == b"phase4 replay content"

    @pytest.mark.unit
    def test_file_materialized_into_subdirectory_path(self, tmp_path):
        """OCR-style relative paths contain subdirectories
        (x.png.ocr/x.png.ocr) — store_file must create them."""
        root = _make_root(tmp_path / "root")
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        store, sha = self._store(tmp_path)
        spec = self._file_spec(sha, file_path="image.png.ocr/image.png.ocr")
        delta = _empty_delta(target, new_observables=[spec])

        apply_delta(root, target, delta, blob_store=store)

        files = [o for o in root.all_observables if o.type == F_FILE]
        assert len(files) == 1
        assert files[0].file_path == "image.png.ocr/image.png.ocr"
        assert files[0].exists

    @pytest.mark.unit
    def test_file_spec_relationship_and_redirection_resolved(self, tmp_path):
        """The relationship/redirection a module set on its output file
        must point at the *target tree's* analyzed observable after replay
        (source uuids are per-alert; resolution goes through the uuid map)."""
        root = _make_root(tmp_path / "root")
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        store, sha = self._store(tmp_path)
        source_target_uuid = "99999999-9999-9999-9999-999999999999"
        spec = self._file_spec(
            sha,
            initial_relationships=[{
                "type": R_EXTRACTED_FROM,
                "target": source_target_uuid,
                "target_type": F_FQDN,
                "target_value": "example.com",
            }],
            initial_redirection=source_target_uuid,
        )
        delta = _empty_delta(target, new_observables=[spec])
        delta.observable_uuid = source_target_uuid  # source alert's uuid for the analyzed observable

        apply_delta(root, target, delta, blob_store=store)

        file_obs = [o for o in root.all_observables if o.type == F_FILE][0]
        rels = [r for r in file_obs.relationships if r.r_type == R_EXTRACTED_FROM]
        assert len(rels) == 1
        assert rels[0].target is target
        assert file_obs._redirection == target.uuid

    @pytest.mark.unit
    def test_file_replay_idempotent(self, tmp_path):
        root = _make_root(tmp_path / "root")
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        store, sha = self._store(tmp_path)
        spec = self._file_spec(sha, initial_tags=["replay"])
        delta = _empty_delta(target, new_observables=[spec])

        apply_delta(root, target, delta, blob_store=store)
        apply_delta(root, target, delta, blob_store=store)

        files = [o for o in root.all_observables if o.type == F_FILE]
        assert len(files) == 1
        assert files[0].tags.count("replay") == 1
        assert files[0].exists

    @pytest.mark.unit
    def test_staging_dir_cleaned_up(self, tmp_path):
        root = _make_root(tmp_path / "root")
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        store, sha = self._store(tmp_path)
        delta = _empty_delta(target, new_observables=[self._file_spec(sha)])

        apply_delta(root, target, delta, blob_store=store)

        leftovers = [d for d in os.listdir(root.storage_dir) if d.startswith(".cache_replay_")]
        assert leftovers == []


class TestApplyDeltaRehydration:

    @pytest.mark.unit
    def test_analysis_rehydrated_on_target(self, tmp_path):
        """A delta carrying ``analysis`` must rehydrate that analysis on
        the target observable's _analysis slot.
        """

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"registrar": "Test Registrar"},
            "summary": "whois ok",
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)
        apply_delta(root, target, delta)

        rehydrated = target.get_analysis(RdapAnalysis)
        assert rehydrated is not None
        assert isinstance(rehydrated, RdapAnalysis)
        assert rehydrated.details == {"registrar": "Test Registrar"}

    @pytest.mark.unit
    def test_external_details_path_stripped(self, tmp_path):
        """external_details_path on the cached dict points at the SOURCE
        alert's storage_dir. Replay must drop it so the persistence
        manager re-derives a fresh path under the TARGET alert.
        """

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"x": 1},
            "external_details_path": "/some/source/alert/path/whois_xxx.json",
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)
        apply_delta(root, target, delta)

        rehydrated = target.get_analysis(RdapAnalysis)
        assert rehydrated.external_details_path is None

    @pytest.mark.unit
    def test_slot_collision_skips_rehydration(self, tmp_path):
        """If the slot already has an Analysis instance (re-analysis or
        retry), the existing one must be preserved rather than replaced
        with a fresh rehydration. Idempotent diffs still apply.
        """

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")

        # Pre-install an existing analysis at the slot.
        existing = RdapAnalysis()
        existing.details = {"sentinel": "preexisting"}
        target.analysis_tree_manager.add_analysis(target, existing)

        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"sentinel": "from_cache"},
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(
            target,
            analysis=analysis_dict,
            target_observable_diff=ObservableDiff(added_tags=["replay-tag"]),
        )
        apply_delta(root, target, delta)

        # Existing analysis preserved (sentinel unchanged).
        kept = target.get_analysis(RdapAnalysis)
        assert kept is existing
        assert kept.details == {"sentinel": "preexisting"}
        # Diffs still applied.
        assert "replay-tag" in target.tags

    @pytest.mark.unit
    def test_missing_analysis_class_logs_error(self, tmp_path, caplog):
        """A cached analysis whose class no longer exists falls back to
        UnknownAnalysis. The module was not declared deprecated, so this
        indicates a problem and is logged as an ERROR."""

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:DoesNotExist",
            "details": {"x": 1},
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)

        caplog.set_level(logging.DEBUG)
        apply_delta(root, target, delta)

        rehydrated = target.get_analysis("saq.modules.rdap:DoesNotExist")
        assert isinstance(rehydrated, UnknownAnalysis)

        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1
        assert "saq.modules.rdap:DoesNotExist" in errors[0].getMessage()

    @pytest.mark.unit
    def test_deprecated_analysis_class_logs_debug(self, tmp_path, caplog, monkeypatch):
        """Same as above except the module is declared deprecated, which
        means the missing class is expected rather than an error."""

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:DoesNotExist",
            "details": {"x": 1},
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)

        monkeypatch.setattr(get_config(), "deprecated_modules", ["saq.modules.rdap:DoesNotExist"])

        caplog.set_level(logging.DEBUG)
        apply_delta(root, target, delta)

        rehydrated = target.get_analysis("saq.modules.rdap:DoesNotExist")
        assert isinstance(rehydrated, UnknownAnalysis)

        assert not [r for r in caplog.records if r.levelno > logging.DEBUG]
        assert any(
            "saq.modules.rdap:DoesNotExist" in r.getMessage()
            for r in caplog.records if r.levelno == logging.DEBUG)

    @pytest.mark.unit
    def test_analysis_tags_rehydrated(self, tmp_path):
        """Tags captured off the Analysis object must be restored on the
        rehydrated analysis (they flow through the analysis.json setter →
        AnalysisSerializer.deserialize → BaseNode.set_json_data)."""

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"registrar": "Test Registrar"},
            "tags": ["registrar:test", "cached"],
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)
        apply_delta(root, target, delta)

        rehydrated = target.get_analysis(RdapAnalysis)
        assert rehydrated.tags == ["registrar:test", "cached"]

    @pytest.mark.unit
    def test_slot_collision_leaves_existing_analysis_tags_alone(self, tmp_path):

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        existing = RdapAnalysis()
        existing.add_tag("preexisting")
        target.analysis_tree_manager.add_analysis(target, existing)

        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {},
            "tags": ["from-cache"],
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)
        apply_delta(root, target, delta)

        kept = target.get_analysis(RdapAnalysis)
        assert kept is existing
        assert kept.tags == ["preexisting"]

    @pytest.mark.unit
    def test_idempotent_double_apply(self, tmp_path):
        """Calling apply_delta twice must produce the same tree state as
        one call — no double tags, no slot replacement, no duplicate
        observables.
        """

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"x": 1},
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(
            target,
            analysis=analysis_dict,
            target_observable_diff=ObservableDiff(added_tags=["once"]),
        )

        apply_delta(root, target, delta)
        apply_delta(root, target, delta)

        assert target.tags.count("once") == 1
        assert isinstance(target.get_analysis(RdapAnalysis), RdapAnalysis)


class TestApplyDeltaContractEnforcement:

    @pytest.mark.unit
    def test_wide_diff_raises(self, tmp_path):
        """Wide-diff deltas must never reach the replay path
        (config validation refuses cache_ttl + wide_diff). Defense-in-depth
        assertion enforces this even if the config check is bypassed.
        """
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(target, wide_diff=True)
        with pytest.raises(AssertionError, match="wide_diff"):
            apply_delta(root, target, delta)

    @pytest.mark.unit
    def test_file_observable_with_missing_blob_raises_before_mutation(self, tmp_path):
        """Phase 4: file deltas replay via the blob store. A missing blob
        raises (executor falls through to a live run) — and because the
        staging pass runs before any tree mutation, the tree is untouched.
        """
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        empty_store = LocalHardlinkBlobStore(
            LocalHardlinkBlobStoreConfig(root_dir=str(tmp_path / "empty_blob_store"))
        )
        delta = _empty_delta(
            target,
            new_observables=[
                ObservableSpec(
                    uuid="33333333-3333-3333-3333-333333333333",
                    type=F_FILE,
                    value="0" * 64,
                    file_path="some/file.txt",
                ),
            ],
            target_observable_diff=ObservableDiff(added_tags=["should-not-apply"]),
        )
        with pytest.raises(BlobNotFound):
            apply_delta(root, target, delta, blob_store=empty_store)
        # Nothing was applied — the raise happened before tree mutation.
        assert "should-not-apply" not in target.tags


class TestApplyDeltaRootLevel:

    @pytest.mark.unit
    def test_root_diff_added_tags(self, tmp_path):
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            target,
            root_diff=RootDiff(added_tags=["root-tag"]),
        )
        apply_delta(root, target, delta)
        assert "root-tag" in root.tags

    @pytest.mark.unit
    def test_root_diff_added_detections(self, tmp_path):
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            target,
            root_diff=RootDiff(
                added_detections=[{"description": "root det", "details": None}],
            ),
        )
        apply_delta(root, target, delta)
        assert len(root.detections) == 1
        assert root.detections[0].description == "root det"
