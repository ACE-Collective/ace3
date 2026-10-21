"""Tests for ModuleExecutionSnapshot capture and diff computation."""

from datetime import datetime, UTC
import pytest

from saq.analysis.analysis import Analysis, SummaryDetail
from saq.analysis.root import RootAnalysis
from saq.analysis.snapshot import ModuleExecutionSnapshot, _ObservableState
from saq.constants import F_FILE, F_IP, F_FQDN, F_EMAIL_ADDRESS, R_EXTRACTED_FROM, R_IS_HASH_OF
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.rdap import RdapAnalysis
from saq.modules.test import TestAnalysis as _TestAnalysis


def _make_root(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    return root


class _SnapshotTestModule(AnalysisModule):
    def __init__(self, analysis_type, **config):
        super().__init__(config=AnalysisModuleConfig(
            name="snapshot_test",
            python_module=__name__,
            python_class="_SnapshotTestModule",
            enabled=True,
            **config,
        ))
        self.analysis_type = analysis_type

    @property
    def generated_analysis_type(self):
        return self.analysis_type


def _make_module(analysis_type=_TestAnalysis, instance=None, version=1, wide_diff=False):
    return _SnapshotTestModule(analysis_type, instance=instance, version=version, wide_diff=wide_diff)


class TestObservableStateCapture:
    @pytest.mark.unit
    def test_capture_empty_observable(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        state = _ObservableState.capture(obs)

        assert state.uuid == obs.uuid
        assert state.tags == frozenset()
        assert state.detection_ids == frozenset()
        assert state.directives == frozenset()
        assert state.relationship_ids == frozenset()
        assert state.excluded_analysis == frozenset()
        assert state.limited_analysis == frozenset()
        assert state.grouping_target is False
        assert state.redirection is None
        assert state.ignored is False

    @pytest.mark.unit
    def test_capture_observable_with_state(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        obs.add_tag("suspicious")
        obs.add_tag("malware")
        obs.add_directive("sandbox")
        obs.add_detection_point("test detection")

        state = _ObservableState.capture(obs)
        assert state.tags == frozenset(["suspicious", "malware"])
        assert state.directives == frozenset(["sandbox"])
        assert len(state.detection_ids) == 1


class TestNarrowSnapshot:
    @pytest.mark.unit
    def test_capture_and_diff_add_tag(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        # Simulate module adding a tag
        obs.add_tag("suspicious")

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.added_tags == ["suspicious"]
        assert not delta.target_observable_diff.removed_tags
        assert not delta.is_empty

    @pytest.mark.unit
    def test_diff_add_detection(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        obs.add_detection_point("found malware", details={"rule": "yara_match"})

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.target_observable_diff.added_detections) == 1
        assert delta.target_observable_diff.added_detections[0]["description"] == "found malware"

    @pytest.mark.unit
    def test_diff_add_directive(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.add_directive("sandbox")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.added_directives == ["sandbox"]

    @pytest.mark.unit
    def test_diff_add_observable(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        new_obs = root.add_observable_by_spec(F_FQDN, "evil.com")

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.new_observables) == 1
        assert delta.new_observables[0].type == F_FQDN
        assert delta.new_observables[0].value == "evil.com"
        assert delta.new_observables[0].uuid == new_obs.uuid

    @pytest.mark.unit
    def test_diff_add_observable_with_time(self, tmp_path):
        from datetime import datetime as _dt, UTC as _UTC

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        event_time = _dt(2026, 4, 13, 12, 0, 0, tzinfo=_UTC)
        new_obs = root.add_observable_by_spec(F_FQDN, "evil.com", o_time=event_time)

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.new_observables) == 1
        assert delta.new_observables[0].time == event_time.isoformat()

    @pytest.mark.unit
    def test_diff_add_observable_with_initial_state(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        new_obs = root.add_observable_by_spec(F_FQDN, "evil.com")
        new_obs.add_tag("new_tag")
        new_obs.add_directive("crawl")

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.new_observables) == 1
        assert "new_tag" in delta.new_observables[0].initial_tags
        assert "crawl" in delta.new_observables[0].initial_directives

    @pytest.mark.unit
    def test_diff_new_observable_captures_excluded_analysis(self, tmp_path):
        """Modules that add a child and immediately call .exclude_analysis(...)
        on it must have that exclusion captured in the ObservableSpec — without
        this, cache replay loses the exclusion and the module re-runs against
        its own children."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        new_obs = root.add_observable_by_spec(F_FQDN, "evil.com")
        new_obs._excluded_analysis.append("UserLookupAnalyzer")
        new_obs._limited_analysis.append("LimitedAnalyzer")

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.new_observables) == 1
        spec = delta.new_observables[0]
        assert "UserLookupAnalyzer" in spec.initial_excluded_analysis
        assert "LimitedAnalyzer" in spec.initial_limited_analysis

    @pytest.mark.unit
    def test_diff_new_file_observable_captures_phase4_fields(self, tmp_path):
        """Phase 4: a new file observable's spec must carry its file_path
        (for blob-backed replay), volatile flag, relationships, and
        redirection — the state OCR/QR-style modules set on their output."""
        root = _make_root(tmp_path)
        source_path = tmp_path / "source.png"
        source_path.write_bytes(b"fake image bytes")
        analyzed = root.add_file_observable(str(source_path))
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, analyzed, module)

        output_path = tmp_path / "source.png.ocr"
        output_path.write_text("extracted text")
        new_file = root.add_file_observable(str(output_path), volatile=True)
        new_file.add_relationship(R_EXTRACTED_FROM, analyzed)
        new_file.redirection = analyzed

        after = ModuleExecutionSnapshot.narrow(root, analyzed, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, analyzed)

        assert len(delta.new_observables) == 1
        spec = delta.new_observables[0]
        assert spec.type == F_FILE
        assert spec.value == new_file.sha256_hash
        assert spec.file_path == new_file.file_path
        assert spec.volatile is True
        assert spec.initial_redirection == analyzed.uuid
        assert len(spec.initial_relationships) == 1
        rel = spec.initial_relationships[0]
        assert rel["type"] == R_EXTRACTED_FROM
        assert rel["target"] == analyzed.uuid
        assert rel["target_type"] == F_FILE
        assert rel["target_value"] == analyzed.value

    @pytest.mark.unit
    def test_diff_new_non_file_observable_has_no_file_path(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        root.add_observable_by_spec(F_FQDN, "evil.com")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.new_observables[0].file_path is None
        assert delta.new_observables[0].volatile is False
        assert delta.new_observables[0].initial_relationships == []
        assert delta.new_observables[0].initial_redirection is None

    @pytest.mark.unit
    def test_diff_remove_tag(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        obs.add_tag("benign")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.remove_tag("benign")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.removed_tags == ["benign"]
        assert delta.has_removals

    @pytest.mark.unit
    def test_diff_no_changes(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.is_empty
        assert not delta.has_removals

    @pytest.mark.unit
    def test_diff_root_tag(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        root.add_tag("alert_tag")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.root_diff.added_tags == ["alert_tag"]

    @pytest.mark.unit
    def test_diff_scalar_transitions(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs._grouping_target = True
        obs._ignored = True
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.grouping_target == (False, True)
        assert delta.target_observable_diff.ignored == (False, True)

    @pytest.mark.unit
    def test_diff_excluded_and_limited_analysis(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs._excluded_analysis.append("saq.modules.test:TestAnalysis")
        obs._limited_analysis.append("saq.modules.other:OtherAnalysis")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.added_excluded_analysis == ["saq.modules.test:TestAnalysis"]
        assert delta.target_observable_diff.added_limited_analysis == ["saq.modules.other:OtherAnalysis"]


class TestWideSnapshot:
    @pytest.mark.unit
    def test_wide_captures_other_observable_mutations(self, tmp_path):
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        other_obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(wide_diff=True)

        before = ModuleExecutionSnapshot.wide(root, target_obs, module)

        # Simulate a wide-diff module mutating a different observable
        other_obs.add_tag("suspicious")
        other_obs.add_directive("sandbox")

        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert delta.wide_diff is True
        assert other_obs.uuid in delta.other_observable_diffs
        other_diff = delta.other_observable_diffs[other_obs.uuid]
        assert "suspicious" in other_diff.added_tags
        assert "sandbox" in other_diff.added_directives

    @pytest.mark.unit
    def test_wide_does_not_include_empty_diffs(self, tmp_path):
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        other_obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(wide_diff=True)

        before = ModuleExecutionSnapshot.wide(root, target_obs, module)
        # Only mutate the target, not the other
        target_obs.add_tag("tagged")
        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert delta.target_observable_diff.added_tags == ["tagged"]
        # other_obs had no changes, so it should not appear
        assert other_obs.uuid not in delta.other_observable_diffs


class TestAnalysisChildrenTracking:
    @pytest.mark.unit
    def test_wide_captures_child_removal_from_analysis(self, tmp_path):
        """Simulate the ignore action: remove an observable from a parent analysis's _observables."""
        root = _make_root(tmp_path)
        # Create observables
        target_obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        child_obs = root.add_observable_by_spec(F_EMAIL_ADDRESS, "victim@example.com")

        # Create an Analysis on target_obs that has child_obs as a child
        analysis = Analysis()
        analysis._observables.append(child_obs)
        target_obs.add_analysis_to_tree(analysis, target_obs)

        module = _make_module(wide_diff=True)
        before = ModuleExecutionSnapshot.wide(root, target_obs, module)

        # Simulate ignore action: remove child_obs from the analysis
        analysis._observables.remove(child_obs)

        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert len(delta.analysis_children_diffs) == 1
        acd = delta.analysis_children_diffs[0]
        assert child_obs.uuid in acd.removed_child_uuids
        assert acd.parent_observable_uuid == target_obs.uuid
        assert delta.has_removals

    @pytest.mark.unit
    def test_wide_captures_child_addition_to_analysis(self, tmp_path):
        """Track when a module adds an observable as a child of an existing analysis."""
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        new_child = root.add_observable_by_spec(F_FQDN, "example.com")

        analysis = Analysis()
        target_obs.add_analysis_to_tree(analysis, target_obs)

        module = _make_module(wide_diff=True)
        before = ModuleExecutionSnapshot.wide(root, target_obs, module)

        # Add new_child to the analysis
        analysis._observables.append(new_child)

        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert len(delta.analysis_children_diffs) == 1
        acd = delta.analysis_children_diffs[0]
        assert new_child.uuid in acd.added_child_uuids

    @pytest.mark.unit
    def test_no_analysis_children_diff_when_unchanged(self, tmp_path):
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        child_obs = root.add_observable_by_spec(F_FQDN, "example.com")

        analysis = Analysis()
        analysis._observables.append(child_obs)
        target_obs.add_analysis_to_tree(analysis, target_obs)

        module = _make_module(wide_diff=True)
        before = ModuleExecutionSnapshot.wide(root, target_obs, module)
        # No changes
        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert len(delta.analysis_children_diffs) == 0

    @pytest.mark.unit
    def test_narrow_does_not_track_analysis_children(self, tmp_path):
        """Narrow snapshots don't capture analysis children — only wide does."""
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        child_obs = root.add_observable_by_spec(F_FQDN, "example.com")

        analysis = Analysis()
        analysis._observables.append(child_obs)
        target_obs.add_analysis_to_tree(analysis, target_obs)

        module = _make_module()
        before = ModuleExecutionSnapshot.narrow(root, target_obs, module)
        analysis._observables.remove(child_obs)
        after = ModuleExecutionSnapshot.narrow(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        # Narrow snapshots don't capture analysis children
        assert len(delta.analysis_children_diffs) == 0


class TestDeltaModuleMetadata:
    @pytest.mark.unit
    def test_module_identity_captured(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module(instance="instance1", version=3)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.add_tag("malicious")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.module_path == "saq.modules.test:TestAnalysis:instance1"
        assert delta.module_instance == "instance1"
        assert delta.module_version == 3
        assert delta.observable_uuid == obs.uuid
        assert delta.observable_type == F_IP
        assert delta.observable_value == "10.0.0.1"

    @pytest.mark.unit
    def test_module_without_analysis_type_is_identified_by_config_name(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module(analysis_type=None)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.add_tag("malicious")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.module_path == "snapshot_test"
        assert delta.analysis is None
        assert delta.target_observable_diff.added_tags == ["malicious"]
        assert delta.created_at is not None


class TestObservableDiffRemovals:
    """Exercise the removal branches in _diff_observable_state."""

    @pytest.mark.parametrize(
        "setup, mutate, field_name, expected",
        [
            (
                lambda obs: obs.add_detection_point("prior", details={"k": "v"}),
                lambda obs: obs.detections.remove(obs.detections[0]),
                "removed_detections",
                lambda v: len(v) == 1 and v[0]["description"] == "prior",
            ),
            (
                lambda obs: obs.add_directive("sandbox"),
                lambda obs: obs.remove_directive("sandbox"),
                "removed_directives",
                lambda v: v == ["sandbox"],
            ),
            (
                lambda obs: obs._excluded_analysis.append("saq.modules.test:Skip"),
                lambda obs: obs._excluded_analysis.remove("saq.modules.test:Skip"),
                "removed_excluded_analysis",
                lambda v: v == ["saq.modules.test:Skip"],
            ),
            (
                lambda obs: obs._limited_analysis.append("saq.modules.test:Only"),
                lambda obs: obs._limited_analysis.remove("saq.modules.test:Only"),
                "removed_limited_analysis",
                lambda v: v == ["saq.modules.test:Only"],
            ),
        ],
        ids=["detection", "directive", "excluded_analysis", "limited_analysis"],
    )
    @pytest.mark.unit
    def test_diff_removal_paths(self, tmp_path, setup, mutate, field_name, expected):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        setup(obs)
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        mutate(obs)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        value = getattr(delta.target_observable_diff, field_name)
        assert expected(value), f"{field_name}={value!r}"
        assert delta.has_removals

    @pytest.mark.unit
    def test_diff_add_relationship(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        other = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.add_relationship(R_IS_HASH_OF, other)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        added = delta.target_observable_diff.added_relationships
        assert len(added) == 1
        assert added[0]["type"] == R_IS_HASH_OF
        assert added[0]["target"] == other.uuid
        # Target spec lets cache replay re-resolve the target on a
        # different root, where the uuid is meaningless.
        assert added[0]["target_type"] == F_FQDN
        assert added[0]["target_value"] == "example.com"
        assert "target_time" not in added[0]

    @pytest.mark.unit
    def test_diff_add_relationship_with_timed_target(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        event_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
        other = root.add_observable_by_spec(F_FQDN, "timed.example.com", o_time=event_time)
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.add_relationship(R_IS_HASH_OF, other)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        added = delta.target_observable_diff.added_relationships
        assert added[0]["target_value"] == "timed.example.com"
        assert added[0]["target_time"] == event_time.isoformat()

    @pytest.mark.unit
    def test_diff_remove_relationship(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        other = root.add_observable_by_spec(F_FQDN, "example.com")
        obs.add_relationship(R_IS_HASH_OF, other)
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs._relationships.pop(0)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        removed = delta.target_observable_diff.removed_relationships
        assert len(removed) == 1
        assert removed[0]["type"] == R_IS_HASH_OF
        assert removed[0]["target"] == other.uuid
        assert delta.has_removals

    @pytest.mark.unit
    def test_diff_redirection_transition(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs._redirection = "00000000-0000-0000-0000-000000000001"
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.redirection == (
            None,
            "00000000-0000-0000-0000-000000000001",
        )


class TestRootDiffPaths:
    """Exercise the root-level add/remove branches in _diff_root_state."""

    @pytest.mark.unit
    def test_root_diff_remove_tag(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        root.add_tag("pending_review")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        root.remove_tag("pending_review")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.root_diff.removed_tags == ["pending_review"]


# ---------------------------------------------------------------------------
# Phase 3 Step 3.1: details capture in _serialize_analysis
# ---------------------------------------------------------------------------

class TestAnalysisDetailsCapture:
    """When a module creates an Analysis, the snapshot must capture the
    in-memory ``analysis.details`` dict so cache replay can reconstruct
    the analysis on a different alert's storage_dir.

    Pre-Step-3.1, ``_serialize_analysis`` only captured metadata
    (``module_path``, ``summary``, ``external_details_path``, etc.) and
    omitted the actual payload — making cache rows useless for replay.
    """

    @pytest.mark.unit
    def test_analysis_dict_includes_details(self, tmp_path):

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(RdapAnalysis)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        # Simulate a module run: install a RdapAnalysis with details.
        analysis = RdapAnalysis()
        analysis.details = {"registrar": "Test", "domain_name": "example.com"}
        obs.analysis_tree_manager.add_analysis(obs, analysis)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.analysis is not None
        assert "details" in delta.analysis, (
            "snapshot must capture analysis.details for cache replay"
        )
        assert delta.analysis["details"]["registrar"] == "Test"

    @pytest.mark.unit
    def test_summary_details_serialized_as_dicts(self, tmp_path):
        """``summary_details`` is a list of SummaryDetail objects; the
        snapshot must convert to dicts via to_dict() so json.dumps
        round-trips cleanly. Pre-Step-3.1 stuffed the raw list and let
        ``json.dumps(default=str)`` silently corrupt them.
        """

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(RdapAnalysis)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        analysis = RdapAnalysis()
        analysis.summary_details.append(
            SummaryDetail(header="Registrar", content="Test Registrar")
        )
        obs.analysis_tree_manager.add_analysis(obs, analysis)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        details = delta.analysis.get("summary_details")
        assert isinstance(details, list)
        assert all(isinstance(d, dict) for d in details), (
            "summary_details must be dicts so json.dumps doesn't fall back "
            "to default=str on SummaryDetail objects"
        )

    @pytest.mark.unit
    def test_analysis_dict_includes_tags(self, tmp_path):
        """Tags set on the Analysis object itself (analysis.add_tag) must
        be captured so cache replay can restore them — they're invisible
        to the observable-level tag diff."""

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(RdapAnalysis)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        analysis = RdapAnalysis()
        analysis.add_tag("registrar:test")
        obs.analysis_tree_manager.add_analysis(obs, analysis)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.analysis["tags"] == ["registrar:test"]
        # Captured list is a copy — mutating the live analysis afterwards
        # must not leak into the already-captured delta.
        analysis.add_tag("late-tag")
        assert delta.analysis["tags"] == ["registrar:test"]

    @pytest.mark.unit
    def test_no_tags_key_when_analysis_untagged(self, tmp_path):

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(RdapAnalysis)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        analysis = RdapAnalysis()
        obs.analysis_tree_manager.add_analysis(obs, analysis)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert "tags" not in delta.analysis


# ---------------------------------------------------------------------------
# Phase 3 Step 3.0: delayed→completed transition capture
# ---------------------------------------------------------------------------

class TestDelayedAnalysisTransitions:
    """For modules using ``delay_analysis()``, the snapshot only fires
    its slot-add capture on the first call (when the analysis is created
    with ``delayed=True``). Without Step 3.0, the post-delay completion
    call wouldn't capture the analysis dict at all, because the slot was
    already populated.

    Step 3.0 adds detection of delayed→completed transitions on
    existing slots so the FINAL post-delay delta carries the populated
    analysis payload — which is the only one that gets cached
    (intermediate ``delayed=True`` deltas are refused at write time).
    """

    @pytest.mark.unit
    def test_first_call_captures_delayed_analysis(self, tmp_path):
        """First call: slot newly populated, analysis.delayed=True.
        Snapshot captures it via the existing slot-add path."""

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(RdapAnalysis)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        analysis = RdapAnalysis()
        analysis.delayed = True
        obs.analysis_tree_manager.add_analysis(obs, analysis)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.analysis is not None
        assert delta.analysis["delayed"] is True

    @pytest.mark.unit
    def test_post_delay_call_captures_via_transition(self, tmp_path):
        """Post-delay call: slot present in BOTH snapshots, but
        ``delayed`` transitions True→False. Step 3.0's transition
        detection fires capture so the final delta carries the now-
        populated analysis payload.
        """

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(RdapAnalysis)

        # First call: delayed analysis already in slot, tagged pre-delay.
        analysis = RdapAnalysis()
        analysis.delayed = True
        analysis.add_tag("pre-delay-tag")
        obs.analysis_tree_manager.add_analysis(obs, analysis)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        # Simulate post-delay completion.
        analysis.delayed = False
        analysis.details = {"registrar": "Test", "completed_at": "2026-05-07"}
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.analysis is not None, (
            "Step 3.0 must fire when delayed flips True→False on an "
            "already-populated slot"
        )
        assert delta.analysis["delayed"] is False
        assert delta.analysis["details"]["registrar"] == "Test"
        # Whole-capture semantics: a tag added in the pre-delay cycle is
        # still on the analysis object, so the final capture carries it.
        assert delta.analysis["tags"] == ["pre-delay-tag"]

    @pytest.mark.unit
    def test_intermediate_delayed_cycle_no_capture(self, tmp_path):
        """Intermediate delayed cycles: slot present in both, both have
        ``delayed=True``. No transition → no capture. Phase 1
        attribution still records the (likely empty) delta but
        ``delta.analysis`` is None so cache write would refuse it
        cleanly via Step 3.2.
        """

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(RdapAnalysis)

        analysis = RdapAnalysis()
        analysis.delayed = True
        obs.analysis_tree_manager.add_analysis(obs, analysis)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        # Module polls but stays delayed — no transition.
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.analysis is None

    @pytest.mark.unit
    def test_no_spurious_capture_on_repeat_non_delayed_call(self, tmp_path):
        """Slot present in both, both have ``delayed=False`` — neither
        the slot-add path nor the transition path fires. This is the
        baseline: a module re-invocation that did nothing shouldn't
        re-emit the analysis dict.
        """

        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module(RdapAnalysis)

        analysis = RdapAnalysis()
        analysis.delayed = False  # synchronous module — already complete
        obs.analysis_tree_manager.add_analysis(obs, analysis)

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.analysis is None

    @pytest.mark.unit
    def test_root_diff_add_detection(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        root.add_detection_point("alert me", details={"rule": "x"})
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.root_diff.added_detections) == 1
        assert delta.root_diff.added_detections[0]["description"] == "alert me"

    @pytest.mark.unit
    def test_root_diff_remove_detection(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        root.add_detection_point("to be removed", details={"rule": "x"})
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        root.detections.pop(0)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.root_diff.removed_detections) == 1
        assert delta.root_diff.removed_detections[0]["description"] == "to be removed"


class TestSnapshotCaptureEdgeCases:
    """Exercise capture-time edge cases: pre-existing state, add during wide diff."""

    @pytest.mark.unit
    def test_narrow_captures_existing_root_detection(self, tmp_path):
        """A pre-existing root detection is recorded in the baseline and not
        reported as added on a subsequent diff."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        root.add_detection_point("pre-existing", details={"k": "v"})
        module = _make_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        # snapshot captured one root detection
        assert len(before.root_detection_ids) == 1

        root.add_detection_point("new one", details={"k": "v"})
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        added = delta.root_diff.added_detections
        assert len(added) == 1
        assert added[0]["description"] == "new one"

    @pytest.mark.unit
    def test_wide_captures_existing_root_detection(self, tmp_path):
        """Same as above but for wide() so the wide-path loop body runs."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IP, "10.0.0.1")
        root.add_detection_point("pre-existing", details={"k": "v"})
        module = _make_module(wide_diff=True)

        before = ModuleExecutionSnapshot.wide(root, obs, module)
        assert len(before.root_detection_ids) == 1

        root.add_detection_point("new one", details={"k": "v"})
        after = ModuleExecutionSnapshot.wide(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        added = delta.root_diff.added_detections
        assert len(added) == 1
        assert added[0]["description"] == "new one"

    @pytest.mark.unit
    def test_wide_ignores_observable_added_between_snapshots(self, tmp_path):
        """An observable added between two wide snapshots is reported in
        new_observables but skipped in the other_observable_diffs loop."""
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_IP, "10.0.0.1")
        existing = root.add_observable_by_spec(F_FQDN, "existing.example.com")
        module = _make_module(wide_diff=True)

        before = ModuleExecutionSnapshot.wide(root, target, module)
        new_obs = root.add_observable_by_spec(F_EMAIL_ADDRESS, "victim@example.com")
        after = ModuleExecutionSnapshot.wide(root, target, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target)

        new_uuids = {o.uuid for o in delta.new_observables}
        assert new_obs.uuid in new_uuids
        assert new_obs.uuid not in delta.other_observable_diffs
        # the pre-existing observable is not in new_observables and had no
        # mutations so it should also be absent from the other_observable_diffs
        assert existing.uuid not in delta.other_observable_diffs


class TestAnalysisSerialization:
    """Exercise _serialize_analysis branches for summary and external_details_path."""

    @pytest.mark.unit
    def test_analysis_dict_captures_summary_and_external_details(self, tmp_path):
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_IP, "10.0.0.1")
        module = _make_module(Analysis)

        before = ModuleExecutionSnapshot.narrow(root, target, module)

        analysis = Analysis()
        analysis.summary = "found 3 matches"
        analysis.external_details_path = "details/analysis.json"
        target.add_analysis_to_tree(analysis, target)

        after = ModuleExecutionSnapshot.narrow(root, target, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target)

        assert delta.analysis is not None
        assert delta.analysis["summary"] == "found 3 matches"
        assert delta.analysis["external_details_path"] == "details/analysis.json"
        assert delta.analysis["module_path"] == "saq.analysis.analysis:Analysis"
