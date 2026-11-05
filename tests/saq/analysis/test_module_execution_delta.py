"""Tests for ModuleExecutionDelta and related dataclasses."""

import pytest

from saq.analysis.module_execution_delta import (
    AnalysisChildrenDiff,
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
    merge_module_execution_deltas,
)


class TestObservableDiff:
    @pytest.mark.unit
    def test_empty_diff(self):
        diff = ObservableDiff()
        assert diff.is_empty
        assert not diff.has_removals

    @pytest.mark.unit
    def test_additions_only(self):
        diff = ObservableDiff(
            added_tags=["suspicious", "malware"],
            added_directives=["sandbox"],
        )
        assert not diff.is_empty
        assert not diff.has_removals

    @pytest.mark.unit
    def test_removals_detected(self):
        diff = ObservableDiff(removed_tags=["benign"])
        assert not diff.is_empty
        assert diff.has_removals

    @pytest.mark.unit
    def test_scalar_transition(self):
        diff = ObservableDiff(grouping_target=(False, True))
        assert not diff.is_empty
        assert not diff.has_removals

    @pytest.mark.unit
    def test_serialized_format(self):
        """The dict is stored in cache rows and root.json, so its key names
        are pinned: a rename in both to_dict and from_dict would still round
        trip, and would drop every stored row's diff on load."""
        diff = ObservableDiff(
            added_tags=["suspicious"],
            removed_tags=["benign"],
            added_detections=[{"description": "test", "details": None}],
            removed_detections=[{"description": "old", "details": None}],
            added_directives=["sandbox"],
            removed_directives=["crawl"],
            added_relationships=[{"type": "downloaded_from", "target": "uuid-1"}],
            removed_relationships=[{"type": "extracted_from", "target": "uuid-3"}],
            added_excluded_analysis=["saq.modules.test:TestAnalysis"],
            removed_excluded_analysis=["saq.modules.test:Gone"],
            added_limited_analysis=["saq.modules.other:OtherAnalysis"],
            removed_limited_analysis=["saq.modules.other:Gone"],
            grouping_target=(False, True),
            redirection=(None, "uuid-2"),
            ignored=(False, True),
        )
        stored = {
            "added_tags": ["suspicious"],
            "removed_tags": ["benign"],
            "added_detections": [{"description": "test", "details": None}],
            "removed_detections": [{"description": "old", "details": None}],
            "added_directives": ["sandbox"],
            "removed_directives": ["crawl"],
            "added_relationships": [{"type": "downloaded_from", "target": "uuid-1"}],
            "removed_relationships": [{"type": "extracted_from", "target": "uuid-3"}],
            "added_excluded_analysis": ["saq.modules.test:TestAnalysis"],
            "removed_excluded_analysis": ["saq.modules.test:Gone"],
            "added_limited_analysis": ["saq.modules.other:OtherAnalysis"],
            "removed_limited_analysis": ["saq.modules.other:Gone"],
            "grouping_target": [False, True],
            "redirection": [None, "uuid-2"],
            "ignored": [False, True],
        }
        assert diff.to_dict() == stored
        assert ObservableDiff.from_dict(stored) == diff


class TestObservableSpec:
    @pytest.mark.unit
    def test_full_spec_format(self):
        """Every field, under the key names stored in cache rows and root.json."""
        spec = ObservableSpec(
            uuid="u2",
            type="file",
            value="a" * 64,
            time="2026-04-10T12:00:00+00:00",
            initial_tags=["suspicious"],
            initial_directives=["sandbox"],
            initial_detections=[{"description": "match", "details": None}],
            initial_excluded_analysis=["MyAnalyzer", "OtherAnalyzer"],
            initial_limited_analysis=["LimitedAnalyzer"],
            file_path="image.png.ocr/image.png.ocr",
            volatile=True,
            initial_relationships=[
                {"type": "extracted_from", "target": "parent-uuid",
                 "target_type": "file", "target_value": "b" * 64},
            ],
            initial_redirection="parent-uuid",
        )
        stored = {
            "uuid": "u2",
            "type": "file",
            "value": "a" * 64,
            "time": "2026-04-10T12:00:00+00:00",
            "initial_tags": ["suspicious"],
            "initial_directives": ["sandbox"],
            "initial_detections": [{"description": "match", "details": None}],
            "initial_excluded_analysis": ["MyAnalyzer", "OtherAnalyzer"],
            "initial_limited_analysis": ["LimitedAnalyzer"],
            "file_path": "image.png.ocr/image.png.ocr",
            "volatile": True,
            "initial_relationships": [
                {"type": "extracted_from", "target": "parent-uuid",
                 "target_type": "file", "target_value": "b" * 64},
            ],
            "initial_redirection": "parent-uuid",
        }
        assert spec.to_dict() == stored
        assert ObservableSpec.from_dict(stored) == spec


class TestRootDiff:
    @pytest.mark.unit
    def test_serialized_format(self):
        diff = RootDiff(
            added_tags=["alert"],
            removed_tags=["stale"],
            added_detections=[{"description": "new", "details": None}],
            removed_detections=[{"description": "old", "details": None}],
        )
        stored = {
            "added_tags": ["alert"],
            "removed_tags": ["stale"],
            "added_detections": [{"description": "new", "details": None}],
            "removed_detections": [{"description": "old", "details": None}],
        }
        assert diff.to_dict() == stored
        assert RootDiff.from_dict(stored) == diff


class TestModuleExecutionDelta:
    def _make_delta(self, **overrides):
        defaults = dict(
            module_path="saq.modules.test:TestAnalysis",
            module_instance=None,
            module_version=1,
            observable_uuid="obs-uuid-1",
            observable_type="ipv4",
            observable_value="10.0.0.1",
            created_at="2026-04-10T12:00:00+00:00",
            execution_time_ms=42,
        )
        defaults.update(overrides)
        return ModuleExecutionDelta(**defaults)

    @pytest.mark.unit
    def test_empty_delta(self):
        delta = self._make_delta()
        assert delta.is_empty
        assert not delta.has_removals

    @pytest.mark.unit
    def test_delta_with_analysis(self):
        delta = self._make_delta(
            analysis={"module_path": "saq.modules.test:TestAnalysis", "completed": True},
        )
        assert not delta.is_empty

    @pytest.mark.unit
    def test_delta_with_new_observables(self):
        spec = ObservableSpec(uuid="new-1", type="fqdn", value="evil.com")
        delta = self._make_delta(new_observables=[spec])
        assert not delta.is_empty

    @pytest.mark.unit
    def test_has_removals_from_target(self):
        diff = ObservableDiff(removed_tags=["old"])
        delta = self._make_delta(target_observable_diff=diff)
        assert delta.has_removals

    @pytest.mark.unit
    def test_has_removals_from_other_observable(self):
        other_diff = ObservableDiff(removed_directives=["crawl"])
        delta = self._make_delta(
            wide_diff=True,
            other_observable_diffs={"other-uuid": other_diff},
        )
        assert delta.has_removals

    @pytest.mark.unit
    def test_full_serialized_format(self):
        """Every top-level field, under the key names stored in cache rows
        and root.json. The nested diffs and the spec carry only some of their
        fields, so this also pins that empty fields are left out and that a
        stored dict without them loads with the defaults."""
        delta = self._make_delta(
            module_instance="instance1",
            root_uuid="root-uuid-1",
            analysis={"module_path": "saq.modules.test:TestAnalysis", "completed": True},
            target_observable_diff=ObservableDiff(added_tags=["suspicious"]),
            new_observables=[ObservableSpec(uuid="new-1", type="fqdn", value="evil.com")],
            root_diff=RootDiff(added_detections=[{"description": "root det", "details": None}]),
            cache_key="abc123",
            wide_diff=True,
            other_observable_diffs={"other-uuid": ObservableDiff(added_directives=["sandbox"])},
            from_cache_hit=True,
            cached_at="2026-04-09T08:00:00+00:00",
        )
        stored = {
            "module_path": "saq.modules.test:TestAnalysis",
            "module_instance": "instance1",
            "module_version": 1,
            "observable_uuid": "obs-uuid-1",
            "observable_type": "ipv4",
            "observable_value": "10.0.0.1",
            "created_at": "2026-04-10T12:00:00+00:00",
            "execution_time_ms": 42,
            "root_uuid": "root-uuid-1",
            "analysis": {"module_path": "saq.modules.test:TestAnalysis", "completed": True},
            "target_observable_diff": {"added_tags": ["suspicious"]},
            "new_observables": [{"uuid": "new-1", "type": "fqdn", "value": "evil.com"}],
            "root_diff": {"added_detections": [{"description": "root det", "details": None}]},
            "cache_key": "abc123",
            "wide_diff": True,
            "other_observable_diffs": {"other-uuid": {"added_directives": ["sandbox"]}},
            "from_cache_hit": True,
            "cached_at": "2026-04-09T08:00:00+00:00",
        }
        assert delta.to_dict() == stored
        assert ModuleExecutionDelta.from_dict(stored) == delta

    @pytest.mark.unit
    def test_compact_serialization_omits_empty_fields(self):
        assert self._make_delta().to_dict() == {
            "module_path": "saq.modules.test:TestAnalysis",
            "module_version": 1,
            "observable_uuid": "obs-uuid-1",
            "observable_type": "ipv4",
            "observable_value": "10.0.0.1",
            "created_at": "2026-04-10T12:00:00+00:00",
            "execution_time_ms": 42,
        }

    @pytest.mark.unit
    def test_has_removals_from_analysis_children(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.email.rfc822:EmailAnalysis",
            parent_observable_uuid="obs-parent",
            removed_child_uuids=["obs-removed"],
        )
        delta = self._make_delta(analysis_children_diffs=[acd])
        assert delta.has_removals

    @pytest.mark.unit
    def test_analysis_children_diff_format(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.email.rfc822:EmailAnalysis",
            parent_observable_uuid="obs-parent",
            added_child_uuids=["obs-added-1"],
            removed_child_uuids=["obs-removed-1", "obs-removed-2"],
        )
        empty = AnalysisChildrenDiff(analysis_module_path="m", parent_observable_uuid="p")
        delta = self._make_delta(wide_diff=True, analysis_children_diffs=[acd, empty])
        stored = [{
            "analysis_module_path": "saq.modules.email.rfc822:EmailAnalysis",
            "parent_observable_uuid": "obs-parent",
            "added_child_uuids": ["obs-added-1"],
            "removed_child_uuids": ["obs-removed-1", "obs-removed-2"],
        }]
        # an empty children diff is not stored
        assert delta.to_dict()["analysis_children_diffs"] == stored
        restored = ModuleExecutionDelta.from_dict(delta.to_dict())
        assert restored.analysis_children_diffs == [acd]

    @pytest.mark.unit
    def test_delta_not_empty_with_analysis_children(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.test:Test",
            parent_observable_uuid="obs-1",
            removed_child_uuids=["obs-2"],
        )
        delta = self._make_delta(analysis_children_diffs=[acd])
        assert not delta.is_empty


class TestWithoutAnalysisDetails:
    def _make_delta(self, **overrides):
        defaults = dict(
            module_path="saq.modules.test:TestAnalysis",
            module_instance=None,
            module_version=1,
            observable_uuid="obs-uuid-1",
            observable_type="ipv4",
            observable_value="10.0.0.1",
            created_at="2026-04-10T12:00:00+00:00",
        )
        defaults.update(overrides)
        return ModuleExecutionDelta(**defaults)

    @pytest.mark.unit
    def test_strips_details_preserves_other_keys(self):
        delta = self._make_delta(
            analysis={
                "module_path": "saq.modules.test:TestAnalysis",
                "summary": "found a thing",
                "completed": True,
                "delayed": False,
                "details": {"big": "payload"},
            },
            target_observable_diff=ObservableDiff(added_tags=["suspicious"]),
            cache_key="ab" * 32,
        )
        stripped = delta.without_analysis_details()
        assert "details" not in stripped.analysis
        assert stripped.analysis["summary"] == "found a thing"
        assert stripped.analysis["completed"] is True
        assert stripped.analysis["delayed"] is False
        # Non-analysis fields are preserved on the copy.
        assert stripped.target_observable_diff.added_tags == ["suspicious"]
        assert stripped.cache_key == delta.cache_key

    @pytest.mark.unit
    def test_original_delta_not_mutated(self):
        delta = self._make_delta(
            analysis={"module_path": "m", "details": {"k": "v"}},
        )
        stripped = delta.without_analysis_details()
        assert stripped is not delta
        assert delta.analysis["details"] == {"k": "v"}

    @pytest.mark.unit
    def test_returns_self_when_no_analysis(self):
        delta = self._make_delta(analysis=None)
        assert delta.without_analysis_details() is delta

    @pytest.mark.unit
    def test_returns_self_when_no_details_key(self):
        delta = self._make_delta(analysis={"module_path": "m", "completed": True})
        assert delta.without_analysis_details() is delta


class TestMergeDeltas:
    """merge_module_execution_deltas: folding a delayed-analysis module's
    earlier per-cycle deltas into the final cycle's delta for caching."""

    def _make_delta(self, **overrides):
        defaults = dict(
            module_path="saq.modules.test:TestAnalysis",
            module_instance=None,
            module_version=1,
            observable_uuid="obs-uuid-1",
            observable_type="fqdn",
            observable_value="example.com",
            created_at="2026-06-10T12:00:00+00:00",
            execution_time_ms=10,
        )
        defaults.update(overrides)
        return ModuleExecutionDelta(**defaults)

    @pytest.mark.unit
    def test_no_priors_returns_final(self):
        final = self._make_delta()
        assert merge_module_execution_deltas([], final) is final

    @pytest.mark.unit
    def test_added_fields_unioned_and_deduped(self):
        prior = self._make_delta(
            target_observable_diff=ObservableDiff(
                added_tags=["cycle1", "both"],
                added_directives=["sandbox"],
                added_detections=[{"description": "d1", "details": None}],
            ),
        )
        final = self._make_delta(
            target_observable_diff=ObservableDiff(
                added_tags=["both", "cycle2"],
                added_detections=[
                    {"description": "d1", "details": None},  # dup of cycle 1
                    {"description": "d2", "details": None},
                ],
            ),
        )
        merged = merge_module_execution_deltas([prior], final)
        assert merged.target_observable_diff.added_tags == ["cycle1", "both", "cycle2"]
        assert merged.target_observable_diff.added_directives == ["sandbox"]
        assert [d["description"] for d in merged.target_observable_diff.added_detections] == ["d1", "d2"]

    @pytest.mark.unit
    def test_prior_removal_makes_merged_has_removals(self):
        """A cycle-1 removal must surface on the merged delta so the
        cache write is refused — replay can't reproduce removals."""
        prior = self._make_delta(
            target_observable_diff=ObservableDiff(removed_tags=["was-here"]),
        )
        final = self._make_delta(
            target_observable_diff=ObservableDiff(added_tags=["new"]),
        )
        merged = merge_module_execution_deltas([prior], final)
        assert merged.has_removals
        assert merged.target_observable_diff.removed_tags == ["was-here"]

    @pytest.mark.unit
    def test_scalar_transitions_composed(self):
        prior = self._make_delta(
            target_observable_diff=ObservableDiff(grouping_target=(False, True)),
        )
        # Final cycle flips it back: composed transition is earliest
        # 'before' to latest 'after'.
        final = self._make_delta(
            target_observable_diff=ObservableDiff(grouping_target=(True, False)),
        )
        merged = merge_module_execution_deltas([prior], final)
        assert merged.target_observable_diff.grouping_target == (False, False)

    @pytest.mark.unit
    def test_scalar_from_prior_only(self):
        prior = self._make_delta(
            target_observable_diff=ObservableDiff(ignored=(False, True)),
        )
        final = self._make_delta(
            target_observable_diff=ObservableDiff(added_tags=["x"]),
        )
        merged = merge_module_execution_deltas([prior], final)
        assert merged.target_observable_diff.ignored == (False, True)

    @pytest.mark.unit
    def test_new_observables_deduped_first_wins(self):
        """Same (type, value, time) across cycles keeps the FIRST spec —
        preserving the uuid that cycle-1 relationships reference."""
        prior = self._make_delta(
            new_observables=[ObservableSpec(uuid="cycle1-uuid", type="ipv4", value="1.2.3.4")],
        )
        final = self._make_delta(
            new_observables=[
                ObservableSpec(uuid="cycle2-uuid", type="ipv4", value="1.2.3.4"),
                ObservableSpec(uuid="cycle2-other", type="fqdn", value="other.com"),
            ],
        )
        merged = merge_module_execution_deltas([prior], final)
        assert [(s.uuid, s.type, s.value) for s in merged.new_observables] == [
            ("cycle1-uuid", "ipv4", "1.2.3.4"),
            ("cycle2-other", "fqdn", "other.com"),
        ]

    @pytest.mark.unit
    def test_final_analysis_and_identity_kept(self):
        prior = self._make_delta(
            analysis={"module_path": "m", "delayed": True},
            created_at="2026-06-10T10:00:00+00:00",
        )
        final = self._make_delta(
            analysis={"module_path": "m", "delayed": False, "details": {"done": True}},
        )
        merged = merge_module_execution_deltas([prior], final)
        assert merged.analysis == final.analysis
        assert merged.created_at == final.created_at
        # execution_time_ms sums across cycles.
        assert merged.execution_time_ms == 20

    @pytest.mark.unit
    def test_root_diff_merged(self):
        prior = self._make_delta(root_diff=RootDiff(added_tags=["from-cycle1"]))
        final = self._make_delta(root_diff=RootDiff(added_tags=["from-cycle2"]))
        merged = merge_module_execution_deltas([prior], final)
        assert merged.root_diff.added_tags == ["from-cycle1", "from-cycle2"]

    @pytest.mark.unit
    def test_three_cycle_merge_with_analysis_none_middle(self):
        """Multi-delay shape: cycle 1 has the delayed analysis dict,
        cycle 2 (mid-delay) has analysis=None, final has the completed
        analysis. All tree mutations survive."""
        c1 = self._make_delta(
            analysis={"module_path": "m", "delayed": True},
            target_observable_diff=ObservableDiff(added_tags=["t1"]),
        )
        c2 = self._make_delta(
            analysis=None,
            target_observable_diff=ObservableDiff(added_tags=["t2"]),
        )
        final = self._make_delta(
            analysis={"module_path": "m", "delayed": False},
            target_observable_diff=ObservableDiff(added_tags=["t3"]),
        )
        merged = merge_module_execution_deltas([c1, c2], final)
        assert merged.target_observable_diff.added_tags == ["t1", "t2", "t3"]
        assert merged.analysis["delayed"] is False

    @pytest.mark.unit
    def test_inputs_not_mutated(self):
        prior = self._make_delta(
            target_observable_diff=ObservableDiff(added_tags=["t1"]),
        )
        final = self._make_delta(
            target_observable_diff=ObservableDiff(added_tags=["t2"]),
        )
        merge_module_execution_deltas([prior], final)
        assert prior.target_observable_diff.added_tags == ["t1"]
        assert final.target_observable_diff.added_tags == ["t2"]

    @pytest.mark.unit
    def test_wide_diff_input_raises(self):
        prior = self._make_delta(wide_diff=True)
        final = self._make_delta()
        with pytest.raises(ValueError):
            merge_module_execution_deltas([prior], final)


class TestHasRemovalsRootDiff:
    @pytest.mark.unit
    def test_root_diff_removals_counted(self):
        delta = ModuleExecutionDelta(
            module_path="saq.modules.test:TestAnalysis",
            module_instance=None,
            module_version=1,
            observable_uuid="obs-uuid-1",
            observable_type="fqdn",
            observable_value="example.com",
            created_at="2026-06-10T12:00:00+00:00",
            root_diff=RootDiff(removed_tags=["gone"]),
        )
        assert delta.has_removals


class TestAnalysisChildrenDiff:
    @pytest.mark.unit
    def test_empty(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.test:Test",
            parent_observable_uuid="obs-1",
        )
        assert acd.is_empty
