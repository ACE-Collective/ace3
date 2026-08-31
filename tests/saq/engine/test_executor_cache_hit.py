"""Tests for the Phase 3 cache-hit short-circuit in
``AnalysisExecutor._execute_module_analysis``.

Mirrors the Phase 1 precedent: full ``_execute_module_analysis`` flow
testing requires mocking the entire engine context (configuration
manager, delayed analysis interface, tracking message manager, work
stacks) and is deliberately deferred. These tests focus on the helper
``_apply_cached_delta`` and the dataclass plumbing that supports it.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from saq.analysis.cache import CacheLookupResult
from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)
from saq.analysis.root import RootAnalysis
from saq.constants import AnalysisExecutionResult, F_FILE, F_FQDN, F_URL
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.modules.rdap import RdapAnalysis


def _make_executor() -> AnalysisExecutor:
    """Minimum-viable AnalysisExecutor for testing the cache-hit helper.

    The helper doesn't touch configuration / delayed-analysis /
    tracking-message state, so MagicMock placeholders are enough.
    """
    return AnalysisExecutor(
        configuration_manager=MagicMock(),
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
        single_threaded_mode=True,
    )


def _make_root(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    return root


def _make_context(root) -> EngineExecutionContext:
    """Real EngineExecutionContext bound to ``root`` so counter bumps
    flow into the same dicts ``record_execution_statistics`` consumes."""
    return EngineExecutionContext(root)


def _make_module(name="rdap_analyzer"):
    """Stub module — only the attributes _apply_cached_delta touches."""
    return SimpleNamespace(config=SimpleNamespace(name=name))


SOURCE_OBSERVABLE_UUID = "00000000-source-source-source-000000000000"
SOURCE_ROOT_UUID = "00000000-source-root-source-root-00000000"


def _make_delta_for(observable, *, with_analysis=True):
    """Build a cached-style delta as if it had been captured from a
    *different* alert — observable_uuid and root_uuid are sentinel
    strings that intentionally do NOT match the current ``observable``
    or its parent root. This mirrors what a real cache hit looks like:
    the cached row carries the source alert's identifiers, and the
    executor's _apply_cached_delta has to rewrite them onto the
    attribution copy. Reusing the current observable's uuid here would
    mask exactly the bug that broke the GUI badge in production.
    """
    analysis = None
    if with_analysis:
        analysis = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"registrar": "Test Registrar"},
            "completed": True,
            "delayed": False,
        }
    delta = ModuleExecutionDelta(
        module_path="saq.modules.rdap:RdapAnalysis",
        module_instance=None,
        module_version=1,
        observable_uuid=SOURCE_OBSERVABLE_UUID,
        observable_type=observable.type,
        observable_value=observable.value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=42,
        root_uuid=SOURCE_ROOT_UUID,
        target_observable_diff=ObservableDiff(added_tags=["replayed"]),
        new_observables=[],
        root_diff=RootDiff(),
        analysis=analysis,
    )
    delta.cache_key = "deadbeef" * 8  # 64-char hex placeholder
    return delta


class TestApplyCachedDelta:

    @pytest.mark.unit
    def test_records_attribution_delta_with_from_cache_hit_flag(self, tmp_path):
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()
        delta = _make_delta_for(obs)

        executor._apply_cached_delta(context, root, obs, module,
                                     CacheLookupResult(delta, None, 4, "abc"))

        assert len(root.module_executions) == 1
        recorded = root.module_executions[0]
        assert recorded.from_cache_hit is True
        # Both root_uuid AND observable_uuid are rewritten to the current
        # alert / observable — the cached delta carried sentinel "source"
        # UUIDs (see _make_delta_for). Confirming both rewrites prevents
        # regressions of the bug where the alert GUI couldn't find the
        # badge because the attribution carried the source observable's
        # uuid instead of the current one.
        assert recorded.root_uuid == root.uuid
        assert recorded.root_uuid != SOURCE_ROOT_UUID
        assert recorded.observable_uuid == obs.uuid
        assert recorded.observable_uuid != SOURCE_OBSERVABLE_UUID
        # Mutation fields preserved from original capture.
        assert recorded.target_observable_diff.added_tags == ["replayed"]
        # Attribution execution_time_ms reflects total hit cost
        # (lookup + replay), not replay alone.
        assert recorded.execution_time_ms >= 4

    @pytest.mark.unit
    def test_attribution_delta_details_stripped(self, tmp_path):
        """The recorded attribution delta must not duplicate the bulk
        analysis.details payload into root.json — the rehydrated analysis
        on the tree already carries it. The input (cached) delta keeps its
        details intact for the actual replay."""
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()
        delta = _make_delta_for(obs)
        assert delta.analysis["details"]  # precondition

        executor._apply_cached_delta(context, root, obs, module,
                                     CacheLookupResult(delta, None, 4, "abc"))

        recorded = root.module_executions[0]
        assert "details" not in recorded.analysis
        # Identity/metadata survives the strip.
        assert recorded.from_cache_hit is True
        assert recorded.analysis["module_path"] == delta.analysis["module_path"]
        # The cached delta itself is untouched — replay used the details.
        assert delta.analysis["details"] == {"registrar": "Test Registrar"}

    @pytest.mark.unit
    def test_bumps_cache_hit_counters_on_context(self, tmp_path):
        """The plain ``analysis cache hit`` log line was replaced by
        per-(root, module) aggregation on the EngineExecutionContext.
        Each call to ``_apply_cached_delta`` must bump cache_hit_count
        and the lookup-latency accumulators for the module.
        """
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()
        delta = _make_delta_for(obs)

        executor._apply_cached_delta(
            context, root, obs, module,
            CacheLookupResult(delta, None, 7, "abc", key_ms=5, db_ms=2, decode_ms=1, blob_ms=4),
        )
        executor._apply_cached_delta(
            context, root, obs, module,
            CacheLookupResult(delta, None, 3, "abc", key_ms=1, db_ms=1, decode_ms=0, blob_ms=2),
        )

        name = module.config.name
        assert context.cache_hit_count[name] == 2
        assert context.cache_lookup_ms_sum[name] == 10
        assert context.cache_lookup_ms_max[name] == 7
        # component sums accumulate across both hits
        assert context.cache_lookup_key_ms_sum[name] == 6
        assert context.cache_lookup_db_ms_sum[name] == 3
        assert context.cache_lookup_decode_ms_sum[name] == 1
        assert context.cache_lookup_blob_ms_sum[name] == 6

    @pytest.mark.unit
    def test_attribution_delta_recorded_even_when_diff_is_empty(self, tmp_path):
        """Phase 1 filters empty deltas to avoid bloating root.json. Phase 3
        cache hits must always be recorded — cache consultation is itself
        information worth keeping (audit/debug).
        """
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()

        # Build a delta with no mutations and no analysis dict.
        empty_delta = ModuleExecutionDelta(
            module_path="saq.modules.x:X",
            module_instance=None,
            module_version=1,
            observable_uuid=obs.uuid,
            observable_type=obs.type,
            observable_value=obs.value,
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=0,
            target_observable_diff=ObservableDiff(),
            new_observables=[],
            root_diff=RootDiff(),
            analysis=None,
        )
        empty_delta.cache_key = "00" * 32

        executor._apply_cached_delta(context, root, obs, module,
                                     CacheLookupResult(empty_delta, None, 2, "abc"))

        # Even though the delta is empty, attribution is recorded.
        assert len(root.module_executions) == 1
        assert root.module_executions[0].from_cache_hit is True

    @pytest.mark.unit
    def test_apply_delta_actually_mutates_target_tree(self, tmp_path):
        """End-to-end: _apply_cached_delta calls apply_delta which
        mutates the observable, then records attribution. Verifies the
        helper isn't a no-op.
        """

        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()
        delta = _make_delta_for(obs)

        executor._apply_cached_delta(context, root, obs, module,
                                     CacheLookupResult(delta, None, 1, "abc"))

        # Diff additions applied.
        assert "replayed" in obs.tags
        # Analysis rehydrated.
        rehydrated = obs.get_analysis(RdapAnalysis)
        assert rehydrated is not None
        assert rehydrated.details == {"registrar": "Test Registrar"}


def _make_cacheable_module(name="rdap_analyzer", ttl=timedelta(hours=1)):
    """Stub module with the attributes _maybe_write_cache_delta touches."""
    return SimpleNamespace(
        name=name,
        config=SimpleNamespace(name=name),
        cache_ttl=ttl,
        version=1,
        extended_version={},
        generated_analysis_type=RdapAnalysis,
        instance=None,
    )


class TestMaybeWriteCacheDelta:
    """Gating and delayed-cycle merging in the executor's cache-write
    helper. ``put_cached_delta`` is mocked — its own refusal logic is
    covered in tests/saq/analysis/test_cache.py."""

    def _delta(self, obs, **overrides):
        defaults = dict(
            module_path="saq.modules.rdap:RdapAnalysis",
            module_instance=None,
            module_version=1,
            observable_uuid=obs.uuid,
            observable_type=obs.type,
            observable_value=obs.value,
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=10,
            target_observable_diff=ObservableDiff(added_tags=["t"]),
        )
        defaults.update(overrides)
        return ModuleExecutionDelta(**defaults)

    @pytest.mark.unit
    def test_incomplete_result_blocks_cache_write(self, tmp_path, monkeypatch):
        """A-0: a delayed module returns INCOMPLETE for every mid-delay
        cycle. An intermediate cycle's delta has analysis=None, which
        slips past put_cached_delta's still-delayed check — the executor
        must not attempt the write at all for non-COMPLETED results."""
        put_mock = MagicMock()
        monkeypatch.setattr("saq.engine.executor.put_cached_delta", put_mock)
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_cacheable_module()
        delta = self._delta(obs, analysis=None)  # mid-delay shape

        executor._maybe_write_cache_delta(
            context, root, obs, module, delta,
            AnalysisExecutionResult.INCOMPLETE, [],
        )
        put_mock.assert_not_called()

    @pytest.mark.unit
    def test_completed_result_writes(self, tmp_path, monkeypatch):
        put_mock = MagicMock(return_value=None)
        monkeypatch.setattr("saq.engine.executor.put_cached_delta", put_mock)
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_cacheable_module()
        delta = self._delta(obs)

        executor._maybe_write_cache_delta(
            context, root, obs, module, delta,
            AnalysisExecutionResult.COMPLETED, [],
        )
        put_mock.assert_called_once()
        assert put_mock.call_args[0][0] is delta

    @pytest.mark.unit
    def test_not_opted_in_blocks_cache_write(self, tmp_path, monkeypatch):
        put_mock = MagicMock()
        monkeypatch.setattr("saq.engine.executor.put_cached_delta", put_mock)
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_cacheable_module(ttl=None)
        delta = self._delta(obs)

        executor._maybe_write_cache_delta(
            context, root, obs, module, delta,
            AnalysisExecutionResult.COMPLETED, [],
        )
        put_mock.assert_not_called()

    @pytest.mark.unit
    def test_prior_deltas_merged_into_cache_write(self, tmp_path, monkeypatch):
        """A delayed resume passes prior cycles' deltas; the written delta
        must carry their mutations merged with the final cycle's."""
        put_mock = MagicMock(return_value=None)
        monkeypatch.setattr("saq.engine.executor.put_cached_delta", put_mock)
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_cacheable_module()
        prior = self._delta(
            obs,
            analysis={"module_path": "saq.modules.rdap:RdapAnalysis", "delayed": True},
            target_observable_diff=ObservableDiff(added_tags=["pre-delay"]),
        )
        final = self._delta(
            obs,
            analysis={"module_path": "saq.modules.rdap:RdapAnalysis",
                      "delayed": False, "details": {"done": True}},
            target_observable_diff=ObservableDiff(added_tags=["post-delay"]),
        )

        executor._maybe_write_cache_delta(
            context, root, obs, module, final,
            AnalysisExecutionResult.COMPLETED, [prior],
        )
        written = put_mock.call_args[0][0]
        assert written.target_observable_diff.added_tags == ["pre-delay", "post-delay"]
        assert written.analysis["details"] == {"done": True}
        # The recorded (final) delta itself is not mutated by the merge.
        assert final.target_observable_diff.added_tags == ["post-delay"]

    @pytest.mark.unit
    def test_delay_timeout_blocks_cache_write(self, tmp_path, monkeypatch):
        """A delayed-analysis deadline expiry returns COMPLETED with the
        analysis closed out empty — the module never received its result.
        The delta still shows a delayed→completed transition, so without
        this gate the empty result gets cached and replays "nothing" into
        every root analyzing the same observable for the TTL."""
        put_mock = MagicMock()
        monkeypatch.setattr("saq.engine.executor.put_cached_delta", put_mock)
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis = obs.add_analysis(RdapAnalysis())
        analysis.delay_analysis_timed_out = True
        module = _make_cacheable_module()
        delta = self._delta(obs)

        executor._maybe_write_cache_delta(
            context, root, obs, module, delta,
            AnalysisExecutionResult.COMPLETED, [],
        )
        put_mock.assert_not_called()

    @pytest.mark.unit
    def test_completed_analysis_without_timeout_marker_writes(self, tmp_path, monkeypatch):
        """Control for the timeout gate: an attached analysis WITHOUT the
        marker (a genuine post-delay completion) still gets cached."""
        put_mock = MagicMock(return_value=None)
        monkeypatch.setattr("saq.engine.executor.put_cached_delta", put_mock)
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        obs.add_analysis(RdapAnalysis())
        module = _make_cacheable_module()
        delta = self._delta(obs)

        executor._maybe_write_cache_delta(
            context, root, obs, module, delta,
            AnalysisExecutionResult.COMPLETED, [],
        )
        put_mock.assert_called_once()


class TestDelayAnalysisTimeoutMarker:
    """base_module.delay_analysis marks the analysis when the engine
    refuses the delay (deadline expired), so the executor's cache write
    can tell that COMPLETED apart from a genuine post-delay completion."""

    def _make_module(self, delay_accepted: bool, root):
        from saq.analysis.adapter import RootAnalysisAdapter
        from saq.modules.base_module import AnalysisModule
        from saq.modules.config import AnalysisModuleConfig
        from saq.modules.context import AnalysisModuleContext

        interface = MagicMock()
        interface.delay_analysis.return_value = delay_accepted
        context = AnalysisModuleContext(
            delayed_analysis_interface=interface,
            root=RootAnalysisAdapter(root),
        )
        config = AnalysisModuleConfig(
            name="test_module",
            python_module="saq.modules.base_module",
            python_class="AnalysisModule",
            enabled=True,
        )
        return AnalysisModule(config, context=context)

    @pytest.mark.unit
    def test_refused_delay_sets_marker(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis = obs.add_analysis(RdapAnalysis())
        module = self._make_module(delay_accepted=False, root=root)

        result = module.delay_analysis(obs, analysis, seconds=3, timeout_seconds=10)

        assert result == AnalysisExecutionResult.COMPLETED
        assert analysis.completed is True
        assert analysis.delayed is False
        assert analysis.delay_analysis_timed_out is True

    @pytest.mark.unit
    def test_accepted_delay_does_not_set_marker(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis = obs.add_analysis(RdapAnalysis())
        module = self._make_module(delay_accepted=True, root=root)

        result = module.delay_analysis(obs, analysis, seconds=3, timeout_seconds=10)

        assert result == AnalysisExecutionResult.INCOMPLETE
        assert analysis.delayed is True
        assert not getattr(analysis, "delay_analysis_timed_out", False)


class TestModuleExecutionDeltaCacheHitMetadata:
    """The dataclass method that the executor helper uses to mint the
    attribution copy — exercised independently of the helper to make
    failure modes easier to localize.
    """

    @pytest.mark.unit
    def test_with_cache_hit_metadata_sets_flag(self):
        original_created_at = "2026-05-10T12:34:56+00:00"
        delta = ModuleExecutionDelta(
            module_path="m",
            module_instance=None,
            module_version=1,
            observable_uuid="u",
            observable_type="t",
            observable_value="v",
            created_at=original_created_at,
            execution_time_ms=1234,
            root_uuid="source-alert-uuid",
            target_observable_diff=ObservableDiff(added_tags=["t1"]),
            new_observables=[],
            root_diff=RootDiff(),
        )
        executed_at = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
        copy = delta.with_cache_hit_metadata(
            executed_at=executed_at,
            execution_time_ms=5,
            root_uuid="current-alert-uuid",
            observable_uuid="current-observable-uuid",
        )
        # Original is untouched.
        assert delta.from_cache_hit is False
        assert delta.execution_time_ms == 1234
        assert delta.root_uuid == "source-alert-uuid"
        assert delta.observable_uuid == "u"
        assert delta.cached_at is None
        # Copy reflects the cache-hit replay.
        assert copy.from_cache_hit is True
        assert copy.execution_time_ms == 5
        assert copy.created_at == executed_at.isoformat()
        # root_uuid AND observable_uuid are rewritten to the current alert /
        # observable. Both UUIDs are per-alert-instance, so leaving the
        # source's in place would (a) misattribute the replay in root.json
        # audits and (b) break the alert GUI's (module_path, observable_uuid)
        # lookup for the "cached" badge.
        assert copy.root_uuid == "current-alert-uuid"
        assert copy.observable_uuid == "current-observable-uuid"
        # cached_at preserves the *original* created_at (when the source
        # delta was first captured), since created_at itself gets rewritten
        # to the replay time. Surfaced in the alert GUI tooltip so analysts
        # can tell at a glance how stale a cached result is.
        assert copy.cached_at == original_created_at
        # Mutations preserved.
        assert copy.target_observable_diff.added_tags == ["t1"]

    @pytest.mark.unit
    def test_from_cache_hit_round_trips_through_dict(self):
        delta = ModuleExecutionDelta(
            module_path="m",
            module_instance=None,
            module_version=1,
            observable_uuid="u",
            observable_type="t",
            observable_value="v",
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=1,
            target_observable_diff=ObservableDiff(),
            new_observables=[],
            root_diff=RootDiff(),
            from_cache_hit=True,
            cached_at="2026-05-10T12:34:56+00:00",
        )
        d = delta.to_dict()
        assert d["from_cache_hit"] is True
        assert d["cached_at"] == "2026-05-10T12:34:56+00:00"
        rebuilt = ModuleExecutionDelta.from_dict(d)
        assert rebuilt.from_cache_hit is True
        assert rebuilt.cached_at == "2026-05-10T12:34:56+00:00"

    @pytest.mark.unit
    def test_from_cache_hit_default_false_on_old_dicts(self):
        """Backward compat: pre-Step-3.7 dicts have no from_cache_hit
        key. from_dict must default to False.
        """
        d = {
            "module_path": "m",
            "module_version": 1,
            "observable_uuid": "u",
            "observable_type": "t",
            "observable_value": "v",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": 1,
        }
        rebuilt = ModuleExecutionDelta.from_dict(d)
        assert rebuilt.from_cache_hit is False

    @pytest.mark.unit
    def test_has_file_observables_property(self):

        delta = ModuleExecutionDelta(
            module_path="m",
            module_instance=None,
            module_version=1,
            observable_uuid="u",
            observable_type="t",
            observable_value="v",
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=1,
            target_observable_diff=ObservableDiff(),
            new_observables=[
                ObservableSpec(uuid="1", type=F_URL, value="https://x"),
            ],
            root_diff=RootDiff(),
        )
        assert delta.has_file_observables is False

        delta.new_observables.append(
            ObservableSpec(uuid="2", type=F_FILE, value="path")
        )
        assert delta.has_file_observables is True
