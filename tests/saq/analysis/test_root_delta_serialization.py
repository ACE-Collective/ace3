"""Tests for RootAnalysis serialization with module execution deltas."""

import pytest

from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)
from saq.analysis.root import RootAnalysis
from saq.analysis.serialize.root_serializer import RootAnalysisSerializer


def _make_root(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    return root


def _make_sample_delta():
    return ModuleExecutionDelta(
        module_path="saq.modules.test:TestAnalysis",
        module_instance=None,
        module_version=1,
        observable_uuid="obs-uuid-1",
        observable_type="ipv4",
        observable_value="10.0.0.1",
        created_at="2026-04-10T12:00:00+00:00",
        execution_time_ms=42,
        target_observable_diff=ObservableDiff(added_tags=["suspicious"]),
        new_observables=[
            ObservableSpec(uuid="new-1", type="fqdn", value="evil.com"),
        ],
        root_diff=RootDiff(added_tags=["alert"]),
    )


class TestRootDeltaSerialization:
    @pytest.mark.unit
    def test_serialize_with_deltas(self, tmp_path):
        root = _make_root(tmp_path)
        delta = _make_sample_delta()
        root.record_module_execution(delta)

        serialized = RootAnalysisSerializer.serialize(root)
        assert "module_executions" in serialized
        assert len(serialized["module_executions"]) == 1
        assert serialized["module_executions"][0]["module_path"] == "saq.modules.test:TestAnalysis"

    @pytest.mark.unit
    def test_deserialize_with_deltas(self, tmp_path):
        root = _make_root(tmp_path)
        delta = _make_sample_delta()
        root.record_module_execution(delta)

        serialized = RootAnalysisSerializer.serialize(root)

        # Deserialize into a fresh root
        root2 = _make_root(tmp_path / "root2")
        RootAnalysisSerializer.deserialize(root2, serialized)

        assert len(root2.module_executions) == 1
        restored = root2.module_executions[0]
        assert restored.module_path == "saq.modules.test:TestAnalysis"
        assert restored.observable_value == "10.0.0.1"
        assert restored.target_observable_diff.added_tags == ["suspicious"]
        assert len(restored.new_observables) == 1
        assert restored.root_diff.added_tags == ["alert"]

    @pytest.mark.unit
    def test_deserialize_without_deltas_key(self, tmp_path):
        """Backward compatibility: root.json without module_executions."""
        root = _make_root(tmp_path)
        serialized = RootAnalysisSerializer.serialize(root)
        # Ensure no key present
        assert "module_executions" not in serialized

        root2 = _make_root(tmp_path / "root2")
        RootAnalysisSerializer.deserialize(root2, serialized)
        assert root2.module_executions == []

    @pytest.mark.unit
    def test_multiple_deltas_round_trip(self, tmp_path):
        root = _make_root(tmp_path)
        for i in range(3):
            delta = ModuleExecutionDelta(
                module_path=f"saq.modules.test:Module{i}",
                module_instance=None,
                module_version=1,
                observable_uuid=f"obs-{i}",
                observable_type="ipv4",
                observable_value=f"10.0.0.{i}",
                created_at="2026-04-10T12:00:00+00:00",
                execution_time_ms=i * 10,
            )
            root.record_module_execution(delta)

        serialized = RootAnalysisSerializer.serialize(root)
        root2 = _make_root(tmp_path / "root2")
        RootAnalysisSerializer.deserialize(root2, serialized)

        assert len(root2.module_executions) == 3
        for i, restored in enumerate(root2.module_executions):
            assert restored.module_path == f"saq.modules.test:Module{i}"
            assert restored.observable_value == f"10.0.0.{i}"
            assert restored.execution_time_ms == i * 10
