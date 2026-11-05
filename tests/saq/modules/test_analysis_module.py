import pytest

from saq.analysis import Analysis, RootAnalysis
from saq.constants import F_TEST
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from tests.saq.test_util import create_test_context

@pytest.mark.unit
def test_accepts(monkeypatch, test_context):
    module = AnalysisModule(
        context=test_context,
        config=AnalysisModuleConfig(
            name="test",
            python_module="saq.modules.base_module",
            python_class="AnalysisModule",
            enabled=True
        )
    )
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_TEST, "test")

    # generated analysis type
    assert module.generated_analysis_type is None
    assert not module.accepts(obs)

    class MockAnalysis(Analysis):
        pass

    class MockAnalysisModule(AnalysisModule):
        @property
        def generated_analysis_type(self):
            return MockAnalysis

        @property
        def valid_observable_types(self):
            return F_TEST

    # requires detection path
    module_config = AnalysisModuleConfig(
        name="test",
        python_module="saq.modules.base_module",
        python_class="AnalysisModule",
        enabled=True,
        requires_detection_path=True
    )
    module = MockAnalysisModule(context=test_context, config=module_config)
    assert not module.accepts(obs)
    obs.add_detection_point("test")
    assert module.accepts(obs)

@pytest.mark.unit
def test_invalid_alert_type(monkeypatch, test_context):
    module = AnalysisModule(
        context=test_context,
        config=AnalysisModuleConfig(
            name="test",
            python_module="saq.modules.base_module",
            python_class="AnalysisModule",
            enabled=True
        )
    )
    root = RootAnalysis(alert_type="test")
    obs = root.add_observable_by_spec(F_TEST, "test")

    # generated analysis type
    assert module.generated_analysis_type is None
    assert not module.accepts(obs)

    class MockAnalysis(Analysis):
        pass

    class MockAnalysisModule(AnalysisModule):
        @property
        def generated_analysis_type(self):
            return MockAnalysis

        @property
        def valid_observable_types(self):
            return F_TEST

    module_config = AnalysisModuleConfig(
        name="test",
        python_module="saq.modules.base_module",
        python_class="AnalysisModule",
        enabled=True
    )

    module = MockAnalysisModule(
        context=create_test_context(root=root),
        config=module_config
    )
    assert module.accepts(obs)

    # single invalid alert type
    module_config.invalid_alert_types = ["test"]
    module = MockAnalysisModule(
        context=create_test_context(root=root),
        config=module_config
    )
    assert not module.accepts(obs)

    # multiple invalid alert types
    module_config.invalid_alert_types = ["blah", "test"]
    module = MockAnalysisModule(
        context=create_test_context(root=root),
        config=module_config
    )
    assert not module.accepts(obs)

    # invalid alert types that are not this alert's
    module_config.invalid_alert_types = ["blah", "other"]
    module = MockAnalysisModule(
        context=create_test_context(root=root),
        config=module_config
    )
    assert module.accepts(obs)