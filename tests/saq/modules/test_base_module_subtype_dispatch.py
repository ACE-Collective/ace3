import pytest

from saq.analysis import Analysis, RootAnalysis
from saq.constants import F_EMAIL_ADDRESS, F_EMAIL_RETURN_PATH, F_TEST
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.type_hierarchy import get_type_hierarchy


class _StubAnalysis(Analysis):
    pass


class _EmailAddressOnlyModule(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return _StubAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS


class _StrictEmailAddressModule(AnalysisModule):
    valid_observable_subtypes = False

    @property
    def generated_analysis_type(self):
        return _StubAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS


def _make_module(cls, test_context, **config):
    return cls(
        context=test_context,
        config=AnalysisModuleConfig(
            name="test",
            python_module="saq.modules.base_module",
            python_class="AnalysisModule",
            enabled=True,
            **config,
        ),
    )


@pytest.fixture
def hierarchy_with_return_path():
    """Ensure return_path -> email_address is in the registry for the test.

    Snapshots and restores the in-memory parent map so the test is hermetic
    even when the YAML config has already been loaded with the same mapping
    (which is the dev/CI default via etc/observable_types.yaml)."""
    h = get_type_hierarchy()
    parent_snapshot = dict(h._parent)
    h._parent[F_EMAIL_RETURN_PATH] = F_EMAIL_ADDRESS
    h._ancestors_cache.clear()
    try:
        yield h
    finally:
        h._parent = parent_snapshot
        h._ancestors_cache.clear()


@pytest.mark.unit
def test_subtype_observable_accepted_by_parent_type_module(test_context, hierarchy_with_return_path):
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_EMAIL_RETURN_PATH, "alice@example.com")
    module = _make_module(_EmailAddressOnlyModule, test_context)

    assert module.accepts(obs) is True


@pytest.mark.unit
def test_exact_type_observable_still_accepted(test_context, hierarchy_with_return_path):
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_EMAIL_ADDRESS, "bob@example.com")
    module = _make_module(_EmailAddressOnlyModule, test_context)

    assert module.accepts(obs) is True


@pytest.mark.unit
def test_unrelated_type_rejected(test_context, hierarchy_with_return_path):
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_TEST, "test")
    module = _make_module(_EmailAddressOnlyModule, test_context)

    assert module.accepts(obs) is False


@pytest.mark.unit
def test_strict_module_rejects_subtype(test_context, hierarchy_with_return_path):
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_EMAIL_RETURN_PATH, "alice@example.com")
    module = _make_module(_StrictEmailAddressModule, test_context)

    assert module.accepts(obs) is False


@pytest.mark.unit
def test_strict_module_still_accepts_exact_type(test_context, hierarchy_with_return_path):
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_EMAIL_ADDRESS, "alice@example.com")
    module = _make_module(_StrictEmailAddressModule, test_context)

    assert module.accepts(obs) is True


@pytest.mark.unit
def test_config_false_rejects_subtype(test_context, hierarchy_with_return_path):
    root = RootAnalysis()
    subtype = root.add_observable_by_spec(F_EMAIL_RETURN_PATH, "alice@example.com")
    exact = root.add_observable_by_spec(F_EMAIL_ADDRESS, "bob@example.com")
    module = _make_module(_EmailAddressOnlyModule, test_context, valid_observable_subtypes=False)

    assert module.accepts(subtype) is False
    assert module.accepts(exact) is True


@pytest.mark.unit
def test_config_true_overrides_strict_class(test_context, hierarchy_with_return_path):
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_EMAIL_RETURN_PATH, "alice@example.com")
    module = _make_module(_StrictEmailAddressModule, test_context, valid_observable_subtypes=True)

    assert module.accepts(obs) is True
