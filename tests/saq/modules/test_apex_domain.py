"""Unit tests for ``saq.modules.apex_domain``."""

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_APEX_DOMAIN_ANALYZER,
    ANALYSIS_MODULE_RDAP_ANALYZER,
    AnalysisExecutionResult,
    F_FQDN,
)
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.apex_domain import ApexDomainAnalysis, ApexDomainAnalyzer
from saq.modules.rdap import RdapAnalysis
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis


def _run(test_context, value):
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, value)

    analyzer = ApexDomainAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_APEX_DOMAIN_ANALYZER),
    )
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    return observable, observable.get_analysis(ApexDomainAnalysis)


@pytest.mark.unit
@pytest.mark.parametrize(
    "value, expected",
    [
        ("abc.example.com", "example.com"),
        ("a.b.c.Example.COM", "example.com"),
        ("login.example.co.uk", "example.co.uk"),
    ],
)
def test_subdomain_adds_apex_observable(test_context, value, expected):
    observable, analysis = _run(test_context, value)

    assert analysis is not None
    assert analysis.apex_domain == expected
    assert expected in analysis.generate_summary()

    apex = analysis.get_observable_by_type(F_FQDN)
    assert apex is not None
    assert apex.value == expected
    assert apex.display_type == f"Apex Domain ({F_FQDN})"
    assert apex.time == observable.time


@pytest.mark.unit
@pytest.mark.parametrize("value", ["example.com", "example.co.uk", "host.corp.internal"])
def test_no_analysis_when_already_apex_or_no_public_suffix(test_context, value):
    _, analysis = _run(test_context, value)
    assert analysis is None


@pytest.mark.integration
def test_engine_adds_apex_and_does_not_expand_it(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    subdomain = root_analysis.add_observable_by_spec(F_FQDN, "abc.example.com")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_APEX_DOMAIN_ANALYZER, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(subdomain.uuid).get_and_load_analysis(ApexDomainAnalysis)
    assert isinstance(analysis, ApexDomainAnalysis)

    apex = root_analysis.find_observable(lambda o: o.type == F_FQDN and o.value == "example.com")
    assert apex is not None
    assert not apex.get_and_load_analysis(ApexDomainAnalysis)


def _run_engine_with_rdap(root_analysis, monkeypatch, modules):
    queried = []

    def _domain(name, *_a, **_kw):
        queried.append(name)
        return {"name": name.upper(), "entities": {}, "raw": {}}

    monkeypatch.setattr("whoisit.is_bootstrapped", lambda: True)
    monkeypatch.setattr("whoisit.domain", _domain)

    root_analysis.analysis_mode = "test_groups"
    subdomain = root_analysis.add_observable_by_spec(F_FQDN, "abc.example.com")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module in modules:
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    return root_analysis, root_analysis.get_observable(subdomain.uuid), queried


@pytest.mark.integration
def test_engine_rdap_runs_on_apex_not_subdomain(root_analysis, monkeypatch):
    root_analysis, subdomain, queried = _run_engine_with_rdap(
        root_analysis, monkeypatch, [ANALYSIS_MODULE_APEX_DOMAIN_ANALYZER, ANALYSIS_MODULE_RDAP_ANALYZER]
    )

    assert not subdomain.get_and_load_analysis(RdapAnalysis)
    apex = root_analysis.find_observable(lambda o: o.type == F_FQDN and o.value == "example.com")
    assert isinstance(apex.get_and_load_analysis(RdapAnalysis), RdapAnalysis)
    assert queried == ["example.com"]


@pytest.mark.integration
def test_engine_rdap_runs_on_subdomain_without_apex_analyzer(root_analysis, monkeypatch):
    _, subdomain, queried = _run_engine_with_rdap(root_analysis, monkeypatch, [ANALYSIS_MODULE_RDAP_ANALYZER])

    assert isinstance(subdomain.get_and_load_analysis(RdapAnalysis), RdapAnalysis)
    assert queried == ["example.com"]
