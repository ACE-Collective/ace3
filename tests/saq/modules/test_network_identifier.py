import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_NETWORK_IDENTIFIER, F_ASSET, F_IP, F_IPV4, AnalysisExecutionResult
from saq.modules.asset.network_identifier import NetworkIdentifier, NetworkIdentifierAnalysis

pytestmark = pytest.mark.unit

NETWORKS = """Indicator,Indicator_Type
10.0.0.0/8,corporate
10.20.0.0/16,datacenter
2001:db8::/32,corporate v6
"""


@pytest.fixture
def analyzer(tmp_path, test_context, root_analysis):
    csv_path = tmp_path / "local_networks.csv"
    csv_path.write_text(NETWORKS)
    config = get_analysis_module_config(ANALYSIS_MODULE_NETWORK_IDENTIFIER).model_copy(update={"csv_file": str(csv_path)})
    analyzer = NetworkIdentifier(context=test_context, config=config)
    analyzer.root = root_analysis
    return analyzer


def _analyze(analyzer, root_analysis, observable_type: str, value: str) -> NetworkIdentifierAnalysis:
    observable = root_analysis.add_observable_by_spec(observable_type, value)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(NetworkIdentifierAnalysis)
    assert isinstance(analysis, NetworkIdentifierAnalysis)
    return analysis


def test_an_address_in_every_network_it_belongs_to_is_an_asset(analyzer, root_analysis):
    analysis = _analyze(analyzer, root_analysis, F_IPV4, "10.20.1.5")

    assert analysis.identified_networks == ["corporate", "datacenter"]
    assert analysis.is_asset
    assert analysis.generate_summary() == "Network Identification Analysis: corporate, datacenter"
    assert [o.value for o in analysis.get_observables_by_type(F_ASSET)] == ["10.20.1.5"]


def test_an_address_in_one_network_is_an_asset(analyzer, root_analysis):
    analysis = _analyze(analyzer, root_analysis, F_IPV4, "10.1.1.1")

    assert analysis.identified_networks == ["corporate"]
    assert [o.value for o in analysis.get_observables_by_type(F_ASSET)] == ["10.1.1.1"]


def test_an_ipv6_address_is_matched_against_the_ipv6_networks(analyzer, root_analysis):
    analysis = _analyze(analyzer, root_analysis, F_IP, "2001:db8::1")

    assert analysis.identified_networks == ["corporate v6"]


def test_an_address_in_no_network_is_not_an_asset(analyzer, root_analysis):
    analysis = _analyze(analyzer, root_analysis, F_IPV4, "8.8.8.8")

    assert analysis.identified_networks == []
    assert not analysis.is_asset
    assert analysis.generate_summary() is None
    assert analysis.get_observables_by_type(F_ASSET) == []


def test_the_analysis_keeps_its_networks_through_its_details():
    analysis = NetworkIdentifierAnalysis()
    analysis.identified_networks = ["corporate"]

    assert analysis.details == {"identified_networks": ["corporate"]}
