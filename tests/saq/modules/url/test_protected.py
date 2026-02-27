import pytest

from saq.analysis.root import RootAnalysis
from saq.constants import F_URL, AnalysisExecutionResult
from saq.modules.config import AnalysisModuleConfig
from saq.modules.url.protected import ProtectedURLAnalyzer, ProtectedURLAnalysis
from saq.util.url import ProtectionType
from tests.saq.test_util import create_test_context


def create_analyzer(root):
    """Create a ProtectedURLAnalyzer with a test context and config."""
    return ProtectedURLAnalyzer(
        context=create_test_context(root=root),
        config=AnalysisModuleConfig(
            name="test_protected_url",
            python_module="saq.modules.url.protected",
            python_class="ProtectedURLAnalyzer",
            enabled=True,
        ),
    )


@pytest.mark.unit
def test_execute_analysis_value_error(monkeypatch):
    """When extract_protected_url raises ValueError, execute_analysis returns COMPLETED early."""
    root = RootAnalysis()
    url_obs = root.add_observable_by_spec(F_URL, "not-a-valid-url")
    analyzer = create_analyzer(root)

    monkeypatch.setattr(
        "saq.modules.url.protected.extract_protected_url",
        lambda url: (_ for _ in ()).throw(ValueError("bad url")),
    )

    result = analyzer.execute_analysis(url_obs)

    assert result == AnalysisExecutionResult.COMPLETED
    # No analysis should have been attached with protection_type set
    analysis = url_obs.get_analysis(ProtectedURLAnalysis)
    assert analysis is None or analysis.protection_type is None


@pytest.mark.unit
def test_execute_analysis_unprotected_url(monkeypatch):
    """When a URL is unprotected, execute_analysis sets details and returns COMPLETED."""
    test_url = "https://example.com/safe"
    root = RootAnalysis()
    url_obs = root.add_observable_by_spec(F_URL, test_url)
    analyzer = create_analyzer(root)

    monkeypatch.setattr(
        "saq.modules.url.protected.extract_protected_url",
        lambda url: (ProtectionType.UNPROTECTED, test_url),
    )

    result = analyzer.execute_analysis(url_obs)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = url_obs.get_analysis(ProtectedURLAnalysis)
    assert analysis is not None
    assert analysis.protection_type == ProtectionType.UNPROTECTED.value
    assert analysis.extracted_url == test_url
    # No new observables should be added for unprotected URLs
    assert not url_obs.has_tag("protected_url")


@pytest.mark.unit
def test_execute_analysis_protected_url(monkeypatch):
    """When a URL is protected, execute_analysis adds extracted URL observable and tags the original."""
    original_url = "https://protect.fireeye.com/v1/url?u=https://malicious.com"
    extracted_url = "https://malicious.com"
    root = RootAnalysis()
    url_obs = root.add_observable_by_spec(F_URL, original_url)
    analyzer = create_analyzer(root)

    monkeypatch.setattr(
        "saq.modules.url.protected.extract_protected_url",
        lambda url: (ProtectionType.FIREEYE, extracted_url),
    )

    result = analyzer.execute_analysis(url_obs)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = url_obs.get_analysis(ProtectedURLAnalysis)
    assert analysis is not None
    assert analysis.protection_type == ProtectionType.FIREEYE.value
    assert analysis.extracted_url == extracted_url
    assert url_obs.has_tag("protected_url")
    # The extracted URL should have been added as an observable on the analysis
    extracted_obs = analysis.find_observable(lambda o: o.type == F_URL and o.value == extracted_url)
    assert extracted_obs is not None
