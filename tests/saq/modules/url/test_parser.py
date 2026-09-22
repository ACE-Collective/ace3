import pytest

from saq.analysis.root import RootAnalysis
from saq.constants import F_FQDN, F_IP, F_URI_PATH, F_URL, AnalysisExecutionResult
from saq.modules.config import AnalysisModuleConfig
from saq.modules.url.parser import ParseURLAnalysis, ParseURLAnalyzer
from tests.saq.test_util import create_test_context


def analyze(value: str) -> ParseURLAnalysis:
    """Run ParseURLAnalyzer against a url observable with the given value."""
    root = RootAnalysis()
    observable = root.add_observable_by_spec(F_URL, value)
    analyzer = ParseURLAnalyzer(
        context=create_test_context(root=root),
        config=AnalysisModuleConfig(
            name="test_parse_url",
            python_module="saq.modules.url.parser",
            python_class="ParseURLAnalyzer",
            enabled=True,
        ),
    )

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(ParseURLAnalysis)
    assert isinstance(analysis, ParseURLAnalysis)
    return analysis


def observable_values(analysis: ParseURLAnalysis, observable_type: str) -> list[str]:
    return [o.value for o in analysis.observables if o.type == observable_type]


@pytest.mark.unit
def test_full_url():
    analysis = analyze("https://www.yahoo.com/login?user=a%20b#top")

    assert analysis.scheme == "https"
    assert analysis.netloc == "www.yahoo.com"
    assert analysis.path == "/login"
    assert analysis.query == "user=a%20b"
    assert analysis.fragment == "top"
    assert observable_values(analysis, F_FQDN) == ["www.yahoo.com"]
    assert observable_values(analysis, F_URI_PATH) == ["/login?user=a%20b#top"]


@pytest.mark.unit
def test_domain_only():
    analysis = analyze("yahoo.com")

    assert analysis.scheme == ""
    assert analysis.netloc == "yahoo.com"
    assert analysis.path == ""
    fqdn = [o for o in analysis.observables if o.type == F_FQDN]
    assert [o.value for o in fqdn] == ["yahoo.com"]
    assert fqdn[0].has_tag("domain_in_url")
    # the domain is not a path
    assert observable_values(analysis, F_URI_PATH) == []


@pytest.mark.unit
@pytest.mark.parametrize("value,netloc,fqdn,uri_path", [
    ("yahoo.com/login?user=a", "yahoo.com", "yahoo.com", "/login?user=a"),
    ("yahoo.com:8080/login", "yahoo.com:8080", "yahoo.com", "/login"),
    ("//www.yahoo.com/login", "www.yahoo.com", "www.yahoo.com", "/login"),
])
def test_no_scheme(value, netloc, fqdn, uri_path):
    analysis = analyze(value)

    assert analysis.scheme == ""
    assert analysis.netloc == netloc
    assert observable_values(analysis, F_FQDN) == [fqdn]
    assert observable_values(analysis, F_URI_PATH) == [uri_path]


@pytest.mark.unit
def test_ip_only():
    analysis = analyze("1.2.3.4/payload.exe")

    assert analysis.netloc == "1.2.3.4"
    ip = [o for o in analysis.observables if o.type == F_IP]
    assert [o.value for o in ip] == ["1.2.3.4"]
    assert ip[0].has_tag("ip_in_url")
    assert observable_values(analysis, F_FQDN) == []
    assert observable_values(analysis, F_URI_PATH) == ["/payload.exe"]


@pytest.mark.unit
@pytest.mark.parametrize("value,scheme,path", [
    # no valid TLD, so nothing says the first segment is a host
    ("notadomain", "", "notadomain"),
    ("report.notatld", "", "report.notatld"),
    ("/just/a/path", "", "/just/a/path"),
    # a real scheme is left alone
    ("mailto:someone@yahoo.com", "mailto", "someone@yahoo.com"),
])
def test_not_a_host(value, scheme, path):
    analysis = analyze(value)

    assert analysis.scheme == scheme
    assert analysis.netloc == ""
    assert analysis.path == path
    assert observable_values(analysis, F_FQDN) == []
    assert observable_values(analysis, F_IP) == []
