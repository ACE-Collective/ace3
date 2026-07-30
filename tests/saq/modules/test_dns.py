"""Unit tests for ``saq.modules.dns``.

Every DNS outcome is exercised with a faked resolver. The point of most of these is that a negative
answer must still produce an analysis object carrying a status — silently producing nothing is what
made "this domain does not exist" invisible to an analyst.
"""

from unittest.mock import MagicMock, patch

import dns.rdatatype
import dns.resolver
import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_FQDN_ANALYZER,
    AnalysisExecutionResult,
    F_FQDN,
    F_IP,
)
from saq.modules.dns import (
    STATUS_DNS_ERROR,
    STATUS_NO_ANSWER,
    STATUS_NXDOMAIN,
    STATUS_OK,
    WILDCARD_PROBE_LABEL,
    FQDNAnalysis,
    FQDNAnalyzer,
)
from tests.saq.helpers import create_root_analysis


def _a_answer(addresses, cnames=()):
    """A stand-in for a dnspython A answer, including the CNAME chain in .response.answer."""
    answer = MagicMock()
    answer.__iter__ = lambda self: iter([MagicMock(address=a) for a in addresses])
    rrsets = []
    for target in cnames:
        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.CNAME
        rrset.__getitem__ = lambda self, i, _t=target: MagicMock(target=_t)
        rrsets.append(rrset)
    a_rrset = MagicMock()
    a_rrset.rdtype = dns.rdatatype.A
    rrsets.append(a_rrset)
    answer.response.answer = rrsets
    return answer


def _mx_answer(exchanges):
    answer = MagicMock()
    answer.__iter__ = lambda self: iter([MagicMock(exchange=e) for e in exchanges])
    return answer


def _analyzer(test_context, root):
    analyzer = FQDNAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_FQDN_ANALYZER),
    )
    analyzer.root = root
    return analyzer


def _run(test_context, value, side_effect):
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, value)
    analyzer = _analyzer(test_context, root)
    resolver = MagicMock()
    resolver.resolve.side_effect = side_effect
    with patch.object(analyzer, "_resolver", return_value=resolver):
        result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    return observable.get_analysis(FQDNAnalysis), resolver


@pytest.mark.unit
def test_analysis_initial_state():
    analysis = FQDNAnalysis()
    assert analysis.status is None
    assert analysis.mx is None
    assert analysis.wildcard_dns is None
    assert analysis.generate_summary() is None


@pytest.mark.unit
def test_nxdomain_still_produces_analysis(test_context):
    analysis, _ = _run(test_context, "does-not-exist.example.com",
                       dns.resolver.NXDOMAIN())
    assert analysis is not None, "a non-existent domain must still produce an analysis"
    assert analysis.status == STATUS_NXDOMAIN
    assert "does not exist" in analysis.generate_summary()
    assert analysis.get_observable_by_type(F_IP) is None


@pytest.mark.unit
def test_dns_error_is_distinct_from_nxdomain(test_context):
    analysis, _ = _run(test_context, "broken.example.com", dns.resolver.NoNameservers())
    assert analysis.status == STATUS_DNS_ERROR
    assert "lookup failed" in analysis.generate_summary()


@pytest.mark.unit
def test_no_answer_on_apex_still_checks_mx(test_context):
    """A mail-only domain has no A record but does have MX -- both facts must survive."""
    def side_effect(name, rdtype):
        if rdtype == "A" and name == "mail-only.com":
            raise dns.resolver.NoAnswer()
        if rdtype == "MX":
            return _mx_answer(["mx1.mail-only.com."])
        raise dns.resolver.NXDOMAIN()

    analysis, _ = _run(test_context, "mail-only.com", side_effect)
    assert analysis.status == STATUS_NO_ANSWER
    assert analysis.mx == ["mx1.mail-only.com"]
    assert analysis.wildcard_dns is False
    assert "no A record" in analysis.generate_summary()


@pytest.mark.unit
def test_successful_resolution_preserves_existing_behaviour(test_context):
    def side_effect(name, rdtype):
        if rdtype == "A" and name == "www.example.com":
            return _a_answer(["93.184.216.34"], cnames=["example-cdn.net."])
        raise dns.resolver.NXDOMAIN()

    analysis, _ = _run(test_context, "www.example.com", side_effect)
    assert analysis.status == STATUS_OK
    assert analysis.all_resolutions == ["93.184.216.34"]
    assert analysis.resolution_count == 1
    assert analysis.aliaslist == ["example-cdn.net"]
    assert analysis.ip_address == "93.184.216.34"
    ip = analysis.get_observable_by_type(F_IP)
    assert ip is not None and ip.value == "93.184.216.34"


@pytest.mark.unit
def test_subdomain_does_not_get_mx_or_wildcard_lookups(test_context):
    """MX/wildcard are apex properties; a subdomain must not pay for them."""
    def side_effect(name, rdtype):
        if rdtype == "A" and name == "www.example.com":
            return _a_answer(["1.2.3.4"])
        raise AssertionError(f"unexpected lookup {name} {rdtype}")

    analysis, resolver = _run(test_context, "www.example.com", side_effect)
    assert analysis.mx is None
    assert analysis.wildcard_dns is None
    assert resolver.resolve.call_count == 1


@pytest.mark.unit
def test_apex_gets_mx_and_wildcard_lookups(test_context):
    def side_effect(name, rdtype):
        if rdtype == "A" and name == "example.com":
            return _a_answer(["1.2.3.4"])
        if rdtype == "MX":
            return _mx_answer(["mx2.example.com.", "mx1.example.com."])
        if name == f"{WILDCARD_PROBE_LABEL}.example.com":
            raise dns.resolver.NXDOMAIN()
        raise AssertionError(f"unexpected lookup {name} {rdtype}")

    analysis, _ = _run(test_context, "example.com", side_effect)
    assert analysis.mx == ["mx1.example.com", "mx2.example.com"], "MX should be sorted"
    assert analysis.wildcard_dns is False
    assert "mx (" in analysis.generate_summary()


@pytest.mark.unit
def test_wildcard_detected_when_impossible_name_resolves(test_context):
    def side_effect(name, rdtype):
        if rdtype == "MX":
            raise dns.resolver.NoAnswer()
        return _a_answer(["185.150.189.123"])

    analysis, _ = _run(test_context, "parked.com", side_effect)
    assert analysis.wildcard_dns is True
    assert analysis.mx == []
    summary = analysis.generate_summary()
    assert "WILDCARD DNS" in summary
    assert "no mx" in summary


@pytest.mark.unit
@pytest.mark.parametrize("fqdn,expected", [
    ("example.com", True),
    ("www.example.com", False),
    ("example.co.uk", True),
    ("mail.example.co.uk", False),
    ("example.com.sg", True),
    ("example.co.id", True),
    ("mail.example.com.sg", False),
])
def test_registrable_apex_detection(test_context, fqdn, expected):
    """Multi-label public suffixes must not be mistaken for subdomains."""
    root = create_root_analysis()
    root.initialize_storage()
    assert _analyzer(test_context, root)._is_registrable_apex(fqdn) is expected
