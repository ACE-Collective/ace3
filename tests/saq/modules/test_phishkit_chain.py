import pytest

from saq.analysis.root import RootAnalysis
from saq.constants import F_URL
from saq.modules.phishkit import PhishkitAnalysis
from saq.modules.phishkit_chain import build_crawl_chains, describe_route, display_url

START = "https://login.example.com/authorize?client_id=x&prompt=none"
REDIRECT = "https://redirect.example.net/css/?error=interaction_required&state=x"
LANDING = "https://landing.example.org/?email=user%40example.com"

PROXIED = {"configured": True, "final_route": "proxy", "fallback_triggered": False,
           "fallback_reason": None, "fallback_details": {}}


def _hop(url, via="script", status=200, error=None, route="direct"):
    return {"url": url, "via": via, "status": status, "error": error, "route": route}


def _scan(target, navigation, proxy_status=None, document_url=None):
    analysis = PhishkitAnalysis()
    target.add_analysis(analysis)
    analysis.metrics = {"navigation": navigation, "document_url": document_url}
    analysis.proxy_status = proxy_status
    return analysis


def _lure_navigation():
    return [
        _hop(START, via="start"),
        _hop(REDIRECT, via="redirect", route="proxy"),
        _hop(LANDING, status=404, error="net::ERR_HTTP_RESPONSE_CODE_FAILURE", route="proxy"),
    ]


@pytest.mark.unit
def test_hops_link_to_their_observables():
    root = RootAnalysis()
    target = root.add_observable_by_spec(F_URL, START)
    analysis = _scan(target, _lure_navigation(), proxy_status=PROXIED)
    redirect = analysis.add_observable_by_spec(F_URL, REDIRECT)
    landing = analysis.add_observable_by_spec(F_URL, LANDING)

    chains = build_crawl_chains(root)

    assert len(chains) == 1
    chain = chains[0]
    assert chain.target is target
    assert chain.route == "via proxy"
    assert chain.show_routes is True
    assert [hop.observable for hop in chain.hops] == [target, redirect, landing]
    assert [hop.via_label for hop in chain.hops] == ["start", "HTTP redirect", "script"]
    assert [hop.route for hop in chain.hops] == ["direct", "proxy", "proxy"]
    assert [hop.failed for hop in chain.hops] == [False, False, True]
    assert chain.hops[2].error == "net::ERR_HTTP_RESPONSE_CODE_FAILURE"


@pytest.mark.unit
def test_hop_not_in_the_tree_has_no_link():
    root = RootAnalysis()
    target = root.add_observable_by_spec(F_URL, START)
    _scan(target, _lure_navigation())

    hops = build_crawl_chains(root)[0].hops
    assert hops[0].observable is target
    assert hops[1].observable is None
    assert hops[2].observable is None


@pytest.mark.unit
@pytest.mark.parametrize("metrics", [
    None,
    {"document_url": START},           # recorded before the scanner wrote "navigation"
    {"navigation": [], "document_url": START},
])
def test_scan_without_navigation_is_left_out(metrics):
    root = RootAnalysis()
    target = root.add_observable_by_spec(F_URL, START)
    analysis = PhishkitAnalysis()
    target.add_analysis(analysis)
    analysis.metrics = metrics

    assert build_crawl_chains(root) == []


@pytest.mark.unit
def test_bad_scan_is_skipped_not_raised():
    root = RootAnalysis()
    bad_target = root.add_observable_by_spec(F_URL, "https://bad.example.com/")
    _scan(bad_target, ["not a hop"])
    target = root.add_observable_by_spec(F_URL, START)
    _scan(target, _lure_navigation())

    chains = build_crawl_chains(root)
    assert [chain.target for chain in chains] == [target]


@pytest.mark.unit
@pytest.mark.parametrize("document_url,expected", [
    ("chrome-error://chromewebdata/", "Chrome's error page"),
    (LANDING, None),
    (None, None),
    (LANDING + "#user@example.com", "landing.example.org/?email=user%40example.com#user@example.com"),
])
def test_final_page(document_url, expected):
    root = RootAnalysis()
    target = root.add_observable_by_spec(F_URL, START)
    _scan(target, _lure_navigation(), document_url=document_url)

    assert build_crawl_chains(root)[0].final_page == expected


@pytest.mark.unit
@pytest.mark.parametrize("proxy_status,expected", [
    (None, "direct"),
    ({"configured": False, "final_route": "none"}, "direct"),
    (PROXIED, "via proxy"),
    ({"configured": True, "final_route": "direct", "fallback_reason": "error_pattern",
      "fallback_details": {"matched_error_patterns": ["ERR_TUNNEL_CONNECTION_FAILED"], "failed_url": START}},
     "direct: the proxy refused login.example.com"),
    ({"configured": True, "final_route": "direct", "fallback_reason": "error_pattern",
      "fallback_details": {"matched_error_patterns": ["ERR_TUNNEL_CONNECTION_FAILED"]}},
     "direct: the proxy failed"),
    ({"configured": True, "final_route": "direct", "fallback_reason": "status_code",
      "fallback_details": {"matched_status_code": 502}},
     "direct: the proxy returned 502"),
    ({"configured": True, "final_route": "direct", "fallback_reason": "timeout", "fallback_details": {}},
     "direct: the proxy attempt timed out"),
])
def test_describe_route(proxy_status, expected):
    assert describe_route(proxy_status) == expected


@pytest.mark.unit
def test_routes_hidden_after_a_fallback():
    """Every hop of a direct retry went direct, which the chain's route already says."""
    root = RootAnalysis()
    target = root.add_observable_by_spec(F_URL, START)
    _scan(target, _lure_navigation(), proxy_status={
        "configured": True, "final_route": "direct", "fallback_reason": "timeout", "fallback_details": {}})

    assert build_crawl_chains(root)[0].show_routes is False


@pytest.mark.unit
def test_display_url():
    assert display_url("https://example.com/a") == "example.com/a"
    assert display_url("file:///phishkit/input/x.html") == "file:///phishkit/input/x.html"
    # cut in the middle, so URLs that differ only at the end still look different
    assert display_url("https://example.com/" + "a" * 200 + "&reload=1", max_len=30) == \
        "example.com/aaaaaaaa...a&reload=1"
