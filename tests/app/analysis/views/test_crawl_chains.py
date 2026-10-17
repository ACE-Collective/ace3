import pytest
from flask import url_for

from saq.constants import F_URL
from saq.database.util.alert import ALERT
from saq.modules.phishkit import PhishkitAnalysis

START = "https://login.example.com/authorize?client_id=x&prompt=none"
REDIRECT = "https://redirect.example.net/css/?error=interaction_required&state=x"
LANDING = "https://landing.example.org/?email=user%40example.com"
HOSTILE = "https://hostile.example.org/?q=<script>alert(1)</script>"


@pytest.mark.integration
def test_alert_page_shows_crawl_chain(web_client, root_analysis, tmp_path):
    target = root_analysis.add_observable_by_spec(F_URL, START)
    analysis = PhishkitAnalysis()
    target.add_analysis(analysis)
    analysis.metrics = {
        "navigation": [
            {"url": START, "via": "start", "status": 200, "error": None, "route": "direct"},
            {"url": REDIRECT, "via": "redirect", "status": 200, "error": None, "route": "direct"},
            {"url": HOSTILE, "via": "script", "status": 302, "error": None, "route": "direct"},
            {"url": LANDING, "via": "redirect", "status": 404,
             "error": "net::ERR_HTTP_RESPONSE_CODE_FAILURE", "route": "direct"},
        ],
        "document_url": "chrome-error://chromewebdata/",
    }
    analysis.proxy_status = {
        "configured": True, "final_route": "direct", "fallback_triggered": True,
        "fallback_reason": "error_pattern",
        "fallback_details": {"matched_error_patterns": ["ERR_TUNNEL_CONNECTION_FAILED"], "failed_url": START},
    }
    landing = analysis.add_observable_by_spec(F_URL, LANDING)
    screenshot_path = tmp_path / "screenshot.png"
    screenshot_path.write_bytes(b"\x89PNG\r\n\x1a\n")
    screenshot = analysis.add_file_observable(str(screenshot_path), "phishkit/job/screenshot.png")
    root_analysis.save()
    ALERT(root_analysis)

    # the view reads the root back from disk, so the chain comes from the saved analysis details
    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    start = result.text.index('id="collapse_crawl_chains"')
    card = result.text[start:result.text.index("final page:", start) + 100]
    assert f'href="#{target.uuid}"' in card
    assert f'href="#{landing.uuid}"' in card
    assert f'href="#{screenshot.uuid}"' in card
    assert "direct: the proxy refused login.example.com" in card
    assert "HTTP redirect" in card
    assert "net::ERR_HTTP_RESPONSE_CODE_FAILURE" in card
    assert "final page: Chrome&#39;s error page" in card
    # a hop's URL is the attacker's text
    assert "<script>alert(1)</script>" not in result.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in card


@pytest.mark.integration
def test_alert_page_without_crawls_has_no_card(web_client, root_analysis):
    root_analysis.add_observable_by_spec(F_URL, START)
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    assert "collapse_crawl_chains" not in result.text
