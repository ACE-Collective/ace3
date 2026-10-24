import pytest
from flask import url_for

from saq.constants import F_URL
from saq.database.util.alert import ALERT
from saq.modules.email.lure import LureURLAnalysis
from saq.modules.file_analysis.url_extraction import URLExtractionAnalysis
from saq.modules.phishkit import PhishkitAnalysis

LURE = "https://evil.example.net/doc/view?id=1"
LANDING = "https://landing.example.org/login"
FOOTER = "https://www.example.com/unsubscribe?q=<script>alert(1)</script>"


def _candidate(observable, score, reasons, highlights=None):
    candidate = {"url": observable.value, "observable_uuid": observable.uuid, "score": score,
                 "sources": ["body"], "anchor_text": None, "reasons": reasons}
    # an analysis saved before highlights were recorded has none
    if highlights is not None:
        candidate["highlights"] = highlights
    return candidate


@pytest.mark.integration
def test_alert_page_shows_lure_url(web_client, root_analysis, tmp_path):
    email_path = tmp_path / "message.email.rfc822"
    email_path.write_text("From: billing@example.com\n\nhello")
    email_file = root_analysis.add_file_observable(str(email_path))
    # extracted URLs are volatile, which a pruned tree hides unless something reveals them
    extraction = URLExtractionAnalysis()
    email_file.add_analysis(extraction)
    lure = extraction.add_observable_by_spec(F_URL, LURE, volatile=True)
    footer = extraction.add_observable_by_spec(F_URL, FOOTER, volatile=True)

    analysis = LureURLAnalysis()
    email_file.add_analysis(analysis)
    analysis.primary = _candidate(
        lure, 90,
        ["found in attachment statement.pdf", "clickable link with text '<i>Review</i>'", "styled as a button"],
        [["statement.pdf"], ["<i>Review</i>"], []])
    analysis.candidates = [analysis.primary, _candidate(footer, -5, ["looks like a footer link (unsubscribe)"])]

    crawl = PhishkitAnalysis()
    lure.add_analysis(crawl)
    crawl.metrics = {"navigation": [
        {"url": LURE, "via": "start", "status": 302, "error": None, "route": "direct"},
        {"url": LANDING, "via": "redirect", "status": 200, "error": None, "route": "direct"},
    ]}
    screenshot_path = tmp_path / "screenshot.png"
    screenshot_path.write_bytes(b"\x89PNG\r\n\x1a\n")
    screenshot = crawl.add_file_observable(str(screenshot_path), "phishkit/job/screenshot.png")
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    start = result.text.index('id="alert_section_lure_urls"')
    card = result.text[start:result.text.index('class="card mb-3', start)]
    assert f'href="#{lure.uuid}"' in card
    # the whole URL, never shortened, and not bold
    assert f'href="#{lure.uuid}">{LURE}</a>' in card
    # the values a reason highlights are bold, and escaped: link text is the attacker's
    assert ("found in attachment <b>statement.pdf</b>; "
            "clickable link with text &#39;<b>&lt;i&gt;Review&lt;/i&gt;</b>&#39;; styled as a button") in card
    assert "<i>Review</i>" not in result.text
    # a candidate without highlights renders plain
    assert "looks like a footer link (unsubscribe)" in card
    # where the lure leads is the Crawl Chains section's to show
    assert "landing.example.org" not in card
    assert f'href="#{screenshot.uuid}"' not in card
    assert '<div class="small" style="word-break: break-all;">' in card
    assert "1 other candidate" in card
    assert f'href="#{footer.uuid}"' in card
    # the candidate URLs are the attacker's text
    assert "<script>alert(1)</script>" not in result.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in card
    # every link in the card has a node in the tree to jump to
    for observable in (lure, footer, screenshot):
        assert f'id="{observable.uuid}"' in result.text
    # the lure is marked in the tree too
    assert 'title="the URL this email lures its recipient to">lure</span>' in result.text


@pytest.mark.integration
def test_alert_page_without_lure_has_no_card(web_client, root_analysis):
    root_analysis.add_observable_by_spec(F_URL, LURE)
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    assert "alert_section_lure_urls" not in result.text
    assert "lures its recipient to" not in result.text
