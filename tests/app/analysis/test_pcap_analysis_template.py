import pytest

from saq.modules.file_analysis.pcap import (
    CATEGORY_FILES,
    CATEGORY_HTTP,
    CATEGORY_TLS,
    JA4_NOTE,
    KEY_INDEX,
    PcapAnalysis,
    PcapAnalysisPresenter,
    PcapCategoryAnalysis,
)

# what a capture can carry in a request line
HOSTILE_URL = 'http://evil.example/"><script>alert(1)</script>'


def _render(app, analysis) -> str:
    template = app.jinja_env.get_template("analysis/pcap_analysis.html")
    return template.render(analysis_presenter=PcapAnalysisPresenter(analysis))


@pytest.mark.integration
def test_pivot_links_render_escaped(app):
    analysis = PcapCategoryAnalysis()
    analysis.details.update({"category": CATEGORY_HTTP, "total": 1,
                             "rows": [{"method": "GET", "url": HOSTILE_URL, "status": "200"}]})
    html = _render(app, analysis)

    assert 'class="pcap-pivot"' in html
    assert 'data-pivot-type="url"' in html
    # the value only ever appears escaped, in an attribute and as the link text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'data-pivot-value="http://evil.example/&#34;&gt;&lt;script&gt;' in html
    # one delegated handler, which reads the values from the data attributes
    assert html.count("click.pcapPivot") == 2


@pytest.mark.integration
def test_file_pivots_render(app):
    analysis = PcapCategoryAnalysis()
    analysis.details.update({"category": CATEGORY_FILES, "total": 1, "rows": [
        {"protocol": "http", "file_name": "payload.bin", "size": 7, "sha256": "ab" * 32, "url": HOSTILE_URL}]})
    html = _render(app, analysis)

    assert 'data-pivot-type="url" data-pivot-value="http://evil.example/&#34;&gt;&lt;script&gt;' in html
    assert "<script>alert(1)</script>" not in html

    assert f'data-pivot-type="file" data-pivot-value="{"ab" * 32}">payload.bin</a>' in html
    assert f'data-pivot-type="sha256" data-pivot-value="{"ab" * 32}">{"ab" * 32}</a>' in html


@pytest.mark.integration
def test_capture_header_and_order_note_render(app):
    analysis = PcapCategoryAnalysis()
    analysis.details.update({"category": CATEGORY_HTTP, "total": 1,
                             "rows": [{"method": "GET", "url": "http://a.example/"}],
                             "capture": {"file_name": "<b>x</b>.pcapng", "format": "pcapng", "packets": 3,
                                         "strict_time_order": True}})
    html = _render(app, analysis)

    assert "From capture" in html
    # the file name is escaped like anything else from the alert
    assert "<b>&lt;b&gt;x&lt;/b&gt;.pcapng</b> &middot; pcapng &middot; 3 packets" in html
    assert "Requests in the order they were sent, which is chronological." in html


@pytest.mark.integration
def test_no_capture_header_without_metadata(app):
    analysis = PcapCategoryAnalysis()
    analysis.details.update({"category": CATEGORY_HTTP, "total": 1, "rows": [{"method": "GET", "url": "http://a.example/"}]})
    assert "From capture" not in _render(app, analysis)


@pytest.mark.integration
def test_tls_note_renders(app):
    analysis = PcapCategoryAnalysis()
    analysis.details.update({"category": CATEGORY_TLS, "total": 1,
                             "rows": [{"server": "198.51.100.7:443", "sni": "a.example", "ja4": "t13_a", "certificates": []}]})
    assert JA4_NOTE in _render(app, analysis)


@pytest.mark.integration
def test_missing_statistics_notice_renders_escaped(app):
    analysis = PcapAnalysis()
    analysis.details[KEY_INDEX] = {"statistics": {}, "statistics_error": "tshark failed: <b>output</b>"}
    html = _render(app, analysis)
    assert "No endpoint or flow tables" in html
    assert "&lt;b&gt;output&lt;/b&gt;" in html
