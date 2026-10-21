import pytest

from saq.modules.file_analysis.pcap import CATEGORY_FILES, CATEGORY_HTTP, PcapAnalysisPresenter, PcapCategoryAnalysis

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
        {"protocol": "http", "file_name": "payload.bin", "size": 7, "sha256": "ab" * 32, "url": None}]})
    html = _render(app, analysis)

    assert f'data-pivot-type="file" data-pivot-value="{"ab" * 32}">payload.bin</a>' in html
    assert f'data-pivot-type="sha256" data-pivot-value="{"ab" * 32}">{"ab" * 32}</a>' in html
