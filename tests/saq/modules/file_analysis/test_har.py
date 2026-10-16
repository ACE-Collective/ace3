import base64
import json
import os

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_HAR_EXTRACTION,
    ANALYSIS_MODULE_HTML_JS_EXTRACTION,
    F_FILE,
    F_URL,
    R_DOWNLOADED_FROM,
    R_EXTRACTED_FROM,
    AnalysisExecutionResult,
)
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.file_type import FileTypeAnalysis
from saq.modules.file_analysis.har import (
    HARAnalysis,
    HARExtractor,
    HARResponse,
    get_har_responses,
    is_har_header,
)
from saq.modules.file_analysis.html_js_extraction import (
    HTMLJavaScriptExtractionAnalysis,
    HTMLJavaScriptExtractor,
)
from saq.modules.file_analysis.js import JavaScriptDeobfuscationAnalysis
from tests.saq.helpers import create_root_analysis
from tests.saq.modules.file_analysis.test_js import _build_analyzer, patched_deobfuscate  # noqa: F401
from tests.saq.test_util import create_test_context

PAGE_URL = "https://landing.example.com/start/#victim@example.com"
KIT_URL = "https://landing.example.com/start/kit.js"
CHUNK_URL = "https://cdn.example.com/assets/chunk.js"
NEXT_HOP = "https://next.example.com/collect"

# The kit reads its target out of an attribute of its own page, which is only
# there when the script runs against that page's DOM.
PAGE = (
    "<!DOCTYPE html><html><head>"
    '<script src="kit.js"></script>'
    "</head><body>"
    f'<div id="cfg" data-u="{base64.b64encode(NEXT_HOP.encode()).decode()}"></div>'
    "<script>var who = window.location.href.split('#')[1]; document.title = who;</script>"
    "</body></html>"
)
KIT = "var u = atob(document.getElementById('cfg').getAttribute('data-u')); window.location.href = u;"
CHUNK = "export function chunk() { return 1; }"


def _entry(url: str, mime_type: str, text: str | None = None, encoding: str | None = None,
           status: int = 200, size: int | None = None) -> dict:
    content = {"mimeType": mime_type, "size": size if size is not None else len(text or "")}
    if text is not None:
        content["text"] = text
    if encoding is not None:
        content["encoding"] = encoding
    return {
        "request": {"method": "GET", "url": url},
        "response": {"status": status, "content": content},
    }


def _har(entries: list[dict]) -> dict:
    return {"log": {"version": "1.2", "creator": {"name": "Firefox", "version": "140.0"}, "entries": entries}}


def _sample_har() -> dict:
    return _har([
        _entry(PAGE_URL, "text/html; charset=utf-8", PAGE),
        _entry(KIT_URL, "text/javascript", base64.b64encode(KIT.encode()).decode(), encoding="base64",
               size=len(KIT)),
        _entry("https://landing.example.com/logo.png", "image/png", "iVBORw0KGgo=", encoding="base64"),
        _entry(CHUNK_URL, "application/javascript", CHUNK),
        _entry("data:image/svg+xml,%3Csvg%3E%3C/svg%3E", "image/svg+xml", "<svg></svg>"),
    ])


def _add_har(root, har: dict | str, name: str = "session.har"):
    path = root.create_file_path(name)
    with open(path, "w") as fp:
        fp.write(har if isinstance(har, str) else json.dumps(har, indent=2))
    return root.add_file_observable(path)


def _extractor(root, **overrides):
    config = get_analysis_module_config(ANALYSIS_MODULE_HAR_EXTRACTION)
    if overrides:
        config = config.model_copy(update=overrides)
    analyzer = AnalysisModuleAdapter(HARExtractor(context=create_test_context(root=root), config=config))
    analyzer.root = root
    return analyzer


def _new_root():
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    return root


@pytest.mark.unit
def test_is_har_header():
    assert is_har_header(b'{\n  "log": {\n    "version": "1.2"')
    assert is_har_header(b'{"log":{}}')
    assert not is_har_header(b'{"data": {"log": []}}')
    assert not is_har_header(b"<!DOCTYPE html><html>")


@pytest.mark.unit
def test_get_har_responses_selects_decodes_and_dedupes():
    har = _sample_har()
    # the same body twice keeps the first
    har["log"]["entries"].append(_entry("https://cdn.example.com/assets/chunk-copy.js", "text/javascript", CHUNK))

    responses = get_har_responses(har)

    assert [(r.index, r.url) for r in responses] == [(0, PAGE_URL), (1, KIT_URL), (3, CHUNK_URL)]
    assert responses[0].mime_type == "text/html"
    assert responses[0].is_document
    assert responses[1].body == KIT.encode()
    assert not responses[1].is_document


@pytest.mark.unit
def test_get_har_responses_records_truncated_bodies():
    har = _har([_entry(CHUNK_URL, "application/javascript", CHUNK, size=len(CHUNK) * 100)])
    assert get_har_responses(har)[0].truncated


@pytest.mark.unit
def test_get_har_responses_tolerates_malformed_members():
    har = _har([
        "not an entry",
        {"request": ["not", "a", "dict"], "response": None},
        {"request": {"url": CHUNK_URL}, "response": {"content": "nope"}},
        _entry(CHUNK_URL, "application/javascript", "not base64!", encoding="base64"),
        _entry(KIT_URL, "text/javascript", KIT),
    ])
    assert [r.url for r in get_har_responses(har)] == [KIT_URL]
    assert get_har_responses({"log": "nope"}) == []
    assert get_har_responses([]) == []


@pytest.mark.unit
@pytest.mark.parametrize("url,mime_type,expected", [
    (PAGE_URL, "text/html", "007_start.html"),
    ("https://x.example.com/", "text/html", "007_x.example.com.html"),
    ("https://x.example.com/login.html?next=/a", "text/html", "007_login.html"),
    ("https://x.example.com/js/app.min.js", "application/javascript", "007_app.min.js"),
    ("https://x.example.com/oauth2/v2.0/authorize", "text/html", "007_authorize.html"),
    ("https://x.example.com/a%2Fb%20c", "text/html", "007_a_b_c.html"),
    ("https://x.example.com/icon", "image/svg+xml", "007_icon.svg"),
    ("file:///usr/share/web/homepage.html", "text/html", "007_homepage.html"),
])
def test_har_response_file_name(url, mime_type, expected):
    assert HARResponse(7, url, mime_type, 200, b"", False).file_name == expected


@pytest.mark.unit
def test_har_extraction():
    root = _new_root()
    har_obs = _add_har(root, _sample_har())

    assert _extractor(root).execute_analysis(har_obs) == AnalysisExecutionResult.COMPLETED

    analysis = har_obs.get_and_load_analysis(HARAnalysis)
    assert isinstance(analysis, HARAnalysis)
    assert analysis.error is None
    assert analysis.creator == "Firefox 140.0"
    assert analysis.entry_count == 5
    assert analysis.skipped_count == 0
    assert [r[HARAnalysis.KEY_URL] for r in analysis.responses] == [PAGE_URL, KIT_URL, CHUNK_URL]
    assert analysis.generate_summary() == (
        "HTTP Archive: extracted 1 pages and 2 scripts from 5 requests (Firefox 140.0)"
    )

    files = {o.file_name: o for o in analysis.observables if o.type == F_FILE}
    assert set(files) == {"000_start.html", "001_kit.js", "003_chunk.js"}
    for file_obs in files.values():
        assert os.path.dirname(file_obs.full_path) == har_obs.full_path + ".extracted"
        assert file_obs.get_relationship_by_type(R_EXTRACTED_FROM).target == har_obs

    with open(files["001_kit.js"].full_path) as fp:
        assert fp.read() == KIT

    # each file points at the URL the browser loaded it from
    page = files["000_start.html"]
    downloaded_from = page.get_relationship_by_type(R_DOWNLOADED_FROM)
    assert downloaded_from.target.type == F_URL
    assert downloaded_from.target.value == PAGE_URL
    assert {o.value for o in analysis.observables if o.type == F_URL} == {PAGE_URL, KIT_URL, CHUNK_URL}

    # the script the page loads runs against the page's DOM, at the page's URL
    with open(files["001_kit.js"].full_path + ".dom.json") as fp:
        snapshot = json.load(fp)
    assert snapshot["url"] == PAGE_URL
    assert any(e["attrs"].get("id") == "cfg" for e in snapshot["elements"])
    kit_record = analysis.responses[1]
    assert kit_record[HARAnalysis.KEY_LOADED_BY] == page.file_path

    # nothing loads the chunk from a page in this archive
    assert not os.path.exists(files["003_chunk.js"].full_path + ".dom.json")
    assert HARAnalysis.KEY_LOADED_BY not in analysis.responses[2]


@pytest.mark.unit
def test_har_extraction_limit_keeps_pages_first():
    root = _new_root()
    har = _har([
        _entry(CHUNK_URL, "application/javascript", CHUNK),
        _entry(KIT_URL, "text/javascript", KIT),
        _entry(PAGE_URL, "text/html", PAGE),
    ])
    har_obs = _add_har(root, har)

    _extractor(root, max_extracted_files=2).execute_analysis(har_obs)

    analysis = har_obs.get_and_load_analysis(HARAnalysis)
    assert [r[HARAnalysis.KEY_URL] for r in analysis.responses] == [PAGE_URL, CHUNK_URL]
    assert analysis.skipped_count == 1
    assert analysis.generate_summary().endswith(", 1 more over the extraction limit")


@pytest.mark.unit
@pytest.mark.parametrize("content", [
    '{"data": [1, 2, 3]}',
    "<!DOCTYPE html><html><body><script>alert(1)</script></body></html>",
])
def test_non_har_files_are_ignored(content):
    root = _new_root()
    obs = _add_har(root, content, name="not_a.har")

    assert _extractor(root).execute_analysis(obs) == AnalysisExecutionResult.COMPLETED
    assert obs.get_analysis(HARAnalysis) is None


@pytest.mark.unit
def test_detected_by_content_not_extension():
    root = _new_root()
    obs = _add_har(root, _sample_har(), name="archive.json")

    _extractor(root).execute_analysis(obs)
    assert len(obs.get_and_load_analysis(HARAnalysis).responses) == 3


@pytest.mark.unit
def test_invalid_har_reports_error():
    root = _new_root()
    obs = _add_har(root, '{"log": {"entries": [', name="truncated.har")

    _extractor(root).execute_analysis(obs)
    analysis = obs.get_and_load_analysis(HARAnalysis)
    assert analysis.error.startswith("not valid JSON")
    assert analysis.generate_summary().startswith("HTTP Archive: failed: not valid JSON")


@pytest.mark.unit
def test_oversized_har_reports_error():
    root = _new_root()
    obs = _add_har(root, _sample_har())

    _extractor(root, max_file_size=10).execute_analysis(obs)
    analysis = obs.get_and_load_analysis(HARAnalysis)
    assert "exceeds max_file_size 10" in analysis.error
    assert analysis.responses == []


@pytest.mark.unit
def test_html_js_extraction_skips_the_har_itself():
    """libmagic calls a HAR text/html; the pages inside it are JSON strings."""
    root = _new_root()
    obs = _add_har(root, _sample_har())
    file_type = FileTypeAnalysis()
    file_type.details = {"type": None, "mime": "text/html"}
    obs.add_analysis(file_type)

    extractor = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    extractor.root = root

    assert extractor.execute_analysis(obs) == AnalysisExecutionResult.COMPLETED
    assert obs.get_analysis(HTMLJavaScriptExtractionAnalysis) is None


@pytest.mark.unit
def test_har_to_deobfuscation_chain(patched_deobfuscate):  # noqa: F811
    """End-to-end: the page's inline script runs at the page's URL, and the
    script the page loads resolves its target out of the page's DOM."""
    root = _new_root()
    har_obs = _add_har(root, _sample_har())
    _extractor(root).execute_analysis(har_obs)
    files = {o.file_name: o for o in har_obs.get_and_load_analysis(HARAnalysis).observables if o.type == F_FILE}

    extractor = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    extractor.root = root
    page = files["000_start.html"]
    assert extractor.execute_analysis(page) == AnalysisExecutionResult.COMPLETED
    inline = [o for o in page.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis).observables if o.type == F_FILE]
    assert len(inline) == 1
    with open(inline[0].full_path + ".dom.json") as fp:
        assert json.load(fp)["url"] == PAGE_URL

    deob = _build_analyzer(root)
    kit = files["001_kit.js"]
    assert deob.execute_analysis(kit) == AnalysisExecutionResult.COMPLETED
    analysis = kit.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis.error is None
    assert analysis.dom_snapshot is True
    emitted = [o for o in analysis.observables if o.type == F_FILE]
    with open(emitted[0].full_path) as fp:
        assert f'location.href = "{NEXT_HOP}";' in fp.read()
