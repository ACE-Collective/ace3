import base64
import re

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.modules.file_analysis.yara import YaraScanResults_v3_4, YaraScanResults_v3_4_Presenter
from tests.saq.modules.test_yara import _rule, _scan, signature_dir, socket_dir, write_rules  # noqa: F401 (fixtures)


def _render(app, scan_result: dict) -> str:
    analysis = YaraScanResults_v3_4()
    analysis.scan_results = [scan_result]
    return _render_analysis(app, analysis)


def _render_analysis(app, analysis: YaraScanResults_v3_4) -> str:
    presenter = YaraScanResults_v3_4_Presenter(analysis)
    template = app.jinja_env.get_template(presenter.template_path)
    return template.render(analysis=analysis, analysis_presenter=presenter, ace_config=get_config())


# the context of a match on "world" at offset 7 of "Hello, world!\n"
HEXDUMP = "00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a        |Hello, world!.|\n0000000e\n"


RULE_TEXT = 'rule test_rule\n{\n    strings:\n        $a = "wor<ld" nocase\n    condition:\n        $a\n}\n'


def _scan_result(**kwargs) -> dict:
    result = {
        "target": "/opt/ace/data/<b>file</b>.txt",
        "rule": "test_rule",
        "meta": {"uuid": "d3f6c2a8-1b4e-4c55-9f3a-2e8b7c6d5a41", "description": "<script>x</script>"},
        "tags": [],
        "strings": [[7, "$a", "world"]],
        "context": [[7, "$a", "world", HEXDUMP]],
        "match_context": [{"data": base64.b64encode(b"Hello, world!\n").decode(), "match_offset": 7, "match_length": 5}],
        "string_patterns": {"$a": '"wor<ld" nocase'},
        "rule_source": {"file": "rules<1>.yar", "start_line": 12, "text": RULE_TEXT},
    }
    result.update(kwargs)
    return result


@pytest.mark.integration
def test_target_and_meta_are_monospaced_and_meta_is_pretty_json(app):
    html = _render(app, _scan_result())

    assert "<td><code>/opt/ace/data/&lt;b&gt;file&lt;/b&gt;.txt</code></td>" in html
    assert ('<pre class="mb-0 yara-meta">'
            '<span class="yara-meta-line">{</span>\n'
            '<span class="yara-meta-line">    &#34;description&#34;: &#34;&lt;script&gt;x&lt;/script&gt;&#34;,</span>\n'
            '<span class="yara-meta-line">    &#34;uuid&#34;: &#34;d3f6c2a8-1b4e-4c55-9f3a-2e8b7c6d5a41&#34;</span>\n'
            '<span class="yara-meta-line">}</span>\n'
            '</pre>') in html


@pytest.mark.integration
def test_string_match_shows_its_pattern(app):
    html = _render(app, _scan_result())
    assert "pattern <code>&#34;wor&lt;ld&#34; nocase</code>" in html


@pytest.mark.integration
def test_string_match_without_context_shows_its_pattern(app):
    result = _scan_result()
    del result["context"]
    html = _render(app, result)
    assert "pattern <code>&#34;wor&lt;ld&#34; nocase</code>" in html


@pytest.mark.integration
def test_result_saved_before_patterns_renders_without_them(app):
    result = _scan_result()
    del result["string_patterns"]
    html = _render(app, result)

    assert "value <b>world</b>" in html
    assert "pattern <code>" not in html


@pytest.mark.integration
def test_patterns_are_hidden_with_hide_intel(app, monkeypatch):
    monkeypatch.setattr(get_config().gui, "hide_intel", True)
    html = _render(app, _scan_result())

    assert "Hidden from public view." in html
    assert "pattern <code>" not in html


@pytest.mark.integration
def test_string_match_identifier_has_one_dollar(app):
    html = _render(app, _scan_result())
    assert "string <b>$a</b>" in html
    assert "$<b>$a</b>" not in html


@pytest.mark.integration
def test_string_match_value_shows_whitespace(app):
    result = _scan_result(context=[[12, "$nl", "!\n", HEXDUMP]], match_context=[], string_patterns={})
    html = _render(app, result)
    assert 'value <b>!<span class="yara-ws">\u240a</span></b>' in html


@pytest.mark.integration
@pytest.mark.parametrize("key", ["context", "strings"])
def test_string_match_values_past_the_cap_are_shown_plain(app, monkeypatch, key):
    monkeypatch.setattr("saq.modules.file_analysis.yara.MAX_HIGHLIGHTED_MATCHES", 1)
    matches = [[7, "$a", "a <b>", HEXDUMP], [9, "$a", "c <d>", HEXDUMP]]
    result = _scan_result(strings=[m[:3] for m in matches], match_context=[], string_patterns={})
    if key == "context":
        result["context"] = matches
    else:
        del result["context"]

    html = _render(app, result)

    assert 'value <b>a<span class="yara-sp"> </span>&lt;b&gt;</b>' in html
    assert "value <b>c &lt;d&gt;</b>" in html


@pytest.mark.integration
def test_string_match_hexdump_is_highlighted(app):
    html = _render(app, _scan_result())
    # the class that takes bootstrap's padding off the marks, which would misalign the columns
    assert '<pre class="yara-hexdump">00000000' in html
    assert ("00000000  48 65 6c 6c 6f 2c 20 <mark>77  6f 72 6c 64</mark> 21 0a        "
            "|Hello, <mark>world</mark>!.|") in html


@pytest.mark.integration
def test_meta_keeps_non_ascii_text(app):
    html = _render(app, _scan_result(meta={"description": "Zugangsdaten f\u00fcr Kunden"}))
    assert "Zugangsdaten f\u00fcr Kunden" in html


@pytest.mark.integration
def test_result_saved_before_match_context_shows_the_stored_dump(app):
    html = _render(app, _scan_result(match_context=None))
    hexdump = re.search(r'<pre class="yara-hexdump">(.*?)</pre>', html, re.S).group(1)
    assert hexdump.startswith("00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a        |Hello, world!.|")
    assert "<mark>" not in hexdump


@pytest.mark.integration
def test_scanned_saved_and_reloaded_result_renders(app, socket_dir, write_rules, root_analysis):
    """The view reads what a scan saved, after it went through the alert's JSON."""
    write_rules(_rule("reloaded_rule", strings='$a = "world" nocase'))
    observable = _scan(root_analysis, content=b"Hello, world!\n")
    root_analysis.save()

    reloaded = load_root(root_analysis.storage_dir)
    analysis = reloaded.get_observable(observable.uuid).get_and_load_analysis(YaraScanResults_v3_4)
    html = _render_analysis(app, analysis)

    assert "pattern <code>&#34;world&#34; nocase</code>" in html
    assert "|Hello, <mark>world</mark>!.|" in html
    assert "Show full rule" in html
    assert '<mark>        $a = &#34;world&#34; nocase</mark>' in html
    assert 'value <b>world</b>' in html


def _rule_view(html: str) -> str:
    """The id class the meta and the rule views share."""
    return re.search(r'data-bs-target="\.(yara_rule_[^"]+)"', html).group(1)


@pytest.mark.integration
def test_meta_is_shown_and_the_full_rule_is_one_click_away(app):
    html = _render(app, _scan_result())
    view = _rule_view(html)

    # meta is the view shown, the rule the one collapsed; both buttons swap the two
    assert f'<div class="collapse show {view}">' in html
    assert f'<div class="collapse {view}">' in html
    assert html.count(f'data-bs-target=".{view}"') == 2
    assert "Show full rule" in html and "Show meta" in html

    assert "rules&lt;1&gt;.yar, line 12" in html
    # numbered from the rule's line in its file
    assert 'style="counter-reset: yara-meta-line 11"' in html
    assert '<span class="yara-meta-line">rule test_rule</span>' in html
    # the declaration of the string that matched is marked
    assert '<span class="yara-meta-line"><mark>        $a = &#34;wor&lt;ld&#34; nocase</mark></span>' in html
    assert '<span class="yara-meta-line">        $a</span>' in html


@pytest.mark.integration
def test_rule_views_are_unique_per_rule(app):
    analysis = YaraScanResults_v3_4()
    analysis.scan_results = [_scan_result(), _scan_result(rule="other_rule")]
    html = _render_analysis(app, analysis)

    views = set(re.findall(r'data-bs-target="\.(yara_rule_[^"]+)"', html))
    assert len(views) == 2
    assert all(analysis.uuid in view for view in views)


@pytest.mark.integration
def test_without_rule_source_only_meta_is_shown(app):
    html = _render(app, _scan_result(rule_source=None))
    assert "Show full rule" not in html
    assert "<td>meta</td>" in html
    assert "yara-meta-line" in html


@pytest.mark.integration
def test_rule_source_is_hidden_with_hide_intel(app, monkeypatch):
    monkeypatch.setattr(get_config().gui, "hide_intel", True)
    html = _render(app, _scan_result())

    assert "Show full rule" not in html
    assert "rule test_rule" not in html
    # meta is still shown
    assert "&#34;uuid&#34;" in html
