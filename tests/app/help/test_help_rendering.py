import os
import re

import pytest

from app.help.rendering import render_markdown_guide, render_markdown_playbook, render_playbook
from saq.configuration.config import get_config

pytestmark = pytest.mark.unit


def test_guide_links_drop_the_md_suffix():
    html = render_markdown_guide("[review](users.md#reviewing-a-run) [admin](administrators.md)").html
    assert 'href="users#reviewing-a-run"' in html
    assert 'href="administrators"' in html


def test_only_absolute_links_open_in_a_new_tab():
    html = render_markdown_guide("[out](https://example.com/x) [in](users.md) [here](#top)").html
    assert '<a href="https://example.com/x" rel="noopener noreferrer" target="_blank">' in html
    assert '<a href="users">' in html
    assert '<a href="#top">' in html


def test_github_alert_becomes_a_callout():
    html = render_markdown_guide("> [!WARNING]\n> Review sets SIMULATED.").html
    assert '<div class="help-callout help-callout-warning">' in html
    assert '<p class="help-callout-title">Warning</p>' in html
    assert "[!WARNING]" not in html
    assert "Review sets SIMULATED." in html


def test_plain_blockquote_is_left_alone():
    html = render_markdown_guide("> just a quote").html
    assert "<blockquote>" in html
    assert "help-callout" not in html


def test_image_links_to_its_full_size_file():
    html = render_markdown_guide("![The runs list](images/runs.png)").html
    assert '<a class="help-image" href="images/runs.png" target="_blank" title="Open the full-size image">' \
           '<img alt="The runs list" src="images/runs.png" /></a>' in html


def test_toc_holds_sections_and_subsections_only():
    rendered = render_markdown_guide("# Guide\n\n## First\n\n### Inner\n\n#### Deep\n\n## Second\n")
    assert [(e.id, e.name) for e in rendered.toc] == [("first", "First"), ("second", "Second")]
    assert [(e.id, e.children) for e in rendered.toc[0].children] == [("inner", ())]


# ---------------------------------------------------------------------------------------- playbooks

def _playbook(text: str):
    return render_markdown_playbook("p.md", text, "/pb/", "/assets/")


def test_playbook_frontmatter_gives_title_and_source():
    rendered = _playbook('---\ntitle: "OAuth phishing"\nsource_url: https://example.com/x/1\n---\n\n# OAuth phishing\n\nbody')
    assert rendered.title == "OAuth phishing"
    assert rendered.source_url == "https://example.com/x/1"
    assert "title:" not in rendered.html
    assert "<p>body</p>" in rendered.html


def test_playbook_without_frontmatter_is_titled_by_file_name():
    rendered = _playbook("# Heading\n\ntext")
    assert rendered.title == "p.md"
    assert rendered.source_url is None


def test_playbook_with_broken_frontmatter_still_renders():
    rendered = _playbook("---\ntitle: [unclosed\n---\ntext")
    assert rendered.title == "p.md"
    assert "<p>text</p>" in rendered.html


def test_playbook_raw_html_is_shown_as_text():
    html = _playbook("<script>alert(1)</script>\n\nlog in to <hostname> with <b>care</b>").html
    assert "<script>" not in html and "<b>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;hostname&gt;" in html


def test_playbook_unsafe_urls_are_dropped():
    html = _playbook("[a](javascript:alert(1)) [b](java\tscript:x) [c](data:text/html,x) ![d](vbscript:x)"
                     " [e](mailto:soc@example.com) [f](https://example.com)").html
    assert "javascript" not in html and "data:" not in html and "vbscript" not in html
    assert 'href="mailto:soc@example.com"' in html
    assert 'href="https://example.com"' in html


def test_playbook_links_and_images_are_rewritten():
    html = _playbook("[other](oauth-phishing.md#triage) ![shot](assets/p/one.png) [here](#top)").html
    assert 'href="/pb/oauth-phishing.md#triage"' in html
    assert 'src="/assets/p/one.png"' in html
    assert '<a class="help-image" href="/assets/p/one.png"' in html
    assert 'href="#top"' in html


def test_playbook_callout():
    html = _playbook("> [!NOTE]\n> read this").html
    assert '<div class="help-callout help-callout-note">' in html


@pytest.fixture
def playbooks_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_config().global_settings, "playbooks_dir", str(tmp_path))
    return tmp_path


def test_render_playbook_reads_the_named_file(playbooks_dir):
    (playbooks_dir / "oauth-phishing.md").write_text("---\ntitle: OAuth\n---\ntext")
    rendered = render_playbook("oauth-phishing.md", "/pb/", "/assets/")
    assert rendered.name == "oauth-phishing.md"
    assert rendered.title == "OAuth"


def test_render_playbook_rerenders_an_edited_file(playbooks_dir):
    path = playbooks_dir / "p.md"
    path.write_text("first")
    assert "first" in render_playbook("p.md", "/pb/", "/assets/").html
    path.write_text("second")
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000_000))
    assert "second" in render_playbook("p.md", "/pb/", "/assets/").html


def test_render_playbook_refuses_paths_and_missing_files(playbooks_dir):
    (playbooks_dir / "sub").mkdir()
    (playbooks_dir / "sub" / "p.md").write_text("x")
    (playbooks_dir.parent / "outside.md").write_text("x")
    for name in ("sub/p.md", "../outside.md", "/etc/passwd", "p.txt", "", "missing.md"):
        assert render_playbook(name, "/pb/", "/assets/") is None, name


def test_playbook_github_style_nested_lists_nest():
    html = _playbook("- parent\n  - child\n\n1. step\n   1. substep\n      - detail\n2. next").html
    shape = re.sub(r"\s+|</?p>", "", html)
    assert shape == ("<ul><li>parent<ul><li>child</li></ul></li></ul>"
                     "<ol><li>step<ol><li>substep<ul><li>detail</li></ul></li></ol></li><li>next</li></ol>")


def test_playbook_item_after_a_nested_list_is_back_at_its_own_level():
    html = _playbook("- parent:\n\n  - child\n  - child two\n- sibling\n  - its child\n    - grandchild\n  - back to child").html
    shape = re.sub(r"\s+|</?p>", "", html)
    assert shape == ("<ul><li>parent:<ul><li>child</li><li>childtwo</li></ul></li>"
                     "<li>sibling<ul><li>itschild<ul><li>grandchild</li></ul></li><li>backtochild</li></ul></li></ul>")


def test_playbook_fence_inside_a_step_is_a_code_block_in_that_step():
    html = _playbook("1. **Run the query.**\n\n   ```spl\n   index=x | stats count by user\n   ```\n\n   Read the count.\n2. Next").html
    item = re.search(r"<li>(.*?)</li>", html, re.S).group(1)
    assert "<pre><code>index=x | stats count by user\n</code></pre>" in item
    assert "Read the count." in item
    assert "```" not in html


def test_playbook_top_level_fence_is_left_alone():
    html = _playbook("```\n- not a list\n  1. nor this\n```").html
    assert "<pre><code>- not a list\n  1. nor this\n</code></pre>" in html


def test_playbook_markdown_cannot_add_attributes():
    html = _playbook("click{onclick=alert(1)}\n\n## head {: onmouseover=alert(1) }\n\n```{.x onclick=alert(1)}\ncode\n```").html
    # the attribute syntax stays as text; no tag carries an event handler
    assert not re.search(r"<[^>]+\son\w+=", html)
    assert "{: onmouseover=alert(1) }" in html


def test_playbook_table_alignment_survives_the_attribute_filter():
    html = _playbook("| a | b |\n|:-:|--:|\n| 1 | 2 |").html
    assert 'style="text-align: center;"' in html
    assert 'style="text-align: right;"' in html


def test_playbook_unclosed_fence_in_a_step_does_not_swallow_the_next_step():
    shape = re.sub(r"\s+|</?p>", "", _playbook("1. one\n\n   ```\n   query\n2. two\n\n## Next").html)
    assert "<li>two</li>" in shape
    assert "<h2>Next</h2>" in shape


def test_playbook_longer_closing_fence_closes_the_block():
    html = _playbook("```\ncode\n````\n\nafter").html
    assert "<pre><code>code\n</code></pre>" in html
    assert "<p>after</p>" in html


def test_render_playbook_refuses_a_symlink_out_of_the_directory(playbooks_dir, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.md"
    outside.write_text("secret")
    (playbooks_dir / "link.md").symlink_to(outside)
    assert render_playbook("link.md", "/pb/", "/assets/") is None
