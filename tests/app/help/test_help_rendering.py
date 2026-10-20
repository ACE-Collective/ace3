import pytest

from app.help.rendering import render_markdown_guide

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
