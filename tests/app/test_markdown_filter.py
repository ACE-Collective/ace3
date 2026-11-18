import pytest

from markupsafe import Markup

from app.application import render_markdown


@pytest.mark.unit
def test_render_markdown_returns_markup():
    result = render_markdown("hello")
    assert isinstance(result, Markup)


@pytest.mark.unit
def test_render_markdown_table():
    table = "| A | B |\n|---|---|\n| 1 | 2 |"
    result = render_markdown(table)
    assert "<table>" in result
