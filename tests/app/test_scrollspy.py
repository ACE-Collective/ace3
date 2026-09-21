"""Bootstrap scrollspy is enabled per page, by the page that has the table of contents it follows.

When its target is missing, scrollspy falls back to every link in the body and runs each URL
fragment through querySelector(). A fragment that is not a valid CSS selector -- a single page
app route, or an element id that starts with a digit, which is most uuids -- raises on page load.
"""

import pytest
from flask import url_for

from saq.database.util.alert import ALERT

SCROLLSPY = 'data-bs-spy="scroll"'


def _body_attribs(app, template_name: str) -> str:
    template = app.jinja_env.get_template(template_name)
    return "".join(template.blocks["body_attribs"](template.new_context()))


@pytest.mark.integration
def test_events_page_enables_scrollspy_on_its_table_of_contents(app):
    body_attribs = _body_attribs(app, "events/index.html")
    assert SCROLLSPY in body_attribs
    assert 'data-bs-target="#toc"' in body_attribs

    source, _, _ = app.jinja_env.loader.get_source(app.jinja_env, "events/index.html")
    assert 'id="toc"' in source


@pytest.mark.integration
def test_alert_page_does_not_enable_scrollspy(web_client, root_analysis):
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index", direct=root_analysis.uuid))

    assert result.status_code == 200
    assert "<body" in result.text
    assert SCROLLSPY not in result.text
