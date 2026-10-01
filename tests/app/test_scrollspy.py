"""No page enables Bootstrap scrollspy, because no page has a table of contents for it to follow.

When its target is missing, scrollspy falls back to every link in the body and runs each URL
fragment through querySelector(). A fragment that is not a valid CSS selector -- a single page
app route, or an element id that starts with a digit, which is most uuids -- raises on page load.
"""

import pytest
from flask import url_for
from jinja2 import nodes

from saq.database.util.alert import ALERT

SCROLLSPY = 'data-bs-spy="scroll"'


def _body_attribs(app, template_name: str) -> str:
    """Renders the body_attribs block as the page sees it: the most derived definition in its extends chain."""
    env = app.jinja_env
    while template_name is not None:
        template = env.get_template(template_name)
        if "body_attribs" in template.blocks:
            return "".join(template.blocks["body_attribs"](template.new_context()))

        source, _, _ = env.loader.get_source(env, template_name)
        extends = env.parse(source).find(nodes.Extends)
        template_name = extends.template.value if extends is not None else None

    return ""


@pytest.mark.integration
def test_events_page_does_not_enable_scrollspy(app):
    assert SCROLLSPY not in _body_attribs(app, "events/index.html")


@pytest.mark.integration
def test_alert_page_does_not_enable_scrollspy(web_client, root_analysis):
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index", direct=root_analysis.uuid))

    assert result.status_code == 200
    assert "<body" in result.text
    assert SCROLLSPY not in result.text
