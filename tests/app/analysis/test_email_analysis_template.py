import pytest

from saq.configuration.config import get_config
from saq.modules.email.constants import KEY_DELIVERIES, KEY_EMAIL, KEY_MESSAGE_ID
from saq.modules.email.rfc822 import EmailAnalysis, EmailAnalysisPresenter


def _render(app, email: dict) -> str:
    analysis = EmailAnalysis()
    analysis.details[KEY_EMAIL] = email
    presenter = EmailAnalysisPresenter(analysis)
    template = app.jinja_env.get_template(presenter.template_path)
    return template.render(analysis=analysis, analysis_presenter=presenter, ace_config=get_config())


@pytest.mark.integration
def test_delivered_to_row_lists_mailboxes_and_notes_the_others(app):
    html = _render(app, {
        KEY_MESSAGE_ID: "<m@x>",
        KEY_DELIVERIES: {
            "manager@x": {"reason": "delivered", "mailboxes": ["manager@x"]},
            "former<b>@x": {"reason": "forwarded", "mailboxes": ["manager@x"]},
        },
    })

    assert "Delivered to" in html
    assert "manager@x" in html
    # addresses come from the message, so they are escaped
    assert "former&lt;b&gt;@x: not delivered to this address; forwarded to manager@x" in html
    assert "<b>@x" not in html


@pytest.mark.integration
def test_no_delivered_to_row_without_a_journal(app):
    html = _render(app, {KEY_MESSAGE_ID: "<m@x>"})

    assert "Delivered to" not in html
