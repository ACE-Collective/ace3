import logging
import re
from types import SimpleNamespace

import pytest
from flask import render_template_string, url_for
from sqlalchemy.exc import OperationalError

from aceapi_v2.sync import run_async_with_session
from aceapi_v2.user_preferences import service
from aceapi_v2.user_preferences.schemas import PREFERENCE_KEY_ALERT_SECTIONS
from app.user_preferences import get_alert_sections_preference
from saq.configuration.config import get_config
from saq.constants import F_EMAIL_DELIVERY, F_URL
from saq.database.model import Remediation, RemediationHistory
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.database.util.user_management import add_user, delete_user
from saq.gui.alert import KEY_ALERT_TEMPLATE
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus

pytestmark = pytest.mark.integration


def _choose(user_id, sections):
    run_async_with_session(service.set_preference, user_id, PREFERENCE_KEY_ALERT_SECTIONS, {"sections": sections})


def _section(html, section_id):
    """The section's header and the opening tag of its body."""
    start = html.index(f'data-section-id="{section_id}"')
    body = re.compile(rf'<div class="alert-section-body" id="alert_section_{section_id}"[^>]*>').search(html, start)
    return html[start:body.end()]


def _is_open(section):
    return 'hidden="until-found"' not in section


def _alert_page(web_client, root_analysis):
    root_analysis.add_observable_by_spec(F_URL, "https://example.com/")
    root_analysis.add_detection_point("a hunt matched")
    root_analysis.add_summary_detail(header="Who", content="the summary detail text")
    root_analysis.save()
    ALERT(root_analysis)
    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})
    assert result.status_code == 200
    return result.text


def test_sections_start_the_site_way_without_a_choice(web_client, root_analysis, analyst):
    html = _alert_page(web_client, root_analysis)

    for section_id in ("detection_chains", "alert_details", "summary_details"):
        section = _section(html, section_id)
        assert _is_open(section), section_id
        assert 'aria-expanded="true"' in section
        assert "Open by default" in section
    assert "(1 detection)" in _section(html, "detection_chains")
    assert "(1)" in _section(html, "summary_details")
    # interesting_toggle.html shows and hides this card by its row id
    assert '<div class="row" id="interesting_observables_card" style="display: none;">' in html


def test_site_config_collapses_alert_details(web_client, root_analysis, analyst, monkeypatch):
    monkeypatch.setattr(get_config().gui, "alert_details_collapsed", True)

    section = _section(_alert_page(web_client, root_analysis), "alert_details")

    assert not _is_open(section)
    assert 'aria-expanded="false"' in section
    assert "Collapsed by default" in section


def test_analyst_choice_overrides_the_default(web_client, root_analysis, analyst, monkeypatch):
    monkeypatch.setattr(get_config().gui, "alert_details_collapsed", True)
    _choose(analyst, {"alert_details": True, "detection_chains": False})

    html = _alert_page(web_client, root_analysis)

    assert _is_open(_section(html, "alert_details"))
    detection_chains = _section(html, "detection_chains")
    assert not _is_open(detection_chains)
    assert "Collapsed by default" in detection_chains
    # collapsed, not removed: find-in-page still searches it
    assert "a hunt matched" in html[html.index('id="alert_section_detection_chains"'):]
    assert _is_open(_section(html, "summary_details"))


def test_another_analysts_choice_does_not_apply(web_client, root_analysis, analyst):
    other = add_user(username="jane", email="jane@localhost", display_name="jane", password="password")
    try:
        _choose(other.id, {"detection_chains": False})
        assert _is_open(_section(_alert_page(web_client, root_analysis), "detection_chains"))
    finally:
        delete_user("jane")


def test_preference_failure_falls_back_to_the_site_default(web_client, root_analysis, analyst, monkeypatch, caplog):
    _choose(analyst, {"detection_chains": False})

    def _broken_db():
        raise OperationalError("SELECT", {}, Exception("database is gone"))

    monkeypatch.setattr("app.user_preferences.get_db", _broken_db)
    with caplog.at_level(logging.ERROR):
        html = _alert_page(web_client, root_analysis)

    assert _is_open(_section(html, "detection_chains"))
    assert any(record.levelno == logging.ERROR
               and f"reading the alert_sections preference of user {analyst}" in record.getMessage()
               for record in caplog.records)


def test_preference_is_read_once_per_page(web_client, root_analysis, analyst, monkeypatch):
    reads = []

    def _counting_read():
        reads.append(1)
        return get_alert_sections_preference()

    monkeypatch.setattr("app.application.get_alert_sections_preference", _counting_read)
    html = _alert_page(web_client, root_analysis)

    assert html.count('class="card mb-3 alert-section"') >= 4
    assert len(reads) == 1


def test_every_card_is_a_section(web_client, root_analysis, analyst, monkeypatch):
    """The cards that need data a plain alert does not have, rendered from stand-ins."""
    # an email ACE removed, which the remediation timeline reads from remediation_history
    delivery = root_analysis.add_observable_by_spec(F_EMAIL_DELIVERY, "<message-id@example.com>|user@example.com")
    remediation = Remediation(name="email", type=F_EMAIL_DELIVERY, key=delivery.value,
                              action=RemediationAction.REMOVE.value,
                              user_id=get_config().global_settings.automation_user_id,
                              status=RemediationStatus.COMPLETED.value)
    get_db().add(remediation)
    get_db().flush()
    get_db().add(RemediationHistory(remediation_id=remediation.id, result=RemediatorStatus.SUCCESS.value,
                                    message="removed", status=RemediationStatus.COMPLETED.value))
    get_db().commit()
    monkeypatch.setattr("app.analysis.views.index.gather_clicker_results",
                        lambda root: SimpleNamespace(events=[], ran=True, errors=[]))
    root_analysis.details = {"correlation_trace": {"event_traces": []}}
    choices = {"remediation_timeline": False, "url_clicks": False, "correlation_trace": False}
    _choose(analyst, choices)

    html = _alert_page(web_client, root_analysis)

    assert "(1 event)" in _section(html, "remediation_timeline")
    assert "(no clicks found)" in _section(html, "url_clicks")
    # the trace's own buttons stay in its header, where its script looks for them
    assert "ct-expand-all" in _section(html, "correlation_trace")
    for section_id in choices:
        assert not _is_open(_section(html, section_id)), section_id
    assert "Remove (Success)" in html


@pytest.mark.parametrize("template, details, section_ids", [
    ("analysis/custom/hunter_splunk.html",
     {"events": [{"host": {"name": "needle-host"}}], "query": "index=main | stats count by host"},
     ["splunk_query", "raw_splunk_details"]),
    ("analysis/custom/email_alert.html",
     {"email": {"headers": [["X-Needle", "needle-header"]]}},
     ["email_headers"]),
])
def test_custom_template_panels_are_collapsed_sections(web_client, root_analysis, analyst, template, details, section_ids):
    root_analysis.extensions = {KEY_ALERT_TEMPLATE: template}
    root_analysis.details = details

    html = _alert_page(web_client, root_analysis)

    # nested in the Alert Details section, which stays open
    assert _is_open(_section(html, "alert_details"))
    for section_id in section_ids:
        section = _section(html, section_id)
        assert not _is_open(section), section_id
        assert "Collapsed by default" in section
    assert 'data-bs-toggle="collapse"' not in html[html.index('id="alert_section_alert_details"'):html.index('id="analysis-overview-card"')]


def test_sections_a_loop_renders_get_their_own_ids(app):
    html = render_template_string(
        "{% from 'analysis/_alert_section.html' import alert_section with context %}"
        "{% for i in [1, 2] %}{% call alert_section('email_headers', 'Headers', instance=i) %}body {{ i }}{% endcall %}{% endfor %}")

    assert html.count('data-section-id="email_headers"') == 2
    for i in (1, 2):
        assert f'aria-controls="alert_section_email_headers_{i}"' in html
        assert f'id="alert_section_email_headers_{i}"' in html
