import pytest
from flask import url_for

from saq.constants import F_EMAIL_ADDRESS, F_URL
from saq.database.util.alert import ALERT
from saq.modules.util.observable_modifier import ObservableModifierAnalysis

HOSTILE = "https://hostile.example.org/?q=<script>alert(1)</script>"


def _record_matches(observable, matched_rules):
    analysis = ObservableModifierAnalysis()
    observable.add_analysis(analysis)
    analysis.details["matched_rules"] = matched_rules
    analysis.matched_rules = matched_rules


def _card(text):
    start = text.index("Observable Modifier Rules")
    return text[start:text.index("</table>", start)]


@pytest.mark.integration
def test_alert_page_shows_ignored_observables(web_client, root_analysis):
    hidden = root_analysis.add_observable_by_spec(F_URL, HOSTILE)
    _record_matches(hidden, [{"name": "Ignore hostile", "uuid": "rule-1", "actions_applied": {"ignore": True}}])
    hidden.ignored = True
    # taken from one parent by a parent-scoped rule, still in the tree under another
    removed = root_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, "team@example.com")
    _record_matches(removed, [
        {"name": "Ignore team", "uuid": "rule-2", "actions_applied": {"ignore": True}},
        {"name": "Skip FQDN", "uuid": "rule-3", "actions_applied": {"exclude_analysis": ["x:Y"]}},
    ])
    root_analysis.save()
    ALERT(root_analysis)

    # the view reads the root back from disk, so the rules come from data.json
    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    # collapsed even when something was ignored: the badge in the header says so
    assert 'class="card-body collapse" id="collapse_observable_modifier_rules"' in result.text
    card = _card(result.text)
    assert "2 ignored" in card
    assert card.index("Ignore hostile") < card.index("Ignore team") < card.index("Skip FQDN")
    assert "hidden from the analysis tree" in card
    assert "team@example.com" in card
    assert "still shown elsewhere" in card
    # observable values are plain text, never links
    assert "<a " not in card.split("</h5>", 1)[1]
    assert "exclude_analysis" in card
    # an observable value is the attacker's text
    assert "<script>alert(1)</script>" not in result.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in card


@pytest.mark.integration
def test_alert_page_without_ignores_has_no_badge(web_client, root_analysis):
    url = root_analysis.add_observable_by_spec(F_URL, "https://example.com/")
    _record_matches(url, [{"name": "Crawl", "uuid": "rule-1", "actions_applied": {"add_directives": ["crawl"]}}])
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    card = _card(result.text)
    assert "ignored" not in card.split("</h5>")[0]
    assert "Crawl" in card
    assert "add_directives" in card


@pytest.mark.integration
def test_alert_page_without_matches_has_no_card(web_client, root_analysis):
    root_analysis.add_observable_by_spec(F_URL, "https://example.com/")
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    assert "collapse_observable_modifier_rules" not in result.text
