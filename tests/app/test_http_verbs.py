"""Regression guard: HTTP verb discipline in the Flask GUI.

Historically several GET endpoints mutated server-side state -- analysis/set_owner even
wrote to the database from a query string, so any prefetcher, link scanner, or <img> tag
could assign alert ownership. These tests pin the verb lists so a mutating endpoint cannot
quietly start accepting GET again. See docs/GUI_VERBS.md.
"""

import pytest

# Endpoints that mutate database or session state. GET must not reach them.
POST_ONLY_ENDPOINTS = [
    "analysis.set_owner",
    "analysis.set_sort_filter",
    "analysis.reset_filters",
    "analysis.select_filter",
    "analysis.revert_temp_filter",
    "analysis.remove_filter",
    "analysis.remove_filter_category",
    "analysis.toggle_prune",
    "analysis.toggle_prune_volatile",
    "analysis.search",
    "analysis.set_page_offset",
    "analysis.set_page_size",
    "auth.logout",
]

# Read-only endpoints that used to accept POST for no reason. Tightened so a mutation
# cannot be added later under an already-accepted verb.
GET_ONLY_ENDPOINTS = [
    "analysis.redirect_to",
    "analysis.download_file",
    "analysis.load_more_events",
    "analysis.new_alert_observable",
    "analysis.new_filter_option",
    "events.new_malware_option",
    "events.index",
    "main.index",
]


def _rules_for(app, endpoint):
    return [rule for rule in app.url_map.iter_rules() if rule.endpoint == endpoint]


@pytest.mark.integration
@pytest.mark.parametrize("endpoint", POST_ONLY_ENDPOINTS)
def test_mutating_endpoint_rejects_get(app, endpoint):
    rules = _rules_for(app, endpoint)
    assert rules, f"{endpoint} is not registered -- renamed or removed?"
    for rule in rules:
        assert "GET" not in rule.methods, f"{endpoint} ({rule.rule}) must not accept GET"


@pytest.mark.integration
@pytest.mark.parametrize("endpoint", GET_ONLY_ENDPOINTS)
def test_read_only_endpoint_rejects_post(app, endpoint):
    rules = _rules_for(app, endpoint)
    assert rules, f"{endpoint} is not registered -- renamed or removed?"
    for rule in rules:
        assert "POST" not in rule.methods, f"{endpoint} ({rule.rule}) must not accept POST"
