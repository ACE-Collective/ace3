"""Grouping a correlated hunt alert's top-level observables by the hunt step that found them."""

import logging
from types import SimpleNamespace

import pytest
from flask import url_for

from app.analysis.views import index as index_view
from app.analysis.views.index import PROVENANCE_PALETTE, build_provenance_groups
from saq.database.model import User
from tests.saq.helpers import insert_alert

STEPS = [
    {"index": 0, "label": "Initial Query", "property_name": None},
    {"index": 1, "label": "user agents", "property_name": "correlate_user_agents"},
    {"index": 2, "label": "logons", "property_name": "correlate_logons"},
]


def _root(provenance):
    return SimpleNamespace(details={"hunt_provenance": provenance} if provenance is not None else {})


@pytest.mark.unit
@pytest.mark.parametrize("provenance", [None, {}, {"steps": [], "observables": {"a": [0]}}])
def test_no_provenance_means_no_groups(provenance):
    assert build_provenance_groups(_root(provenance)) is None


@pytest.mark.unit
def test_details_that_are_not_set():
    assert build_provenance_groups(SimpleNamespace(details=None)) is None


@pytest.mark.unit
def test_observables_are_grouped_by_the_steps_that_found_them():
    groups = build_provenance_groups(_root({
        "steps": STEPS,
        "observables": {
            "initial-only": [0],
            "pivot": [1, 0],
            "agent": [1],
            "agent-2": [1],
            "everywhere": [0, 1, 2],
            "logon-and-agent": [2, 1],
            # a step the hunt no longer has
            "orphan": [7],
        },
    }))

    by_key = {group["key"]: group for group in groups}
    assert list(by_key) == ["0", "0-1", "0-1-2", "1", "1-2"]

    initial = by_key["0"]
    assert (initial["label"], initial["full_label"], initial["sublabel"]) == ("Initial Query", "Initial Query", None)
    assert initial["observable_uuids"] == {"initial-only"}
    assert initial["colors"] == [PROVENANCE_PALETTE[0]]
    assert initial["trace_steps"] == []
    assert initial["anchor_id"] == "provenance-group-0"

    agent = by_key["1"]
    assert agent["label"] == "Correlated: user agents"
    assert agent["observable_uuids"] == {"agent", "agent-2"}
    assert agent["trace_steps"] == [{"index": 1, "label": "user agents", "property_name": "correlate_user_agents"}]

    # the pivot value the hunt correlated on
    pivot = by_key["0-1"]
    assert pivot["label"] == "Found by Both Steps"
    assert pivot["full_label"] == "Initial Query  +  Correlated: user agents"
    assert pivot["sublabel"].startswith("returned by both the initial query and this correlated step")
    assert pivot["colors"] == [PROVENANCE_PALETTE[0], PROVENANCE_PALETTE[1]]
    assert pivot["steps"] == [0, 1]

    # two correlated steps, neither the initial query
    both_correlated = by_key["1-2"]
    assert both_correlated["label"] == "Found by Both Steps"
    assert both_correlated["sublabel"] == "returned by multiple hunt steps: Correlated: user agents + Correlated: logons"
    assert [step["index"] for step in both_correlated["trace_steps"]] == [1, 2]

    everywhere = by_key["0-1-2"]
    assert everywhere["label"] == "Found by Multiple Steps"
    assert everywhere["sublabel"].startswith("returned by multiple hunt steps: Initial Query + ")


@pytest.mark.unit
def test_only_unknown_steps_means_no_groups():
    assert build_provenance_groups(_root({"steps": STEPS, "observables": {"orphan": [7]}})) is None


@pytest.mark.integration
def test_alert_page_retries_listing_the_users_after_a_rollback(web_client, monkeypatch, caplog):
    alert = insert_alert()
    real_get_db = index_view.get_db
    failures = []

    class FirstUserQueryFails:
        def __getattr__(self, name):
            return getattr(real_get_db(), name)

        def query(self, *entities, **kwargs):
            if entities == (User,) and not failures:
                failures.append(entities)
                raise RuntimeError("the session's transaction was already rolled back")
            return real_get_db().query(*entities, **kwargs)

    monkeypatch.setattr(index_view, "get_db", FirstUserQueryFails)

    with caplog.at_level(logging.ERROR):
        response = web_client.get(url_for("analysis.index", direct=alert.uuid))

    assert response.status_code == 200
    assert failures
    [record] = [r for r in caplog.records if "unable to list the users for alert" in r.getMessage()]
    assert alert.uuid in record.getMessage()
    assert record.exc_info is not None
