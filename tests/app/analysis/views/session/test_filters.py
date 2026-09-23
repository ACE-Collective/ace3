"""Tests for the alert-management filter registry and sentinel resolution in
app.analysis.views.session.filters.

The config-driven quick-filter subsystem this module used to test is gone: quick filters
are per-user saved filters now, covered by tests/aceapi_v2/saved_filters/.
"""

from unittest.mock import MagicMock

import pytest

import app.analysis.views.session.filters as filters_mod
from app.analysis.views.session.filters import (
    getFilters,
    overlay_filters,
    resolve_filter_sentinels,
    resolve_saved_filter,
)
from saq.gui.filter_names import FILTER_NAMES


@pytest.mark.integration
def test_filter_names_match_get_filters():
    """FILTER_NAMES is what stored and URL-supplied filters are validated against; if it
    drifts from the actual filter registry then either a valid name gets rejected or an
    invalid one reaches the filter list and breaks /manage. (integration: SelectFilter
    queries the database for its options.)"""
    assert set(FILTER_NAMES) == set(getFilters())


@pytest.mark.integration
def test_filter_slugs_match_get_filters():
    """Every filter needs a URL slug and every slug needs a live filter -- in both
    directions. A filter with no slug cannot appear in a share link; a slug with no filter
    means published links point at nothing.

    Slugs are a PERMANENT contract: if this fails because a filter was renamed, add the new
    display name to FILTER_SLUGS and leave the old slug value alone. Repointing a slug
    silently redirects already-published links to different data."""
    from saq.gui.filter_names import FILTER_NAMES_BY_SLUG, FILTER_SLUGS

    assert set(FILTER_SLUGS) == set(getFilters())
    assert len(FILTER_NAMES_BY_SLUG) == len(FILTER_SLUGS), "two filters share a slug"


@pytest.mark.integration
def test_date_range_filter_names_are_actually_date_range_filters():
    """DATE_RANGE_FILTER_NAMES drives which values get run through the relative-time
    validator. If it drifts, a bad date token reaches the database unvalidated."""
    from app.filters import DateRangeFilter
    from saq.gui.filter_names import DATE_RANGE_FILTER_NAMES

    actual = {name for name, f in getFilters().items() if isinstance(f, DateRangeFilter)}
    assert actual == set(DATE_RANGE_FILTER_NAMES)



#
# sentinel resolution
#

@pytest.fixture
def fake_user(monkeypatch):
    user = MagicMock()
    user.queue = "their_queue"
    user.display_name = "Their Name"
    monkeypatch.setattr(filters_mod, "current_user", user)
    return user


@pytest.mark.unit
def test_resolves_user_sentinels(fake_user):
    assert resolve_filter_sentinels("$USER_QUEUE") == "their_queue"
    assert resolve_filter_sentinels("$USER") == "Their Name"


@pytest.mark.unit
def test_leaves_ordinary_values_alone(fake_user):
    assert resolve_filter_sentinels("default") == "default"
    assert resolve_filter_sentinels("-7d") == "-7d"


@pytest.mark.unit
def test_resolves_sentinels_inside_observable_pairs(fake_user):
    assert resolve_filter_sentinels(["email_address", "$USER"]) == ["email_address", "Their Name"]


@pytest.mark.unit
def test_sentinels_make_a_shared_link_adapt_to_the_viewer(fake_user):
    """This is why the sentinels survived the move off config: a runbook link written as
    queue:$USER_QUEUE shows each reader their OWN queue rather than the author's."""
    resolved = resolve_saved_filter([{"name": "Queue", "inverted": False, "values": ["$USER_QUEUE"]}])

    assert resolved == [{"name": "Queue", "inverted": False, "values": ["their_queue"]}]


@pytest.mark.unit
def test_merges_entries_sharing_name_and_inversion(fake_user):
    """Filter entries are ANDed together, so two separate Queue entries would match NOTHING
    rather than either queue. Merging them into one ORed entry is what makes a filter with
    repeated names behave the way it reads."""
    resolved = resolve_saved_filter([
        {"name": "Queue", "inverted": False, "values": ["a"]},
        {"name": "Queue", "inverted": False, "values": ["b"]},
    ])

    assert resolved == [{"name": "Queue", "inverted": False, "values": ["a", "b"]}]


@pytest.mark.unit
def test_does_not_merge_across_inversion(fake_user):
    resolved = resolve_saved_filter([
        {"name": "Tag", "inverted": False, "values": ["a"]},
        {"name": "Tag", "inverted": True, "values": ["b"]},
    ])

    assert len(resolved) == 2


@pytest.mark.unit
def test_missing_inverted_key_defaults_to_false(fake_user):
    assert resolve_saved_filter([{"name": "Queue", "values": ["a"]}])[0]["inverted"] is False


@pytest.mark.unit
def test_empty_input(fake_user):
    assert resolve_saved_filter([]) == []
    assert resolve_saved_filter(None) == []


#
# overlaying a pivot on the filter in effect
#

OPEN = {"name": "Disposition", "inverted": False, "values": ["OPEN"]}
QUEUE = {"name": "Queue", "inverted": False, "values": ["default"]}


def _observable(*values):
    return {"name": "Observable", "inverted": False, "values": [list(v) for v in values]}


@pytest.mark.unit
def test_overlay_keeps_every_entry_in_effect():
    assert overlay_filters([OPEN, QUEUE], [_observable(("ipv4", "1.2.3.4"))]) == [
        OPEN, QUEUE, _observable(("ipv4", "1.2.3.4"))]


@pytest.mark.unit
def test_overlay_narrows_a_filter_already_in_effect():
    """The clicked row matched the filter, so its owner is one of the owners allowed;
    replacing the entry narrows to it. Merging would change nothing."""
    owner = {"name": "Owner", "inverted": False, "values": ["None", "analyst"]}
    mine = {"name": "Owner", "inverted": False, "values": ["analyst"]}

    assert overlay_filters([OPEN, owner, QUEUE], [mine]) == [OPEN, mine, QUEUE]


@pytest.mark.unit
def test_overlay_switches_to_a_second_observable():
    """"Has both" is not expressible (one entry per filter and polarity, values ORed), and
    ORing the new value in would widen the list, so a second pivot on the same filter
    replaces the first."""
    result = overlay_filters([OPEN, _observable(("ipv4", "1.2.3.4"))],
                             [_observable(("email_address", "a@example.com"))])

    assert result == [OPEN, _observable(("email_address", "a@example.com"))]


@pytest.mark.unit
def test_overlay_leaves_an_inverted_entry_alone():
    """NOT observable:x and observable:y are different filters; folding one into the other
    would invert the pivot."""
    excluded = {"name": "Observable", "inverted": True, "values": [["ipv4", "10.0.0.1"]]}

    result = overlay_filters([excluded], [_observable(("ipv4", "1.2.3.4"))])

    assert result == [excluded, _observable(("ipv4", "1.2.3.4"))]


@pytest.mark.unit
def test_overlay_does_not_mutate_the_filter_in_effect():
    """The base is get_effective_filters(), which is memoized for the rest of the request."""
    base = [_observable(("ipv4", "1.2.3.4"))]

    overlay_filters(base, [_observable(("ipv4", "5.6.7.8"))])

    assert base == [_observable(("ipv4", "1.2.3.4"))]
