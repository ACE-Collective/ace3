"""The alert filter chips the search index can pre-filter on (session/search_filters.py)."""

import datetime
from types import SimpleNamespace

import pytest
import pytz

from app.analysis.views.session import search_filters
from app.analysis.views.session.search_filters import effective_filters_to_search_filters
from saq.configuration.config import get_config

pytestmark = pytest.mark.unit

NOW = datetime.datetime(2026, 10, 23, 12, 0, tzinfo=pytz.utc)


@pytest.fixture(autouse=True)
def analyst(monkeypatch):
    monkeypatch.setattr(search_filters, "current_user", SimpleNamespace(timezone="America/New_York"))
    monkeypatch.setattr(get_config().gui, "local_node_only", False)
    monkeypatch.setattr(get_config().gui, "display_node_list", [])


def test_mapped_filters():
    result = effective_filters_to_search_filters([
        {"name": "Alert Type", "values": ["mailbox", "splunk"]},
        {"name": "Disposition", "values": ["FALSE_POSITIVE"], "inverted": True},
        {"name": "Queue", "values": ["external"]},
        {"name": "Tag", "values": ["Phish", "malware"], "inverted": True},
    ])

    assert (result.alert_types, result.alert_types_inverted) == (("mailbox", "splunk"), False)
    assert (result.dispositions, result.dispositions_inverted) == (("FALSE_POSITIVE",), True)
    assert (result.queues, result.queues_inverted) == (("external",), False)
    # tags are compared the way the tags.name unique key compares them
    assert (result.tags, result.tags_inverted) == (("phish", "malware"), True)
    assert result.timezone == pytz.timezone("America/New_York")
    # the rest is the SQL post-filter's job
    assert result.filter_list == ()


def test_a_relative_alert_date_resolves_in_the_analysts_timezone(monkeypatch):
    class FrozenDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz else NOW

    monkeypatch.setattr(search_filters.datetime, "datetime", FrozenDateTime)

    result = effective_filters_to_search_filters([
        {"name": "Alert Date", "values": ["@d", "not a date"], "inverted": True},
    ])

    # an unparsable value is dropped; "today" started at midnight in New York, 04:00 UTC
    [(start, end)] = result.insert_date_ranges
    assert start == datetime.datetime(2026, 10, 23, 4, 0, tzinfo=pytz.utc)
    assert end == NOW
    assert result.insert_date_inverted is True


def test_unusable_filters_are_left_out():
    result = effective_filters_to_search_filters([
        # no payload equivalent for a wildcard tag
        {"name": "Tag", "values": ["phish*"]},
        # nothing selected
        {"name": "Queue", "values": ["", None]},
        # every date unparsable
        {"name": "Alert Date", "values": ["whenever"]},
        # not a pre-filter at all
        {"name": "Owner", "values": ["john"]},
    ])

    assert result.tags == () and result.queues == () and result.insert_date_ranges == ()
    assert result.locations is None


def test_no_filters_and_no_timezone(monkeypatch):
    monkeypatch.setattr(search_filters, "current_user", SimpleNamespace(timezone=None))
    monkeypatch.setattr(get_config().gui, "display_node_list", ["node-1", "node-2"])

    result = effective_filters_to_search_filters(None)

    assert result.timezone == pytz.utc
    # node scoping applies to the search too, so it never shows an alert the list would not
    assert result.locations == ("node-1", "node-2")
