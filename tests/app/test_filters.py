"""Tests for the alert management filter classes in app/filters.py.

DateRangeFilter had no coverage at all before this file, which is how the DST bug below
survived.
"""

from datetime import datetime

import pytest
import pytz
from sqlalchemy import and_

from app.filters import DateRangeFilter
from saq.gui.alert import GUIAlert

EASTERN = "America/New_York"
UTC = pytz.utc


class _CapturingQuery:
    """Stands in for a SQLAlchemy query and records what got filtered onto it."""

    def __init__(self):
        self.conditions = []

    def filter(self, *conditions):
        self.conditions.extend(conditions)
        return self


class _FakeUser:
    def __init__(self, timezone):
        self.timezone = timezone


def _bounds(monkeypatch, value, timezone=EASTERN):
    """Apply a DateRangeFilter and pull the (start, end) datetimes back out of the
    generated SQL expression."""
    import app.filters

    monkeypatch.setattr(app.filters, "current_user", _FakeUser(timezone))
    query = _CapturingQuery()
    DateRangeFilter(GUIAlert.insert_date).apply(query, [value])

    # one and_(col >= start, col <= end), possibly wrapped in an or_ of a single clause
    clause = query.conditions[0]
    literals = [c.right.value for c in _flatten(clause)]
    assert len(literals) == 2, f"expected two bounds, got {literals}"
    return tuple(_as_utc(d) for d in literals)


def _flatten(clause):
    """Yield the leaf comparison expressions of a possibly-nested boolean clause."""
    if hasattr(clause, "clauses"):
        for child in clause.clauses:
            yield from _flatten(child)
    else:
        yield clause


def _as_utc(value):
    return value.astimezone(UTC) if value.tzinfo else UTC.localize(value)


@pytest.mark.unit
def test_absolute_range_across_dst_boundary_uses_each_endpoint_own_offset(monkeypatch):
    """US spring-forward is 2026-03-08. A range straddling it has one endpoint in EST
    (UTC-5) and one in EDT (UTC-4), so each must be converted with the offset in effect at
    its OWN wall clock.

    The old implementation took a single offset from datetime.now() and applied it to both
    endpoints, so exactly one of these two assertions was wrong at any time of year --
    which half depends on the season the test runs in."""
    start, end = _bounds(monkeypatch, "03-01-2026 12:00 - 03-15-2026 12:00")

    assert start == UTC.localize(datetime(2026, 3, 1, 17, 0)), "March 1 is EST (UTC-5)"
    assert end == UTC.localize(datetime(2026, 3, 15, 16, 0)), "March 15 is EDT (UTC-4)"


@pytest.mark.unit
def test_absolute_range_same_side_of_dst(monkeypatch):
    start, end = _bounds(monkeypatch, "01-15-2026 08:00 - 01-22-2026 08:00")

    assert start == UTC.localize(datetime(2026, 1, 15, 13, 0))
    assert end == UTC.localize(datetime(2026, 1, 22, 13, 0))


@pytest.mark.unit
def test_utc_user_absolute_range(monkeypatch):
    start, end = _bounds(monkeypatch, "01-15-2026 08:00 - 01-22-2026 08:00", timezone="UTC")

    assert start == UTC.localize(datetime(2026, 1, 15, 8, 0))
    assert end == UTC.localize(datetime(2026, 1, 22, 8, 0))


@pytest.mark.unit
def test_relative_range(monkeypatch):
    before = datetime.now(UTC)
    start, end = _bounds(monkeypatch, "-7d - now", timezone="UTC")
    after = datetime.now(UTC)

    assert before <= end <= after
    assert (end - start).days == 7


@pytest.mark.unit
def test_bare_relative_token(monkeypatch):
    start, end = _bounds(monkeypatch, "-24h", timezone="UTC")

    assert 23.9 < (end - start).total_seconds() / 3600 < 24.1


@pytest.mark.unit
def test_relative_snap_resolves_in_user_timezone(monkeypatch):
    """-0d@d is the analyst's local midnight, not UTC midnight."""
    start, _ = _bounds(monkeypatch, "@d - now")
    local_midnight = start.astimezone(pytz.timezone(EASTERN))

    assert (local_midnight.hour, local_midnight.minute) == (0, 0)


@pytest.mark.unit
def test_unparseable_value_raises_rather_than_silently_matching_everything(monkeypatch):
    from saq.util.relative_time import RelativeTimeError

    with pytest.raises((RelativeTimeError, ValueError)):
        _bounds(monkeypatch, "-7dd - now", timezone="UTC")
