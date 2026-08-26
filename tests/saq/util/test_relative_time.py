from datetime import datetime, timedelta

import pytest
import pytz

from saq.util.relative_time import (
    RelativeTimeError,
    is_relative_time,
    parse_date_range,
    parse_relative_time,
)

UTC = pytz.utc
EASTERN = pytz.timezone("America/New_York")

# a fixed anchor so every expectation is exact
NOW = UTC.localize(datetime(2026, 1, 22, 15, 37, 42, 500000))


@pytest.mark.unit
@pytest.mark.parametrize("value", [
    "now", "NOW",
    "-7d", "+7d", "-24h", "-90m", "-8h30m30s", "-1w", "-1y", "-1d 12h",
    "-1d@d", "-24h@h", "+1w@w", "-1y@mon",
    "@d", "@h", "@w", "@mon", "@y",
])
def test_is_relative_time_accepts(value):
    assert is_relative_time(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", [
    "7d",            # unsigned -- would be ambiguous with a bare number
    "-7dd",          # the case parse_timespec's findall() would silently accept as 7d
    "--7d",
    "-7d@",          # snap marker with no unit
    "-7d@x",         # unknown snap unit
    "- 7 d",
    "-",
    "@",
    "",
    "   ",
    "01-15-2026 08:00",   # absolute must never be mistaken for relative
    "nowish",
    "-7dgarbage",
])
def test_is_relative_time_rejects(value):
    assert not is_relative_time(value)


@pytest.mark.unit
def test_parse_relative_time_rejects_junk():
    for value in ["7d", "-7dd", "--7d", "-7d@x", "", "01-15-2026 08:00"]:
        with pytest.raises(RelativeTimeError):
            parse_relative_time(value, now=NOW, tz=UTC)


@pytest.mark.unit
@pytest.mark.parametrize("value,expected", [
    ("now", NOW),
    ("-7d", NOW - timedelta(days=7)),
    ("+7d", NOW + timedelta(days=7)),
    ("-24h", NOW - timedelta(hours=24)),
    ("-90m", NOW - timedelta(minutes=90)),
    ("-8h30m30s", NOW - timedelta(hours=8, minutes=30, seconds=30)),
    ("-1w", NOW - timedelta(weeks=1)),
])
def test_parse_relative_offsets(value, expected):
    assert parse_relative_time(value, now=NOW, tz=UTC) == expected


@pytest.mark.unit
@pytest.mark.parametrize("value,expected", [
    ("@s",   datetime(2026, 1, 22, 15, 37, 42)),
    ("@m",   datetime(2026, 1, 22, 15, 37, 0)),
    ("@h",   datetime(2026, 1, 22, 15, 0, 0)),
    ("@d",   datetime(2026, 1, 22, 0, 0, 0)),
    ("@mon", datetime(2026, 1, 1, 0, 0, 0)),
    ("@y",   datetime(2026, 1, 1, 0, 0, 0)),
])
def test_snap_units(value, expected):
    assert parse_relative_time(value, now=NOW, tz=UTC) == UTC.localize(expected)


@pytest.mark.unit
def test_snap_week_is_preceding_sunday():
    # 2026-01-22 is a Thursday; Splunk's @w floors to the preceding Sunday, 2026-01-18.
    assert parse_relative_time("@w", now=NOW, tz=UTC) == UTC.localize(datetime(2026, 1, 18))


@pytest.mark.unit
def test_offset_applied_before_snap():
    # -1d@d is "yesterday, floored to midnight", not "midnight, minus a day"
    assert parse_relative_time("-1d@d", now=NOW, tz=UTC) == UTC.localize(datetime(2026, 1, 21))


@pytest.mark.unit
def test_snap_happens_in_user_timezone_not_utc():
    """@d must mean local midnight. At 15:37 UTC the analyst in New York is at 10:37, so
    their "start of today" is 05:00 UTC -- not 00:00 UTC."""
    assert parse_relative_time("@d", now=NOW, tz=EASTERN) == UTC.localize(datetime(2026, 1, 22, 5, 0))


@pytest.mark.unit
def test_offset_across_dst_boundary_keeps_wall_clock():
    """US spring-forward is 2026-03-08. Going back 1 day from noon local on the 9th must
    land on noon local on the 8th -- a 23-hour real-time step, not 24."""
    now = EASTERN.localize(datetime(2026, 3, 9, 12, 0)).astimezone(UTC)
    result = parse_relative_time("-1d", now=now, tz=EASTERN).astimezone(EASTERN)
    assert (result.year, result.month, result.day, result.hour) == (2026, 3, 8, 12)


@pytest.mark.unit
def test_absolute_range_still_parses():
    start, end = parse_date_range("01-15-2026 08:00 - 01-22-2026 08:00", now=NOW, tz=UTC)
    assert start == UTC.localize(datetime(2026, 1, 15, 8, 0))
    assert end == UTC.localize(datetime(2026, 1, 22, 8, 0))


@pytest.mark.unit
def test_relative_range_both_endpoints():
    start, end = parse_date_range("-7d - now", now=NOW, tz=UTC)
    assert start == NOW - timedelta(days=7)
    assert end == NOW


@pytest.mark.unit
def test_mixed_range():
    start, end = parse_date_range("-7d - 01-22-2026 08:00", now=NOW, tz=UTC)
    assert start == NOW - timedelta(days=7)
    assert end == UTC.localize(datetime(2026, 1, 22, 8, 0))


@pytest.mark.unit
def test_bare_token_is_shorthand_for_token_to_now():
    assert parse_date_range("-7d", now=NOW, tz=UTC) == (NOW - timedelta(days=7), NOW)


@pytest.mark.unit
def test_bare_future_token_orders_the_pair():
    """+1d must produce (now, now+1d), not an inverted range that matches nothing."""
    assert parse_date_range("+1d", now=NOW, tz=UTC) == (NOW, NOW + timedelta(days=1))


@pytest.mark.unit
@pytest.mark.parametrize("value", ["-7dd", "a - b - c", "01-99-2026 08:00 - now", "garbage"])
def test_parse_date_range_rejects(value):
    with pytest.raises(RelativeTimeError):
        parse_date_range(value, now=NOW, tz=UTC)


@pytest.mark.unit
def test_relative_tokens_reevaluate_against_now():
    """THE load-bearing invariant. A stored token must resolve to a DIFFERENT window as
    time passes -- that is what keeps a saved "Last 24h" meaning the last 24 hours and a
    wiki link meaning "the last week" years later. If anyone ever "helpfully" normalizes a
    token to an absolute range at write time, this test is what catches it."""
    later = NOW + timedelta(hours=6)
    first = parse_date_range("-24h", now=NOW, tz=UTC)
    second = parse_date_range("-24h", now=later, tz=UTC)

    assert first != second
    assert second[0] - first[0] == timedelta(hours=6)
    assert second[1] - first[1] == timedelta(hours=6)
