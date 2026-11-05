from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

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
    "NOW",
    "+7d", "-8h30m30s", "-1d 12h",
    "-1d@d", "-24h@h", "+1w@w", "-1y@mon",
    "@d", "@h", "@w", "@mon", "@y",
])
def test_is_relative_time_accepts(value):
    assert is_relative_time(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", [
    "7d",            # unsigned -- would be ambiguous with a bare number
    "--7d",
    "-7d@",          # snap marker with no unit; also what the end anchor rejects
    "-7d@x",         # unknown snap unit
    "- 7 d",
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
    ("+7d", NOW + timedelta(days=7)),
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
@pytest.mark.parametrize("now_local, is_dst, token, expected_local, expected_is_dst", [
    # US fall-back is 2026-11-01 at 02:00 EDT: midnight was EDT, now is EST
    (datetime(2026, 11, 1, 10, 0), False, "@d", datetime(2026, 11, 1, 0, 0), True),
    (datetime(2026, 11, 15, 10, 0), False, "@mon", datetime(2026, 11, 1, 0, 0), True),
    # US spring-forward is 2026-03-08 at 02:00 EST: midnight was EST, now is EDT
    (datetime(2026, 3, 8, 10, 0), True, "@d", datetime(2026, 3, 8, 0, 0), False),
    (datetime(2026, 3, 9, 10, 0), True, "-1d@d", datetime(2026, 3, 8, 0, 0), False),
    # 01:xx happens twice on fall-back day; @h stays in the occurrence it started in
    (datetime(2026, 11, 1, 1, 30), True, "@h", datetime(2026, 11, 1, 1, 0), True),
    (datetime(2026, 11, 1, 1, 30), False, "@h", datetime(2026, 11, 1, 1, 0), False),
])
@pytest.mark.parametrize("tz", [EASTERN, ZoneInfo("America/New_York")], ids=["pytz", "zoneinfo"])
def test_snap_on_a_dst_change_day_uses_the_offset_at_the_snapped_time(
        now_local, is_dst, token, expected_local, expected_is_dst, tz):
    now = EASTERN.localize(now_local, is_dst=is_dst).astimezone(UTC)
    expected = EASTERN.localize(expected_local, is_dst=expected_is_dst).astimezone(UTC)

    assert parse_relative_time(token, now=now, tz=tz) == expected


@pytest.mark.unit
def test_offset_across_dst_boundary_is_real_time():
    """US spring-forward is 2026-03-08 at 02:00. -1d from noon EDT on the 8th is 24 real
    hours back, which is 11:00 EST on the 7th, not noon."""
    now = EASTERN.localize(datetime(2026, 3, 8, 12, 0)).astimezone(UTC)
    result = parse_relative_time("-1d", now=now, tz=EASTERN)

    assert now - result == timedelta(hours=24)
    assert result == EASTERN.localize(datetime(2026, 3, 7, 11, 0)).astimezone(UTC)


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
# the three endpoints of the second are each valid
@pytest.mark.parametrize("value", ["-7dd", "-7d - now - now"])
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
