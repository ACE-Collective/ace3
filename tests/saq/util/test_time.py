import pytest
from datetime import datetime

from saq.environment import get_local_timezone
from saq.util.time import calculate_backoff_delay, parse_event_time, parse_iso8601

@pytest.mark.unit
def test_util_000_date_parsing():
    default_format = '2018-10-19 14:06:34 +0000'
    old_default_format = '2018-10-19 14:06:34'
    json_format = '2018-10-19T18:08:08.346118-05:00'
    old_json_format = '2018-10-19T18:08:08.346118'
    splunk_format = '2015-02-19T09:50:49.000-05:00'

    result = parse_event_time(default_format)
    assert result.year == 2018
    assert result.month == 10
    assert result.day == 19
    assert result.hour == 14
    assert result.minute == 6
    assert result.second == 34
    assert result.tzinfo
    assert int(result.tzinfo.utcoffset(None).total_seconds()) == 0

    result = parse_event_time(old_default_format)
    assert result.year == 2018
    assert result.month == 10
    assert result.day == 19
    assert result.hour == 14
    assert result.minute == 6
    assert result.second == 34
    assert result.tzinfo
    assert get_local_timezone().tzname == result.tzinfo.tzname
    
    result = parse_event_time(json_format)
    assert result.year == 2018
    assert result.month == 10
    assert result.day == 19
    assert result.hour == 18
    assert result.minute == 8
    assert result.second == 8
    assert result.tzinfo
    assert int(result.tzinfo.utcoffset(None).total_seconds()) == -(5 * 60 * 60)

    result = parse_event_time(old_json_format)
    assert result.year == 2018
    assert result.month == 10
    assert result.day == 19
    assert result.hour == 18
    assert result.minute == 8
    assert result.second == 8
    assert result.tzinfo
    assert get_local_timezone().tzname == result.tzinfo.tzname

    result = parse_event_time(splunk_format)
    assert result.year == 2015
    assert result.month == 2
    assert result.day == 19
    assert result.hour == 9
    assert result.minute == 50
    assert result.second == 49
    assert result.tzinfo
    assert int(result.tzinfo.utcoffset(None).total_seconds()), -(5 * 60 * 60)

@pytest.mark.unit
@pytest.mark.parametrize("iso_string,year,month,day,hour,minute,second,microsecond,tz_offset_seconds", [
    ('2023-06-15T14:23:45.123456+05:00', 2023, 6, 15, 14, 23, 45, 123456, 5 * 60 * 60),
    ('2023-06-15T14:23:45.123456-05:00', 2023, 6, 15, 14, 23, 45, 123456, -(5 * 60 * 60)),
    ('2023-06-15T14:23:45.123456Z', 2023, 6, 15, 14, 23, 45, 123456, 0),
    ('2023-06-15T14:23:45+00:00', 2023, 6, 15, 14, 23, 45, 0, 0),
    ('2023-12-31T23:59:59.999999+00:00', 2023, 12, 31, 23, 59, 59, 999999, 0),
])
def test_util_001_parse_iso8601(iso_string, year, month, day, hour, minute, second, microsecond, tz_offset_seconds):
    result = parse_iso8601(iso_string)
    assert result.year == year
    assert result.month == month
    assert result.day == day
    assert result.hour == hour
    assert result.minute == minute
    assert result.second == second
    assert result.microsecond == microsecond
    assert result.tzinfo
    assert int(result.tzinfo.utcoffset(None).total_seconds()) == tz_offset_seconds


#
# Tests for calculate_backoff_delay
#


@pytest.mark.unit
def test_calculate_backoff_delay_initial():
    """Test calculate_backoff_delay returns initial delay for attempt 0."""
    delay = calculate_backoff_delay(attempt=0, initial_delay=60, max_delay=3600)
    assert delay == 60


@pytest.mark.unit
@pytest.mark.parametrize("attempt,expected", [
    (0, 60),
    (1, 120),
    (2, 240),
    (3, 480),
    (4, 960),
    (5, 1920),
])
def test_calculate_backoff_delay_exponential(attempt, expected):
    """Test calculate_backoff_delay doubles with each attempt."""
    delay = calculate_backoff_delay(attempt, initial_delay=60, max_delay=3600)
    assert delay == expected


@pytest.mark.unit
@pytest.mark.parametrize("attempt,expected", [
    (6, 3600),   # 3840 -> capped to 3600
    (7, 3600),   # 7680 -> capped to 3600
    (10, 3600),  # 61440 -> capped to 3600
])
def test_calculate_backoff_delay_capped_at_max(attempt, expected):
    """Test calculate_backoff_delay is capped at max_delay."""
    delay = calculate_backoff_delay(attempt, initial_delay=60, max_delay=3600)
    assert delay == expected


@pytest.mark.unit
def test_calculate_backoff_delay_custom_values():
    """Test calculate_backoff_delay with custom initial and max values."""
    # Fast initial with low max (for testing)
    assert calculate_backoff_delay(0, initial_delay=10, max_delay=100) == 10
    assert calculate_backoff_delay(1, initial_delay=10, max_delay=100) == 20
    assert calculate_backoff_delay(2, initial_delay=10, max_delay=100) == 40
    assert calculate_backoff_delay(3, initial_delay=10, max_delay=100) == 80
    assert calculate_backoff_delay(4, initial_delay=10, max_delay=100) == 100  # capped