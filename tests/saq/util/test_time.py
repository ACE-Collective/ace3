import pytest
from datetime import datetime

from saq.environment import get_local_timezone
from saq.util.time import parse_event_time, parse_iso8601

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