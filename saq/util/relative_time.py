"""Splunk-style relative time tokens for the alert management filter system.

A date range filter value is a single string with one of these shapes:

    "01-15-2026 08:00 - 01-22-2026 08:00"   two absolute endpoints (the legacy form)
    "-7d - now"                             two relative endpoints
    "-7d - 01-15-2026 08:00"                mixed
    "-7d"                                   shorthand for "-7d - now"

A relative endpoint is `now`, a signed offset (`-7d`, `+1w`, `-8h30m`), an offset with a
snap (`-1d@d`, `-24h@h`), or a bare snap (`@d` == `now@d`).

Relative tokens are stored VERBATIM -- in saved_filters.filters_json and in share URLs --
and resolved here on every query. Nothing may materialize a token into an absolute range
at write time: that is what keeps a saved "Last 24h" meaning the last 24 hours, and a wiki
link reading `alert_date:-7d` meaning "the last week" years after it was written.
"""

import re
from datetime import datetime, timedelta, tzinfo

import pytz

from saq.util.timespec import parse_timespec

DATE_RANGE_SEPARATOR = " - "
ABSOLUTE_DATE_FORMAT = "%m-%d-%Y %H:%M"

# Anchored, and this anchoring is load-bearing: parse_timespec() scans with findall() and
# would happily read "7dd" as 7 days. Only the `magnitude` group -- already constrained to
# a digit-led run of <int><unit> components -- is ever handed to it, so junk is rejected here
# reinterpreted.
_RELATIVE_RE = re.compile(
    r"^(?:now|(?P<sign>[-+])(?P<magnitude>\d+\s*[smhdwy](?:\s*\d+\s*[smhdwy])*))?"
    r"(?:@(?P<snap>mon|[smhdwy]))?$",
    re.IGNORECASE,
)

# Ordered coarsest-last; each entry zeroes everything finer than itself.
_SNAP_FIELDS = {
    "s": {"microsecond": 0},
    "m": {"microsecond": 0, "second": 0},
    "h": {"microsecond": 0, "second": 0, "minute": 0},
    "d": {"microsecond": 0, "second": 0, "minute": 0, "hour": 0},
    "w": {"microsecond": 0, "second": 0, "minute": 0, "hour": 0},
    "mon": {"microsecond": 0, "second": 0, "minute": 0, "hour": 0, "day": 1},
    "y": {"microsecond": 0, "second": 0, "minute": 0, "hour": 0, "day": 1, "month": 1},
}


class RelativeTimeError(ValueError):
    """A token is not valid relative-time syntax."""


def is_relative_time(value: str) -> bool:
    """True if `value` is relative-time syntax rather than an absolute timestamp.

    An absolute "MM-DD-YYYY HH:mm" string can never match: it has no leading sign or '@',
    is not "now", and contains a space and a colon."""
    if not isinstance(value, str):
        return False

    value = value.strip()
    if not value:
        return False

    # the empty match -- neither an offset nor a snap -- is not a token
    match = _RELATIVE_RE.match(value)
    if match is None:
        return False

    return value.lower() == "now" or match.group("magnitude") is not None or match.group("snap") is not None


def _snap(value: datetime, unit: str) -> datetime:
    """Floor `value` to the start of `unit`, toward the past (Splunk's direction)."""
    unit = unit.lower()
    result = value.replace(**_SNAP_FIELDS[unit])
    if unit == "w":
        # Splunk's @w is the preceding Sunday. weekday() is Mon=0..Sun=6.
        result -= timedelta(days=(result.weekday() + 1) % 7)

    return result


def parse_relative_time(value: str, *, now: datetime, tz: tzinfo) -> datetime:
    """Resolve a relative-time token to an aware UTC datetime.

    `now` must be tz-aware. The offset is applied first and then the snap, in `tz` -- the
    analyst's timezone -- so "-1d@d" is local midnight rather than UTC midnight. Arithmetic
    is done on the localized wall clock so a window spanning a DST boundary stays correct.
    """
    if not isinstance(value, str):
        raise RelativeTimeError(f"invalid relative time: {value!r}")

    token = value.strip()
    match = _RELATIVE_RE.match(token)
    if match is None or not is_relative_time(token):
        raise RelativeTimeError(f"invalid relative time: {value!r}")

    result = now.astimezone(tz)

    magnitude = match.group("magnitude")
    if magnitude is not None:
        delta = parse_timespec(magnitude)
        result = result + delta if match.group("sign") == "+" else result - delta
        # re-normalize the wall clock against the offset actually in effect after the shift
        result = _renormalize(result, tz)

    snap = match.group("snap")
    if snap is not None:
        result = _renormalize(_snap(result, snap), tz)

    return result.astimezone(pytz.utc)


def _renormalize(value: datetime, tz: tzinfo) -> datetime:
    """Re-attach the UTC offset that `tz` actually uses at this wall-clock time."""

    # Adding a timedelta to an aware datetime keeps the original offset, so crossing a DST
    # boundary otherwise leaves the result an hour off. pytz needs normalize()/localize() to
    # fix that up; other tzinfo implementations handle it themselves.

    if hasattr(tz, "normalize"):
        return tz.normalize(value)

    return value.replace(tzinfo=None).replace(tzinfo=tz)


def _parse_endpoint(token: str, *, now: datetime, tz: tzinfo) -> datetime:
    """Resolve one endpoint -- relative token or absolute timestamp -- to aware UTC."""
    token = token.strip()
    if is_relative_time(token):
        return parse_relative_time(token, now=now, tz=tz)

    try:
        naive = datetime.strptime(token, ABSOLUTE_DATE_FORMAT)
    except ValueError:
        raise RelativeTimeError(
            f"invalid date {token!r}: expected MM-DD-YYYY HH:mm or a relative time like -7d"
        ) from None

    # localize() picks the offset in effect at THIS wall clock, which is what fixes the
    # long-standing DST bug: the old code took strftime("%z") from *now* and applied that
    # one offset to both endpoints of the range.
    if hasattr(tz, "localize"):
        aware = tz.localize(naive)
    else:
        aware = naive.replace(tzinfo=tz)

    return aware.astimezone(pytz.utc)


def parse_date_range(value: str, *, now: datetime, tz: tzinfo) -> tuple[datetime, datetime]:
    """Parse a date range filter value into an aware UTC (start, end) pair.

    Accepts the absolute wire format, a range with either endpoint relative, or a bare
    relative token (shorthand for "that token .. now"). Raises RelativeTimeError."""
    if not isinstance(value, str):
        raise RelativeTimeError(f"invalid date range: {value!r}")

    parts = value.split(DATE_RANGE_SEPARATOR)
    if len(parts) == 1:
        # shorthand: a single token, bounded by now. Ordering the pair rather than assuming
        # the token is in the past also makes "+1d" work as a future window on Event Date.
        resolved = _parse_endpoint(parts[0], now=now, tz=tz)
        now_utc = now.astimezone(pytz.utc)
        return (resolved, now_utc) if resolved <= now_utc else (now_utc, resolved)

    if len(parts) != 2:
        raise RelativeTimeError(
            f"invalid date range {value!r}: expected '<start> - <end>' or a single relative time"
        )

    return (
        _parse_endpoint(parts[0], now=now, tz=tz),
        _parse_endpoint(parts[1], now=now, tz=tz),
    )


def resolve_date_range_for_display(value: str) -> str:
    """Render a filter value as the concrete window it currently means, for tooltips and
    the live hint under the relative date input. Returns "" if it cannot be parsed -- this
    is display sugar and must never raise into a template."""
    try:
        from flask_login import current_user
        tz = pytz.timezone(current_user.timezone) if getattr(current_user, "timezone", None) else pytz.utc
    except Exception:
        tz = pytz.utc

    try:
        start, end = parse_date_range(value, now=datetime.now(pytz.utc), tz=tz)
    except (RelativeTimeError, ValueError):
        return ""

    return (f"{start.astimezone(tz).strftime(ABSOLUTE_DATE_FORMAT)} – "
            f"{end.astimezone(tz).strftime(ABSOLUTE_DATE_FORMAT)}")
