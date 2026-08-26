import re
from datetime import timedelta

_TIMESPEC_PATTERN = re.compile(
    r"(\d+)\s*([smhdwy])",
    re.IGNORECASE,
)

_UNIT_MAP = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
    "y": "days",  # handled specially below
}

_YEAR_DAYS = 365


def parse_timespec(value: str) -> timedelta:
    """Parse a timespec string like '8h30m30s' into a timedelta.

    Supported units: s (seconds), m (minutes), h (hours), d (days), w (weeks), y (years).
    Units can be combined with optional whitespace: '1d 12h', '8h30m30s'.

    Raises ValueError if the string cannot be parsed.
    """
    matches = _TIMESPEC_PATTERN.findall(value)
    if not matches:
        raise ValueError(f"invalid timespec: {value!r}")

    kwargs = {}
    for count_str, unit in matches:
        count = int(count_str)
        unit = unit.lower()
        if unit == "y":
            kwargs["days"] = kwargs.get("days", 0) + count * _YEAR_DAYS
        else:
            key = _UNIT_MAP[unit]
            kwargs[key] = kwargs.get(key, 0) + count

    return timedelta(**kwargs)
