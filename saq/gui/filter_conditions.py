"""SQL building blocks of the filter screens' conditions (saq/gui/filter_screens.py).

Each filter entry ({name, inverted, values}) becomes one condition: the values of an entry are
ORed, the entries are ANDed, and repeats of one filter with the same polarity are merged into one
entry first.
"""

from datetime import datetime, tzinfo

import pytz
from sqlalchemy import and_, case, false, or_, true
from sqlalchemy.sql.elements import ColumnElement

from saq.util.relative_time import parse_date_range


def merge_entries(entries: list[dict]) -> list[dict]:
    """The entries with the repeats of one filter and polarity merged into one."""
    merged: dict[tuple[str, bool], list] = {}
    for entry in entries:
        merged.setdefault((entry["name"], bool(entry.get("inverted"))), []).extend(entry["values"])

    return [{"name": name, "inverted": inverted, "values": values} for (name, inverted), values in merged.items()]


def inverse(condition: ColumnElement[bool]) -> ColumnElement[bool]:
    """The rows an inverted entry matches: exactly those the entry does not, including the rows
    whose value is NULL, which NOT (condition) would leave out."""
    return case((condition, false()), else_=true())


def contains_any(column, values: list[str]) -> ColumnElement[bool]:
    return or_(*[column.contains(value, autoescape=True) for value in values])


def date_range_condition(column, values: list[str], tz: tzinfo) -> ColumnElement[bool]:
    """A date range filter on a column of naive UTC timestamps."""
    now = datetime.now(pytz.utc)
    conditions = []
    for value in values:
        start, end = parse_date_range(value, now=now, tz=tz)
        conditions.append(and_(column >= start.replace(tzinfo=None), column <= end.replace(tzinfo=None)))
    return or_(*conditions)
