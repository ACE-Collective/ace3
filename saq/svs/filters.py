"""The SQL of the SVS samples screen's filters (saq.gui.filter_screens.SVS_SAMPLES_SCREEN).

Each entry becomes one condition on a row of saq.svs.samples.samples_subquery(): the values of an
entry are ORed, the entries are ANDed (repeats of one filter are merged first), and an inverted
entry matches exactly the rows the entry does not, including rows whose value is NULL.

Most filters test the sample's own columns. Alert, File Name and Rule test its captures: a sample
matches when any of its captures does (a sample captured from three alerts matches each of them,
and a rule renamed between commits matches under either name).
"""

from datetime import datetime, tzinfo

import pytz
from sqlalchemy import and_, case, exists, false, literal, or_, select, true
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import SVSYaraCapture
from saq.svs.constants import LABEL_FILTER_NONE
from saq.svs.samples import captures_of
from saq.util.relative_time import parse_date_range


def _in_or_null(expression, values: list[str], null_value: str) -> ColumnElement[bool]:
    conditions = []
    named = [value for value in values if value != null_value]
    if named:
        conditions.append(expression.in_(named))
    if null_value in values:
        conditions.append(expression.is_(None))
    return or_(*conditions)


def _any_capture(samples, condition_for_value, values: list[str]) -> ColumnElement[bool]:
    return exists(
        select(literal(1))
        .where(captures_of(samples))
        .where(or_(*[condition_for_value(value) for value in values])))


def _date_range(column, values: list[str], tz: tzinfo) -> ColumnElement[bool]:
    now = datetime.now(pytz.utc)
    conditions = []
    for value in values:
        start, end = parse_date_range(value, now=now, tz=tz)
        # the capture timestamps are naive UTC
        conditions.append(and_(column >= start.replace(tzinfo=None), column <= end.replace(tzinfo=None)))
    return or_(*conditions)


def _flag(count_column, values: list[str]) -> ColumnElement[bool]:
    if values == ["true"]:
        return count_column > 0
    if values == ["false"]:
        return count_column == 0
    return true()


def sample_filter_condition(samples, entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition of one validated filter entry ({name, inverted, values}) on samples, a
    samples_subquery()."""
    name, values = entry["name"], entry["values"]
    if name == "Signature":
        condition = samples.c.rule_uuid.in_(values)
    elif name == "SHA256":
        condition = samples.c.sha256.in_(values)
    elif name == "Alert":
        condition = _any_capture(samples, lambda value: SVSYaraCapture.alert_uuid == value, values)
    elif name == "File Name":
        condition = _any_capture(
            samples, lambda value: SVSYaraCapture.file_path.contains(value, autoescape=True), values)
    elif name == "Rule":
        condition = _any_capture(
            samples, lambda value: SVSYaraCapture.rule_name.contains(value, autoescape=True), values)
    elif name == "Label":
        condition = _in_or_null(samples.c.label, values, LABEL_FILTER_NONE)
    elif name == "Label Source":
        condition = samples.c.label_source.in_(values)
    elif name == "Last Captured":
        condition = _date_range(samples.c.last_captured, values, tz)
    elif name == "Stored":
        condition = _flag(samples.c.stored, values)
    elif name == "Missing Data":
        condition = _flag(samples.c.missing_data, values)
    elif name == "Unknown Version":
        condition = _flag(samples.c.unknown_version, values)
    else:
        raise ValueError(f"unknown samples filter {name!r}")

    if not entry.get("inverted"):
        return condition

    # NOT of a comparison with NULL is NULL, which would drop the rows whose value is NULL from
    # both a filter and its inverse; a CASE sends NULL to the ELSE branch, so it keeps them
    return case((condition, false()), else_=true())


def sample_filter_conditions(samples, entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list, to be ANDed. Repeats of one filter with the same polarity
    are merged into one entry first, so `f=label:tp&f=label:fp` means either label, as it does for
    alerts (docs/ALERT_FILTER_URLS.md)."""
    merged: dict[tuple[str, bool], list[str]] = {}
    for entry in entries:
        merged.setdefault((entry["name"], bool(entry.get("inverted"))), []).extend(entry["values"])

    return [sample_filter_condition(samples, {"name": name, "inverted": inverted, "values": values}, tz)
            for (name, inverted), values in merged.items()]
