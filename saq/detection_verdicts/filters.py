"""The SQL of the detection points screen's filters (saq.gui.filter_screens.DETECTION_POINTS_SCREEN).

Each entry becomes one condition on detection_points_select() (saq.detection_verdicts.query):
the values of an entry are ORed, the entries are ANDed (repeats of one filter are merged first),
and an inverted entry matches exactly the rows the entry does not, including rows whose value is
NULL.
"""

from datetime import datetime, tzinfo

import pytz
from sqlalchemy import and_, case, false, not_, or_, true
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import Alert, DetectionPoint, DetectionPointVerdict
from saq.detection_verdicts.effective import effective_verdict_expr, verdict_source_expr
from saq.gui.detection_point_value import parse_detection_point_value
from saq.gui.filter_entry import VERDICT_FILTER_NONE
from saq.util.relative_time import parse_date_range


def _signature(values: list[str]) -> ColumnElement[bool]:
    conditions = []
    for value in values:
        signature_uuid, signature_version = parse_detection_point_value(value)
        condition = DetectionPoint.signature_uuid == signature_uuid
        if signature_version is not None:
            condition = and_(condition, DetectionPoint.signature_version == signature_version)
        conditions.append(condition)
    return or_(*conditions)


def _alert_date(values: list[str], tz: tzinfo) -> ColumnElement[bool]:
    now = datetime.now(pytz.utc)
    conditions = []
    for value in values:
        start, end = parse_date_range(value, now=now, tz=tz)
        conditions.append(and_(Alert.insert_date >= start, Alert.insert_date <= end))
    return or_(*conditions)


def _in_or_null(expression, values: list[str], null_value: str) -> ColumnElement[bool]:
    conditions = []
    named = [value for value in values if value != null_value]
    if named:
        conditions.append(expression.in_(named))
    if null_value in values:
        conditions.append(expression.is_(None))
    return or_(*conditions)


def detection_point_filter_condition(entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition of one validated filter entry ({name, inverted, values})."""
    name, values = entry["name"], entry["values"]
    if name == "Signature":
        condition = _signature(values)
    elif name == "Family":
        condition = DetectionPoint.signature_family.in_(values)
    elif name == "Alert Date":
        condition = _alert_date(values, tz)
    elif name == "Queue":
        condition = Alert.queue.in_(values)
    elif name == "Verdict":
        condition = _in_or_null(
            effective_verdict_expr(Alert, DetectionPoint, DetectionPointVerdict), values, VERDICT_FILTER_NONE)
    elif name == "Source":
        condition = verdict_source_expr(Alert, DetectionPoint, DetectionPointVerdict).in_(values)
    elif name == "Has Override":
        has_override = DetectionPointVerdict.verdict.is_not(None)
        if values == ["true"]:
            condition = has_override
        elif values == ["false"]:
            condition = not_(has_override)
        else:
            condition = true()
    else:
        raise ValueError(f"unknown detection points filter {name!r}")

    if not entry.get("inverted"):
        return condition

    # NOT of a comparison with NULL is NULL, which would drop the rows whose value is NULL from
    # both a filter and its inverse; a CASE sends NULL to the ELSE branch, so it keeps them
    return case((condition, false()), else_=true())


def detection_point_filter_conditions(entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list, to be ANDed. Repeats of one filter with the same polarity
    are merged into one entry first, so `f=queue:a&f=queue:b` means either queue, as it does for
    alerts (docs/ALERT_FILTER_URLS.md)."""
    merged: dict[tuple[str, bool], list[str]] = {}
    for entry in entries:
        merged.setdefault((entry["name"], bool(entry.get("inverted"))), []).extend(entry["values"])

    return [detection_point_filter_condition({"name": name, "inverted": inverted, "values": values}, tz)
            for (name, inverted), values in merged.items()]

