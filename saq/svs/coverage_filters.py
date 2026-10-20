"""The SQL of the SVS coverage screens' filters (saq.gui.filter_screens.SVS_COVERAGE_SCREEN and
SVS_COVERAGE_HISTORY_SCREEN).

Each entry becomes one condition on svs_coverage (or svs_coverage_snapshots): the values of an
entry are ORed, the entries are ANDed (repeats of one filter are merged first), and an inverted
entry matches exactly the rows the entry does not, including rows whose value is NULL. A technique
matches its sub-techniques too: T1059 finds T1059.001.
"""

from datetime import datetime, tzinfo

import pytz
from sqlalchemy import and_, case, false, or_, true
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import SVSCoverage, SVSCoverageSnapshot
from saq.gui.filter_conditions import date_range_condition
from saq.svs.catalog_filters import technique_condition
from saq.util.relative_time import parse_date_range


def _flag(condition: ColumnElement[bool], values: list[str]) -> ColumnElement[bool]:
    if values == ["true"]:
        return condition
    if values == ["false"]:
        return case((condition, false()), else_=true())
    return true()


def _level(table, values: list[str]) -> ColumnElement[bool]:
    return table.is_subtechnique.in_([value == "sub-technique" for value in values])


def _merged(entries: list[dict]) -> list[dict]:
    """Repeats of one filter with the same polarity merged into one entry."""
    merged: dict[tuple[str, bool], list[str]] = {}
    for entry in entries:
        merged.setdefault((entry["name"], bool(entry.get("inverted"))), []).extend(entry["values"])
    return [{"name": name, "inverted": inverted, "values": values} for (name, inverted), values in merged.items()]


def _inverted(entry: dict, condition: ColumnElement[bool]) -> ColumnElement[bool]:
    if not entry.get("inverted"):
        return condition

    # a CASE keeps the rows whose value is NULL in the inverse
    return case((condition, false()), else_=true())


def coverage_filter_condition(entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition on svs_coverage of one validated filter entry ({name, inverted, values})."""
    name, values = entry["name"], entry["values"]
    if name == "Technique":
        condition = or_(*[technique_condition(SVSCoverage.technique, value) for value in values])
    elif name == "Name":
        condition = or_(*[SVSCoverage.technique_name.contains(value, autoescape=True) for value in values])
    elif name == "Tactic":
        # tactics is a JSON list of tactic ids
        condition = or_(*[SVSCoverage.tactics.contains(f'"{value}"', autoescape=True) for value in values])
    elif name == "Platform":
        condition = SVSCoverage.platform.in_(values)
    elif name == "State":
        condition = SVSCoverage.state.in_(values)
    elif name == "Own State":
        condition = SVSCoverage.own_state.in_(values)
    elif name == "Level":
        condition = _level(SVSCoverage, values)
    elif name == "ATT&CK Platform":
        condition = _flag(SVSCoverage.attack_platform.is_(True), values)
    elif name == "Catalog Status":
        condition = SVSCoverage.catalog_status.in_(values)
    elif name == "Has Manual":
        condition = _flag(SVSCoverage.manual_signatures > 0, values)
    elif name == "State Changed":
        condition = date_range_condition(SVSCoverage.state_changed_at, values, tz)
    elif name == "Retired":
        condition = _flag(SVSCoverage.retired_at.isnot(None), values)
    else:
        raise ValueError(f"unknown coverage filter {name!r}")

    return _inverted(entry, condition)


def coverage_filter_conditions(entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list on svs_coverage, to be ANDed."""
    return [coverage_filter_condition(entry, tz) for entry in _merged(entries)]


def _date_condition(values: list[str], tz: tzinfo) -> ColumnElement[bool]:
    """The snapshots of the days a date range touches."""
    now = datetime.now(pytz.utc)
    conditions = []
    for value in values:
        start, end = parse_date_range(value, now=now, tz=tz)
        conditions.append(and_(SVSCoverageSnapshot.snapshot_date >= start.date(),
                               SVSCoverageSnapshot.snapshot_date <= end.date()))
    return or_(*conditions)


def history_filter_condition(entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition on svs_coverage_snapshots of one validated filter entry."""
    name, values = entry["name"], entry["values"]
    if name == "Date":
        condition = _date_condition(values, tz)
    elif name == "Technique":
        condition = or_(*[technique_condition(SVSCoverageSnapshot.technique, value) for value in values])
    elif name == "Platform":
        condition = SVSCoverageSnapshot.platform.in_(values)
    elif name == "State":
        condition = SVSCoverageSnapshot.state.in_(values)
    elif name == "Own State":
        condition = SVSCoverageSnapshot.own_state.in_(values)
    elif name == "Level":
        condition = _level(SVSCoverageSnapshot, values)
    else:
        raise ValueError(f"unknown coverage history filter {name!r}")

    return _inverted(entry, condition)


def history_filter_conditions(entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list on svs_coverage_snapshots, to be ANDed."""
    return [history_filter_condition(entry, tz) for entry in _merged(entries)]
