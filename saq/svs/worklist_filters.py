"""The SQL of the SVS worklist screen's filters (saq.gui.filter_screens.SVS_WORKLIST_SCREEN).

Each entry becomes one condition on svs_technique_worklist: the values of an entry are ORed, the
entries are ANDed (repeats of one filter are merged first), and an inverted entry matches exactly
the rows the entry does not, including rows whose value is NULL. A technique matches its
sub-techniques too: T1059 finds T1059.001. Signature matches a signature's uuid, or text in its
name.
"""

from datetime import tzinfo

import pytz
from sqlalchemy import case, false, or_, select, true
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import SVSTechniqueWorklist, User
from saq.gui.filter_conditions import date_range_condition
from saq.gui.filter_entry import WORKLIST_RESOLUTION_NONE
from saq.svs.catalog_filters import technique_condition


def _signature(value: str) -> ColumnElement[bool]:
    return or_(SVSTechniqueWorklist.signature_uuid == value,
               SVSTechniqueWorklist.signature_name.contains(value, autoescape=True))


def _resolution(values: list[str]) -> ColumnElement[bool]:
    conditions = []
    resolutions = [value for value in values if value != WORKLIST_RESOLUTION_NONE]
    if resolutions:
        conditions.append(SVSTechniqueWorklist.resolution.in_(resolutions))
    if WORKLIST_RESOLUTION_NONE in values:
        conditions.append(SVSTechniqueWorklist.resolution.is_(None))
    return or_(*conditions)


def _merged(entries: list[dict]) -> list[dict]:
    """Repeats of one filter with the same polarity merged into one entry."""
    merged: dict[tuple[str, bool], list[str]] = {}
    for entry in entries:
        merged.setdefault((entry["name"], bool(entry.get("inverted"))), []).extend(entry["values"])
    return [{"name": name, "inverted": inverted, "values": values} for (name, inverted), values in merged.items()]


def worklist_filter_condition(entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition on svs_technique_worklist of one validated filter entry ({name, inverted, values})."""
    name, values = entry["name"], entry["values"]
    if name == "Signature":
        condition = or_(*[_signature(value) for value in values])
    elif name == "Family":
        condition = SVSTechniqueWorklist.signature_family.in_(values)
    elif name == "Technique":
        condition = or_(*[technique_condition(SVSTechniqueWorklist.technique, value) for value in values])
    elif name == "Status":
        condition = SVSTechniqueWorklist.status.in_(values)
    elif name == "Kind":
        condition = SVSTechniqueWorklist.kind.in_(values)
    elif name == "Resolution":
        condition = _resolution(values)
    elif name == "Resolved By":
        condition = SVSTechniqueWorklist.resolved_by_user_id.in_(select(User.id).where(User.username.in_(values)))
    elif name == "Resolved":
        condition = date_range_condition(SVSTechniqueWorklist.resolved_at, values, tz)
    else:
        raise ValueError(f"unknown worklist filter {name!r}")

    if not entry.get("inverted"):
        return condition
    # a CASE keeps the rows whose value is NULL in the inverse
    return case((condition, false()), else_=true())


def worklist_filter_conditions(entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list on svs_technique_worklist, to be ANDed."""
    return [worklist_filter_condition(entry, tz) for entry in _merged(entries)]
