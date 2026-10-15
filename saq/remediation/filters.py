"""The SQL of the Remediations screen's filters (saq.gui.filter_screens.REMEDIATIONS_SCREEN).

Each entry becomes one condition on remediation (see saq/gui/filter_conditions.py); an inverted
entry also matches the rows whose value is NULL, such as a remediation that has no result yet.
"""

from datetime import tzinfo

import pytz
from sqlalchemy import or_, select
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import Remediation, User
from saq.gui.filter_conditions import contains_any, date_range_condition, inverse, merge_entries


def remediation_filter_condition(entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition of one validated filter entry ({name, inverted, values})."""
    name, values = entry["name"], entry["values"]
    if name == "ID":
        condition = Remediation.id.in_([int(value) for value in values])
    elif name == "Remediator":
        condition = contains_any(Remediation.name, values)
    elif name == "Type":
        condition = contains_any(Remediation.type, values)
    elif name == "Value":
        condition = contains_any(Remediation.key, values)
    elif name == "Analyst":
        condition = Remediation.user_id.in_(
            select(User.id).where(or_(contains_any(User.display_name, values), contains_any(User.username, values))))
    elif name == "Action":
        condition = Remediation.action.in_(values)
    elif name == "Status":
        condition = Remediation.status.in_(values)
    elif name == "Result":
        condition = Remediation.result.in_(values)
    elif name == "Created":
        condition = date_range_condition(Remediation.insert_date, values, tz)
    else:
        raise ValueError(f"unknown remediations filter {name!r}")

    return inverse(condition) if entry.get("inverted") else condition


def remediation_filter_conditions(entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list, to be ANDed."""
    return [remediation_filter_condition(entry, tz) for entry in merge_entries(entries)]
