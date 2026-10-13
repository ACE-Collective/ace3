"""The SQL of the SVS validations screen's filters (saq.gui.filter_screens.SVS_VALIDATIONS_SCREEN).

Each entry becomes one condition on svs_validations: the values of an entry are ORed, the entries
are ANDed (repeats of one filter are merged first), and an inverted entry matches exactly the rows
the entry does not, including rows whose value is NULL (a validation that has not completed has no
counts).
"""

from datetime import tzinfo

import pytz
from sqlalchemy import case, false, or_, true
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import SVSValidation
from saq.svs.filters import date_range_condition, flag_condition


def validation_filter_condition(entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition of one validated filter entry ({name, inverted, values})."""
    name, values = entry["name"], entry["values"]
    if name == "Repository":
        condition = or_(*[SVSValidation.repository.contains(value, autoescape=True) for value in values])
    elif name == "Branch":
        condition = or_(*[SVSValidation.branch.contains(value, autoescape=True) for value in values])
    elif name == "Head":
        condition = or_(*[SVSValidation.head_sha.startswith(value, autoescape=True) for value in values])
    elif name == "State":
        condition = SVSValidation.state.in_(values)
    elif name == "Has Regressions":
        condition = flag_condition(SVSValidation.regressions, values)
    elif name == "Has New FP":
        condition = flag_condition(SVSValidation.new_fps, values)
    elif name == "Compile Errors":
        condition = flag_condition(SVSValidation.compile_errors, values)
    elif name == "Created":
        condition = date_range_condition(SVSValidation.created_at, values, tz)
    else:
        raise ValueError(f"unknown validations filter {name!r}")

    if not entry.get("inverted"):
        return condition

    # as for samples: a CASE keeps the rows whose value is NULL in the inverse
    return case((condition, false()), else_=true())


def validation_filter_conditions(entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list, to be ANDed; repeats of one filter with the same polarity are
    merged into one entry first."""
    merged: dict[tuple[str, bool], list[str]] = {}
    for entry in entries:
        merged.setdefault((entry["name"], bool(entry.get("inverted"))), []).extend(entry["values"])

    return [validation_filter_condition({"name": name, "inverted": inverted, "values": values}, tz)
            for (name, inverted), values in merged.items()]
