"""The SQL of the File Collections screen's filters
(saq.gui.filter_screens.FILE_COLLECTIONS_SCREEN).

Each entry becomes one condition on file_collection (see saq/gui/filter_conditions.py); an
inverted entry also matches the rows whose value is NULL, such as a collection that has no result
yet or no alert.
"""

from datetime import tzinfo

import pytz
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import FileCollection
from saq.gui.filter_conditions import contains_any, date_range_condition, inverse, merge_entries


def file_collection_filter_condition(entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition of one validated filter entry ({name, inverted, values})."""
    name, values = entry["name"], entry["values"]
    if name == "ID":
        condition = FileCollection.id.in_([int(value) for value in values])
    elif name == "Collector":
        condition = contains_any(FileCollection.name, values)
    elif name == "Type":
        condition = contains_any(FileCollection.type, values)
    elif name == "Value":
        condition = contains_any(FileCollection.key, values)
    elif name == "Alert":
        condition = FileCollection.alert_uuid.in_(values)
    elif name == "Status":
        condition = FileCollection.status.in_(values)
    elif name == "Result":
        condition = FileCollection.result.in_(values)
    elif name == "Created":
        condition = date_range_condition(FileCollection.insert_date, values, tz)
    else:
        raise ValueError(f"unknown file collections filter {name!r}")

    return inverse(condition) if entry.get("inverted") else condition


def file_collection_filter_conditions(entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list, to be ANDed."""
    return [file_collection_filter_condition(entry, tz) for entry in merge_entries(entries)]
