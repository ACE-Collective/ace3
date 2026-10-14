"""The SQL of the SVS tests screen's filters (saq.gui.filter_screens.SVS_TESTS_SCREEN).

Each entry becomes one condition on svs_catalog_tests: the values of an entry are ORed, the entries
are ANDed (repeats of one filter are merged first), and an inverted entry matches exactly the rows
the entry does not, including rows whose value is NULL. A technique matches its sub-techniques
too: T1059 finds T1059.001.
"""

from sqlalchemy import case, false, or_, true
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import SVSCatalogTest


def _technique(value: str) -> ColumnElement[bool]:
    if "." in value:
        return SVSCatalogTest.technique == value
    return or_(SVSCatalogTest.technique == value, SVSCatalogTest.technique.startswith(f"{value}.", autoescape=True))


def catalog_filter_condition(entry: dict) -> ColumnElement[bool]:
    """The condition of one validated filter entry ({name, inverted, values})."""
    name, values = entry["name"], entry["values"]
    if name == "Technique":
        condition = or_(*[_technique(value) for value in values])
    elif name == "Name":
        condition = or_(*[SVSCatalogTest.name.contains(value, autoescape=True) for value in values])
    elif name == "Platform":
        # platforms is a JSON list of lower-case names
        condition = or_(*[SVSCatalogTest.platforms.contains(f'"{value}"', autoescape=True) for value in values])
    elif name == "Executor":
        condition = SVSCatalogTest.executor.in_(values)
    elif name == "Repository":
        condition = or_(*[SVSCatalogTest.repository.contains(value, autoescape=True) for value in values])
    elif name == "Removed":
        if values == ["true"]:
            condition = SVSCatalogTest.removed_at.isnot(None)
        elif values == ["false"]:
            condition = SVSCatalogTest.removed_at.is_(None)
        else:
            condition = true()
    else:
        raise ValueError(f"unknown tests filter {name!r}")

    if not entry.get("inverted"):
        return condition

    # a CASE keeps the rows whose value is NULL in the inverse
    return case((condition, false()), else_=true())


def catalog_filter_conditions(entries: list[dict]) -> list[ColumnElement[bool]]:
    """The conditions of a filter list, to be ANDed; repeats of one filter with the same polarity are
    merged into one entry first."""
    merged: dict[tuple[str, bool], list[str]] = {}
    for entry in entries:
        merged.setdefault((entry["name"], bool(entry.get("inverted"))), []).extend(entry["values"])

    return [catalog_filter_condition({"name": name, "inverted": inverted, "values": values})
            for (name, inverted), values in merged.items()]
