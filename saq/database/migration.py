"""Alembic autogenerate hooks shared by alembic/ace/env.py and bin/check_model_drift.py."""

from sqlalchemy import Index
from sqlalchemy.sql.elements import UnaryExpression


def _column_names(index: Index) -> list[str]:
    """Returns the column names of an index, with any desc()/asc() ordering removed."""
    names = []
    for expr in index.expressions:
        if isinstance(expr, UnaryExpression) and expr.modifier is not None:
            expr = expr.element
        names.append(getattr(expr, "name", None) or str(expr))
    return names


def _has_ordering(index: Index) -> bool:
    return any(isinstance(expr, UnaryExpression) and expr.modifier is not None for expr in index.expressions)


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Alembic include_object hook that suppresses false index changes on ordered indexes.

    MySQL reflection drops the direction of an index column, so an index declared with
    desc('col') always compares as changed against the database: autogenerate emits a drop
    and a re-create of the same index even though the schema matches. When alembic is
    comparing an existing index (compare_to is the reflected one), the model index has an
    ordering expression, and the two agree on columns and uniqueness, the change is skipped.

    A DESC <-> ASC flip on the same columns is therefore not detected; reflection cannot see
    it either way. Added and removed indexes (compare_to is None) are never filtered.
    """
    if type_ != "index" or compare_to is None:
        return True

    if not _has_ordering(obj):
        return True

    return not (
        _column_names(obj) == _column_names(compare_to)
        and bool(obj.unique) == bool(compare_to.unique)
    )
