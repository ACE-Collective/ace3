import pytest
from sqlalchemy import Column, DateTime, Index, Integer, MetaData, String, Table, desc

from saq.database.migration import include_object


def _table(name: str) -> Table:
    return Table(
        name,
        MetaData(),
        Column("id", Integer, primary_key=True),
        Column("status", String(32)),
        Column("name", String(512)),
        Column("insert_date", DateTime),
    )


def _model_index(*expressions, unique: bool = False) -> Index:
    """An index as declared on a model, e.g. with desc('insert_date')."""
    table = _table("model")
    return Index("idx_test", *[table.c[e] if isinstance(e, str) else e for e in expressions], unique=unique, _table=table)


def _reflected_index(*columns: str, unique: bool = False) -> Index:
    """An index as reflected from MySQL, which carries no column direction."""
    table = _table("reflected")
    return Index("idx_test", *[table.c[c] for c in columns], unique=unique, _table=table)


@pytest.mark.unit
def test_ordered_index_matching_reflection_is_skipped():
    model = _model_index("status", "name", desc("insert_date"))
    reflected = _reflected_index("status", "name", "insert_date")
    assert include_object(model, "idx_test", "index", False, reflected) is False


@pytest.mark.unit
def test_ordered_index_with_different_columns_is_included():
    model = _model_index("status", desc("insert_date"))
    reflected = _reflected_index("status", "name", "insert_date")
    assert include_object(model, "idx_test", "index", False, reflected) is True


@pytest.mark.unit
def test_ordered_index_with_different_uniqueness_is_included():
    model = _model_index("status", "name", desc("insert_date"), unique=True)
    reflected = _reflected_index("status", "name", "insert_date")
    assert include_object(model, "idx_test", "index", False, reflected) is True


@pytest.mark.unit
@pytest.mark.parametrize("reflected", [False, True])
def test_added_or_removed_index_is_included(reflected):
    index = _model_index("status", "name", desc("insert_date"))
    assert include_object(index, "idx_test", "index", reflected, None) is True


@pytest.mark.unit
def test_plain_index_is_left_to_alembic():
    model = _model_index("status", "name", "insert_date")
    reflected = _reflected_index("status", "name", "insert_date")
    assert include_object(model, "idx_test", "index", False, reflected) is True


@pytest.mark.unit
def test_non_index_objects_are_included():
    table = _table("model")
    assert include_object(table, "model", "table", False, _table("reflected")) is True
    assert include_object(table.c.status, "status", "column", False, None) is True
