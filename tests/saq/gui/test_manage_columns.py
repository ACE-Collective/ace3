import re
from pathlib import Path

import pytest

from saq.gui.manage_columns import (
    MANAGE_COLUMN_IDS,
    MANAGE_COLUMNS,
    REQUIRED_MANAGE_COLUMN_IDS,
    normalize_column_order,
    normalize_hidden_columns,
)

pytestmark = pytest.mark.unit


def test_registry_is_well_formed():
    assert len(set(MANAGE_COLUMN_IDS)) == len(MANAGE_COLUMN_IDS)
    assert "description" in REQUIRED_MANAGE_COLUMN_IDS
    assert all(column.label for column in MANAGE_COLUMNS)


def test_normalize_column_order():
    assert normalize_column_order([]) == list(MANAGE_COLUMN_IDS)
    assert normalize_column_order(["status", "bogus", "status", "date"])[:2] == ["status", "date"]
    assert set(normalize_column_order(["status"])) == set(MANAGE_COLUMN_IDS)
    reversed_ids = list(reversed(MANAGE_COLUMN_IDS))
    assert normalize_column_order(reversed_ids) == reversed_ids


def test_normalize_hidden_columns():
    assert normalize_hidden_columns([]) == []
    assert normalize_hidden_columns(["description"]) == []
    assert normalize_hidden_columns(["bogus", "status", "date", "date"]) == ["date", "status"]


def test_every_registered_column_has_template_markup():
    """A ColumnSpec without a branch in _manage_columns.html would render an empty header
    and cell for that column."""
    template = Path(__file__).resolve().parents[3] / "app" / "templates" / "analysis" / "_manage_columns.html"
    source = template.read_text()
    header_ids = set(re.findall(r"column\.id == '([a-z_]+)'", source.split("{% macro column_cell")[0]))
    cell_ids = set(re.findall(r"data-col-id=\"([a-z_]+)\"", source))
    for column_id in MANAGE_COLUMN_IDS:
        assert column_id in cell_ids, f"no cell markup for column {column_id!r}"
    # header branches beyond the generic one must name real columns
    assert header_ids <= set(MANAGE_COLUMN_IDS)
