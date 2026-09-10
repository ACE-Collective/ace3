"""The column registry of the alert management page.

Every column the alert table can show is declared here, in default order. The table
template renders whichever of these the analyst's `manage_columns` preference (see
aceapi_v2/user_preferences/schemas.py) leaves visible, in the order it gives, so this
module is the one place that knows what a column IS. The header and cell markup for each
id lives in app/templates/analysis/_manage_columns.html; test_manage_columns_registry
keeps the two in step.

Kept free of Flask and Pydantic imports so both the preference schema and the Flask
views can import it.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ColumnSpec:
    id: str
    label: str
    # the sort_filter name a click on the header sorts by; None means not sortable
    sort_key: str | None = None
    # a required column can be reordered but never hidden
    required: bool = False


MANAGE_COLUMNS: tuple[ColumnSpec, ...] = (
    ColumnSpec("date", "Date", sort_key="Alert Date"),
    ColumnSpec("description", "Alert", sort_key="Description", required=True),
    ColumnSpec("remediation", "Remediation"),
    ColumnSpec("queue", "Queue", sort_key="Queue"),
    ColumnSpec("owner", "Owner", sort_key="Owner"),
    ColumnSpec("disposition", "Disposition", sort_key="Disposition"),
    ColumnSpec("status", "Status"),
)

MANAGE_COLUMNS_BY_ID: dict[str, ColumnSpec] = {column.id: column for column in MANAGE_COLUMNS}
MANAGE_COLUMN_IDS: tuple[str, ...] = tuple(column.id for column in MANAGE_COLUMNS)
REQUIRED_MANAGE_COLUMN_IDS: frozenset[str] = frozenset(column.id for column in MANAGE_COLUMNS if column.required)


def normalize_column_order(order: list[str]) -> list[str]:
    """The complete column order for a stored (possibly stale) preference: unknown ids are
    dropped, duplicates collapse to their first position, and any column the preference
    does not mention is appended in default order. A column added in a later release
    therefore shows up for everyone instead of silently never rendering."""
    seen: list[str] = []
    for column_id in order:
        if column_id in MANAGE_COLUMNS_BY_ID and column_id not in seen:
            seen.append(column_id)

    for column_id in MANAGE_COLUMN_IDS:
        if column_id not in seen:
            seen.append(column_id)

    return seen


def normalize_hidden_columns(hidden: list[str]) -> list[str]:
    """The hidden set of a stored preference: unknown ids and required columns are dropped,
    duplicates collapse, and the result is in default column order so two preferences
    that hide the same columns serialize identically."""
    wanted = set(hidden) - REQUIRED_MANAGE_COLUMN_IDS
    return [column_id for column_id in MANAGE_COLUMN_IDS if column_id in wanted]
