"""User preference schemas for ACE API v2.

A preference is a durable per-user GUI setting: something an analyst configures once and
expects to keep across browsers and logins. Transient view state (sort order, page offset,
checked rows) is NOT a preference and stays in the Flask session.

Every preference key is registered in PREFERENCE_SCHEMAS with the Pydantic model that
validates and normalizes its value. That model is the single gate for the API, for the
Flask views that read the stored value back, and for the defaults a user without a stored
row gets -- so a stale stored value (a column id that no longer exists) is repaired the
same way on every path.

To add a preference: write its model with defaults for every field, and add it to
PREFERENCE_SCHEMAS. Nothing else needs to change.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from saq.gui.manage_columns import normalize_column_order, normalize_hidden_columns


class ManageColumnsPreference(BaseModel):
    """Which columns the alert management table shows, and in what order.

    Two lists rather than one list of visible columns: with one list, a column added in a
    later release would be indistinguishable from one the analyst hid, and would stay
    hidden for everyone who had ever customized. `order` is always normalized to the
    complete column set, and `hidden` never contains a required column."""

    model_config = ConfigDict(extra="forbid")

    # validate_default: the validator is what expands an empty list to the full column set,
    # and pydantic skips validators on defaults unless told otherwise
    order: list[str] = Field(default_factory=list, validate_default=True, description="every column id, in display order")
    hidden: list[str] = Field(default_factory=list, description="the column ids not shown")

    @field_validator("order")
    @classmethod
    def normalize_order(cls, value: list[str]) -> list[str]:
        return normalize_column_order(value)

    @field_validator("hidden")
    @classmethod
    def normalize_hidden(cls, value: list[str]) -> list[str]:
        return normalize_hidden_columns(value)

    @property
    def visible(self) -> list[str]:
        return [column_id for column_id in self.order if column_id not in self.hidden]


PREFERENCE_KEY_MANAGE_COLUMNS = "manage_columns"

# key -> the model that validates its value. The model's defaults are the preference's
# default, so every key has a value even for a user who never stored one.
PREFERENCE_SCHEMAS: dict[str, type[BaseModel]] = {
    PREFERENCE_KEY_MANAGE_COLUMNS: ManageColumnsPreference,
}


class PreferenceRead(BaseModel):
    """One preference as returned to callers."""

    key: str
    value: dict[str, Any]
    # None when the caller has no stored row and is seeing the default
    updated_at: datetime | None = None
    # True when the value is the built-in default rather than something the caller saved
    is_default: bool


class PreferencesRead(BaseModel):
    """Every registered preference for the caller, defaults filled in."""

    data: dict[str, PreferenceRead]
