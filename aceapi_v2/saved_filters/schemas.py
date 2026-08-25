"""Saved filter schemas for ACE API v2."""

from datetime import datetime
from typing import Optional, Union

import pytz
from pydantic import BaseModel, ConfigDict, Field, field_validator

from saq.gui.filter_names import DATE_RANGE_FILTER_NAMES, FILTER_NAMES
from saq.util.relative_time import parse_date_range

# the row kinds a client is allowed to write directly
SCRATCH_KINDS = ("working", "temp")


class FilterEntry(BaseModel):
    """One entry of a filter list -- the {name, inverted, values} shape the GUI's filter
    editor produces, the database stores, and a share URL encodes.

    This is the single validation gate for all three doors: a modal save, an API call, and
    a hand-edited wiki link are all held to the same standard."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="a filter name supported by create_filter()")
    inverted: bool = Field(default=False, description="negate this filter")
    # str for every filter except Observable, whose values are [type, value] pairs
    values: list[Union[str, list[str]]] = Field(min_length=1, description="the values to filter on")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in FILTER_NAMES:
            raise ValueError(f"unknown filter name {value!r} (expected one of {', '.join(sorted(FILTER_NAMES))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        """Reject an unparseable date token at WRITE time.
        """
        if info.data.get("name") not in DATE_RANGE_FILTER_NAMES:
            return values

        now = datetime.now(pytz.utc)
        for value in values:
            if not isinstance(value, str):
                raise ValueError(f"date range value must be a string, got {value!r}")
            try:
                parse_date_range(value, now=now, tz=pytz.utc)
            except ValueError as e:
                raise ValueError(f"invalid date range {value!r}: {e}") from None

        return values


class SavedFilterRead(BaseModel):
    """A saved filter as returned to callers."""

    # Services return THIS, never the ORM row: run_async_with_session() closes the async
    # session before the caller sees the result, so a returned SavedFilter would be detached
    # and touching a lazy relationship in a Jinja template would raise at render time.

    uuid: str
    kind: str
    name: Optional[str] = None
    description: Optional[str] = None
    filters: list[FilterEntry]
    quick_filter_order: Optional[int] = None
    quick_filter_indicator: bool = False
    owner_id: int
    owner_display_name: str
    created_at: datetime
    updated_at: datetime


class SavedFilterCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1024)
    filters: list[FilterEntry] = Field(min_length=1)
    quick_filter: bool = Field(default=False, description="pin as a quick filter badge")
    quick_filter_indicator: bool = Field(default=False, description="show an alert count on the badge")


class SavedFilterUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1024)
    filters: Optional[list[FilterEntry]] = Field(default=None, min_length=1)
    quick_filter_indicator: Optional[bool] = None


class QuickFilterOrder(BaseModel):
    """The complete, ordered set of pinned quick filters. Anything not listed is unpinned,
    which makes the call idempotent and lets a reorder UI submit its whole state."""

    model_config = ConfigDict(extra="forbid")

    filter_uuids: list[str] = Field(default_factory=list)


class ScratchFilterWrite(BaseModel):
    """Replace the caller's singleton `working` or `temp` row."""

    model_config = ConfigDict(extra="forbid")

    filters: list[FilterEntry] = Field(default_factory=list)
    label: Optional[str] = Field(default=None, max_length=1024)
