"""Saved filter schemas for ACE API v2."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

# FilterEntry is the alert screen's entry model; it is re-exported here because the search API
# and the Flask views import it from this module
from saq.gui.filter_entry import FilterEntry, FilterEntryBase

__all__ = [
    "FilterEntry",
    "FilterEntryBase",
    "QuickFilterOrder",
    "SavedFilterCreate",
    "SavedFilterRead",
    "SavedFilterUpdate",
    "ScratchFilterWrite",
    "SCRATCH_KINDS",
]

# the row kinds a client is allowed to write directly
SCRATCH_KINDS = ("working", "temp")


class SavedFilterRead(BaseModel):
    """A saved filter as returned to callers."""

    # Services return THIS, never the ORM row: run_async_with_session() closes the async
    # session before the caller sees the result, so a returned SavedFilter would be detached
    # and touching a lazy relationship in a Jinja template would raise at render time.

    uuid: str
    screen: str
    kind: str
    name: Optional[str] = None
    description: Optional[str] = None
    filters: list[FilterEntryBase]
    quick_filter_order: Optional[int] = None
    quick_filter_indicator: bool = False
    owner_id: int
    owner_display_name: str
    created_at: datetime
    updated_at: datetime


# The request models below check only the SHAPE of their filters (FilterEntryBase): which
# names and values are valid depends on the screen the filter belongs to, which the body does
# not carry, so the service validates them against that screen (FilterScreen.validate_entries).


class SavedFilterCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1024)
    filters: list[FilterEntryBase] = Field(min_length=1)
    quick_filter: bool = Field(default=False, description="pin as a quick filter badge")
    quick_filter_indicator: bool = Field(default=False, description="show an alert count on the badge")


class SavedFilterUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1024)
    filters: Optional[list[FilterEntryBase]] = Field(default=None, min_length=1)
    quick_filter_indicator: Optional[bool] = None


class QuickFilterOrder(BaseModel):
    """The complete, ordered set of pinned quick filters. Anything not listed is unpinned,
    which makes the call idempotent and lets a reorder UI submit its whole state."""

    model_config = ConfigDict(extra="forbid")

    filter_uuids: list[str] = Field(default_factory=list)


class ScratchFilterWrite(BaseModel):
    """Replace the caller's singleton `working` or `temp` row."""

    model_config = ConfigDict(extra="forbid")

    filters: list[FilterEntryBase] = Field(default_factory=list)
    label: Optional[str] = Field(default=None, max_length=1024)
