"""Filter screen schemas for ACE API v2."""

from pydantic import BaseModel, ConfigDict, Field

from saq.gui.filter_entry import FilterEntryBase
from saq.gui.filter_screens import FilterFieldKind


class FilterDescriptor(BaseModel):
    """One filter a screen supports."""

    name: str = Field(description="the filter's name, as it appears in a filter entry")
    slug: str = Field(description="the filter's name in a share link's f= parameter; permanent")
    kind: FilterFieldKind | None = Field(default=None, description="how a generic editor edits it; null when the screen has its own editor")
    options: list[str] = Field(default_factory=list, description="the values a multi field offers")


class FilterScreenRead(BaseModel):
    """What a screen filters on, for a generic filter editor."""

    name: str
    filters: list[FilterDescriptor]


class FilterList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filters: list[FilterEntryBase] = Field(default_factory=list)


class EncodedFilters(BaseModel):
    f: list[str] = Field(description="the f= query parameter values of a share link, in order")


class DecodedFilters(BaseModel):
    filters: list[FilterEntryBase]
    warnings: list[str] = Field(default_factory=list, description="filters the link names that no longer exist; they were skipped")
