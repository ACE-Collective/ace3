"""The screens that have filter lists, saved filters and share links.

Every list screen (the alert manage page, and later the SVS screens) filters with the same
{name, inverted, values} entries and stores them in the same saved_filters table, keyed by
screen. What differs per screen is which filter names exist, what their values may be, and
the URL slugs its share links use, and who may use it. A FilterScreen carries exactly that.

A screen built as a shell over the API (the SVS screens) also describes its filters as fields,
so a generic filter editor (app/static/js/filter_list_page.js) can be built from the
descriptor GET /api/v2/filter-screens/{screen} returns. The alert manage page has its own
editor and describes none."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable, Mapping

from pydantic import BaseModel

from saq.gui.filter_entry import DetectionPointFilterEntry, FilterEntry, FilterEntryBase
from saq.gui.filter_names import DETECTION_POINT_FILTER_SLUGS, FILTER_SLUGS


class UnknownFilterScreen(LookupError):
    """No screen with that name is registered."""


class FilterFieldKind(StrEnum):
    TEXT = "text"              # free text, one or more values
    MULTI = "multi"            # one or more of a fixed set of options
    DATE_RANGE = "date_range"  # a relative token (-7d) or an absolute range
    BOOL = "bool"              # true or false


@dataclass(frozen=True)
class FilterField:
    """How a generic editor edits one filter of a screen."""
    # the filter's display name, a key of FilterScreen.slugs
    name: str
    kind: FilterFieldKind
    # the values a MULTI field offers
    options: tuple[str, ...] = ()


@dataclass(frozen=True)
class FilterScreen:
    # the saved_filters.screen value; never rename one, saved filters are keyed on it
    name: str
    # validates one entry: the filter names this screen supports and their values
    entry_model: type[FilterEntryBase]
    # display name -> URL slug, a permanent contract (see saq/gui/filter_names.py)
    slugs: Mapping[str, str]
    # filters whose values are [type, value] pairs in a share link
    pair_filter_names: frozenset[str] = field(default_factory=frozenset)
    # (major, minor): the permission that reads this screen's data, which is also the one its
    # saved filters and its filter descriptor require
    permission: tuple[str, str] = ("alert", "read")
    # how a generic editor edits each filter, for screens that have one
    fields: tuple[FilterField, ...] = ()

    def __post_init__(self):
        unknown = [f.name for f in self.fields if f.name not in self.slugs]
        if unknown:
            raise ValueError(f"filter screen {self.name!r} describes unknown filters: {', '.join(unknown)}")

    @property
    def filter_names(self) -> frozenset[str]:
        return frozenset(self.slugs)

    @property
    def names_by_slug(self) -> dict[str, str]:
        return {slug: name for name, slug in self.slugs.items()}

    def validate_entries(self, entries: Iterable) -> list[FilterEntryBase]:
        """Validate a filter list for this screen. Raises pydantic.ValidationError."""
        return [
            self.entry_model.model_validate(entry.model_dump() if isinstance(entry, BaseModel) else entry)
            for entry in entries or []
        ]


ALERTS_SCREEN = FilterScreen(
    name="alerts",
    entry_model=FilterEntry,
    slugs=FILTER_SLUGS,
    pair_filter_names=frozenset(["Observable"]),
)

# detections with their verdicts (GET /api/v2/detection-points, docs/SVS_API.md)
DETECTION_POINTS_SCREEN = FilterScreen(
    name="detection_points",
    entry_model=DetectionPointFilterEntry,
    slugs=DETECTION_POINT_FILTER_SLUGS,
)

FILTER_SCREENS: dict[str, FilterScreen] = {
    ALERTS_SCREEN.name: ALERTS_SCREEN,
    DETECTION_POINTS_SCREEN.name: DETECTION_POINTS_SCREEN,
}


def register_filter_screen(screen: FilterScreen) -> None:
    if screen.name in FILTER_SCREENS:
        raise ValueError(f"filter screen {screen.name!r} is already registered")

    FILTER_SCREENS[screen.name] = screen


def get_filter_screen(name: str) -> FilterScreen:
    try:
        return FILTER_SCREENS[name]
    except KeyError:
        raise UnknownFilterScreen(f"unknown filter screen {name!r}") from None
