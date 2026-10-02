"""The screens that have filter lists, saved filters and share links.

Every list screen (the alert manage page, and later the SVS screens) filters with the same
{name, inverted, values} entries and stores them in the same saved_filters table, keyed by
screen. What differs per screen is which filter names exist, what their values may be, and
the URL slugs its share links use. A FilterScreen carries exactly that."""

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from pydantic import BaseModel

from saq.gui.filter_entry import FilterEntry, FilterEntryBase
from saq.gui.filter_names import FILTER_SLUGS


class UnknownFilterScreen(LookupError):
    """No screen with that name is registered."""


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

FILTER_SCREENS: dict[str, FilterScreen] = {ALERTS_SCREEN.name: ALERTS_SCREEN}


def register_filter_screen(screen: FilterScreen) -> None:
    if screen.name in FILTER_SCREENS:
        raise ValueError(f"filter screen {screen.name!r} is already registered")

    FILTER_SCREENS[screen.name] = screen


def get_filter_screen(name: str) -> FilterScreen:
    try:
        return FILTER_SCREENS[name]
    except KeyError:
        raise UnknownFilterScreen(f"unknown filter screen {name!r}") from None
