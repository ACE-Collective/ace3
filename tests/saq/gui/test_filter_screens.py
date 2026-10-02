"""The filter screen registry (saq/gui/filter_screens.py)."""

import pytest
from pydantic import ValidationError

from saq.gui.filter_entry import FilterEntry, FilterEntryBase
from saq.gui.filter_names import FILTER_NAMES, FILTER_SLUGS
from saq.gui.filter_screens import (
    ALERTS_SCREEN,
    FILTER_SCREENS,
    FilterScreen,
    UnknownFilterScreen,
    get_filter_screen,
    register_filter_screen,
)

pytestmark = pytest.mark.unit


def test_the_alert_screen_is_the_manage_page_vocabulary():
    assert get_filter_screen("alerts") is ALERTS_SCREEN
    assert ALERTS_SCREEN.entry_model is FilterEntry
    assert ALERTS_SCREEN.filter_names == FILTER_NAMES
    assert ALERTS_SCREEN.slugs == FILTER_SLUGS
    assert ALERTS_SCREEN.names_by_slug["alert_date"] == "Alert Date"


def test_unknown_screen():
    with pytest.raises(UnknownFilterScreen):
        get_filter_screen("nope")


def test_register_refuses_a_duplicate(monkeypatch):
    monkeypatch.setattr("saq.gui.filter_screens.FILTER_SCREENS", dict(FILTER_SCREENS))
    screen = FilterScreen(name="test_screen", entry_model=FilterEntryBase, slugs={"Color": "color"})
    register_filter_screen(screen)
    assert get_filter_screen("test_screen") is screen
    with pytest.raises(ValueError):
        register_filter_screen(screen)


def test_validate_entries_uses_the_screens_entry_model():
    entries = ALERTS_SCREEN.validate_entries([{"name": "Queue", "inverted": False, "values": ["default"]}])
    assert isinstance(entries[0], FilterEntry)

    # an existing model instance is revalidated against the screen, not trusted
    shape_only = FilterEntryBase(name="Color", values=["red"])
    with pytest.raises(ValidationError):
        ALERTS_SCREEN.validate_entries([shape_only])

    with pytest.raises(ValidationError):
        ALERTS_SCREEN.validate_entries([{"name": "Alert Date", "inverted": False, "values": ["not a date"]}])


def test_entry_base_checks_shape_only():
    entry = FilterEntryBase.model_validate({"name": "anything", "values": ["x", ["a", "b"]]})
    assert entry.inverted is False
    with pytest.raises(ValidationError):
        FilterEntryBase.model_validate({"name": "x", "values": []})
    with pytest.raises(ValidationError):
        FilterEntryBase.model_validate({"name": "x", "values": ["y"], "extra": 1})
