"""The filter screen registry (saq/gui/filter_screens.py)."""

import pytest
from pydantic import ValidationError

from aceapi_v2.saved_filters.service import DEFAULT_SAVED_FILTERS
from saq.gui.filter_entry import DetectionPointFilterEntry, FilterEntry, FilterEntryBase, SampleFilterEntry
from saq.gui.filter_names import FILTER_NAMES, FILTER_SLUGS
from saq.gui.filter_screens import (
    ALERTS_SCREEN,
    DETECTION_POINTS_SCREEN,
    FILTER_SCREENS,
    SVS_SAMPLES_SCREEN,
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


def test_the_detection_points_screen():
    assert get_filter_screen("detection_points") is DETECTION_POINTS_SCREEN
    assert DETECTION_POINTS_SCREEN.entry_model is DetectionPointFilterEntry
    assert DETECTION_POINTS_SCREEN.names_by_slug["verdict"] == "Verdict"


@pytest.mark.parametrize("name, values, expected", [
    ("Signature", ["AAAAAAAA-aaaa-aaaa-aaaa-aaaaaaaaaaaa:abc123"], ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:abc123"]),
    ("Family", ["YARA", "hunt"], ["yara", "hunt"]),
    ("Verdict", ["TP", "none"], ["tp", "none"]),
    ("Source", ["inherited_multi"], ["inherited_multi"]),
    ("Has Override", ["True"], ["true"]),
    ("Queue", ["default"], ["default"]),
    ("Alert Date", ["-90d"], ["-90d"]),
])
def test_detection_points_values_are_normalized(name, values, expected):
    (entry,) = DETECTION_POINTS_SCREEN.validate_entries([{"name": name, "values": values}])
    assert entry.values == expected


@pytest.mark.parametrize("name, values", [
    ("Signature", ["not-a-uuid"]),
    ("Family", ["sigma"]),
    ("Verdict", ["maybe"]),
    ("Source", ["inherited"]),
    ("Has Override", ["yes"]),
    ("Alert Date", ["not a date"]),
    ("Queue", [["pair", "value"]]),
    ("Tag", ["x"]),
])
def test_detection_points_rejects_bad_entries(name, values):
    with pytest.raises(ValidationError):
        DETECTION_POINTS_SCREEN.validate_entries([{"name": name, "values": values}])


def test_unconfirmed_detections_takes_true_or_false():
    (entry,) = ALERTS_SCREEN.validate_entries([{"name": "Unconfirmed Detections", "values": ["True"]}])
    assert entry.values == ["True"]
    with pytest.raises(ValidationError):
        ALERTS_SCREEN.validate_entries([{"name": "Unconfirmed Detections", "values": ["yes"]}])


def test_screens_default_to_the_alert_permission():
    assert ALERTS_SCREEN.permission == ("alert", "read")
    assert DETECTION_POINTS_SCREEN.permission == ("alert", "read")


def test_the_svs_samples_screen():
    assert get_filter_screen("svs_samples") is SVS_SAMPLES_SCREEN
    assert SVS_SAMPLES_SCREEN.entry_model is SampleFilterEntry
    # part of the Signatures area
    assert SVS_SAMPLES_SCREEN.permission == ("signature", "read")
    # a generic editor edits every filter
    assert {f.name for f in SVS_SAMPLES_SCREEN.fields} == SVS_SAMPLES_SCREEN.filter_names


def test_the_svs_sample_slugs_are_a_permanent_contract():
    # share links and saved filters carry these; never rename or remove one
    assert dict(SVS_SAMPLES_SCREEN.slugs) == {
        "Alert": "alert",
        "File Name": "file_name",
        "Label": "label",
        "Label Source": "label_source",
        "Last Captured": "last_captured",
        "Missing Data": "missing_data",
        "Rule": "rule",
        "SHA256": "sha256",
        "Signature": "signature",
        "Stored": "stored",
        "Unknown Version": "unknown_version",
    }


@pytest.mark.parametrize("name, values, expected", [
    ("Signature", ["7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f"], ["7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f"]),
    ("SHA256", [" " + "AB" * 32], ["ab" * 32]),
    ("Alert", ["AAAAAAAA-aaaa-aaaa-aaaa-aaaaaaaaaaaa"], ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]),
    ("Label", ["TP", "Conflicted", "none"], ["tp", "conflicted", "none"]),
    ("Label Source", ["explicit"], ["explicit"]),
    ("Stored", ["True"], ["true"]),
    ("Last Captured", ["-30d"], ["-30d"]),
    ("Rule", ["Some_Rule"], ["Some_Rule"]),
    ("File Name", [".DOC"], [".DOC"]),
])
def test_svs_sample_values_are_normalized(name, values, expected):
    (entry,) = SVS_SAMPLES_SCREEN.validate_entries([{"name": name, "values": values}])
    assert entry.values == expected


@pytest.mark.parametrize("name, values", [
    ("Signature", ["a b"]),
    ("SHA256", ["abc"]),
    ("Alert", ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa-trailing"]),
    ("Label", ["maybe"]),
    ("Label Source", ["inherited"]),
    ("Missing Data", ["yes"]),
    ("Last Captured", ["not a date"]),
    ("Rule", [["pair", "value"]]),
    ("Verdict", ["tp"]),
])
def test_svs_samples_rejects_bad_entries(name, values):
    with pytest.raises(ValidationError):
        SVS_SAMPLES_SCREEN.validate_entries([{"name": name, "values": values}])


@pytest.mark.parametrize("screen", sorted(DEFAULT_SAVED_FILTERS))
def test_default_saved_filters_are_valid_on_their_screen(screen):
    for spec in DEFAULT_SAVED_FILTERS[screen]:
        get_filter_screen(screen).validate_entries(spec["filters"])


def test_fields_must_name_the_screens_filters():
    from saq.gui.filter_screens import FilterField, FilterFieldKind

    FilterScreen(name="ok", entry_model=FilterEntryBase, slugs={"Color": "color"},
                 fields=(FilterField("Color", FilterFieldKind.MULTI, ("red", "blue")),))
    with pytest.raises(ValueError, match="Shape"):
        FilterScreen(name="bad", entry_model=FilterEntryBase, slugs={"Color": "color"},
                     fields=(FilterField("Shape", FilterFieldKind.TEXT),))
