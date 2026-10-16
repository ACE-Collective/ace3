"""The filter screen registry (saq/gui/filter_screens.py)."""

import pytest
from pydantic import ValidationError

from aceapi_v2.saved_filters.service import DEFAULT_SAVED_FILTERS
from saq.gui.filter_entry import (
    DetectionPointFilterEntry,
    FileCollectionFilterEntry,
    FilterEntry,
    FilterEntryBase,
    RemediationFilterEntry,
    RunFilterEntry,
    SampleFilterEntry,
    ValidationFilterEntry,
)
from saq.gui.filter_names import FILTER_NAMES, FILTER_SLUGS
from saq.gui.filter_screens import (
    ALERTS_SCREEN,
    DETECTION_POINTS_SCREEN,
    FILE_COLLECTIONS_SCREEN,
    FILTER_SCREENS,
    REMEDIATIONS_SCREEN,
    SVS_COVERAGE_HISTORY_SCREEN,
    SVS_COVERAGE_SCREEN,
    SVS_RUNS_SCREEN,
    SVS_SAMPLES_SCREEN,
    SVS_VALIDATIONS_SCREEN,
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
        "Retired": "retired",
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
    ("Retired", ["False"], ["false"]),
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
    ("Retired", ["maybe"]),
    ("Last Captured", ["not a date"]),
    ("Rule", [["pair", "value"]]),
    ("Verdict", ["tp"]),
])
def test_svs_samples_rejects_bad_entries(name, values):
    with pytest.raises(ValidationError):
        SVS_SAMPLES_SCREEN.validate_entries([{"name": name, "values": values}])


def test_the_svs_validations_screen():
    assert get_filter_screen("svs_validations") is SVS_VALIDATIONS_SCREEN
    assert SVS_VALIDATIONS_SCREEN.entry_model is ValidationFilterEntry
    assert SVS_VALIDATIONS_SCREEN.permission == ("signature", "read")
    assert {f.name for f in SVS_VALIDATIONS_SCREEN.fields} == SVS_VALIDATIONS_SCREEN.filter_names


def test_the_svs_validation_slugs_are_a_permanent_contract():
    # share links and saved filters carry these; never rename or remove one
    assert dict(SVS_VALIDATIONS_SCREEN.slugs) == {
        "Branch": "branch",
        "Compile Errors": "compile_errors",
        "Created": "created",
        "Has New FP": "has_new_fp",
        "Has Regressions": "has_regressions",
        "Head": "head",
        "Repository": "repository",
        "State": "state",
    }


@pytest.mark.parametrize("name, values, expected", [
    ("Head", [" ABCD1234"], ["abcd1234"]),
    ("State", ["Completed", "failed"], ["completed", "failed"]),
    ("Has Regressions", ["True"], ["true"]),
    ("Compile Errors", ["false"], ["false"]),
    ("Created", ["-7d"], ["-7d"]),
    ("Repository", ["Signatures"], ["Signatures"]),
])
def test_svs_validation_values_are_normalized(name, values, expected):
    (entry,) = SVS_VALIDATIONS_SCREEN.validate_entries([{"name": name, "values": values}])
    assert entry.values == expected


@pytest.mark.parametrize("name, values", [
    ("Head", ["abc"]),
    ("Head", ["not-hex!"]),
    ("State", ["done"]),
    ("Has New FP", ["yes"]),
    ("Created", ["not a date"]),
    ("Branch", [["pair", "value"]]),
    ("Label", ["tp"]),
])
def test_svs_validations_rejects_bad_entries(name, values):
    with pytest.raises(ValidationError):
        SVS_VALIDATIONS_SCREEN.validate_entries([{"name": name, "values": values}])


def test_the_svs_runs_screen():
    assert get_filter_screen("svs_runs") is SVS_RUNS_SCREEN
    assert SVS_RUNS_SCREEN.entry_model is RunFilterEntry
    assert SVS_RUNS_SCREEN.permission == ("svs", "run_read")
    assert {f.name for f in SVS_RUNS_SCREEN.fields} == SVS_RUNS_SCREEN.filter_names


def test_the_svs_run_slugs_are_a_permanent_contract():
    # share links and saved filters carry these; never rename or remove one
    assert dict(SVS_RUNS_SCREEN.slugs) == {
        "Batch": "batch",
        "Changed Since Review": "changed_since_review",
        "Created": "created",
        "Ended": "ended",
        "Has Candidates": "has_candidates",
        "Has Context Only": "has_context_only",
        "Has Late": "has_late",
        "Has Missing": "has_missing",
        "Has Open Alerts": "has_open_alerts",
        "Has Possibly Suppressed": "has_possibly_suppressed",
        "Launcher": "launcher",
        "Needs Attention": "needs_attention",
        "Owner": "owner",
        "Platform": "platform",
        "Reason": "reason",
        "Reviewed": "reviewed",
        "Reviewer": "reviewer",
        "Started": "started",
        "State": "state",
        "Target": "target",
        "Technique": "technique",
        "Test": "test",
        "Test Name": "test_name",
    }


@pytest.mark.parametrize("name, values, expected", [
    ("State", ["Ended", "error"], ["ended", "error"]),
    ("Technique", [" t1059.001"], ["T1059.001"]),
    ("Test", ["AAAAAAAA-1111-4111-8111-111111111111"], ["aaaaaaaa-1111-4111-8111-111111111111"]),
    ("Target", [" WIN10-01.Lab.Example"], ["win10-01.lab.example"]),
    ("Owner", [" Alice "], ["Alice"]),
    ("Needs Attention", ["True"], ["true"]),
    ("Started", ["-7d"], ["-7d"]),
    ("Reviewed", ["-30d"], ["-30d"]),
    ("Launcher", ["ART"], ["ART"]),
    ("Platform", [" Linux", "iaas:aws", "azure-ad"], ["linux", "iaas", "identity-provider"]),
])
def test_svs_run_values_are_normalized(name, values, expected):
    (entry,) = SVS_RUNS_SCREEN.validate_entries([{"name": name, "values": values}])
    assert entry.values == expected


@pytest.mark.parametrize("name, values", [
    ("State", ["done"]),
    ("Technique", ["1059"]),
    ("Test", ["not-a-guid"]),
    ("Needs Attention", ["yes"]),
    ("Changed Since Review", ["1"]),
    ("Ended", ["not a date"]),
    ("Reviewed", ["not a date"]),
    ("Batch", [["pair", "value"]]),
    ("Label", ["tp"]),
])
def test_svs_runs_rejects_bad_entries(name, values):
    with pytest.raises(ValidationError):
        SVS_RUNS_SCREEN.validate_entries([{"name": name, "values": values}])


@pytest.mark.parametrize("screen, entry_model, permission", [
    (REMEDIATIONS_SCREEN, RemediationFilterEntry, ("remediation", "read")),
    (FILE_COLLECTIONS_SCREEN, FileCollectionFilterEntry, ("file_collection", "read")),
])
def test_the_request_screens(screen, entry_model, permission):
    assert get_filter_screen(screen.name) is screen
    assert screen.entry_model is entry_model
    assert screen.permission == permission
    assert {f.name for f in screen.fields} == screen.filter_names


def test_the_request_screen_slugs_are_a_permanent_contract():
    # share links and saved filters carry these; never rename or remove one
    assert dict(REMEDIATIONS_SCREEN.slugs) == {
        "Action": "action",
        "Analyst": "analyst",
        "Created": "created",
        "ID": "id",
        "Remediator": "remediator",
        "Result": "result",
        "Status": "status",
        "Type": "type",
        "Value": "value",
    }
    assert dict(FILE_COLLECTIONS_SCREEN.slugs) == {
        "Alert": "alert",
        "Collector": "collector",
        "Created": "created",
        "ID": "id",
        "Result": "result",
        "Status": "status",
        "Type": "type",
        "Value": "value",
    }


@pytest.mark.parametrize("screen, name, values, expected", [
    (REMEDIATIONS_SCREEN, "ID", [" 42"], ["42"]),
    (REMEDIATIONS_SCREEN, "Action", ["REMOVE"], ["remove"]),
    (REMEDIATIONS_SCREEN, "Status", ["in_progress", "new"], ["IN_PROGRESS", "NEW"]),
    (REMEDIATIONS_SCREEN, "Result", ["not_found"], ["NOT_FOUND"]),
    (REMEDIATIONS_SCREEN, "Created", ["-7d"], ["-7d"]),
    (REMEDIATIONS_SCREEN, "Value", ["Evil.Example"], ["Evil.Example"]),
    (FILE_COLLECTIONS_SCREEN, "Alert", ["E5F7A1C2-0B3D-4E6F-8A9B-1C2D3E4F5A6B"], ["e5f7a1c2-0b3d-4e6f-8a9b-1c2d3e4f5a6b"]),
    (FILE_COLLECTIONS_SCREEN, "Result", ["host_offline"], ["HOST_OFFLINE"]),
])
def test_request_screen_values_are_normalized(screen, name, values, expected):
    (entry,) = screen.validate_entries([{"name": name, "values": values}])
    assert entry.values == expected


@pytest.mark.parametrize("screen, name, values", [
    (REMEDIATIONS_SCREEN, "ID", ["seven"]),
    (REMEDIATIONS_SCREEN, "Action", ["obliterate"]),
    (REMEDIATIONS_SCREEN, "Result", ["HOST_OFFLINE"]),
    (REMEDIATIONS_SCREEN, "Created", ["not a date"]),
    (REMEDIATIONS_SCREEN, "Alert", ["e5f7a1c2-0b3d-4e6f-8a9b-1c2d3e4f5a6b"]),
    (REMEDIATIONS_SCREEN, "Value", [["pair", "value"]]),
    (FILE_COLLECTIONS_SCREEN, "Alert", ["not-a-uuid"]),
    (FILE_COLLECTIONS_SCREEN, "Result", ["IGNORE"]),
    (FILE_COLLECTIONS_SCREEN, "Analyst", ["me"]),
])
def test_request_screens_reject_bad_entries(screen, name, values):
    with pytest.raises(ValidationError):
        screen.validate_entries([{"name": name, "values": values}])


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


def test_the_svs_coverage_screens():
    assert get_filter_screen("svs_coverage") is SVS_COVERAGE_SCREEN
    assert get_filter_screen("svs_coverage_history") is SVS_COVERAGE_HISTORY_SCREEN
    for screen in (SVS_COVERAGE_SCREEN, SVS_COVERAGE_HISTORY_SCREEN):
        assert screen.permission == ("svs", "run_read")
        assert {f.name for f in screen.fields} == screen.filter_names


def test_the_svs_coverage_slugs_are_a_permanent_contract():
    # share links and saved filters carry these; never rename or remove one
    assert dict(SVS_COVERAGE_SCREEN.slugs) == {
        "ATT&CK Platform": "attack_platform",
        "Catalog Status": "catalog_status",
        "Has Manual": "has_manual",
        "Level": "level",
        "Name": "name",
        "Own State": "own_state",
        "Platform": "platform",
        "Retired": "retired",
        "State": "state",
        "State Changed": "state_changed",
        "Tactic": "tactic",
        "Technique": "technique",
    }
    assert dict(SVS_COVERAGE_HISTORY_SCREEN.slugs) == {
        "Date": "date",
        "Level": "level",
        "Own State": "own_state",
        "Platform": "platform",
        "State": "state",
        "Technique": "technique",
    }


@pytest.mark.parametrize("name, values, expected", [
    ("Technique", [" t1059.001"], ["T1059.001"]),
    ("Tactic", ["execution", "ta0003"], ["TA0002", "TA0003"]),
    ("Platform", ["Windows", "iaas:aws", "azure-ad"], ["windows", "iaas", "identity-provider"]),
    ("State", ["Failing"], ["failing"]),
    ("Level", ["Sub-Technique"], ["sub-technique"]),
    ("Catalog Status", ["deprecated"], ["deprecated"]),
    ("Has Manual", ["True"], ["true"]),
    ("State Changed", ["-7d"], ["-7d"]),
])
def test_svs_coverage_values_are_normalized(name, values, expected):
    (entry,) = SVS_COVERAGE_SCREEN.validate_entries([{"name": name, "values": values}])
    assert entry.values == expected


@pytest.mark.parametrize("name, values", [
    ("Technique", ["TA0002"]),
    ("Tactic", ["T1059"]),
    ("State", ["great"]),
    ("Level", ["tactic"]),
    ("Retired", ["yes"]),
    ("State Changed", ["not a date"]),
    ("Date", ["-7d"]),
])
def test_svs_coverage_rejects_bad_entries(name, values):
    with pytest.raises(ValidationError):
        SVS_COVERAGE_SCREEN.validate_entries([{"name": name, "values": values}])


def test_svs_coverage_history_takes_a_date():
    (entry,) = SVS_COVERAGE_HISTORY_SCREEN.validate_entries([{"name": "Date", "values": ["-30d"]}])
    assert entry.values == ["-30d"]
    with pytest.raises(ValidationError):
        SVS_COVERAGE_HISTORY_SCREEN.validate_entries([{"name": "Tactic", "values": ["execution"]}])
