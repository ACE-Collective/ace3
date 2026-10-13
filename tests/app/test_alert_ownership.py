import pytest

from app.alert_ownership import TAKE_OWNED_FIELD, confirmed_takes_from_form, describe_frozen, describe_skipped
from saq.database.util.alert import OwnershipCheck


@pytest.mark.unit
@pytest.mark.parametrize("raw,expected", [
    ("", {}),
    ("a:3", {"a": 3}),
    ("a:3,b:4", {"a": 3, "b": 4}),
    (" a:3 , b:4 ", {"a": 3, "b": 4}),
    # malformed pairs are dropped, which leaves those alerts unconfirmed
    ("a,b:x,c:5", {"c": 5}),
])
def test_confirmed_takes_from_form(raw, expected):
    assert confirmed_takes_from_form({TAKE_OWNED_FIELD: raw}) == expected


@pytest.mark.unit
def test_confirmed_takes_from_form_without_field():
    assert confirmed_takes_from_form({}) == {}


@pytest.mark.unit
@pytest.mark.parametrize("skipped,expected", [
    ({}, None),
    ({"a": "Jane"}, "left 1 alert owned by Jane alone"),
    ({"a": "Jane", "b": "Jane"}, "left 2 alerts owned by Jane alone"),
    ({"a": "Jane", "b": "Jane", "c": "Raj"}, "left 3 alerts owned by other analysts alone (Jane 2, Raj 1)"),
])
def test_describe_skipped(skipped, expected):
    assert describe_skipped(OwnershipCheck(skipped=skipped)) == expected


@pytest.mark.unit
@pytest.mark.parametrize("frozen,expected", [
    ({}, None),
    ({"a": "SIMULATED"}, "left 1 SIMULATED alert alone (only ACE sets that disposition)"),
    ({"a": "SIMULATED", "b": "SIMULATED"}, "left 2 SIMULATED alerts alone (only ACE sets that disposition)"),
    ({"a": "SIMULATED", "b": "SIMULATED", "c": "OTHER"},
     "left 3 alerts alone whose disposition only ACE sets (SIMULATED 2, OTHER 1)"),
])
def test_describe_frozen(frozen, expected):
    assert describe_frozen(frozen) == expected


@pytest.mark.unit
def test_describe_skipped_names_owned_and_frozen_alerts():
    ownership = OwnershipCheck(skipped={"a": "Jane"}, frozen={"b": "SIMULATED"})
    assert describe_skipped(ownership) == (
        "left 1 alert owned by Jane alone; left 1 SIMULATED alert alone (only ACE sets that disposition)")
