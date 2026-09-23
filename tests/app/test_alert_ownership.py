import pytest

from app.alert_ownership import TAKE_OWNED_FIELD, confirmed_takes_from_form, describe_skipped
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
