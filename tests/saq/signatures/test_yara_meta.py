import pytest

from saq.signatures.yara_meta import meta_enabled, meta_is_qa, meta_modifiers


@pytest.mark.unit
@pytest.mark.parametrize("meta, expected", [
    (None, True),
    ({}, True),
    ({"enabled": True}, True),
    ({"enabled": False}, False),
    ({"enabled": 0}, False),
    ({"enabled": 1}, True),
    ({"enabled": "false"}, False),
    ({"enabled": " Disabled "}, False),
    ({"enabled": "off"}, False),
    ({"enabled": "no"}, False),
    ({"enabled": "0"}, False),
    ({"enabled": "true"}, True),
    ({"enabled": "anything else"}, True),
])
def test_meta_enabled(meta, expected):
    assert meta_enabled(meta) is expected


@pytest.mark.unit
@pytest.mark.parametrize("meta, expected", [
    (None, []),
    ({}, []),
    ({"modifiers": "qa"}, ["qa"]),
    ({"modifiers": " no_alert , qa,, directive=sandbox "}, ["no_alert", "qa", "directive=sandbox"]),
    ({"modifiers": ""}, []),
])
def test_meta_modifiers(meta, expected):
    assert meta_modifiers(meta) == expected


@pytest.mark.unit
def test_meta_is_qa():
    assert meta_is_qa({"modifiers": "no_alert,qa"})
    assert not meta_is_qa({"modifiers": "no_alert"})
    # a modifier that merely contains the letters is not qa mode
    assert not meta_is_qa({"modifiers": "qa_later"})
    assert not meta_is_qa(None)
