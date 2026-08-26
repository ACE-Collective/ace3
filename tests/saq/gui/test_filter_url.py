"""Tests for the durable filter URL codec.

This is the single most failure-prone piece of the filter feature: the codec is a permanent
public interface, and an escaping bug breaks already-published links silently and forever.
Weighted accordingly.
"""

import json

import pytest

from saq.gui.filter_names import FILTER_NAMES, FILTER_NAMES_BY_SLUG, FILTER_SLUGS, LEGACY_FILTER_NAME_ALIASES
from saq.gui.filter_url import (
    FilterQueryError,
    decode_filter_query,
    decode_legacy_filter_json,
    encode_filter_query,
)


def _roundtrip(filters):
    decoded, warnings = decode_filter_query(encode_filter_query(filters))
    assert warnings == []
    return decoded


@pytest.mark.unit
def test_documented_example_encodes_exactly_as_specified():
    """The shape in the plan and in docs -- pin it so a refactor cannot quietly change the
    published URL format."""
    params = encode_filter_query([
        {"name": "Queue", "inverted": False, "values": ["default"]},
        {"name": "Disposition", "inverted": False, "values": ["OPEN", "FALSE_POSITIVE"]},
        {"name": "Tag", "inverted": True, "values": ["whitelisted"]},
        {"name": "Alert Date", "inverted": False, "values": ["-7d"]},
    ])

    assert params == [
        "queue:default",
        "disposition:OPEN,FALSE_POSITIVE",
        "!tag:whitelisted",
        "alert_date:-7d",
    ]


@pytest.mark.unit
@pytest.mark.parametrize("value", [
    "plain",
    "with space",
    "with:colon",
    "with,comma",
    "with%percent",
    "with%3Aalready-encoded-looking",
    "with+plus",
    "!leading-bang",
    "trailing:",
    ":leading",
    "unicode-ünïcødé-値",
    "quote'and\"double",
    "slash/and\\backslash",
    "amp&and=equals?and#hash",
    "-7d",
])
def test_scalar_value_round_trip(value):
    """Every structural character has to survive a trip through the URL unchanged."""
    filters = [{"name": "Description", "inverted": False, "values": [value]}]
    assert _roundtrip(filters) == filters


@pytest.mark.unit
@pytest.mark.parametrize("observable_type,observable_value", [
    ("ipv4", "1.2.3.4"),
    ("url", "https://evil.com/path"),
    ("url", "https://evil.com/a,b"),
    ("url", "https://evil.com/a:b,c?d=e&f=g#h"),
    ("email_address", "user@example.com"),
    ("file_path", "C:\\Users\\bob\\Desktop\\a,b.exe"),
    ("url", "https://evil.com/100%25off"),
    ("test", "value:with:many:colons"),
])
def test_observable_pair_round_trip(observable_type, observable_value):
    """The Observable case is the one the escaping rules exist for: the type/value colon is
    literal, so any colon inside the value must be encoded or the split goes wrong."""
    filters = [{"name": "Observable", "inverted": False,
                "values": [[observable_type, observable_value]]}]
    assert _roundtrip(filters) == filters


@pytest.mark.unit
def test_url_observable_does_not_split_on_the_scheme_colon():
    """Regression guard for the ambiguity this grammar was designed around: a `url`
    observable must not decode to a type of "https"."""
    params = encode_filter_query(
        [{"name": "Observable", "inverted": False, "values": [["url", "https://evil.com"]]}])
    decoded, _ = decode_filter_query(params)

    assert decoded[0]["values"] == [["url", "https://evil.com"]]


@pytest.mark.unit
def test_multi_value_or_round_trip():
    filters = [{"name": "Disposition", "inverted": False,
                "values": ["OPEN", "FALSE_POSITIVE", "IGNORE"]}]
    assert _roundtrip(filters) == filters


@pytest.mark.unit
def test_inverted_round_trip():
    filters = [{"name": "Tag", "inverted": True, "values": ["a", "b"]}]
    assert _roundtrip(filters) == filters


@pytest.mark.unit
def test_every_slug_round_trips():
    """Nothing in the registry may be un-encodable."""
    for name in sorted(FILTER_NAMES):
        values = [["ipv4", "1.2.3.4"]] if name == "Observable" else ["x"]
        filters = [{"name": name, "inverted": False, "values": values}]
        assert _roundtrip(filters) == filters, name


@pytest.mark.unit
def test_multiple_filters_round_trip_in_order():
    filters = [
        {"name": "Queue", "inverted": False, "values": ["default"]},
        {"name": "Owner", "inverted": True, "values": ["None", "jane"]},
        {"name": "Observable", "inverted": False, "values": [["url", "https://x/a,b"]]},
        {"name": "Alert Date", "inverted": False, "values": ["-24h@h - now"]},
    ]
    assert _roundtrip(filters) == filters


@pytest.mark.unit
def test_empty_query_decodes_to_empty_list():
    assert decode_filter_query([]) == ([], [])
    assert decode_filter_query(None) == ([], [])


@pytest.mark.unit
def test_filters_with_no_values_are_dropped_on_encode():
    assert encode_filter_query([{"name": "Tag", "inverted": False, "values": []}]) == []


@pytest.mark.unit
def test_empty_values_are_dropped_on_encode():
    """An empty value is meaningless at best. For a TextFilter it becomes `ilike '%%'`,
    which matches EVERYTHING -- so a share link must never carry one."""
    assert encode_filter_query(
        [{"name": "Description", "inverted": False, "values": [""]}]) == []
    assert encode_filter_query(
        [{"name": "Description", "inverted": False, "values": ["", "real"]}]) == ["description:real"]


@pytest.mark.unit
@pytest.mark.parametrize("param", ["description:", "disposition:OPEN,", "disposition:,OPEN"])
def test_empty_value_in_url_is_rejected(param):
    """Refuse rather than guess: silently reading `description:` as an empty match would
    widen the analyst's result set without telling them."""
    with pytest.raises(FilterQueryError):
        decode_filter_query([param])


@pytest.mark.unit
def test_unknown_slug_is_skipped_with_a_warning_not_dropped_and_not_fatal():
    """A link naming a filter type that no longer exists must still work for its remaining
    filters -- but the analyst has to be told, because a missing filter shows MORE alerts
    than the author intended."""
    filters, warnings = decode_filter_query(["queue:default", "obsolete_thing:x", "tag:y"])

    assert [f["name"] for f in filters] == ["Queue", "Tag"]
    assert len(warnings) == 1
    assert "obsolete_thing" in warnings[0]


@pytest.mark.unit
@pytest.mark.parametrize("param", [
    "noseparator",
    ":novalue",
    "queue:",
    "",
    "   ",
    "!",
    "!:x",
])
def test_malformed_parameter_raises(param):
    """A broken link is different from an outdated one: fail loudly rather than showing the
    analyst a filter that is not what the URL said."""
    with pytest.raises(FilterQueryError):
        decode_filter_query([param])


@pytest.mark.unit
def test_encode_rejects_unknown_filter_name():
    with pytest.raises(FilterQueryError):
        encode_filter_query([{"name": "Nonexistent", "inverted": False, "values": ["x"]}])


@pytest.mark.unit
def test_encode_rejects_wrong_value_shape_for_observable():
    with pytest.raises(FilterQueryError):
        encode_filter_query([{"name": "Observable", "inverted": False, "values": ["notapair"]}])


@pytest.mark.unit
def test_slug_registry_is_bijective():
    assert len(FILTER_NAMES_BY_SLUG) == len(FILTER_SLUGS)
    assert set(FILTER_SLUGS) == set(FILTER_NAMES)


#
# legacy compatibility
#

@pytest.mark.unit
def test_legacy_payload_decodes_identically_to_the_modern_url():
    """THE property that makes the legacy 302 lossless. If these two ever diverge, following
    an old wiki link silently lands the analyst on a different alert list."""
    modern = [
        {"name": "Queue", "inverted": False, "values": ["default"]},
        {"name": "Disposition", "inverted": False, "values": ["OPEN", "FALSE_POSITIVE"]},
        {"name": "Tag", "inverted": True, "values": ["whitelisted"]},
        {"name": "Observable", "inverted": False, "values": [["url", "https://evil.com/a,b:c"]]},
        {"name": "Alert Date", "inverted": False, "values": ["-7d"]},
    ]
    legacy_raw = json.dumps(modern)

    from_legacy = decode_legacy_filter_json(legacy_raw)
    from_url, warnings = decode_filter_query(encode_filter_query(modern))

    assert from_legacy == from_url == modern
    assert warnings == []


@pytest.mark.unit
def test_legacy_payload_missing_inverted_defaults_to_false():
    assert decode_legacy_filter_json('[{"name": "Queue", "values": ["default"]}]') == [
        {"name": "Queue", "inverted": False, "values": ["default"]}]


@pytest.mark.unit
def test_legacy_very_old_dict_shape():
    """alert.html:490 has been passing {'Tag': [...]} for years."""
    assert decode_legacy_filter_json('{"Tag": ["needs_research"]}') == [
        {"name": "Tag", "inverted": False, "values": ["needs_research"]}]


@pytest.mark.unit
@pytest.mark.parametrize("raw", ["not json", "[", '[{"values": ["x"]}]', '"a string"', "42"])
def test_legacy_malformed_payload_raises(raw):
    with pytest.raises(FilterQueryError):
        decode_legacy_filter_json(raw)


@pytest.mark.unit
def test_legacy_alias_map_covers_every_current_display_name():
    """Guards the subtle failure mode: someone renames a display name, the slug registry is
    updated so the lockstep test still passes, and the only thing that breaks is URLs
    written before the rename -- which nobody checks by hand."""
    for name in FILTER_NAMES:
        assert name in LEGACY_FILTER_NAME_ALIASES, f"{name!r} missing from the legacy alias map"


@pytest.mark.unit
def test_every_legacy_alias_points_at_a_live_slug():
    for legacy_name, slug in LEGACY_FILTER_NAME_ALIASES.items():
        assert slug in FILTER_NAMES_BY_SLUG, f"{legacy_name!r} -> {slug!r} is a dead slug"


@pytest.mark.unit
def test_real_world_legacy_link_shape_round_trips():
    """The shape that is actually out in the wild: a URL-encoded JSON payload holding an
    observable pair plus a disposition, as minted by the old copy_filter_link().

    Values here are synthesized -- the real links live in a separate, non-public repo and
    reference customer infrastructure, so only the STRUCTURE is reproduced."""
    from urllib.parse import unquote

    encoded = (
        "%5B%7B%22name%22%3A%22Observable%22%2C%22inverted%22%3Afalse%2C%22values%22%3A"
        "%5B%5B%22fqdn%22%2C%22example.invalid%22%5D%5D%7D%2C%7B%22name%22%3A%22Disposition%22"
        "%2C%22inverted%22%3Afalse%2C%22values%22%3A%5B%22DELIVERY%22%5D%7D%5D"
    )

    legacy = decode_legacy_filter_json(unquote(encoded))
    params = encode_filter_query(legacy)
    back, warnings = decode_filter_query(params)

    assert params == ["observable:fqdn:example.invalid", "disposition:DELIVERY"]
    assert back == legacy
    assert warnings == []
    # the point of the new format: ~200 characters of encoded JSON becomes ~50 readable ones
    assert len("&f=".join(params)) < len(encoded) / 2
