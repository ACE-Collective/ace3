"""Observable Pattern values: which patterns an index can serve, and the LIKE patterns built
from them (saq/gui/observable_pattern.py, saq/gui/filter_query.py)."""

import pytest
from pydantic import ValidationError

from saq.gui.filter_entry import FilterEntry
from saq.gui.filter_query import value_like_pattern, value_rev_like_pattern
from saq.gui.filter_url import decode_filter_query, encode_filter_query
from saq.gui.observable_pattern import ObservablePatternError, check_observable_pattern

pytestmark = pytest.mark.unit


class TestCheckObservablePattern:
    @pytest.mark.parametrize("pattern", ["*.evil.com", "https://evil.com/*", "evil.com*.net", "*a", "a*",
                                         "no wildcard at all", "*a*b"])
    def test_a_pattern_with_text_at_one_end_is_accepted(self, pattern):
        assert check_observable_pattern(pattern) == pattern

    def test_surrounding_whitespace_is_dropped(self):
        assert check_observable_pattern("  *.evil.com\t") == "*.evil.com"

    @pytest.mark.parametrize("pattern", ["*evil*", "**", "*", "*a*b*", "  *evil*  "])
    def test_a_wildcard_at_both_ends_is_refused(self, pattern):
        with pytest.raises(ObservablePatternError, match="both ends|no text"):
            check_observable_pattern(pattern)

    @pytest.mark.parametrize("pattern", ["", "   ", "*", "***"])
    def test_a_pattern_with_no_text_is_refused(self, pattern):
        with pytest.raises(ObservablePatternError, match="no text"):
            check_observable_pattern(pattern)

    def test_a_pattern_must_be_a_string(self):
        with pytest.raises(ObservablePatternError, match="must be a string"):
            check_observable_pattern(["*.evil.com"])


class TestLikePatterns:
    def test_each_wildcard_becomes_a_percent(self):
        assert value_like_pattern("*.evil.com") == b"%.evil.com"
        assert value_like_pattern("C:\\Users\\*\\evil.exe") == b"C:\\Users\\%\\evil.exe"

    def test_like_wildcards_and_the_escape_character_are_escaped(self):
        assert value_like_pattern("50%_off!*") == b"50!%!_off!!%"

    def test_value_rev_is_only_used_for_a_pattern_that_starts_with_a_wildcard(self):
        """i_obs_value serves a pattern that starts with text, whatever it ends with."""
        assert value_rev_like_pattern("https://evil.com/*") is None
        assert value_rev_like_pattern("evil.com*.net") is None
        assert value_rev_like_pattern("evil.com") is None

    def test_value_rev_pattern_is_the_trailing_text_reversed(self):
        assert value_rev_like_pattern("*.evil.com") == b"moc.live.%"
        assert value_rev_like_pattern("*evil*.com") == b"moc.%"

    def test_value_rev_pattern_is_escaped_after_reversing(self):
        assert value_rev_like_pattern("*_off!%") == b"!%!!ffo!_%"

    def test_value_rev_pattern_keeps_only_what_value_rev_holds(self):
        """value_rev is the last 255 bytes of the value, reversed; a longer suffix is cut to them."""
        pattern = value_rev_like_pattern("*" + "x" * 254 + "ab")
        assert pattern == b"ba" + b"x" * 253 + b"%"

    def test_multibyte_text_is_reversed_by_byte(self):
        """REVERSE() of a BLOB reverses its bytes, so the pattern has to as well."""
        assert value_rev_like_pattern("*é") == "é".encode()[::-1] + b"%"


class TestFilterEntry:
    def test_a_pattern_pair_is_accepted_and_stripped(self):
        entry = FilterEntry.model_validate({"name": "Observable Pattern", "values": [["fqdn", " *.evil.com "]]})
        assert entry.values == [["fqdn", "*.evil.com"]]

    def test_a_wildcard_at_both_ends_is_refused_at_write_time(self):
        """The same gate a modal save, an API call and a hand-edited link go through."""
        with pytest.raises(ValidationError, match="both ends"):
            FilterEntry.model_validate({"name": "Observable Pattern", "values": [["fqdn", "*evil*"]]})

    @pytest.mark.parametrize("value", ["*.evil.com", ["fqdn"], ["fqdn", "*.evil.com", "x"]])
    def test_a_value_that_is_not_a_type_and_pattern_pair_is_refused(self, value):
        with pytest.raises(ValidationError, match="pairs"):
            FilterEntry.model_validate({"name": "Observable Pattern", "values": [value]})

    def test_the_exact_observable_filter_still_takes_a_literal_star(self):
        """A value with a `*` in it (***SPAM*** subjects) is still an exact match there."""
        entry = FilterEntry.model_validate({"name": "Observable", "values": [["email_subject", "***SPAM***"]]})
        assert entry.values == [["email_subject", "***SPAM***"]]


class TestShareLink:
    def test_round_trip(self):
        filters = [{"name": "Observable Pattern", "inverted": True, "values": [["url", "https://evil.com/a,b*"]]}]
        params = encode_filter_query(filters)
        assert params[0].startswith("!observable_pattern:url:")
        assert decode_filter_query(params, strict=True) == (filters, [])
