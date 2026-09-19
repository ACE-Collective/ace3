"""The search query language (saq/search/syntax.py).

Free text never produces an exact lookup: "docusign phish invoice" does not look up the tag
"phish". A literal is only searched for when it is written as a field term.
"""

import pytest

from saq.search.syntax import (
    FIELD_ALERT_UUID,
    FIELD_OBSERVABLE,
    FIELD_TAG,
    mask_quoted,
    parse_search_query,
    resolve_field,
)

pytestmark = pytest.mark.unit

ALERT_UUID = "2f1e4d3c-1111-2222-3333-444455556666"
SHA256_HEX = "ab" * 32


def _exact(parsed, field):
    return [term for term in parsed.exact if term.field == field]


def _filter(parsed, name):
    return [entry for entry in parsed.filters if entry["name"] == name]


class TestFreeText:
    def test_prose_produces_no_terms(self):
        parsed = parse_search_query("docusign phish invoice")
        assert parsed.exact == () and parsed.filters == ()
        assert parsed.text == "docusign phish invoice"

    def test_bare_indicator_is_free_text(self):
        """The whole point: a bare ip is prose now, not an exact lookup."""
        parsed = parse_search_query("10.20.30.40")
        assert parsed.exact == ()
        assert parsed.text == "10.20.30.40"

    def test_url_is_not_a_field_term(self):
        parsed = parse_search_query("https://evil.com/a?b=c")
        assert parsed.exact == () and parsed.filters == ()
        assert parsed.text == "https://evil.com/a?b=c"

    def test_windows_path_is_not_a_field_term(self):
        parsed = parse_search_query(r"C:\windows\system32\cmd.exe")
        assert parsed.exact == () and parsed.filters == ()
        assert parsed.text == r"C:\windows\system32\cmd.exe"

    def test_unknown_field_stays_literal(self):
        parsed = parse_search_query("foo:bar")
        assert parsed.exact == () and parsed.filters == () and parsed.errors == ()
        assert parsed.text == "foo:bar"

    def test_blank(self):
        assert parse_search_query("   ").is_empty()


class TestExactTerms:
    def test_tag(self):
        parsed = parse_search_query("tag:phish")
        assert _exact(parsed, FIELD_TAG)[0].values == ("phish",)
        assert parsed.text == ""

    def test_observable_type_shorthand(self):
        parsed = parse_search_query("ipv4:10.20.30.40")
        assert _exact(parsed, FIELD_OBSERVABLE)[0].values == (("ipv4", "10.20.30.40"),)

    def test_signature_id_shorthand(self):
        """The driving use case: find alerts carrying a signature's uuid observable."""
        parsed = parse_search_query(f"signature_id:{ALERT_UUID}")
        assert _exact(parsed, FIELD_OBSERVABLE)[0].values == (("signature_id", ALERT_UUID),)

    def test_explicit_observable_splits_at_first_colon_only(self):
        parsed = parse_search_query("observable:url:https://evil.com/a:b")
        assert _exact(parsed, FIELD_OBSERVABLE)[0].values == (("url", "https://evil.com/a:b"),)

    def test_explicit_observable_accepts_an_unregistered_type(self):
        """A type that is not in the registry is still searchable through the explicit form."""
        parsed = parse_search_query("observable:no_such_type_xyz:value")
        assert _exact(parsed, FIELD_OBSERVABLE)[0].values == (("no_such_type_xyz", "value"),)

    def test_explicit_observable_needs_a_type(self):
        parsed = parse_search_query("observable:justavalue")
        assert parsed.exact == ()
        assert parsed.errors and "observable:<type>:<value>" in parsed.errors[0]

    def test_alert_uuid_and_prefix(self):
        assert _exact(parse_search_query(f"uuid:{ALERT_UUID}"), FIELD_ALERT_UUID)[0].values == (ALERT_UUID,)
        assert _exact(parse_search_query("uuid:2f1e4d3c-11"), FIELD_ALERT_UUID)[0].values == ("2f1e4d3c-11",)

    def test_uuid_field_wins_over_the_uuid_observable_type(self):
        """`uuid` is also a registered observable type; the alert reading wins, and the
        observable is reachable through the explicit form."""
        assert resolve_field("uuid") == FIELD_ALERT_UUID
        parsed = parse_search_query(f"observable:uuid:{ALERT_UUID}")
        assert _exact(parsed, FIELD_OBSERVABLE)[0].values == (("uuid", ALERT_UUID),)

    def test_file_hash(self):
        parsed = parse_search_query(f"sha256:{SHA256_HEX}")
        assert _exact(parsed, FIELD_OBSERVABLE)[0].values == (("sha256", SHA256_HEX),)

    def test_terms_and_free_text_together(self):
        parsed = parse_search_query("tag:phish docusign invoice")
        assert _exact(parsed, FIELD_TAG)[0].values == ("phish",)
        assert parsed.text == "docusign invoice"


class TestFilterTerms:
    def test_queue_and_disposition(self):
        parsed = parse_search_query("queue:default disposition:DELIVERY,FALSE_POSITIVE")
        assert _filter(parsed, "Queue")[0]["values"] == ["default"]
        assert _filter(parsed, "Disposition")[0]["values"] == ["DELIVERY", "FALSE_POSITIVE"]
        assert parsed.exact == ()

    def test_relative_date(self):
        assert _filter(parse_search_query("alert_date:-7d"), "Alert Date")[0]["values"] == ["-7d"]

    def test_bad_date_is_an_error_not_a_dropped_filter(self):
        parsed = parse_search_query("alert_date:-7dd")
        assert parsed.filters == ()
        assert parsed.errors and "time window" in parsed.errors[0]

    def test_inverted_tag_becomes_a_filter(self):
        """`-tag:x` means alerts WITHOUT x -- there is nothing for the exact lane to return."""
        for query in ("-tag:whitelisted", "!tag:whitelisted"):
            parsed = parse_search_query(query)
            assert parsed.exact == ()
            entry = _filter(parsed, "Tag")[0]
            assert entry["inverted"] is True and entry["values"] == ["whitelisted"]

    def test_inverted_observable_becomes_a_filter(self):
        parsed = parse_search_query("-ipv4:10.20.30.40")
        assert parsed.exact == ()
        entry = _filter(parsed, "Observable")[0]
        assert entry["inverted"] is True and entry["values"] == [["ipv4", "10.20.30.40"]]

    def test_wildcard_tag_becomes_a_filter(self):
        """The lexical lane matches tag names exactly, so a pattern has to go through SQL."""
        parsed = parse_search_query("tag:phish*")
        assert parsed.exact == ()
        assert _filter(parsed, "Tag")[0]["values"] == ["phish*"]

    def test_repeated_field_is_merged_not_anded(self):
        """`queue:a queue:b` must mean either; as two ANDed entries it would match nothing."""
        parsed = parse_search_query("queue:a queue:b")
        assert _filter(parsed, "Queue") == [{"name": "Queue", "inverted": False, "values": ["a", "b"]}]

    def test_inverted_and_positive_forms_stay_separate(self):
        parsed = parse_search_query("tag:a -tag:b")
        assert _exact(parsed, FIELD_TAG)[0].values == ("a",)
        assert _filter(parsed, "Tag") == [{"name": "Tag", "inverted": True, "values": ["b"]}]

    def test_inverted_uuid_is_rejected(self):
        parsed = parse_search_query(f"-uuid:{ALERT_UUID}")
        assert parsed.exact == () and parsed.filters == ()
        assert parsed.errors and "cannot be inverted" in parsed.errors[0]


class TestQuoting:
    def test_quoted_value_with_a_space(self):
        parsed = parse_search_query('tag:"vendor mailer"')
        assert _exact(parsed, FIELD_TAG)[0].values == ("vendor mailer",)

    def test_quoted_value_with_a_comma_is_one_value(self):
        parsed = parse_search_query('observable:url:"https://evil.com/a,b"')
        assert _exact(parsed, FIELD_OBSERVABLE)[0].values == (("url", "https://evil.com/a,b"),)

    def test_quoted_free_text_keeps_its_space(self):
        assert parse_search_query('"invoice scan.pdf"').text == "invoice scan.pdf"

    def test_unterminated_quote_is_an_error(self):
        parsed = parse_search_query('tag:"phish')
        assert parsed.errors and "unterminated quote" in parsed.errors[0]

    def test_mask_quoted_roundtrip(self):
        masked, quoted = mask_quoted('a "b c" d')
        assert " " not in masked.split("\x00")[1]
        assert quoted == ["b c"]


class TestErrors:
    def test_invalid_value_for_its_type(self):
        parsed = parse_search_query("ipv4:not-an-ip")
        assert parsed.exact == ()
        assert parsed.errors
        # the rejected term must NOT leak into the free text and become a semantic query
        assert parsed.text == ""

    def test_bad_uuid(self):
        parsed = parse_search_query("uuid:nope")
        assert parsed.exact == () and parsed.errors

    def test_too_many_terms(self):
        parsed = parse_search_query(" ".join(f"tag:t{i}" for i in range(40)))
        assert parsed.errors and "too many field terms" in parsed.errors[-1]


class TestHint:
    def test_bare_ip_gets_a_hint(self):
        assert "ipv4:10.20.30.40" in parse_search_query("10.20.30.40").hint()

    def test_bare_hash_gets_a_hint(self):
        assert parse_search_query(SHA256_HEX).hint() is not None

    def test_no_hint_when_an_exact_term_was_given(self):
        assert parse_search_query("ipv4:10.20.30.40").hint() is None

    def test_no_hint_for_prose(self):
        assert parse_search_query("docusign phish invoice").hint() is None
