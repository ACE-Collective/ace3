"""Running a definition's rule over an entry (docs/FEED_WATCHES.md, *Matching*)."""

import pytest

from saq.feeds.matching import EXCERPT_CONTEXT, RuleError, compile_rule, scan_entry

TITLE_ONLY = """rule in_title
{
    strings:
        $a = "exploited" nocase
    condition:
        $a and field == "title"
}"""


@pytest.mark.unit
def test_each_field_is_scanned_with_its_name_in_field():
    rules = compile_rule(TITLE_ONLY)
    assert not scan_entry(rules, {"title": "New release", "content": "a flaw that is exploited"}).matched

    found = scan_entry(rules, {"title": "Vendor says flaw is Exploited", "content": "exploited"})
    assert found.matched
    assert found.field == "title"
    assert found.rules == ["in_title"]
    assert found.excerpt == "Vendor says flaw is Exploited"


@pytest.mark.unit
def test_the_excerpt_is_the_matched_string_in_context():
    rules = compile_rule('rule r { strings: $a = "CVE-2026-1234" condition: $a }')
    before, after = "x" * 500, "y" * 500
    found = scan_entry(rules, {"content": f"{before}é CVE-2026-1234 é{after}"})
    assert found.field == "content"
    assert "CVE-2026-1234" in found.excerpt
    # a multibyte character before the match does not shift the excerpt
    assert found.excerpt.startswith("x") and found.excerpt.endswith("y")
    assert len(found.excerpt) == len("é CVE-2026-1234 é") + 2 * EXCERPT_CONTEXT - 4


@pytest.mark.unit
def test_a_rule_that_does_not_compile():
    with pytest.raises(RuleError):
        compile_rule("rule broken {")
