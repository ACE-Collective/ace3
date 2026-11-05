import pytest

from saq.domain_similarity import (
    compare_against_set,
    compare_domains,
    registrable_domain,
    to_ascii,
)

# cyrillic 'а' (U+0430) standing in for latin 'a'
CYRILLIC_PAYPAL = "pаypal.com"


@pytest.mark.unit
def test_registrable_domain_reduces_to_etld_plus_one():
    assert registrable_domain("mail.example.com") == "example.com"
    assert registrable_domain("a.b.c.example.co.uk") == "example.co.uk"
    assert registrable_domain("EXAMPLE.COM") == "example.com"
    # tldextract drops a trailing dot itself; only a name without a public suffix shows ACE's own strip
    assert registrable_domain("intranet.") == "intranet"


@pytest.mark.unit
def test_registrable_domain_handles_empty():
    assert registrable_domain("") == ""
    assert registrable_domain(None) == ""


@pytest.mark.unit
def test_to_ascii_punycode():
    assert to_ascii("example.com") == "example.com"
    # "pаypal.com".encode("idna") in Python, outside ACE
    assert to_ascii(CYRILLIC_PAYPAL) == "xn--pypal-4ve.com"


@pytest.mark.unit
def test_cyrillic_homoglyph_is_similar():
    result = compare_domains(CYRILLIC_PAYPAL, "paypal.com")
    assert not result.is_identical
    assert result.suspect_mixed_script is True
    assert result.suspect_non_ascii is True
    assert result.suspect_punycode is True
    # one codepoint apart: the distance is taken on the unicode forms, not on the xn-- ones
    assert result.damerau_levenshtein == 1
    # folds to the same latin skeleton
    assert result.skeleton_equal is True
    assert "confusable_skeleton" in result.techniques
    assert result.is_similar is True


@pytest.mark.unit
def test_rn_to_m_multigraph_is_confusable():
    result = compare_domains("rnodernbank.com", "modernbank.com")
    assert result.skeleton_equal is True
    assert "confusable_skeleton" in result.techniques
    assert result.is_similar is True


@pytest.mark.unit
def test_digit_typo_caught_by_edit_distance():
    result = compare_domains("examp1e.com", "example.com")
    assert not result.is_identical
    assert result.damerau_levenshtein == 1
    # jellyfish.jaro_winkler_similarity("examp1e.com", "example.com"), run outside ACE
    assert result.jaro_winkler == pytest.approx(0.9636363636363636)
    assert "edit_distance" in result.techniques
    assert result.is_similar is True


@pytest.mark.unit
def test_transposition_caught_by_edit_distance():
    result = compare_domains("mircosoft.com", "microsoft.com")
    assert not result.is_identical
    # damerau-levenshtein counts a transposition as a single edit
    assert result.damerau_levenshtein == 1
    assert "edit_distance" in result.techniques


@pytest.mark.unit
def test_subdomain_reduced_before_comparison():
    # both reduce to example.com -> identical, not a look-a-like
    result = compare_domains("mail.example.com", "www.example.com")
    assert result.is_identical is True
    assert result.is_similar is False


@pytest.mark.unit
def test_identical_is_not_similar():
    result = compare_domains("example.com", "example.com")
    assert result.is_identical is True
    assert result.skeleton_equal is False
    assert result.damerau_levenshtein == 0
    assert result.is_similar is False
    assert result.techniques == []


@pytest.mark.unit
def test_unrelated_domains_not_similar():
    result = compare_domains("example.com", "google.com")
    assert result.is_identical is False
    assert result.skeleton_equal is False
    assert result.damerau_levenshtein > 2
    assert result.jaro_winkler < 0.92
    assert result.is_similar is False
    assert result.techniques == []
