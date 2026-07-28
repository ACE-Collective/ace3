# vim: sw=4:ts=4:et:cc=120
#
# visual (look-a-like) similarity scoring for domains
#
# used to surface BEC look-a-like domains
#

from dataclasses import dataclass, field

import idna
import jellyfish
import tldextract

from confusable_homoglyphs import confusables

# default thresholds - advisory only (analysts tune in hunts over the raw signals)
DEFAULT_DL_MAX = 2          # damerau-levenshtein distance considered "close" (inclusive, > 0)
DEFAULT_JW_THRESHOLD = 0.92 # jaro-winkler similarity considered "close"

# visual multigraph folds applied when building the skeleton: things that look like a single glyph to a
# human but are written with multiple ascii characters. applied to both sides so equality is symmetric.
# kept deliberately small and conservative - single-character typos and digit swaps are handled by the
# edit-distance signal instead, so they are intentionally not folded here.
MULTIGRAPH_FOLDS = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
)


def registrable_domain(value: str) -> str:
    """Reduce a domain or FQDN to its registrable domain (eTLD+1), lowercased.

    look-a-like attacks target the registrable portion (e.g. paypal in paypal.com), so all comparison
    happens at this level. falls back to the cleaned input when no public suffix is identifiable
    (bare hostnames, internal names). mirrors saq.modules.rdap._registrable_domain.
    """
    normalized = (value or "").strip().lower().rstrip(".")
    if not normalized:
        return ""

    registrable = tldextract.extract(normalized).top_domain_under_public_suffix
    return registrable or normalized


def to_ascii(domain: str) -> str:
    """Return the punycode (IDNA/ascii) form of a domain, falling back to the lowercased input."""
    cleaned = (domain or "").strip().lower().rstrip(".")
    if not cleaned:
        return ""

    try:
        return idna.encode(cleaned).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return cleaned


def _unicode_fold(value: str) -> str:
    """Map unicode confusable characters to their latin homoglyph (e.g. cyrillic 'а' -> latin 'a')."""
    try:
        found = confusables.is_confusable(value, greedy=True, preferred_aliases=["latin"])
    except Exception:
        return value

    if not found:
        return value

    mapping = {}
    for item in found:
        homoglyphs = item.get("homoglyphs") or []
        if homoglyphs:
            mapping[item["character"]] = homoglyphs[0]["c"]

    if not mapping:
        return value

    return "".join(mapping.get(c, c) for c in value)


def skeleton(domain: str) -> str:
    """Build a visual skeleton of a domain for confusable comparison.

    folds unicode confusables to their latin homoglyph and collapses common visual multigraphs
    (rn->m, vv->w, cl->d). two domains with equal skeletons look alike to a human even though their
    codepoints differ. single-character typos / digit swaps are handled by the edit-distance signal,
    not here, to keep skeleton equality from colliding unrelated domains.
    """
    folded = _unicode_fold(domain).lower()
    for multigraph, replacement in MULTIGRAPH_FOLDS:
        folded = folded.replace(multigraph, replacement)

    return folded


def _is_mixed_script(value: str) -> bool:
    try:
        return bool(confusables.is_mixed_script(value))
    except Exception:
        return False


def domain_attributes(domain: str) -> dict:
    """Return the suspect-only attributes of a single domain (independent of any reference)."""
    reg = registrable_domain(domain)
    ascii_form = to_ascii(reg)
    return {
        "domain": reg,
        "ascii": ascii_form,
        "punycode": "xn--" in ascii_form,
        "mixed_script": _is_mixed_script(reg),
        "non_ascii": any(ord(c) > 127 for c in reg),
    }


@dataclass
class DomainSimilarityResult:
    """The full set of similarity signals between a suspect domain and a reference domain.

    all fields are raw signals meant for logging. is_similar / techniques are advisory values derived
    from the default thresholds and should not be treated as authoritative.
    """

    suspect: str
    reference: str
    suspect_ascii: str
    reference_ascii: str
    is_identical: bool
    # suspect-only attributes (do not depend on the reference)
    suspect_punycode: bool
    suspect_mixed_script: bool
    suspect_non_ascii: bool
    # pairwise signals
    skeleton_equal: bool
    damerau_levenshtein: int
    jaro_winkler: float
    techniques: list = field(default_factory=list)
    is_similar: bool = False

    def to_dict(self) -> dict:
        return {
            "suspect_domain": self.suspect,
            "reference_domain": self.reference,
            "suspect_ascii": self.suspect_ascii,
            "reference_ascii": self.reference_ascii,
            "is_identical": self.is_identical,
            "suspect_punycode": self.suspect_punycode,
            "suspect_mixed_script": self.suspect_mixed_script,
            "suspect_non_ascii": self.suspect_non_ascii,
            "skeleton_equal": self.skeleton_equal,
            "damerau_levenshtein": self.damerau_levenshtein,
            "jaro_winkler": self.jaro_winkler,
            "techniques": list(self.techniques),
            "is_similar": self.is_similar,
        }


def compare_domains(suspect: str, reference: str, *, dl_max: int = DEFAULT_DL_MAX,
                    jw_threshold: float = DEFAULT_JW_THRESHOLD) -> DomainSimilarityResult:
    """Compute every look-a-like signal between two domains, reduced to their registrable form.

    no early return - all signals are computed even for clearly-unrelated or identical pairs, because
    analysts need the full data to tune hunts.
    """
    suspect_reg = registrable_domain(suspect)
    reference_reg = registrable_domain(reference)

    suspect_ascii = to_ascii(suspect_reg)
    reference_ascii = to_ascii(reference_reg)

    is_identical = suspect_reg == reference_reg
    suspect_non_ascii = any(ord(c) > 127 for c in suspect_reg)
    suspect_punycode = "xn--" in suspect_ascii
    suspect_mixed_script = _is_mixed_script(suspect_reg)

    skeleton_equal = (not is_identical) and skeleton(suspect_reg) == skeleton(reference_reg)

    # edit distance is computed on the unicode registrable forms (not punycode): a homoglyph swap shows
    # up as a small codepoint distance, whereas the xn-- ascii forms would compare as gibberish.
    damerau_levenshtein = jellyfish.damerau_levenshtein_distance(suspect_reg, reference_reg)
    jaro_winkler = jellyfish.jaro_winkler_similarity(suspect_reg, reference_reg)

    edit_close = (not is_identical) and (0 < damerau_levenshtein <= dl_max or jaro_winkler >= jw_threshold)

    techniques = []
    if skeleton_equal:
        techniques.append("confusable_skeleton")
    if edit_close:
        techniques.append("edit_distance")

    return DomainSimilarityResult(
        suspect=suspect_reg,
        reference=reference_reg,
        suspect_ascii=suspect_ascii,
        reference_ascii=reference_ascii,
        is_identical=is_identical,
        suspect_punycode=suspect_punycode,
        suspect_mixed_script=suspect_mixed_script,
        suspect_non_ascii=suspect_non_ascii,
        skeleton_equal=skeleton_equal,
        damerau_levenshtein=damerau_levenshtein,
        jaro_winkler=jaro_winkler,
        techniques=techniques,
        is_similar=(not is_identical) and bool(techniques),
    )


@dataclass
class LocalPartSimilarityResult:
    """How closely the local parts (the bit before the @) of two addresses match."""

    suspect_local: str
    reference_local: str
    # the local parts are the same string, ignoring case - the strongest identity-cloning signal
    is_exact: bool
    skeleton_equal: bool
    damerau_levenshtein: int
    jaro_winkler: float
    is_similar: bool = False


def local_part(address: str) -> str:
    """Return the lowercased local part of an email address ('' when there is no @)."""
    cleaned = (address or "").strip().lower()
    at = cleaned.rfind("@")
    return cleaned[:at] if at > 0 else ""


def compare_local_parts(suspect: str, reference: str, *, dl_max: int = DEFAULT_DL_MAX,
                        jw_threshold: float = DEFAULT_JW_THRESHOLD) -> LocalPartSimilarityResult:
    """Compare the local parts of two email addresses.

    a look-a-like domain that reuses an existing conversation participant's local part verbatim
    (jane.doe@exarnple.com against jane.doe@example.com) is impersonating a specific person, not just
    a company - a much stronger signal than domain similarity alone. exact match is the dominant
    real-world case; the edit-distance signals catch nickname-style near misses.

    takes full addresses rather than bare local parts so callers don't each have to split them, and
    deliberately does NOT run registrable_domain() the way compare_domains() does - that would mangle
    a local part.
    """
    suspect_local = local_part(suspect)
    reference_local = local_part(reference)

    if not suspect_local or not reference_local:
        return LocalPartSimilarityResult(
            suspect_local=suspect_local,
            reference_local=reference_local,
            is_exact=False,
            skeleton_equal=False,
            damerau_levenshtein=-1,
            jaro_winkler=0.0,
            is_similar=False)

    is_exact = suspect_local == reference_local
    skeleton_equal = (not is_exact) and skeleton(suspect_local) == skeleton(reference_local)
    damerau_levenshtein = jellyfish.damerau_levenshtein_distance(suspect_local, reference_local)
    jaro_winkler = jellyfish.jaro_winkler_similarity(suspect_local, reference_local)

    edit_close = (not is_exact) and (0 < damerau_levenshtein <= dl_max or jaro_winkler >= jw_threshold)

    return LocalPartSimilarityResult(
        suspect_local=suspect_local,
        reference_local=reference_local,
        is_exact=is_exact,
        skeleton_equal=skeleton_equal,
        damerau_levenshtein=damerau_levenshtein,
        jaro_winkler=jaro_winkler,
        is_similar=is_exact or skeleton_equal or edit_close)


def compare_against_set(suspect: str, references, *, dl_max: int = DEFAULT_DL_MAX,
                        jw_threshold: float = DEFAULT_JW_THRESHOLD) -> list:
    """Compare a suspect domain against every reference domain, returning all results (not just similar ones)."""
    results = []
    for reference in references:
        if not reference:
            continue

        results.append(compare_domains(suspect, reference, dl_max=dl_max, jw_threshold=jw_threshold))

    return results
