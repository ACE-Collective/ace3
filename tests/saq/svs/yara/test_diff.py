"""Comparing the two scans against the labels (saq.svs.yara.diff)."""

from collections import Counter

import pytest

from saq.detection_verdicts.constants import SOURCE_EXPLICIT, SOURCE_INHERITED_MULTI, SOURCE_INHERITED_SINGLE
from saq.svs.yara.corpus import Corpus, Sample, Unit
from saq.svs.yara.diff import Category, Outcome, RuleInfo, SideScan, categorize, detection_blocker, diff, duplicate_uuids

MATCH, MISS = Outcome.MATCH, Outcome.MISS
A, B, C = "a" * 64, "b" * 64, "c" * 64


@pytest.mark.unit
@pytest.mark.parametrize("label, source, base, head, expected", [
    ("tp", SOURCE_INHERITED_SINGLE, MATCH, MISS, Category.REGRESSION),
    ("tp", SOURCE_EXPLICIT, MATCH, MISS, Category.REGRESSION),
    ("tp", SOURCE_INHERITED_MULTI, MATCH, MISS, Category.REGRESSION_UNCONFIRMED),
    ("tp", SOURCE_INHERITED_SINGLE, MISS, MATCH, Category.RECOVERED),
    ("tp", SOURCE_INHERITED_SINGLE, MISS, MISS, Category.ALREADY_BROKEN),
    ("tp", SOURCE_INHERITED_SINGLE, MATCH, MATCH, Category.UNCHANGED),
    ("fp", SOURCE_INHERITED_SINGLE, MATCH, MISS, Category.IMPROVEMENT),
    ("fp", SOURCE_INHERITED_SINGLE, MISS, MATCH, Category.NEW_FP),
    ("fp", SOURCE_INHERITED_SINGLE, MATCH, MATCH, Category.KNOWN_FP),
    ("fp", SOURCE_INHERITED_SINGLE, MISS, MISS, Category.UNCHANGED),
    ("conflicted", SOURCE_EXPLICIT, MATCH, MISS, Category.UNLABELED_CHANGE),
    (None, None, MISS, MATCH, Category.UNLABELED_CHANGE),
    (None, None, MATCH, MATCH, Category.UNCHANGED),
])
def test_a_sample_is_judged_by_its_own_label(label, source, base, head, expected):
    # the other samples of the file never change it
    assert categorize(label, source, True, ["fp", "tp", label], base, head) == expected


@pytest.mark.unit
@pytest.mark.parametrize("file_labels, base, head, expected", [
    (["fp"], MISS, MATCH, Category.NEW_FP_OTHER_RULE),
    (["fp", "fp"], MISS, MATCH, Category.NEW_FP_OTHER_RULE),
    (["fp", "tp"], MISS, MATCH, Category.NEW_MATCH_REAL_HIT),
    (["tp"], MISS, MATCH, Category.NEW_MATCH_REAL_HIT),
    (["fp", None], MISS, MATCH, Category.UNLABELED_CHANGE),
    (["conflicted"], MISS, MATCH, Category.UNLABELED_CHANGE),
    (["fp"], MATCH, MISS, Category.UNLABELED_CHANGE),
    (["fp"], MATCH, MATCH, Category.UNCHANGED),
    (["tp"], MISS, MISS, Category.UNCHANGED),
])
def test_another_rule_is_judged_by_the_files_labels(file_labels, base, head, expected):
    assert categorize(None, None, False, file_labels, base, head) == expected


@pytest.mark.unit
@pytest.mark.parametrize("meta, expected", [
    ({}, None),
    ({"enabled": False}, "enabled = false"),
    ({"enabled": "no"}, "enabled = false"),
    ({"modifiers": "qa"}, "in QA mode"),
    ({"modifiers": "directive=sandbox, no_alert"}, "no_alert"),
    ({"modifiers": "directive=sandbox"}, None),
])
def test_detection_blocker(meta, expected):
    assert detection_blocker(meta) == expected


def _corpus(samples: dict, units: dict[str, int] | None = None) -> Corpus:
    """samples: (sha256, rule uuid) -> (label, source). One replayed unit per file."""
    corpus = Corpus()
    sha256s = sorted({sha256 for sha256, _ in samples} | set(units or {}))
    for index, sha256 in enumerate(sha256s):
        corpus.units.append(Unit(index, sha256, f"{index}.bin", (), path=f"/work/u/{index}/files/{index}.bin"))
        corpus.nodes[sha256] = "node"
    for (sha256, rule_uuid), (label, source) in samples.items():
        corpus.samples[(sha256, rule_uuid)] = Sample(sha256, rule_uuid, f"rule_{rule_uuid}", label, source)
    return corpus


def _side(corpus: Corpus, rules: dict[str, dict], matches: dict[str, list[str]], errors: dict[str, set] | None = None,
          source: set[str] | None = None) -> SideScan:
    """rules: uuid -> meta (each in namespace ns). matches: sha256 -> uuids that matched it."""
    unit_of = {unit.sha256: unit.id for unit in corpus.units}
    scan = SideScan(
        loaded={rule_uuid: [RuleInfo(rule_uuid, f"rule_{rule_uuid}", "ns", "yara/ns/r.yar", {"uuid": rule_uuid, **meta})]
                for rule_uuid, meta in rules.items()},
        source_uuids=set(rules) if source is None else source)
    for sha256, rule_uuids in matches.items():
        scan.matches[unit_of[sha256]] = [("ns", f"rule_{u}", {"uuid": u, **rules.get(u, {})}) for u in rule_uuids]
    for sha256, namespaces in (errors or {}).items():
        scan.errors[unit_of[sha256]] = namespaces
    return scan


def _by_pair(rows):
    return {(row.sha256, row.rule_uuid): row for row in rows}


@pytest.mark.unit
def test_diff_lists_changes_and_counts_the_rest():
    corpus = _corpus({
        (A, "r1"): ("tp", SOURCE_INHERITED_SINGLE),
        (B, "r2"): ("fp", SOURCE_INHERITED_SINGLE),
        (C, "r3"): ("fp", SOURCE_INHERITED_SINGLE),
    })
    base = _side(corpus, {"r1": {}, "r2": {}, "r3": {}}, {A: ["r1"], C: ["r3"]})
    head = _side(corpus, {"r1": {}, "r2": {}, "r3": {}, "new": {}}, {B: ["r2", "new"], C: ["r3"], A: ["new"]})

    rows, counts = diff(corpus, base, head, retired=set(), not_testable=set())
    pairs = _by_pair(rows)
    assert pairs[(A, "r1")].category == Category.REGRESSION
    assert pairs[(B, "r2")].category == Category.NEW_FP
    assert pairs[(B, "new")].category == Category.NEW_FP_OTHER_RULE
    assert pairs[(A, "new")].category == Category.NEW_MATCH_REAL_HIT
    assert (C, "r3") not in pairs
    assert counts[Category.KNOWN_FP] == 1
    assert pairs[(A, "r1")].label == "tp" and pairs[(A, "new")].label is None


@pytest.mark.unit
def test_a_rule_that_no_longer_makes_a_detection_regresses_with_a_note():
    corpus = _corpus({(A, "r1"): ("tp", SOURCE_INHERITED_SINGLE)})
    base = _side(corpus, {"r1": {}}, {A: ["r1"]})
    head = _side(corpus, {"r1": {"modifiers": "qa"}}, {A: ["r1"]})

    (row,) = diff(corpus, base, head, retired=set(), not_testable=set())[0]
    assert row.category == Category.REGRESSION
    assert (row.raw_base, row.raw_head) == (True, True)
    assert (row.base, row.head) == (Outcome.MATCH, Outcome.MISS)
    assert "QA mode" in row.note


@pytest.mark.unit
def test_retired_not_testable_removed_and_foreign_rules():
    corpus = _corpus({
        (A, "retired"): ("tp", SOURCE_INHERITED_SINGLE),
        (A, "shared"): ("tp", SOURCE_INHERITED_SINGLE),
        (A, "removed"): ("tp", SOURCE_INHERITED_SINGLE),
        (A, "foreign"): ("tp", SOURCE_INHERITED_SINGLE),
        (B, "dropped"): ("tp", SOURCE_INHERITED_SINGLE),
    })
    base = _side(corpus, {"retired": {}, "shared": {}, "removed": {}, "dropped": {}},
                 {A: ["retired", "shared", "removed"], B: ["dropped"]})
    # "dropped" is still in head's source, but its file does not compile
    head = _side(corpus, {"shared": {}}, {}, source={"retired", "shared", "dropped"})
    head.loaded.pop("retired", None)

    rows, counts = diff(corpus, base, head, retired={(A, "retired")}, not_testable={"shared"})
    pairs = _by_pair(rows)
    assert counts[Category.RETIRED] == 1 and (A, "retired") not in pairs
    assert counts[Category.NOT_TESTABLE] == 1 and (A, "shared") not in pairs
    assert pairs[(A, "removed")].category == Category.RULE_REMOVED
    assert (A, "foreign") not in pairs and sum(counts.values()) == 4
    assert pairs[(B, "dropped")].category == Category.REGRESSION
    assert "does not compile in head" in pairs[(B, "dropped")].note


@pytest.mark.unit
def test_a_scan_that_failed_is_never_a_miss():
    corpus = _corpus({(A, "r1"): ("tp", SOURCE_INHERITED_SINGLE), (B, "r1"): ("tp", SOURCE_INHERITED_SINGLE)})
    base = _side(corpus, {"r1": {}}, {A: ["r1"], B: ["r1"]})
    head = _side(corpus, {"r1": {}}, {B: ["r1"]}, errors={A: {"ns"}, B: {"ns"}})

    pairs = _by_pair(diff(corpus, base, head, retired=set(), not_testable=set())[0])
    assert pairs[(A, "r1")].category == Category.SCAN_ERROR
    assert pairs[(A, "r1")].head == Outcome.ERROR
    # a match found despite the error elsewhere still counts
    assert (B, "r1") not in pairs

    # an error in another namespace does not touch the rule
    head = _side(corpus, {"r1": {}}, {B: ["r1"]}, errors={A: {"other"}})
    pairs = _by_pair(diff(corpus, base, head, retired=set(), not_testable=set())[0])
    assert pairs[(A, "r1")].category == Category.REGRESSION


@pytest.mark.unit
def test_a_file_matches_if_any_of_its_scans_matches():
    corpus = _corpus({(A, "r1"): ("tp", SOURCE_INHERITED_SINGLE)})
    corpus.units.append(Unit(1, A, "renamed.txt", (), path="/work/u/1/files/renamed.txt"))
    base = _side(corpus, {"r1": {}}, {A: ["r1"]})
    head = _side(corpus, {"r1": {}}, {})
    head.matches[1] = [("ns", "rule_r1", {"uuid": "r1"})]

    rows, counts = diff(corpus, base, head, retired=set(), not_testable=set())
    assert rows == [] and counts[Category.UNCHANGED] == 1


@pytest.mark.unit
def test_duplicate_uuids():
    scan = SideScan(loaded={"x": [RuleInfo("x", "one", "ns", "f"), RuleInfo("x", "two", "ns", "f")], "y": []})
    assert duplicate_uuids(scan, Counter({"z": 2, "y": 1})) == {"x", "z"}
