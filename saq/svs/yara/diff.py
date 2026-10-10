"""Comparing a corpus scanned under two commits (docs/SVS.md, Part 2, *Report and baseline*).

The baseline is the set of labels. Every (sample, rule uuid) pair is decided under base and under
head, and only a difference (or a TP that misses on both) is reported. A **match** means the rule
would make a detection: it matched, it is enabled, and its modifiers do not include qa or no_alert
(saq.signatures.yara_meta, as the YARA module reads them). The raw match is kept beside it, so a
rule that still matches but was switched to QA mode reads as what it is.

| own label | base | head | category |
|---|---|---|---|
| tp | match | miss | regression (regression_unconfirmed for an inherited_multi label) |
| tp | miss | match | recovered |
| tp | miss | miss | already_broken |
| fp | match | miss | improvement |
| fp | miss | match | new_fp |
| fp | match | match | known_fp (counted) |
| none / conflicted | differs | differs | unlabeled_change |

A pair that is not a sample is a rule matching a file captured for another rule. A new match there
is judged by the labels the file has: all fp makes it new_fp_other_rule, any tp
new_match_real_hit (informational), anything else an unlabeled_change. A rule's own label always
wins over the file's.

Before any of that: a retired pair is only counted; a rule in neither commit belongs to another
repository and is dropped; a rule whose uuid two rules of head share is not_testable; a sample
whose rule head no longer has at all is rule_removed; and a side that could not scan the file in
the rule's namespace (a timeout, an error) makes it scan_error, never a miss.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Optional

from saq.detection_verdicts.constants import SOURCE_INHERITED_MULTI
from saq.signatures.yara_meta import MODIFIER_NO_ALERT, MODIFIER_QA, meta_enabled, meta_modifiers
from saq.svs.constants import LABEL_FP, LABEL_TP
from saq.svs.yara.corpus import Corpus


class Category(StrEnum):
    REGRESSION = "regression"
    REGRESSION_UNCONFIRMED = "regression_unconfirmed"
    NEW_FP = "new_fp"
    NEW_FP_OTHER_RULE = "new_fp_other_rule"
    RULE_REMOVED = "rule_removed"
    SCAN_ERROR = "scan_error"
    RECOVERED = "recovered"
    IMPROVEMENT = "improvement"
    ALREADY_BROKEN = "already_broken"
    NEW_MATCH_REAL_HIT = "new_match_real_hit"
    UNLABELED_CHANGE = "unlabeled_change"
    KNOWN_FP = "known_fp"
    RETIRED = "retired"
    NOT_TESTABLE = "not_testable"
    UNCHANGED = "unchanged"


# counted, never listed
COUNTED_ONLY = frozenset({Category.KNOWN_FP, Category.RETIRED, Category.NOT_TESTABLE, Category.UNCHANGED})


class Outcome(StrEnum):
    MATCH = "match"
    MISS = "miss"
    ERROR = "error"


@dataclass(frozen=True)
class RuleInfo:
    uuid: str
    name: str
    namespace: str
    # relative to the repository root
    file: str
    meta: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


@dataclass
class SideScan:
    """What one commit's rules did over the corpus, as the diff needs it."""
    # rules in files that compiled, by uuid (two or more when the uuid is shared)
    loaded: dict[str, list[RuleInfo]] = field(default_factory=dict)
    # uuids of every rule in the commit's source, compiled or not
    source_uuids: set[str] = field(default_factory=set)
    # unit id -> [(namespace, rule name, meta)] of every match
    matches: dict[int, list[tuple[str, str, dict]]] = field(default_factory=dict)
    # unit id -> namespaces whose scan of the unit failed
    errors: dict[int, set[str]] = field(default_factory=dict)

    def knows(self, rule_uuid: str) -> bool:
        return rule_uuid in self.source_uuids or rule_uuid in self.loaded


@dataclass(frozen=True)
class ResultRow:
    sha256: str
    rule_uuid: str
    rule_name: str
    namespace: Optional[str]
    label: Optional[str]
    label_source: Optional[str]
    base: Outcome
    head: Outcome
    raw_base: bool
    raw_head: bool
    category: Category
    note: Optional[str] = None


def detection_blocker(meta: dict) -> Optional[str]:
    """Why a match of a rule with this meta would make no detection, or None if it would."""
    if not meta_enabled(meta):
        return "enabled = false"

    modifiers = meta_modifiers(meta)
    if MODIFIER_QA in modifiers:
        return "in QA mode"
    if MODIFIER_NO_ALERT in modifiers:
        return "no_alert"

    return None


def _uuid(meta: dict) -> Optional[str]:
    value = (meta or {}).get("uuid")
    return str(value).strip() if value else None


@dataclass
class _PairState:
    raw: bool = False
    detects: bool = False
    blocker: Optional[str] = None


def _side_pairs(corpus: Corpus, side: SideScan) -> dict[tuple[str, str], _PairState]:
    units = {unit.id: unit for unit in corpus.units if unit.path is not None}
    result: dict[tuple[str, str], _PairState] = defaultdict(_PairState)
    for unit_id, matches in side.matches.items():
        unit = units.get(unit_id)
        if unit is None:
            continue

        for _, _, meta in matches:
            rule_uuid = _uuid(meta)
            if rule_uuid is None:
                continue

            state = result[(unit.sha256, rule_uuid)]
            state.raw = True
            blocker = detection_blocker(meta)
            if blocker is None:
                state.detects = True
            else:
                state.blocker = blocker

    return result


def _errored(corpus: Corpus, side: SideScan) -> dict[str, set[str]]:
    """sha256 -> the namespaces in which a scan of one of its units failed."""
    result: dict[str, set[str]] = defaultdict(set)
    for unit in corpus.units:
        if unit.path is not None and unit.id in side.errors:
            result[unit.sha256] |= side.errors[unit.id]
    return result


def _outcome(pair: _PairState, rule_uuid: str, sha256: str, side: SideScan, errored: dict[str, set[str]]) -> Outcome:
    if pair.detects:
        return Outcome.MATCH

    namespaces = {rule.namespace for rule in side.loaded.get(rule_uuid, [])}
    if namespaces & errored.get(sha256, set()):
        return Outcome.ERROR

    return Outcome.MISS


def _note(rule_uuid: str, base: _PairState, head: _PairState, head_scan: SideScan) -> Optional[str]:
    notes = []
    if head.raw and not head.detects:
        notes.append(f"matches in head but makes no detection ({head.blocker})")
    if base.raw and not base.detects:
        notes.append(f"matches in base but makes no detection ({base.blocker})")
    if rule_uuid in head_scan.source_uuids and rule_uuid not in head_scan.loaded:
        notes.append("its file does not compile in head")
    return "; ".join(notes) or None


def categorize(own_label: Optional[str], label_source: Optional[str], is_sample: bool,
               file_labels: list[Optional[str]], base: Outcome, head: Outcome) -> Category:
    """The category of one pair whose rule both commits know and neither scan failed on."""
    b, h = base == Outcome.MATCH, head == Outcome.MATCH
    if is_sample and own_label == LABEL_TP:
        if b and not h:
            return Category.REGRESSION_UNCONFIRMED if label_source == SOURCE_INHERITED_MULTI else Category.REGRESSION
        if h and not b:
            return Category.RECOVERED
        if not b and not h:
            return Category.ALREADY_BROKEN
        return Category.UNCHANGED

    if is_sample and own_label == LABEL_FP:
        if b and not h:
            return Category.IMPROVEMENT
        if h and not b:
            return Category.NEW_FP
        if b and h:
            return Category.KNOWN_FP
        return Category.UNCHANGED

    if b == h:
        return Category.UNCHANGED

    if not is_sample and h:
        if file_labels and all(label == LABEL_FP for label in file_labels):
            return Category.NEW_FP_OTHER_RULE
        if LABEL_TP in file_labels:
            return Category.NEW_MATCH_REAL_HIT

    return Category.UNLABELED_CHANGE


def duplicate_uuids(side: SideScan, source_counts: Counter) -> set[str]:
    """uuids that more than one rule of the commit carries."""
    return {rule_uuid for rule_uuid, rules in side.loaded.items() if len(rules) > 1} | {
        rule_uuid for rule_uuid, count in source_counts.items() if count > 1}


def diff(corpus: Corpus, base: SideScan, head: SideScan, *, retired: set[tuple[str, str]],
         not_testable: set[str]) -> tuple[list[ResultRow], Counter]:
    """Every listed pair as a row (COUNTED_ONLY categories are counted only), and the count of
    every category."""
    base_pairs = _side_pairs(corpus, base)
    head_pairs = _side_pairs(corpus, head)
    base_errors = _errored(corpus, base)
    head_errors = _errored(corpus, head)
    replayed = corpus.replayed_sha256s()
    file_labels: dict[str, list[Optional[str]]] = defaultdict(list)
    for (sha256, _), sample in corpus.samples.items():
        file_labels[sha256].append(sample.label)

    pairs = {pair for pair in corpus.samples if pair[0] in replayed} | set(base_pairs) | set(head_pairs)
    rows: list[ResultRow] = []
    counts: Counter = Counter()
    for sha256, rule_uuid in sorted(pairs):
        if not (base.knows(rule_uuid) or head.knows(rule_uuid)):
            # a rule of another repository
            continue

        sample = corpus.samples.get((sha256, rule_uuid))
        if sample is None and not head.knows(rule_uuid):
            # a rule head removed, matching a file it was never captured for
            continue

        base_pair = base_pairs.get((sha256, rule_uuid), _PairState())
        head_pair = head_pairs.get((sha256, rule_uuid), _PairState())
        base_outcome = _outcome(base_pair, rule_uuid, sha256, base, base_errors)
        head_outcome = _outcome(head_pair, rule_uuid, sha256, head, head_errors)

        if (sha256, rule_uuid) in retired:
            category = Category.RETIRED
        elif rule_uuid in not_testable:
            category = Category.NOT_TESTABLE
        elif not head.knows(rule_uuid):
            category = Category.RULE_REMOVED
        elif Outcome.ERROR in (base_outcome, head_outcome):
            category = Category.SCAN_ERROR
        else:
            category = categorize(
                sample.label if sample else None, sample.label_source if sample else None, sample is not None,
                file_labels[sha256], base_outcome, head_outcome)

        counts[category] += 1
        if category in COUNTED_ONLY:
            continue

        rules = head.loaded.get(rule_uuid) or base.loaded.get(rule_uuid) or []
        rows.append(ResultRow(
            sha256=sha256,
            rule_uuid=rule_uuid,
            rule_name=rules[0].name if rules else (sample.rule_name if sample else ""),
            namespace=rules[0].namespace if rules else None,
            label=sample.label if sample else None,
            label_source=sample.label_source if sample else None,
            base=base_outcome,
            head=head_outcome,
            raw_base=base_pair.raw,
            raw_head=head_pair.raw,
            category=category,
            note=_note(rule_uuid, base_pair, head_pair, head)))

    return rows, counts
