"""ATT&CK coverage per technique and platform (docs/SVS_COVERAGE.md), kept in svs_coverage.

compute_rows() derives every row from the inputs alone:
- each catalog test that isn't removed, judged on each of its platforms (saq.svs.test_state);
- the mitre: tags of the hunts and YARA rules (saq.svs.signatures.signature_techniques);
- the pinned ATT&CK release (saq.svs.attack).

refresh_coverage() locks svs_coverage_state, refreshes the declared-vs-measured worklist
(saq.svs.worklist) first, computes, and writes only the columns that changed, so a row's updated_at
moves only on a real change. A row the computation no longer produces is retired,
never deleted. service_svs refreshes every svs.coverage.refresh_interval_seconds on the primary node;
`ace svs coverage refresh` does it at once. write_snapshot() refreshes, then copies the rows into
svs_coverage_snapshots under the day's date (`ace svs coverage snapshot`, daily from cron).
technique_detail() is the live part of a technique's drill-down (GET /api/v2/svs/coverage/{technique}).

A test's contribution to the row of its technique on a platform is its state there:
- validated, failing and stale count as themselves;
- an expectation that no reviewed run there has judged yet makes it stale;
- otherwise (never run there, no reviewed run there, nothing expected there) it is untested.
A signature's mitre: tag naming technique t, when it counts (not resolved remove on the worklist,
unless measurement confirms it), makes every row of t manual (not those of t's sub-techniques). A row's state is the worst of what counts toward it and toward its
sub-techniques' rows on the same platform (CoverageState order); own_state leaves the
sub-techniques out; a row nothing counts toward is none.
"""

import json
import logging
import time
from dataclasses import dataclass, field, fields
from datetime import date, datetime, timezone
from typing import Iterable, Optional

from sqlalchemy import delete, func, insert, literal, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.database.model import SVSCatalogTest, SVSCoverage, SVSCoverageSnapshot, SVSCoverageState
from saq.database.private_session import private_transaction
from saq.svs.attack import AttackCatalog, TechniqueStatus, get_attack_catalog
from saq.svs.catalog import platform_slugs
from saq.svs.constants import CoverageState
from saq.svs.coverage_lock import STATE_ID, lock_refresh
from saq.svs.signatures import SignatureTags, SignatureTagsUnavailable, signature_techniques
from saq.svs.test_state import Evaluation, TestState, evaluate_tests
from saq.svs.worklist import Measured, excluded_mappings, log_worklist_refresh, refresh_worklist

# worst first: a row is in the first of these anything counting toward it is in
WORST_FIRST = (CoverageState.FAILING, CoverageState.STALE, CoverageState.VALIDATED, CoverageState.MANUAL,
               CoverageState.UNTESTED)


@dataclass(frozen=True)
class CoverageRow:
    """The computed columns of one svs_coverage row; refresh_coverage compares exactly these."""
    technique: str
    platform: str
    parent: Optional[str]
    is_subtechnique: bool
    technique_name: Optional[str]
    # JSON-serialized tactic ids
    tactics: str
    catalog_status: str
    attack_platform: bool
    state: str
    own_state: str
    tests_total: int
    tests_validated: int
    tests_failing: int
    tests_stale: int
    manual_signatures: int
    measured_signatures: int
    last_reviewed_at: Optional[datetime]


# the columns a refresh may change on an existing row
COMPUTED_COLUMNS = tuple(f.name for f in fields(CoverageRow) if f.name not in ("technique", "platform"))


@dataclass
class ComputedCoverage:
    rows: dict[tuple[str, str], CoverageRow]
    # mitre: tags naming an id the release doesn't have; mitre: tags that aren't technique ids
    unknown_tags: int = 0
    ignored_tags: int = 0
    # catalog tests whose technique isn't a technique id
    skipped_tests: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Contribution:
    """What one test counts toward one row of its technique."""
    guid: str
    state: CoverageState
    reviewed_at: Optional[datetime]
    # the signatures expected of the test on the platform, ignores applied
    measured: frozenset[str]


@dataclass(frozen=True)
class CoverageRefresh:
    rows: int
    changed: int
    inserted: int
    retired: int
    duration_ms: int
    # worklist rows that aren't retired, and how many changed
    worklist_rows: int = 0
    worklist_changed: int = 0


def contribution_state(evaluation: Optional[Evaluation]) -> CoverageState:
    """What a test's state on a platform counts as toward coverage."""
    if evaluation is None:
        return CoverageState.UNTESTED
    if evaluation.state == TestState.VALIDATED:
        return CoverageState.VALIDATED
    if evaluation.state == TestState.FAILING:
        return CoverageState.FAILING
    if evaluation.state == TestState.STALE:
        return CoverageState.STALE
    if evaluation.state == TestState.AWAITING_REVIEW and evaluation.run is not None \
            and evaluation.unjudged_expectations:
        # expected only after its latest review there: what was validated no longer says enough
        return CoverageState.STALE
    return CoverageState.UNTESTED


def _worst(states: Iterable[CoverageState]) -> CoverageState:
    states = set(states)
    return next((state for state in WORST_FIRST if state in states), CoverageState.NONE)


def evaluations_by_test(evaluations: dict[tuple[str, str], Evaluation]) -> dict[str, dict[str, Evaluation]]:
    """evaluate_tests() results as {guid: {platform: evaluation}}."""
    by_test: dict[str, dict[str, Evaluation]] = {}
    for (guid, platform), evaluation in evaluations.items():
        by_test.setdefault(guid, {})[platform] = evaluation
    return by_test


def test_contributions(catalog: AttackCatalog, test: SVSCatalogTest,
                       evaluations: dict[str, Evaluation]) -> tuple[Optional[str], dict[str, Contribution]]:
    """The technique a catalog test counts toward (None when its technique isn't a technique id),
    and what it counts toward that technique's row on each platform. evaluations are the test's
    evaluate_tests() results by platform. compute_rows() and the coverage drill-down both count a
    test through this."""
    try:
        technique = catalog.resolve(test.technique).technique
    except ValueError:
        return None, {}

    # a run or a decision on a platform the test no longer supports still counts there; the empty
    # platform of a decision from before runs had one doesn't
    platforms = (set(platform_slugs(test)) | set(evaluations)) - {""}
    counted = {}
    for platform in sorted(platforms):
        evaluation = evaluations.get(platform)
        counted[platform] = Contribution(
            test.guid, contribution_state(evaluation),
            evaluation.run.reviewed_at if evaluation is not None and evaluation.run is not None else None,
            frozenset(evaluation.expected) if evaluation is not None else frozenset())
    return technique, counted


def measured_by_signature(catalog: AttackCatalog, tests: Iterable[SVSCatalogTest],
                          evaluations: dict[tuple[str, str], Evaluation]) -> Measured:
    """{signature uuid: {technique: {(test guid, platform)}}}: where each signature is expected,
    ignores applied, counted as compute_rows() counts the tests."""
    measured: Measured = {}
    by_test = evaluations_by_test(evaluations)
    for test in tests:
        technique, counted = test_contributions(catalog, test, by_test.get(test.guid, {}))
        if technique is None:
            continue
        for platform, contribution in counted.items():
            for signature_uuid in contribution.measured:
                measured.setdefault(signature_uuid, {}).setdefault(technique, set()).add((test.guid, platform))
    return measured


def compute_rows(catalog: AttackCatalog, tests: Iterable[SVSCatalogTest],
                 evaluations: dict[tuple[str, str], Evaluation],
                 tags: dict[str, SignatureTags],
                 excluded: frozenset[tuple[str, str]] = frozenset()) -> ComputedCoverage:
    """Every coverage row. tests are the catalog tests that count (not removed), evaluations
    evaluate_tests() of them, tags signature_techniques(), and excluded the (signature uuid,
    technique) tags the worklist resolved remove (saq.svs.worklist.excluded_mappings)."""
    computed = ComputedCoverage(rows={})
    by_test = evaluations_by_test(evaluations)

    # (technique, platform) -> what each test counts toward it
    contributions: dict[tuple[str, str], list[Contribution]] = {}
    # technique -> its tests' platforms
    test_platforms: dict[str, set[str]] = {}
    # technique -> the technique name a test gives it, for one the release doesn't have
    test_names: dict[str, str] = {}
    for test in sorted(tests, key=lambda test: test.guid):
        technique, counted = test_contributions(catalog, test, by_test.get(test.guid, {}))
        if technique is None:
            computed.skipped_tests.append(test.guid)
            continue

        if test.technique_name:
            test_names.setdefault(technique, test.technique_name)
        test_platforms.setdefault(technique, set()).update(counted)
        for platform, contribution in counted.items():
            contributions.setdefault((technique, platform), []).append(contribution)

    # technique -> the signatures whose tags make it manual
    manual: dict[str, set[str]] = {}
    for signature in tags.values():
        computed.ignored_tags += len(signature.ignored)
        for declared in signature.declared:
            resolution = catalog.resolve(declared)
            if resolution.status == TechniqueStatus.UNKNOWN:
                computed.unknown_tags += 1
            elif signature.counts and (signature.uuid, resolution.technique) not in excluded:
                manual.setdefault(resolution.technique, set()).add(signature.uuid)

    # the techniques with rows: every active one in the release, every one a test or a counting tag
    # names, and the parent of each of those
    techniques = {technique.id for technique in catalog.techniques.values() if not technique.deprecated}
    techniques |= set(test_platforms) | set(manual)
    techniques |= {parent for parent in (catalog.parent_of(technique) for technique in techniques) if parent}

    children: dict[str, set[str]] = {}
    for technique in techniques:
        parent = catalog.parent_of(technique)
        if parent is not None:
            children.setdefault(parent, set()).add(technique)

    def own_platforms(technique: str) -> set[str]:
        known = catalog.technique(technique)
        return set(known.platforms if known is not None else ()) | test_platforms.get(technique, set())

    for technique in sorted(techniques):
        known = catalog.technique(technique)
        attack_platforms = set(known.platforms) if known is not None else set()
        mine = own_platforms(technique)
        subs = sorted(children.get(technique, ()))
        sub_platforms = {sub: own_platforms(sub) for sub in subs}
        platforms = mine.union(*sub_platforms.values())
        parent = catalog.parent_of(technique)

        for platform in sorted(platforms):
            own = contributions.get((technique, platform), [])
            own_manual = manual.get(technique, set())
            rolled = list(own)
            rolled_manual = set(own_manual)
            for sub in subs:
                if platform in sub_platforms[sub]:
                    rolled.extend(contributions.get((sub, platform), []))
                    rolled_manual |= manual.get(sub, set())

            own_states = [contribution.state for contribution in own] + ([CoverageState.MANUAL] if own_manual else [])
            rolled_states = [contribution.state for contribution in rolled] + (
                [CoverageState.MANUAL] if rolled_manual else [])
            reviewed = [contribution.reviewed_at for contribution in rolled if contribution.reviewed_at is not None]

            computed.rows[(technique, platform)] = CoverageRow(
                technique=technique, platform=platform, parent=parent, is_subtechnique="." in technique,
                technique_name=known.name if known is not None else test_names.get(technique),
                tactics=json.dumps(list(known.tactics) if known is not None else []),
                catalog_status=(known.status if known is not None else TechniqueStatus.UNKNOWN).value,
                attack_platform=platform in attack_platforms,
                state=_worst(rolled_states).value, own_state=_worst(own_states).value,
                tests_total=len(rolled),
                tests_validated=sum(1 for c in rolled if c.state == CoverageState.VALIDATED),
                tests_failing=sum(1 for c in rolled if c.state == CoverageState.FAILING),
                tests_stale=sum(1 for c in rolled if c.state == CoverageState.STALE),
                manual_signatures=len(rolled_manual),
                measured_signatures=len(set().union(*(contribution.measured for contribution in rolled))),
                last_reviewed_at=max(reviewed, default=None))

    return computed


@dataclass
class _Written:
    changed: int = 0
    inserted: int = 0
    retired: int = 0
    # (technique, platform, from_state, to_state) of each row whose state changed
    transitions: list[tuple[str, str, str, str]] = field(default_factory=list)


def _write(session, computed: ComputedCoverage, now: datetime) -> _Written:
    """Writes the computed rows over the stored ones."""
    stored = {(row.technique, row.platform): row for row in session.execute(select(SVSCoverage)).scalars()}
    written = _Written()

    for key, row in computed.rows.items():
        current = stored.get(key)
        if current is None:
            session.add(SVSCoverage(**{f.name: getattr(row, f.name) for f in fields(CoverageRow)},
                                    state_changed_at=now, first_seen_at=now))
            written.changed += 1
            written.inserted += 1
            continue

        differs = [name for name in COMPUTED_COLUMNS if getattr(current, name) != getattr(row, name)]
        if not differs and current.retired_at is None:
            continue

        if current.state != row.state:
            written.transitions.append((row.technique, row.platform, current.state, row.state))
            current.state_changed_at = now
        for name in differs:
            setattr(current, name, getattr(row, name))
        current.retired_at = None
        written.changed += 1

    for key, current in stored.items():
        if key not in computed.rows and current.retired_at is None:
            current.retired_at = now
            written.changed += 1
            written.retired += 1

    return written


def _record_error(error: str):
    try:
        with private_transaction() as session:
            session.execute(insert(SVSCoverageState).prefix_with("IGNORE").values(id=STATE_ID))
            session.execute(update(SVSCoverageState).where(SVSCoverageState.id == STATE_ID).values(error=error))
    except Exception as e:
        logging.warning("unable to record the svs coverage refresh error: %s", e)


def refresh_coverage(actor: str, *, now: Optional[datetime] = None) -> CoverageRefresh:
    """Recomputes svs_coverage. A failure (a YARA rule location that can't be read, a database
    error) changes no row; it is recorded on svs_coverage_state and raised."""
    started = time.monotonic()
    now = now or datetime.now()
    catalog = get_attack_catalog()
    try:
        # read from the filesystem before taking the lock; nothing else waits on it, but refreshes do
        tags = signature_techniques()
        with private_transaction() as session:
            state = lock_refresh(session)
            # read after the lock, so a refresh never writes what it read before another one wrote
            tests = list(session.execute(
                select(SVSCatalogTest).where(SVSCatalogTest.removed_at.is_(None))).scalars())
            evaluations = evaluate_tests(session, tests)
            # the worklist first: what it resolved remove doesn't count
            worklist = refresh_worklist(session, catalog, tags, measured_by_signature(catalog, tests, evaluations),
                                        now)
            computed = compute_rows(catalog, tests, evaluations, tags, worklist.excluded)
            written = _write(session, computed, now)

            duration_ms = int((time.monotonic() - started) * 1000)
            state.attack_release = catalog.release
            state.refreshed_at = now
            state.duration_ms = duration_ms
            state.rows = len(computed.rows)
            state.changed = written.changed
            state.retired = written.retired
            state.unknown_tags = computed.unknown_tags
            state.ignored_tags = computed.ignored_tags
            state.error = None
    except Exception as e:
        _record_error(str(e) or type(e).__name__)
        raise

    # logged once committed
    log_worklist_refresh(worklist, actor)
    for technique, platform, from_state, to_state in written.transitions:
        logging.info("svs coverage of %s on %s: %s -> %s", technique, platform, from_state, to_state,
                     extra={"technique": technique, "platform": platform, "from_state": from_state,
                            "to_state": to_state})
    if computed.skipped_tests:
        logging.warning("svs coverage left out %d catalog tests whose technique isn't an ATT&CK technique id",
                        len(computed.skipped_tests), extra={"svs_tests": computed.skipped_tests})
    logging.info("svs coverage refreshed: %d rows, %d changed, %d retired in %dms; worklist %d rows, %d changed",
                 len(computed.rows), written.changed, written.retired, duration_ms, worklist.rows, worklist.changed,
                 extra={"attack_release": catalog.release, "rows": len(computed.rows), "changed": written.changed,
                        "retired": written.retired, "duration_ms": duration_ms, "worklist_rows": worklist.rows,
                        "worklist_changed": worklist.changed, "actor": actor})
    return CoverageRefresh(len(computed.rows), written.changed, written.inserted, written.retired, duration_ms,
                           worklist.rows, worklist.changed)


def coverage_counts(session) -> dict[str, dict[str, int]]:
    """{platform: {state: rows}} over the rows that aren't retired."""
    counts: dict[str, dict[str, int]] = {}
    for platform, state, count in session.execute(
            select(SVSCoverage.platform, SVSCoverage.state, func.count())
            .where(SVSCoverage.retired_at.is_(None))
            .group_by(SVSCoverage.platform, SVSCoverage.state)):
        counts.setdefault(platform, {})[state] = count
    return counts


#
# snapshots
#

# the svs_coverage columns a snapshot copies, besides technique and platform
SNAPSHOT_COLUMNS = ("parent", "is_subtechnique", "state", "own_state", "tests_total", "tests_validated",
                    "tests_failing", "tests_stale", "manual_signatures", "measured_signatures")


@dataclass(frozen=True)
class CoverageSnapshot:
    snapshot_date: date
    attack_release: str
    rows: int
    # rows of an earlier snapshot the same day that are no longer in coverage
    deleted: int


def write_snapshot(actor: str, *, snapshot_date: Optional[date] = None,
                   now: Optional[datetime] = None) -> CoverageSnapshot:
    """Refreshes coverage, then files its rows that aren't retired under snapshot_date (default:
    today, UTC). A second snapshot on the same day replaces the day. A failed refresh raises before
    anything is written."""
    refresh_coverage(actor, now=now)
    snapshot_date = snapshot_date or datetime.now(timezone.utc).date()
    with private_transaction() as session:
        state = lock_refresh(session)
        attack_release = state.attack_release
        live = SVSCoverage.retired_at.is_(None)
        statement = mysql_insert(SVSCoverageSnapshot).from_select(
            ["snapshot_date", "attack_release", "technique", "platform", *SNAPSHOT_COLUMNS],
            select(literal(snapshot_date), literal(attack_release), SVSCoverage.technique, SVSCoverage.platform,
                   *[getattr(SVSCoverage, name) for name in SNAPSHOT_COLUMNS])
            .where(live).order_by(SVSCoverage.technique, SVSCoverage.platform))
        session.execute(statement.on_duplicate_key_update(
            attack_release=statement.inserted.attack_release,
            **{name: getattr(statement.inserted, name) for name in SNAPSHOT_COLUMNS}))
        deleted = session.execute(
            delete(SVSCoverageSnapshot)
            .where(SVSCoverageSnapshot.snapshot_date == snapshot_date,
                   ~select(SVSCoverage.id).where(SVSCoverage.technique == SVSCoverageSnapshot.technique,
                                                 SVSCoverage.platform == SVSCoverageSnapshot.platform,
                                                 live).exists())).rowcount
        rows = session.execute(select(func.count()).select_from(SVSCoverage).where(live)).scalar_one()

    logging.info("svs coverage snapshot of %s written: %d rows", snapshot_date, rows,
                 extra={"snapshot_date": snapshot_date.isoformat(), "rows": rows, "attack_release": attack_release,
                        "actor": actor})
    return CoverageSnapshot(snapshot_date, attack_release, rows, deleted)


#
# the drill-down
#

@dataclass(frozen=True)
class TestCoverage:
    """One catalog test on one platform, as it counts toward its technique's row there."""
    __test__ = False

    test: SVSCatalogTest
    # the technique it counts toward (its own, revoked ids remapped)
    technique: str
    platform: str
    # None: nothing reviewed or decided there
    evaluation: Optional[Evaluation]
    contribution: Contribution


@dataclass(frozen=True)
class ManualMapping:
    """A signature's mitre: tag naming the technique or one of its sub-techniques."""
    signature: SignatureTags
    # the id as the tag names it, and the technique it counts as
    declared: str
    technique: str
    counts: bool
    # why it doesn't count: disabled (or a YARA rule in QA mode), an id the release doesn't have, or
    # resolved remove on the worklist
    reason: Optional[str]


@dataclass
class TechniqueDetail:
    technique: str
    tests: list[TestCoverage]
    removed_tests: list[SVSCatalogTest]
    manual: list[ManualMapping]
    # why the manual mappings couldn't be read (they are then empty)
    manual_error: Optional[str] = None


def _covers(catalog: AttackCatalog, technique: str, candidate: str) -> bool:
    return candidate == technique or catalog.parent_of(candidate) == technique


def technique_detail(session, catalog: AttackCatalog, technique: str) -> TechniqueDetail:
    """What counts toward a technique's rows now, and toward its sub-techniques' (the technique is
    already resolved). Reads the catalog tests, evaluates the ones of the technique, and reads the
    signature tags."""
    tests, removed = [], []
    # every test's technique, to resolve it as compute_rows() does; the full rows only for the matches
    matches = {}
    for test_id, raw, removed_at in session.execute(
            select(SVSCatalogTest.id, SVSCatalogTest.technique, SVSCatalogTest.removed_at)):
        try:
            resolved = catalog.resolve(raw).technique
        except ValueError:
            continue
        if _covers(catalog, technique, resolved):
            matches[test_id] = removed_at is not None

    if matches:
        rows = session.execute(select(SVSCatalogTest).where(SVSCatalogTest.id.in_(sorted(matches)))
                               .order_by(SVSCatalogTest.technique, SVSCatalogTest.name, SVSCatalogTest.id)).scalars()
        current = []
        for test in rows:
            (removed if matches[test.id] else current).append(test)
        by_test = evaluations_by_test(evaluate_tests(session, current))
        for test in current:
            evaluations = by_test.get(test.guid, {})
            resolved, counted = test_contributions(catalog, test, evaluations)
            for platform, contribution in counted.items():
                tests.append(TestCoverage(test, resolved, platform, evaluations.get(platform), contribution))

    detail = TechniqueDetail(technique, tests, removed, [])
    try:
        tags = signature_techniques()
    except SignatureTagsUnavailable as e:
        detail.manual_error = str(e)
        tags = {}

    excluded = excluded_mappings(session)
    for signature in sorted(tags.values(), key=lambda signature: signature.uuid):
        for declared in signature.declared:
            resolution = catalog.resolve(declared)
            if not _covers(catalog, technique, resolution.technique):
                continue
            if resolution.status == TechniqueStatus.UNKNOWN:
                reason = "unknown_technique"
            elif not signature.counts:
                reason = "not_counting"
            elif (signature.uuid, resolution.technique) in excluded:
                reason = "removed"
            else:
                reason = None
            detail.manual.append(ManualMapping(signature, declared, resolution.technique, reason is None, reason))

    return detail
