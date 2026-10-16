"""What the Tests screen shows of each Atomic Red Team test's runs (docs/SVS.md, Part 5, *Tests*): its
state, its last run and last reviewed run, its expected signatures, and how many of its recent runs
missed one. Read per page, for any number of tests in a fixed number of queries; nothing here is
stored.

A test is judged on each platform on its own (evaluate_tests), by its latest reviewed run on that
platform against what is expected of it there:
- awaiting_review: none of its runs on the platform is reviewed yet, or something was expected of it
  there only after that run was reviewed, so no reviewed run has judged it;
- no_expectations: it has a reviewed run there, and nothing is expected of it there;
- failing: that run, as signed off, missed an expected signature (possibly suppressed counts as
  missed);
- stale: it would be validated, but the test or the rule of an expected signature changed since
  that run was reviewed (a rule whose current content ACE can't read doesn't count as changed);
- validated: that run, as signed off, hit every expected signature.
Expected signatures are those expected of the test on the platform that no ignore applies to.

A test's state is never_run when no run was ever registered for it, else the worst of its
platforms' states: failing, stale, awaiting_review, validated, no_expectations. A platform counts
when the test has a run or a decision there.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Iterable, Optional

from sqlalchemy import func, select

from saq.database.model import SVSCatalogTest, SVSExpectation, SVSIgnore, SVSRun, SVSRunResult
from saq.svs.catalog import platform_slugs
from saq.svs.constants import GLOBAL_SCOPE_KEY, ExpectationState, ResultStatus, RunState
from saq.svs.signatures import SignatureInfo, describe_signatures

# how many of a test's latest ended or reviewed runs "missing in recent runs" looks at
RECENT_RUNS = 5

MISSED = (ResultStatus.MISSING.value, ResultStatus.POSSIBLY_SUPPRESSED.value)


class TestState(StrEnum):
    __test__ = False

    NEVER_RUN = "never_run"
    AWAITING_REVIEW = "awaiting_review"
    NO_EXPECTATIONS = "no_expectations"
    FAILING = "failing"
    STALE = "stale"
    VALIDATED = "validated"


TEST_STATES = tuple(state.value for state in TestState)

# a test's state over its platforms: the first of these any platform is in
WORST_FIRST = (TestState.FAILING, TestState.STALE, TestState.AWAITING_REVIEW, TestState.VALIDATED,
               TestState.NO_EXPECTATIONS)


@dataclass(frozen=True)
class Evaluation:
    """How a test does on one platform."""
    state: TestState
    # its latest reviewed run on the platform
    run: Optional[SVSRun] = None
    # the signatures expected of it there that no ignore applies to
    expected: frozenset[str] = frozenset()
    # something is expected of it there that its latest reviewed run there didn't judge
    unjudged_expectations: bool = False


@dataclass(frozen=True)
class PlatformHistory:
    state: TestState
    last_reviewed_run_uuid: Optional[str] = None
    last_reviewed_at: Optional[datetime] = None
    expected: int = 0


@dataclass(frozen=True)
class TestHistory:
    __test__ = False

    state: TestState
    run_count: int = 0
    last_run_uuid: Optional[str] = None
    last_run_at: Optional[datetime] = None
    last_reviewed_run_uuid: Optional[str] = None
    last_reviewed_at: Optional[datetime] = None
    # signatures expected of it on any platform
    expected: int = 0
    # of the test's latest RECENT_RUNS ended or reviewed runs: how many there are, and how many of
    # them miss an expected signature in their live result
    recent_runs: int = 0
    recent_runs_missing: int = 0
    # by platform: each one it has a run or a decision on, and each supported one (never_run when it
    # has neither there)
    platform_states: dict[str, PlatformHistory] = field(default_factory=dict)


def _latest(session, guids: list[str], *conditions, order) -> dict[str, SVSRun]:
    """The first run of each test in the order given."""
    ranked = (select(SVSRun.id, func.row_number().over(partition_by=SVSRun.test_guid, order_by=order).label("rank"))
              .where(SVSRun.test_guid.in_(guids), *conditions)
              .subquery())
    return {run.test_guid: run for run in session.execute(
        select(SVSRun).join(ranked, ranked.c.id == SVSRun.id).where(ranked.c.rank == 1)).scalars()}


def _latest_reviewed(session, guids: list[str]) -> dict[tuple[str, str], SVSRun]:
    """The latest reviewed run of each test on each platform."""
    ranked = (select(SVSRun.id,
                     func.row_number().over(partition_by=(SVSRun.test_guid, SVSRun.platform),
                                            order_by=(SVSRun.reviewed_at.desc(), SVSRun.id.desc())).label("rank"))
              .where(SVSRun.test_guid.in_(guids), SVSRun.state == RunState.REVIEWED.value)
              .subquery())
    return {(run.test_guid, run.platform): run for run in session.execute(
        select(SVSRun).join(ranked, ranked.c.id == SVSRun.id).where(ranked.c.rank == 1)).scalars()}


def _expected(session, guids: list[str]) -> dict[tuple[str, str], set[str]]:
    """Per (test, platform) with a decision: the expected signatures no ignore applies to (empty
    when every decision there is a rejection or ignored)."""
    ignored: dict[str, set[str]] = {}
    for scope_key, signature_uuid in session.execute(
            select(SVSIgnore.scope_key, SVSIgnore.signature_uuid)
            .where(SVSIgnore.scope_key.in_([GLOBAL_SCOPE_KEY, *guids]))):
        ignored.setdefault(scope_key, set()).add(signature_uuid)

    expected: dict[tuple[str, str], set[str]] = {}
    for guid, platform, signature_uuid, state in session.execute(
            select(SVSExpectation.test_guid, SVSExpectation.platform, SVSExpectation.signature_uuid,
                   SVSExpectation.state)
            .where(SVSExpectation.test_guid.in_(guids))):
        signatures = expected.setdefault((guid, platform), set())
        if state == ExpectationState.EXPECTED.value and \
                signature_uuid not in ignored.get(GLOBAL_SCOPE_KEY, set()) | ignored.get(guid, set()):
            signatures.add(signature_uuid)
    return expected


def _signed_off(session, run_ids: Iterable[int]) -> dict[int, dict[str, SVSRunResult]]:
    """The result rows of each run, by signature."""
    run_ids = sorted(set(run_ids))
    signed_off: dict[int, dict[str, SVSRunResult]] = {run_id: {} for run_id in run_ids}
    if run_ids:
        for row in session.execute(select(SVSRunResult).where(SVSRunResult.run_id.in_(run_ids))).scalars():
            signed_off[row.run_id][row.signature_uuid] = row
    return signed_off


def _all_hit(expected: Iterable[str], signed_off: dict[str, SVSRunResult]) -> bool:
    return all(uuid in signed_off and signed_off[uuid].reviewed_status == ResultStatus.HIT.value for uuid in expected)


def judge(run: Optional[SVSRun], expected: Iterable[str], signed_off: dict[str, SVSRunResult],
          test_content_hash: str, current: dict[str, SignatureInfo]) -> Evaluation:
    """How a test does on a platform: run is its latest reviewed run there, expected what is expected
    of it there, signed_off that run's result rows by signature and current what ACE knows of the
    expected signatures now."""
    expected = frozenset(expected)
    if run is None:
        return Evaluation(TestState.AWAITING_REVIEW, expected=expected, unjudged_expectations=bool(expected))
    if not expected:
        return Evaluation(TestState.NO_EXPECTATIONS, run)

    statuses = [signed_off[uuid].reviewed_status if uuid in signed_off else None for uuid in expected]
    if any(status in MISSED for status in statuses):
        return Evaluation(TestState.FAILING, run, expected)
    if not _all_hit(expected, signed_off):
        # expected only after the review: no reviewed run has judged it
        return Evaluation(TestState.AWAITING_REVIEW, run, expected, unjudged_expectations=True)

    changed = test_content_hash != run.test_content_hash or any(
        uuid in current and current[uuid].content_hash is not None
        and current[uuid].content_hash != signed_off[uuid].reviewed_content_hash
        for uuid in expected)
    return Evaluation(TestState.STALE if changed else TestState.VALIDATED, run, expected)


def evaluate_tests(session, tests: Iterable[SVSCatalogTest]) -> dict[tuple[str, str], Evaluation]:
    """How each catalog test does on each platform it has a run or a decision on, by (guid,
    platform)."""
    tests = {test.guid: test for test in tests}
    guids = sorted(tests)
    if not guids:
        return {}

    platforms = set(session.execute(
        select(SVSRun.test_guid, SVSRun.platform).distinct().where(SVSRun.test_guid.in_(guids))).tuples())
    reviewed = _latest_reviewed(session, guids)
    expected = _expected(session, guids)
    signed_off = _signed_off(session, [run.id for run in reviewed.values()])
    keys = sorted(platforms | set(expected))

    # what ACE knows now of the expected signatures of the platforms that would be validated
    current = describe_signatures({
        uuid for key in keys if key in reviewed and expected.get(key)
        and _all_hit(expected[key], signed_off[reviewed[key].id])
        for uuid in expected[key]})

    evaluations = {}
    for key in keys:
        run = reviewed.get(key)
        evaluations[key] = judge(run, expected.get(key, ()), signed_off[run.id] if run else {},
                                 tests[key[0]].content_hash, current)
    return evaluations


def _recent(session, guids: list[str]) -> dict[str, tuple[int, int]]:
    """(recent runs, how many of them missed an expected signature) per test."""
    ranked = (select(SVSRun.id, SVSRun.test_guid,
                     func.row_number().over(partition_by=SVSRun.test_guid,
                                            order_by=(SVSRun.created_at.desc(), SVSRun.id.desc())).label("rank"))
              .where(SVSRun.test_guid.in_(guids), SVSRun.state.in_([RunState.ENDED.value, RunState.REVIEWED.value]))
              .subquery())
    recent = {run_id: guid for run_id, guid in session.execute(
        select(ranked.c.id, ranked.c.test_guid).where(ranked.c.rank <= RECENT_RUNS))}
    if not recent:
        return {}

    missed = set(session.execute(
        select(SVSRunResult.run_id).distinct()
        .where(SVSRunResult.run_id.in_(list(recent)), SVSRunResult.status.in_(MISSED))).scalars())
    result: dict[str, tuple[int, int]] = {}
    for run_id, guid in recent.items():
        runs, missing = result.get(guid, (0, 0))
        result[guid] = (runs + 1, missing + (run_id in missed))
    return result


def catalog_histories(session, tests: Iterable[SVSCatalogTest]) -> dict[str, TestHistory]:
    """The history of each catalog test, by guid."""
    tests = {test.guid: test for test in tests}
    guids = sorted(tests)
    if not guids:
        return {}

    counts = dict(session.execute(
        select(SVSRun.test_guid, func.count()).where(SVSRun.test_guid.in_(guids)).group_by(SVSRun.test_guid)).all())
    last = _latest(session, guids, order=(SVSRun.created_at.desc(), SVSRun.id.desc()))
    recent = _recent(session, guids)
    by_test: dict[str, dict[str, Evaluation]] = {guid: {} for guid in guids}
    for (guid, platform), evaluation in evaluate_tests(session, tests.values()).items():
        by_test[guid][platform] = evaluation

    histories = {}
    for guid in guids:
        evaluations = by_test[guid]
        if guid not in counts:
            state = TestState.NEVER_RUN
        else:
            states = {evaluation.state for evaluation in evaluations.values()}
            state = next(state for state in WORST_FIRST if state in states)

        platform_states = {}
        for platform in sorted(set(platform_slugs(tests[guid])) | set(evaluations)):
            evaluation = evaluations.get(platform)
            if evaluation is None:
                platform_states[platform] = PlatformHistory(TestState.NEVER_RUN)
                continue
            run = evaluation.run
            platform_states[platform] = PlatformHistory(
                evaluation.state, last_reviewed_run_uuid=run.uuid if run else None,
                last_reviewed_at=run.reviewed_at if run else None, expected=len(evaluation.expected))

        reviewed_runs = [evaluation.run for evaluation in evaluations.values() if evaluation.run is not None]
        latest_reviewed = max(reviewed_runs, key=lambda run: (run.reviewed_at, run.id), default=None)
        latest = last.get(guid)
        recent_runs, recent_missing = recent.get(guid, (0, 0))
        histories[guid] = TestHistory(
            state=state, run_count=counts.get(guid, 0),
            last_run_uuid=latest.uuid if latest else None, last_run_at=latest.created_at if latest else None,
            last_reviewed_run_uuid=latest_reviewed.uuid if latest_reviewed else None,
            last_reviewed_at=latest_reviewed.reviewed_at if latest_reviewed else None,
            expected=len(set().union(*(evaluation.expected for evaluation in evaluations.values()))),
            recent_runs=recent_runs, recent_runs_missing=recent_missing, platform_states=platform_states)
    return histories
