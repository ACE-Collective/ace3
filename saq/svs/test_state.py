"""What the Tests screen shows of each Atomic Red Team test's runs (docs/SVS.md, Part 5, *Tests*): its
state, its last run and last reviewed run, its expected signatures, and how many of its recent runs
missed one. Read per page, for any number of tests in a fixed number of queries; nothing here is
stored.

A test's state:
- never_run: no run was ever registered for it;
- awaiting_review: none of its runs is reviewed yet, or something was expected of it only after its
  latest reviewed run, so no reviewed run has judged it;
- no_expectations: it has a reviewed run, and nothing is expected of it;
- failing: its latest reviewed run, as signed off, missed an expected signature (possibly
  suppressed counts as missed);
- stale: it would be validated, but the test or the rule of an expected signature changed since
  that run was reviewed (a rule whose current content ACE can't read doesn't count as changed);
- validated: its latest reviewed run, as signed off, hit every expected signature.
Expected signatures are those expected of the test that no ignore applies to.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Iterable, Optional

from sqlalchemy import func, select

from saq.database.model import SVSExpectation, SVSIgnore, SVSRun, SVSRunResult
from saq.svs.constants import GLOBAL_SCOPE_KEY, ExpectationState, ResultStatus, RunState
from saq.svs.signatures import describe_signatures

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


@dataclass(frozen=True)
class TestHistory:
    __test__ = False

    state: TestState
    run_count: int = 0
    last_run_uuid: Optional[str] = None
    last_run_at: Optional[datetime] = None
    last_reviewed_run_uuid: Optional[str] = None
    last_reviewed_at: Optional[datetime] = None
    expected: int = 0
    # of the test's latest RECENT_RUNS ended or reviewed runs: how many there are, and how many of
    # them miss an expected signature in their live result
    recent_runs: int = 0
    recent_runs_missing: int = 0


def _latest(session, guids: list[str], *conditions, order) -> dict[str, SVSRun]:
    """The first run of each test in the order given."""
    ranked = (select(SVSRun.id, func.row_number().over(partition_by=SVSRun.test_guid, order_by=order).label("rank"))
              .where(SVSRun.test_guid.in_(guids), *conditions)
              .subquery())
    return {run.test_guid: run for run in session.execute(
        select(SVSRun).join(ranked, ranked.c.id == SVSRun.id).where(ranked.c.rank == 1)).scalars()}


def _expected(session, guids: list[str]) -> dict[str, set[str]]:
    ignored: dict[str, set[str]] = {}
    for scope_key, signature_uuid in session.execute(
            select(SVSIgnore.scope_key, SVSIgnore.signature_uuid)
            .where(SVSIgnore.scope_key.in_([GLOBAL_SCOPE_KEY, *guids]))):
        ignored.setdefault(scope_key, set()).add(signature_uuid)

    expected: dict[str, set[str]] = {guid: set() for guid in guids}
    for guid, signature_uuid in session.execute(
            select(SVSExpectation.test_guid, SVSExpectation.signature_uuid)
            .where(SVSExpectation.test_guid.in_(guids), SVSExpectation.state == ExpectationState.EXPECTED.value)):
        if signature_uuid not in ignored.get(GLOBAL_SCOPE_KEY, set()) | ignored.get(guid, set()):
            expected[guid].add(signature_uuid)
    return expected


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


def catalog_histories(session, tests: Iterable) -> dict[str, TestHistory]:
    """The history of each catalog test (SVSCatalogTest rows), by guid."""
    tests = {test.guid: test for test in tests}
    guids = sorted(tests)
    if not guids:
        return {}

    counts = dict(session.execute(
        select(SVSRun.test_guid, func.count()).where(SVSRun.test_guid.in_(guids)).group_by(SVSRun.test_guid)).all())
    last = _latest(session, guids, order=(SVSRun.created_at.desc(), SVSRun.id.desc()))
    reviewed = _latest(session, guids, SVSRun.state == RunState.REVIEWED.value,
                       order=(SVSRun.reviewed_at.desc(), SVSRun.id.desc()))
    expected = _expected(session, guids)
    recent = _recent(session, guids)

    signed_off: dict[int, dict[str, SVSRunResult]] = {}
    if reviewed:
        for row in session.execute(select(SVSRunResult).where(
                SVSRunResult.run_id.in_([run.id for run in reviewed.values()]))).scalars():
            signed_off.setdefault(row.run_id, {})[row.signature_uuid] = row

    states = {}
    validated = {}
    for guid in guids:
        run = reviewed.get(guid)
        if guid not in counts:
            states[guid] = TestState.NEVER_RUN
        elif run is None:
            states[guid] = TestState.AWAITING_REVIEW
        elif not expected[guid]:
            states[guid] = TestState.NO_EXPECTATIONS
        else:
            rows = signed_off.get(run.id, {})
            reviewed_statuses = {uuid: (rows[uuid].reviewed_status if uuid in rows else None) for uuid in expected[guid]}
            if any(status in MISSED for status in reviewed_statuses.values()):
                states[guid] = TestState.FAILING
            elif any(status != ResultStatus.HIT.value for status in reviewed_statuses.values()):
                # expected only after the review: no reviewed run has judged it
                states[guid] = TestState.AWAITING_REVIEW
            else:
                validated[guid] = run

    # stale: the test, or an expected signature's rule, changed since the review
    current = describe_signatures({uuid for guid in validated for uuid in expected[guid]})
    for guid, run in validated.items():
        rows = signed_off[run.id]
        changed = tests[guid].content_hash != run.test_content_hash or any(
            uuid in current and current[uuid].content_hash is not None
            and current[uuid].content_hash != rows[uuid].reviewed_content_hash
            for uuid in expected[guid])
        states[guid] = TestState.STALE if changed else TestState.VALIDATED

    histories = {}
    for guid in guids:
        latest, latest_reviewed = last.get(guid), reviewed.get(guid)
        recent_runs, recent_missing = recent.get(guid, (0, 0))
        histories[guid] = TestHistory(
            state=states[guid], run_count=counts.get(guid, 0),
            last_run_uuid=latest.uuid if latest else None, last_run_at=latest.created_at if latest else None,
            last_reviewed_run_uuid=latest_reviewed.uuid if latest_reviewed else None,
            last_reviewed_at=latest_reviewed.reviewed_at if latest_reviewed else None,
            expected=len(expected[guid]), recent_runs=recent_runs, recent_runs_missing=recent_missing)
    return histories
