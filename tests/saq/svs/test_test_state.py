"""The Tests screen's state and run history of each test (saq.svs.test_state) and the runs screen's
result and alert summary (saq.svs.run_summary)."""

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, update

from saq.database.model import SVSAttribution, SVSCatalogTest, SVSRun, SVSRunResult, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.signatures.loaders.util import content_hash
from saq.svs import expectations
from saq.svs.run_filters import run_filter_conditions
from saq.svs.run_summary import run_summaries
from saq.svs.test_state import RECENT_RUNS, TestState, catalog_histories, evaluate_tests
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run, write_yara_rule, yara_rule_source

# several runs on one test host are fixtures here; the host's claim is tested in test_runs.py
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("overlapping_runs")]

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
SIGNATURE = "22222222-bbbb-4bbb-8bbb-222222222222"
OTHER = "44444444-dddd-4ddd-8ddd-444444444444"
MULTI = "eeeeeeee-5555-4555-8555-555555555555"
# the inventory's hash of the rule: the rule's own source
RULE_HASH = content_hash(yara_rule_source("Suspicious_Macro", SIGNATURE))


@pytest.fixture(autouse=True)
def setup(no_hunts, yara_dir):
    write_yara_rule(yara_dir, "Suspicious_Macro", SIGNATURE)
    add_catalog_test(GUID)
    add_test_host("win10-01")


@pytest.fixture
def user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()


def _run(state: str, created_ago: timedelta = timedelta(hours=1), **values) -> SVSRun:
    run = started_run(GUID)
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id)
               .values(state=state, created_at=datetime.now() - created_ago, **values))
    db.commit()
    db.expire_all()
    return db.get(SVSRun, run.id)


def _reviewed(created_ago: timedelta = timedelta(hours=1), **values) -> SVSRun:
    return _run("reviewed", created_ago, reviewed_at=datetime.now() - created_ago + timedelta(minutes=30), **values)


def _result(run: SVSRun, signature_uuid: str, status, reviewed_status=None, reviewed_content_hash=RULE_HASH):
    with private_transaction() as session:
        session.add(SVSRunResult(run_id=run.id, signature_uuid=signature_uuid, status=status,
                                 reviewed_status=reviewed_status, reviewed_content_hash=reviewed_content_hash))


def _history():
    test = get_db().execute(select(SVSCatalogTest).where(SVSCatalogTest.guid == GUID)).scalar_one()
    return catalog_histories(get_db(), [test])[GUID]


class TestStates:
    def test_never_run(self):
        assert _history().state == TestState.NEVER_RUN

    def test_awaiting_review_until_a_run_is_reviewed(self, user_id):
        expectations.set_expectation(GUID, SIGNATURE, "expected", user_id, platform="windows")
        _run("ended")
        assert _history().state == TestState.AWAITING_REVIEW

    def test_no_expectations(self):
        _reviewed()
        assert _history().state == TestState.NO_EXPECTATIONS

    def test_validated(self, user_id):
        expectations.set_expectation(GUID, SIGNATURE, "expected", user_id, platform="windows")
        run = _reviewed()
        _result(run, SIGNATURE, "hit", "hit")
        history = _history()
        assert (history.state, history.expected, history.last_reviewed_run_uuid) == (
            TestState.VALIDATED, 1, run.uuid)

    @pytest.mark.parametrize("reviewed_status", ["missing", "possibly_suppressed"])
    def test_failing(self, user_id, reviewed_status):
        expectations.set_expectation(GUID, SIGNATURE, "expected", user_id, platform="windows")
        _result(_reviewed(), SIGNATURE, "hit", reviewed_status)
        # judged as signed off: a live hit since doesn't change it
        assert _history().state == TestState.FAILING

    def test_only_the_latest_reviewed_run_counts(self, user_id):
        expectations.set_expectation(GUID, SIGNATURE, "expected", user_id, platform="windows")
        _result(_reviewed(timedelta(days=2)), SIGNATURE, "missing", "missing")
        _result(_reviewed(), SIGNATURE, "hit", "hit")
        assert _history().state == TestState.VALIDATED

    def test_an_expectation_added_after_the_review_waits_for_one(self, user_id):
        expectations.set_expectation(GUID, SIGNATURE, "expected", user_id, platform="windows")
        _result(_reviewed(), SIGNATURE, "hit", "hit")
        expectations.set_expectation(GUID, OTHER, "expected", user_id, platform="windows")
        assert _history().state == TestState.AWAITING_REVIEW
        # an ignored one doesn't count
        expectations.set_ignore(OTHER, user_id, test_guid=GUID)
        assert _history().state == TestState.VALIDATED

    def test_stale_when_the_rule_changed(self, user_id):
        expectations.set_expectation(GUID, SIGNATURE, "expected", user_id, platform="windows")
        _result(_reviewed(), SIGNATURE, "hit", "hit", reviewed_content_hash="b" * 64)
        assert _history().state == TestState.STALE

    def test_stale_when_the_test_changed(self, user_id):
        expectations.set_expectation(GUID, SIGNATURE, "expected", user_id, platform="windows")
        _result(_reviewed(test_content_hash="c" * 64), SIGNATURE, "hit", "hit")
        assert _history().state == TestState.STALE

    def test_a_rule_ace_cannot_read_is_not_counted_as_changed(self, user_id, yara_dir):
        (yara_dir / "unittest" / "Suspicious_Macro.yar").unlink()
        expectations.set_expectation(GUID, SIGNATURE, "expected", user_id, platform="windows")
        _result(_reviewed(), SIGNATURE, "hit", "hit", reviewed_content_hash="b" * 64)
        assert _history().state == TestState.VALIDATED


def _platform_run(platform: str, state: str = "reviewed", created_ago: timedelta = timedelta(hours=1)) -> SVSRun:
    """A run of MULTI on the platform's test host."""
    run = started_run(MULTI, f"{platform}-01")
    values = {"state": state, "created_at": datetime.now() - created_ago}
    if state == "reviewed":
        values["reviewed_at"] = datetime.now() - created_ago + timedelta(minutes=30)
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(**values))
    db.commit()
    db.expire_all()
    return db.get(SVSRun, run.id)


class TestPlatforms:
    """A test is judged on each platform by its runs there against what is expected of it there."""

    @pytest.fixture(autouse=True)
    def multi(self):
        add_catalog_test(MULTI, platforms=("windows", "linux", "macos"))
        add_test_host("windows-01", platform="windows")
        add_test_host("linux-01", platform="linux")

    def _history(self):
        test = get_db().execute(select(SVSCatalogTest).where(SVSCatalogTest.guid == MULTI)).scalar_one()
        return catalog_histories(get_db(), [test])[MULTI]

    def _evaluations(self):
        test = get_db().execute(select(SVSCatalogTest).where(SVSCatalogTest.guid == MULTI)).scalar_one()
        return {platform: evaluation for (_, platform), evaluation in evaluate_tests(get_db(), [test]).items()}

    def test_each_platform_on_its_own(self, user_id):
        for platform in ("windows", "linux"):
            expectations.set_expectation(MULTI, SIGNATURE, "expected", user_id, platform=platform)
        _result(_platform_run("windows"), SIGNATURE, "hit", "hit")
        _result(_platform_run("linux"), SIGNATURE, "missing", "missing")

        history = self._history()
        assert history.state == TestState.FAILING
        assert {platform: state.state for platform, state in history.platform_states.items()} == {
            "linux": TestState.FAILING, "macos": TestState.NEVER_RUN, "windows": TestState.VALIDATED}
        assert history.platform_states["windows"].expected == 1 and history.platform_states["macos"].expected == 0
        # a signature expected on two platforms is one expected signature
        assert history.expected == 1
        # a platform without a run or a decision isn't evaluated
        assert set(self._evaluations()) == {"windows", "linux"}

    def test_worst_first(self, user_id):
        expectations.set_expectation(MULTI, SIGNATURE, "expected", user_id, platform="windows")
        _result(_platform_run("windows"), SIGNATURE, "hit", "hit")
        linux = _platform_run("linux", "ended")
        # a platform whose runs aren't reviewed yet holds the test in review
        assert self._history().state == TestState.AWAITING_REVIEW

        # nothing expected on linux: validated wins over no expectations
        get_db().execute(update(SVSRun).where(SVSRun.id == linux.id).values(state="reviewed",
                                                                           reviewed_at=datetime.now()))
        get_db().commit()
        history = self._history()
        assert history.state == TestState.VALIDATED
        assert history.platform_states["linux"].state == TestState.NO_EXPECTATIONS
        assert history.last_reviewed_run_uuid == linux.uuid

    def test_an_expectation_on_a_platform_without_runs(self, user_id):
        expectations.set_expectation(MULTI, SIGNATURE, "expected", user_id, platform="windows")
        _result(_platform_run("windows"), SIGNATURE, "hit", "hit")
        expectations.set_expectation(MULTI, OTHER, "expected", user_id, platform="macos")

        assert self._history().state == TestState.AWAITING_REVIEW
        macos = self._evaluations()["macos"]
        assert (macos.state, macos.run, macos.unjudged_expectations) == (TestState.AWAITING_REVIEW, None, True)

    def test_an_expectation_after_the_review_is_unjudged(self, user_id):
        expectations.set_expectation(MULTI, SIGNATURE, "expected", user_id, platform="linux")
        run = _platform_run("linux")
        _result(run, SIGNATURE, "hit", "hit")
        assert not self._evaluations()["linux"].unjudged_expectations

        expectations.set_expectation(MULTI, OTHER, "expected", user_id, platform="linux")
        linux = self._evaluations()["linux"]
        assert (linux.state, linux.run.id, linux.unjudged_expectations) == (TestState.AWAITING_REVIEW, run.id, True)
        assert linux.expected == {SIGNATURE, OTHER}


class TestRunHistory:
    def test_runs_and_recent_misses(self):
        runs = [_run("ended", timedelta(hours=hours)) for hours in range(RECENT_RUNS + 2, 0, -1)]
        _run("closed", timedelta(minutes=5))
        # the oldest run misses, but it is not among the latest RECENT_RUNS ended ones
        _result(runs[0], SIGNATURE, "missing")
        _result(runs[-1], SIGNATURE, "possibly_suppressed")
        _result(runs[-2], SIGNATURE, "missing")
        _result(runs[-3], OTHER, "candidate")

        history = _history()
        assert history.run_count == RECENT_RUNS + 3
        assert (history.recent_runs, history.recent_runs_missing) == (RECENT_RUNS, 2)
        assert history.last_run_at > runs[-1].created_at
        assert history.last_reviewed_run_uuid is None


def _attribute(run: SVSRun, *, confidence="marker", late=False, alert_uuid=None, removed=False) -> str:
    alert_uuid = alert_uuid or str(uuid.uuid4())
    with private_transaction() as session:
        session.add(SVSAttribution(
            run_id=run.id, alert_uuid=alert_uuid, content_hash=uuid.uuid4().hex * 2, signature_uuid=SIGNATURE,
            confidence=confidence, late=late, source="router", actor="svs", created_at=datetime.now(),
            removed_at=datetime.now() if removed else None))
    return alert_uuid


class TestRunSummary:
    def test_counts(self):
        run = _run("ended")
        for status in ("hit", "missing", "possibly_suppressed", "candidate"):
            _result(run, str(uuid.uuid4()), status)
        _result(run, str(uuid.uuid4()), None, "hit")
        marked = _attribute(run)
        _attribute(run, confidence="context", alert_uuid=marked)
        _attribute(run, confidence="context", late=True)
        _attribute(run, removed=True)
        empty = _run("ended")

        summaries = run_summaries(get_db(), [run.id, empty.id])
        summary = summaries[run.id]
        assert (summary.hit, summary.missing, summary.possibly_suppressed, summary.candidate) == (1, 1, 1, 1)
        assert summary.expected == 3
        assert (summary.alerts, summary.marker_alerts, summary.context_alerts, summary.late_alerts) == (2, 1, 1, 1)
        assert summaries[empty.id].alerts == 0 and summaries[empty.id].expected == 0


def _matching(name: str, value: str = "true") -> set[str]:
    db = get_db()
    db.expire_all()
    return set(db.execute(select(SVSRun.uuid).where(*run_filter_conditions(
        [{"name": name, "values": [value]}]))).scalars())


def test_the_result_and_alert_filters():
    missing, suppressed, candidate, late, context, plain = (_run("ended") for _ in range(6))
    _result(missing, SIGNATURE, "missing")
    _result(suppressed, SIGNATURE, "possibly_suppressed")
    _result(candidate, SIGNATURE, "candidate")
    _attribute(late, late=True)
    _attribute(context, confidence="context")
    _attribute(plain)
    # a removed attribution doesn't count
    _attribute(plain, late=True, confidence="context", removed=True)

    assert _matching("Has Missing") == {missing.uuid, suppressed.uuid}
    assert _matching("Has Possibly Suppressed") == {suppressed.uuid}
    assert _matching("Has Candidates") == {candidate.uuid}
    assert _matching("Has Late") == {late.uuid}
    assert _matching("Has Context Only") == {context.uuid}
    assert plain.uuid in _matching("Has Late", "false")
