"""A run's result (saq.svs.results, docs/SVS_RUNS.md, *Results*), when it is computed and kept
current (saq.svs.result_state), and the decisions it is computed against (saq.svs.expectations)."""

import json
import logging
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import pytest
from sqlalchemy import select, update

from saq.database.model import (
    Alert,
    DetectionPoint,
    SVSAttribution,
    SVSRun,
    SVSRunEvent,
    SVSRunResult,
    SVSRunResultState,
    User,
)
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.signatures.builtin import GENERIC, OBSERVABLE_FLAGGED
from saq.signatures.loaders.util import content_hash
from saq.svs import expectations, results, runs, windows
from saq.svs.constants import ObservationSource, RunEventKind, RunState
from saq.svs.result_state import mark_runs_stale
from saq.svs.runs import Registration, TargetSpec
from tests.saq.helpers import insert_alert
from tests.saq.svs.conftest import (
    LAUNCHER,
    add_catalog_test,
    add_test_host,
    started_run,
    write_hunt,
    write_yara_rule,
    yara_rule_source,
)

# several runs on one test host are fixtures here; the host's claim is tested in test_runs.py
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("overlapping_runs")]

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
OTHER_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
HUNT = "11111111-aaaa-4aaa-8aaa-111111111111"
YARA = "22222222-bbbb-4bbb-8bbb-222222222222"
NOISE = "33333333-cccc-4ccc-8ccc-333333333333"
OTHER = "44444444-dddd-4ddd-8ddd-444444444444"
MULTI = "eeeeeeee-5555-4555-8555-555555555555"


def _multi_platform_test():
    """MULTI, a test of windows and linux, and a test host on each."""
    add_catalog_test(MULTI, platforms=("windows", "linux"))
    add_test_host("windows-01", platform="windows")
    add_test_host("linux-01", platform="linux")


@pytest.fixture(autouse=True)
def setup(no_hunts, yara_dir):
    add_catalog_test(GUID)
    add_catalog_test(OTHER_GUID)
    add_test_host("win10-01")


@pytest.fixture
def user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()


def _run(test_guid: str = GUID, *, ended: bool = True, started_at: timedelta = timedelta(hours=2)) -> SVSRun:
    """A run of the test started started_at ago, ended (half an hour ago) unless asked not to be."""
    run = started_run(test_guid, now=datetime.now() - started_at)
    if ended:
        db = get_db()
        db.execute(update(SVSRun).where(SVSRun.id == run.id)
                   .values(state=RunState.ENDED.value, ended_at=datetime.now() - timedelta(minutes=30)))
        db.commit()
        db.expire_all()
    return get_db().get(SVSRun, run.id)


def _attribute(run: SVSRun, signature_uuid: str, *, alert_uuid=None, late=False, confidence="marker",
               removed=False) -> str:
    alert_uuid = alert_uuid or str(uuid.uuid4())
    with private_transaction() as session:
        session.add(SVSAttribution(
            run_id=run.id, alert_uuid=alert_uuid, content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
            signature_uuid=signature_uuid, signature_family="yara", confidence=confidence, late=late,
            source="router", actor="svs", created_at=datetime.now(),
            removed_at=datetime.now() if removed else None, removed_by="svs" if removed else None))
    return alert_uuid


def _statuses(run: SVSRun) -> dict[str, str]:
    db = get_db()
    db.expire_all()
    return {row.signature_uuid: row.status for row in db.execute(
        select(SVSRunResult).where(SVSRunResult.run_id == run.id)).scalars()}


def _row(run: SVSRun, signature_uuid: str) -> SVSRunResult:
    db = get_db()
    db.expire_all()
    return db.execute(select(SVSRunResult).where(
        SVSRunResult.run_id == run.id, SVSRunResult.signature_uuid == signature_uuid)).scalar_one()


def _state(run: SVSRun) -> SVSRunResultState:
    db = get_db()
    db.expire_all()
    return db.get(SVSRunResultState, run.id)


def _hunt(hunt_dir: Path, *, suppression: Optional[str] = "1:00:00:00", grouped=False, latency="01:00:00") -> Path:
    """HUNT's file: a hunt whose latency is its frequency."""
    rule = {"name": "suspicious powershell"}
    if suppression:
        rule["suppression"] = suppression
    if grouped:
        rule["group_by"] = "hostname"
    path = write_hunt(hunt_dir, HUNT, frequency=latency, **rule)
    windows.clear_cache()
    return path


def _hunt_alert(inserted_at: datetime) -> str:
    """An alert of the hunt (one carrying a detection of it), inserted at inserted_at."""
    alert = insert_alert()
    db = get_db()
    db.add(DetectionPoint(alert_id=alert.id, description="hunt suspicious powershell (splunk) matched",
                          signature_uuid=HUNT, signature_version="v1", content_hash=uuid.uuid4().hex * 2))
    db.execute(update(Alert).where(Alert.id == alert.id).values(insert_date=inserted_at))
    db.commit()
    return alert.uuid


class TestStatuses:
    def test_each_status(self, user_id):
        run = _run()
        for signature in (HUNT, YARA, NOISE, OTHER):
            _attribute(run, signature)
        expectations.set_expectation(GUID, HUNT, "expected", user_id, platform="windows")
        expectations.set_expectation(GUID, YARA, "rejected", user_id, platform="windows")
        expectations.set_ignore(NOISE, user_id, reason="winrm")
        # expected and never fired
        missing = "55555555-eeee-4eee-8eee-555555555555"
        expectations.set_expectation(GUID, missing, "expected", user_id, platform="windows")

        results.compute_result(run.id)
        assert _statuses(run) == {HUNT: "hit", YARA: "rejected", NOISE: "ignored", OTHER: "candidate",
                                  missing: "missing"}

    def test_an_ignore_wins_over_an_expectation(self, user_id):
        run = _run()
        _attribute(run, HUNT)
        expectations.set_expectation(GUID, HUNT, "expected", user_id, platform="windows")
        expectations.set_expectation(GUID, YARA, "expected", user_id, platform="windows")
        expectations.set_ignore(HUNT, user_id, test_guid=GUID)
        expectations.set_ignore(YARA, user_id, test_guid=GUID)

        results.compute_result(run.id)
        # an ignored signature that fired is ignored, and one that didn't is not missing
        assert _statuses(run) == {HUNT: "ignored"}

    def test_another_tests_decisions_do_not_apply(self, user_id):
        run = _run()
        _attribute(run, HUNT)
        expectations.set_expectation(OTHER_GUID, HUNT, "expected", user_id, platform="windows")
        expectations.set_ignore(HUNT, user_id, test_guid=OTHER_GUID)
        results.compute_result(run.id)
        assert _statuses(run) == {HUNT: "candidate"}

    def test_another_platforms_decisions_do_not_apply(self, user_id):
        _multi_platform_test()
        run = started_run(MULTI, "linux-01")
        _attribute(run, HUNT)
        expectations.set_expectation(MULTI, HUNT, "rejected", user_id, platform="windows")
        expectations.set_expectation(MULTI, YARA, "expected", user_id, platform="windows")
        results.compute_result(run.id)
        assert _statuses(run) == {HUNT: "candidate"}

        # but the test's ignores apply on every platform
        expectations.set_ignore(HUNT, user_id, test_guid=MULTI)
        results.compute_result(run.id)
        assert _statuses(run) == {HUNT: "ignored"}

    def test_signatures_that_stand_for_many_never_count(self):
        run = _run()
        _attribute(run, GENERIC.uuid)
        _attribute(run, OBSERVABLE_FLAGGED.uuid)
        _attribute(run, "")
        results.compute_result(run.id)
        assert _statuses(run) == {}

    def test_alerts_late_and_context(self):
        run = _run()
        alert = _attribute(run, HUNT, late=True, confidence="context")
        _attribute(run, HUNT, alert_uuid=alert, late=True, confidence="context")
        _attribute(run, HUNT, late=True, confidence="context")
        _attribute(run, YARA, late=True)
        _attribute(run, YARA)
        _attribute(run, OTHER, removed=True)

        results.compute_result(run.id)
        hunt, yara = _row(run, HUNT), _row(run, YARA)
        assert (hunt.alert_count, hunt.late_only, hunt.context_only) == (2, True, True)
        assert (yara.alert_count, yara.late_only, yara.context_only) == (2, False, False)
        # a removed attribution doesn't count
        assert OTHER not in _statuses(run)

    def test_names_and_rule_hashes(self, hunt_dir, yara_dir, user_id):
        run = _run()
        _attribute(run, YARA)
        write_yara_rule(yara_dir, "Suspicious_Macro", YARA)
        hunt_file = _hunt(hunt_dir)
        expectations.set_expectation(GUID, HUNT, "expected", user_id, platform="windows")

        results.compute_result(run.id)
        yara, hunt = _row(run, YARA), _row(run, HUNT)
        assert (yara.signature_name, yara.signature_family, yara.content_hash) == (
            "Suspicious_Macro", "yara", content_hash(yara_rule_source("Suspicious_Macro", YARA)))
        # a missing signature records its rule hash too: coverage needs it
        assert (hunt.signature_name, hunt.signature_family, hunt.content_hash) == (
            "suspicious powershell", "hunt", content_hash(hunt_file.read_text()))

    def test_an_unknown_signature_keeps_what_was_known(self):
        run = _run()
        _attribute(run, OTHER)
        results.compute_result(run.id)
        row = _row(run, OTHER)
        assert (row.signature_family, row.signature_name, row.content_hash) == ("yara", None, None)


class TestSuppression:
    @pytest.fixture(autouse=True)
    def expected_hunt(self, user_id):
        expectations.set_expectation(GUID, HUNT, "expected", user_id, platform="windows")

    def test_a_hunt_alert_within_its_suppression_period(self, hunt_dir):
        _hunt(hunt_dir)
        run = _run()
        before = _hunt_alert(run.started_at - timedelta(hours=3))
        during = _hunt_alert(run.started_at + timedelta(minutes=10))

        results.compute_result(run.id)
        row = _row(run, HUNT)
        assert row.status == "possibly_suppressed"
        assert row.suppressing_alert_uuid == during != before
        assert row.suppression_imprecise is False

    def test_a_grouped_hunt_is_imprecise(self, hunt_dir):
        _hunt(hunt_dir, grouped=True)
        run = _run()
        _hunt_alert(run.started_at - timedelta(hours=3))
        results.compute_result(run.id)
        assert _row(run, HUNT).suppression_imprecise is True

    @pytest.mark.parametrize("hunt, offset", [
        ({}, timedelta(days=-2)),                     # before the suppression period
        ({"suppression": None}, timedelta(hours=-3)),  # the hunt doesn't suppress
    ])
    def test_missing(self, hunt_dir, hunt, offset):
        _hunt(hunt_dir, **hunt)
        run = _run()
        _hunt_alert(run.started_at + offset)
        results.compute_result(run.id)
        assert _row(run, HUNT).status == "missing"

    def test_an_alert_after_the_window_or_of_the_run_itself_does_not_suppress(self, hunt_dir):
        _hunt(hunt_dir)
        run = _run()
        _hunt_alert(run.ended_at + timedelta(minutes=1))
        own = _hunt_alert(run.started_at + timedelta(minutes=5))
        # the run's own alert, attributed by another of its detections
        _attribute(run, YARA, alert_uuid=own)

        results.compute_result(run.id)
        assert _row(run, HUNT).status == "missing"


class TestKeepingRows:
    def test_a_row_that_left_the_result_is_deleted_unless_it_holds_the_reviewed_result(self, user_id):
        run = _run()
        _attribute(run, YARA)
        _attribute(run, OTHER)
        results.compute_result(run.id)
        db = get_db()
        db.execute(update(SVSRunResult).where(SVSRunResult.run_id == run.id, SVSRunResult.signature_uuid == YARA)
                   .values(reviewed_status="candidate"))
        db.execute(update(SVSAttribution).where(SVSAttribution.run_id == run.id)
                   .values(removed_at=datetime.now(), removed_by="analyst"))
        db.commit()

        results.compute_result(run.id)
        assert _statuses(run) == {YARA: None}
        assert _row(run, YARA).reviewed_status == "candidate"

    def test_an_event_and_a_record_only_when_the_result_changes(self, user_id, caplog):
        run = _run()
        _attribute(run, YARA)
        expectations.set_expectation(GUID, HUNT, "expected", user_id, platform="windows")

        with caplog.at_level(logging.DEBUG):
            results.compute_result(run.id)
            results.compute_result(run.id)

        db = get_db()
        db.expire_all()
        events = [json.loads(e.details) for e in db.execute(select(SVSRunEvent).where(
            SVSRunEvent.run_id == run.id, SVSRunEvent.kind == RunEventKind.RESULT_COMPUTED.value)).scalars()]
        assert events == [{"counts": {"candidate": 1, "missing": 1}, "previous": {}}]

        computed = [r for r in caplog.records if r.getMessage().startswith(f"svs run {run.uuid} result computed")]
        assert len(computed) == 2 and computed[0].counts == {"candidate": 1, "missing": 1}
        missing = [r for r in caplog.records if "is missing expected signature" in r.getMessage()]
        assert len(missing) == 1
        assert (missing[0].signature_uuid, missing[0].possibly_suppressed) == (HUNT, False)
        assert any(r.levelno == logging.DEBUG and getattr(r, "signature_uuid", None) == YARA for r in caplog.records)


class TestStaleness:
    def test_a_computation_clears_stale(self):
        run = _run()
        with private_transaction() as session:
            mark_runs_stale(session, run_ids=[run.id])
        assert (_state(run).stale, _state(run).generation) == (True, 1)

        computed = results.compute_result(run.id)
        assert computed.current
        state = _state(run)
        assert (state.stale, state.computed_generation) == (False, 1)
        assert state.computed_at is not None

    def test_a_change_while_computing_keeps_the_run_stale(self, monkeypatch):
        run = _run()
        with private_transaction() as session:
            mark_runs_stale(session, run_ids=[run.id])
        fired = results.fired_signatures

        def a_write_lands(session, run_id):
            with private_transaction() as other:
                mark_runs_stale(other, run_ids=[run_id])
            return fired(session, run_id)

        monkeypatch.setattr(results, "fired_signatures", a_write_lands)
        assert results.compute_result(run.id).current is False
        assert (_state(run).stale, _state(run).generation) == (True, 2)

        monkeypatch.setattr(results, "fired_signatures", fired)
        assert results.recompute_stale_results() == 1
        assert _state(run).stale is False

    def test_only_runs_in_result_states_are_marked(self):
        started, ended = _run(ended=False), _run()
        canceled = _run(ended=False)
        runs.cancel(canceled.uuid, LAUNCHER)
        with private_transaction() as session:
            mark_runs_stale(session, run_ids=[started.id, ended.id, canceled.id])
        assert _state(started).stale and _state(ended).stale
        assert _state(canceled) is None

    def test_the_timers_recompute_ended_runs_only(self):
        # a run started a moment ago, still inside its window
        started, ended = _run(ended=False, started_at=timedelta(minutes=1)), _run()
        _attribute(ended, YARA)
        _attribute(started, YARA)
        with private_transaction() as session:
            mark_runs_stale(session, run_ids=[started.id, ended.id])

        assert runs.run_timers().results_computed == 1
        assert _statuses(ended) == {YARA: "candidate"}
        assert _statuses(started) == {}
        assert _state(started).stale

    def test_a_run_is_computed_as_it_ends(self):
        run = _run(ended=False)
        _attribute(run, YARA)
        runs.run_timers(now=run.observation_ends_at + timedelta(seconds=1))
        assert _statuses(run) == {YARA: "candidate"}
        assert _state(run).stale is False

    def test_a_failed_computation_leaves_the_end_and_the_run_stale(self, monkeypatch):
        run = _run(ended=False)
        monkeypatch.setattr("saq.error.reporting.write_error_report", lambda *a, **k: None)

        def broken(run_id, now=None):
            raise RuntimeError("database down")

        monkeypatch.setattr(runs, "compute_result", broken)
        monkeypatch.setattr(results, "compute_result", broken)
        runs.run_timers(now=run.observation_ends_at + timedelta(seconds=1))
        db = get_db()
        db.expire_all()
        assert db.get(SVSRun, run.id).state == RunState.ENDED
        assert _state(run).stale


class TestDecisionsMarkRunsStale:
    def _clear(self, *runs_):
        for run in runs_:
            results.compute_result(run.id)

    def test_a_decision_marks_only_the_platforms_runs(self, user_id):
        _multi_platform_test()
        linux, windows_run = started_run(MULTI, "linux-01"), started_run(MULTI, "windows-01")
        self._clear(linux, windows_run)
        expectations.set_expectation(MULTI, YARA, "expected", user_id, platform="linux")
        assert _state(linux).stale and not _state(windows_run).stale

        self._clear(linux)
        expectations.remove_expectation(MULTI, "linux", YARA, user_id)
        assert _state(linux).stale and not _state(windows_run).stale

    def test_a_tests_decision_marks_its_runs(self, user_id):
        mine, other = _run(), _run(OTHER_GUID)
        self._clear(mine, other)
        expectations.set_expectation(GUID, YARA, "expected", user_id, platform="windows")
        assert _state(mine).stale and not _state(other).stale

        self._clear(mine)
        expectations.set_ignore(YARA, user_id, test_guid=GUID)
        assert _state(mine).stale and not _state(other).stale

    def test_a_global_ignore_marks_every_run(self, user_id):
        mine, other = _run(), _run(OTHER_GUID)
        self._clear(mine, other)
        expectations.set_ignore(YARA, user_id)
        assert _state(mine).stale and _state(other).stale

        self._clear(mine, other)
        expectations.remove_ignore(YARA, user_id)
        assert _state(mine).stale and _state(other).stale


class TestDecisions:
    def test_an_expectation_made_from_a_run_is_in_its_event_log(self, user_id):
        run = _run()
        _attribute(run, YARA)
        results.compute_result(run.id)
        expectation = expectations.set_expectation(GUID, YARA, "expected", user_id, reason="the macro",
                                                   run_uuid=run.uuid, actor="analyst")
        assert (expectation.decided_from_run_id, expectation.signature_family) == (run.id, "yara")

        db = get_db()
        (event,) = db.execute(select(SVSRunEvent).where(
            SVSRunEvent.run_id == run.id, SVSRunEvent.kind == RunEventKind.CANDIDATE_DECISION.value)).scalars()
        assert json.loads(event.details) == {"signature_uuid": YARA, "platform": "windows", "state": "expected",
                                           "reason": "the macro"}

    def test_a_decision_is_about_one_of_the_tests_platforms(self, user_id):
        _multi_platform_test()
        linux = started_run(MULTI, "linux-01")
        with pytest.raises(expectations.InvalidDecision, match="is not one of"):
            expectations.set_expectation(MULTI, YARA, "expected", user_id, platform="macos")
        with pytest.raises(expectations.InvalidDecision, match="is not one of"):
            expectations.set_expectation(MULTI, YARA, "expected", user_id)
        with pytest.raises(expectations.InvalidDecision, match="is on linux"):
            expectations.set_expectation(MULTI, YARA, "expected", user_id, platform="windows", run_uuid=linux.uuid)
        # from a run, the decision is about the run's platform
        assert expectations.set_expectation(MULTI, YARA, "expected", user_id, run_uuid=linux.uuid).platform == "linux"
        with pytest.raises(expectations.UnknownDecision):
            expectations.get_expectation(MULTI, "windows", YARA)

    def test_a_run_of_another_test_is_refused(self, user_id):
        other = _run(OTHER_GUID)
        with pytest.raises(expectations.InvalidDecision):
            expectations.set_expectation(GUID, YARA, "expected", user_id, run_uuid=other.uuid)

    @pytest.mark.parametrize("test_guid, signature_uuid, state, error", [
        ("cccccccc-0000-4000-8000-000000000000", YARA, "expected", expectations.UnknownTest),
        (GUID, "not a uuid", "expected", expectations.InvalidDecision),
        (GUID, YARA, "candidate", expectations.InvalidDecision),
    ])
    def test_refused(self, user_id, test_guid, signature_uuid, state, error):
        with pytest.raises(error):
            expectations.set_expectation(test_guid, signature_uuid, state, user_id, platform="windows")

    def test_deciding_again_replaces_the_decision_and_removing_it_forgets_it(self, user_id):
        expectations.set_expectation(GUID, YARA, "expected", user_id, platform="windows")
        assert expectations.set_expectation(GUID, YARA, "rejected", user_id, platform="windows").state == "rejected"
        expectations.remove_expectation(GUID, "windows", YARA, user_id)
        with pytest.raises(expectations.UnknownDecision):
            expectations.get_expectation(GUID, "windows", YARA)

    def test_settings_are_bounded(self, user_id):
        with pytest.raises(expectations.InvalidDecision):
            expectations.set_test_settings(GUID, user_id, observation_minutes=0)
        with pytest.raises(expectations.InvalidDecision):
            expectations.set_test_settings(GUID, user_id, observation_minutes=expectations.max_observation_minutes() + 1)
        assert expectations.set_test_settings(GUID, user_id, observation_minutes=90).observation_minutes == 90
        expectations.remove_test_settings(GUID, user_id)
        assert expectations.get_test_settings(GUID) is None


class TestWindows:
    def _register(self) -> SVSRun:
        return runs.register(Registration(test_guid=GUID, targets=[TargetSpec("win10-01")], launcher="art"), LAUNCHER)

    def _source(self, run: SVSRun) -> str:
        (event,) = get_db().execute(select(SVSRunEvent).where(
            SVSRunEvent.run_id == run.id, SVSRunEvent.kind == RunEventKind.REGISTERED.value)).scalars()
        return json.loads(event.details)["observation_source"]

    def test_all_hunts_without_expectations(self, hunt_dir):
        _hunt(hunt_dir, latency="10:00:00")
        run = self._register()
        assert self._source(run) == ObservationSource.ALL_HUNTS
        assert run.observation_seconds == int(timedelta(hours=10, minutes=30).total_seconds())

    def test_the_expected_signatures(self, hunt_dir, user_id):
        write_hunt(hunt_dir, OTHER, name="slow", frequency="20:00:00")
        _hunt(hunt_dir, latency="02:00:00")
        expectations.set_expectation(GUID, HUNT, "expected", user_id, platform="windows")
        expectations.set_expectation(GUID, OTHER, "expected", user_id, platform="windows")
        # an ignored expectation doesn't hold the window open
        expectations.set_ignore(OTHER, user_id, test_guid=GUID)

        run = self._register()
        assert self._source(run) == ObservationSource.EXPECTED
        assert run.observation_seconds == int(timedelta(hours=2, minutes=30).total_seconds())

    def test_only_the_runs_platforms_expected_signatures(self, hunt_dir, user_id):
        _multi_platform_test()
        _hunt(hunt_dir, latency="02:00:00")
        expectations.set_expectation(MULTI, HUNT, "expected", user_id, platform="linux")

        def register(hostname: str) -> SVSRun:
            return runs.register(Registration(test_guid=MULTI, targets=[TargetSpec(hostname)], launcher="art"),
                                 LAUNCHER)

        assert self._source(register("linux-01")) == ObservationSource.EXPECTED
        assert self._source(register("windows-01")) == ObservationSource.ALL_HUNTS

    def test_the_tests_override(self, user_id):
        expectations.set_test_settings(GUID, user_id, observation_minutes=15)
        run = self._register()
        assert self._source(run) == ObservationSource.OVERRIDE
        # used as it is: no slack, no floor
        assert run.observation_seconds == 15 * 60
