"""What a person does to a run (saq.svs.review, saq.svs.run_comments, docs/SVS_RUNS.md, *Reviewing
runs*): take it, cancel it, close it, review it and comment on it."""

import json
import threading
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, update

from saq.alert_routing import reset_alert_routers
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_OPEN, DISPOSITION_SIMULATED, F_HOSTNAME
from saq.database.model import (
    Alert,
    Comment,
    DetectionPointVerdict,
    SVSRun,
    SVSRunEvent,
    SVSRunResult,
    SVSRunResultState,
    User,
)
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.database.util.alert import ALERT
from saq.database.util.user_management import add_user
from saq.detection_verdicts.store import set_verdicts
from saq.svs import association, expectations, results, review, run_comments, runs
from saq.svs.constants import RunEventKind, RunState
from saq.svs.result_state import mark_runs_stale
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import LAUNCHER, add_catalog_test, add_test_host, started_run

# several runs on one test host are fixtures here; the host's claim is tested in test_runs.py
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("overlapping_runs")]

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
ACTOR = "unittest"
RULE = "22222222-bbbb-4bbb-8bbb-222222222222"
NOISE = "33333333-cccc-4ccc-8ccc-333333333333"


@pytest.fixture(autouse=True)
def setup(no_hunts, yara_dir):
    reset_alert_routers()
    add_catalog_test(GUID)
    add_test_host("win10-01")
    yield
    reset_alert_routers()


@pytest.fixture
def user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == ACTOR)).scalar_one()


@pytest.fixture
def bob() -> User:
    return add_user("bob", "bob@localhost", "Bob", "bob")


def _alert(run: SVSRun, *signatures_: str, host="win10-01", marker=True) -> str:
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now() - timedelta(hours=2))
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    if marker:
        root.details = {"cmd": f"whoami & REM {run.marker}"}
    for signature_uuid in signatures_ or (None,):
        root.add_detection_point(f"detection {signature_uuid}", signature_uuid=signature_uuid)
    root.save()
    ALERT(root)
    return root.uuid


def _ended(run: SVSRun) -> SVSRun:
    """Ends the run as its timer would, which computes its result."""
    runs.run_timers(now=run.observation_ends_at + timedelta(seconds=1))
    db = get_db()
    db.expire_all()
    return db.get(SVSRun, run.id)


def _run() -> SVSRun:
    # started three hours ago: its alerts happened during its observation window
    return started_run(GUID, now=datetime.now() - timedelta(hours=3))


def _row(alert_uuid: str) -> Alert:
    db = get_db()
    db.expire_all()
    return db.execute(select(Alert).where(Alert.uuid == alert_uuid)).unique().scalar_one()


def _run_row(run: SVSRun) -> SVSRun:
    db = get_db()
    db.expire_all()
    return db.get(SVSRun, run.id)


def _events(run: SVSRun, kind: RunEventKind) -> list[SVSRunEvent]:
    db = get_db()
    db.expire_all()
    return list(db.execute(select(SVSRunEvent).where(
        SVSRunEvent.run_id == run.id, SVSRunEvent.kind == kind.value).order_by(SVSRunEvent.id)).scalars())


def _set_owner(run: SVSRun, user_id) -> None:
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(owner_id=user_id))
    db.commit()


class TestOwnership:
    def test_taking_runs(self, user_id, bob):
        free, bobs, disabled = _run(), _run(), _run()
        _set_owner(bobs, bob.id)
        ghost = add_user("ghost", "ghost@localhost", "Ghost", "ghost")
        _set_owner(disabled, ghost.id)
        db = get_db()
        db.execute(update(User).where(User.id == ghost.id).values(enabled=False))
        db.commit()

        result = review.take_ownership([free.uuid, bobs.uuid, disabled.uuid, str(uuid.uuid4())], user_id, ACTOR)
        assert sorted(result.done) == sorted([free.uuid, disabled.uuid])
        assert result.left_alone == {bobs.uuid: "bob"} and len(result.unknown) == 1
        assert _run_row(free).owner_id == user_id
        (event,) = _events(disabled, RunEventKind.OWNERSHIP_TAKEN)
        assert json.loads(event.details) == {"from": "ghost"}

        # confirmed: taken from bob
        result = review.take_ownership([bobs.uuid], user_id, ACTOR, {bobs.uuid: bob.id})
        assert result.done == [bobs.uuid] and _run_row(bobs).owner_id == user_id


class TestCancelAndClose:
    def test_cancel(self, user_id):
        # ended first: the timers that end it would end every run started as long ago
        ended = _ended(_run())
        started = _run()
        created = runs.register(runs.Registration(test_guid=GUID, targets=[runs.TargetSpec("win10-01")],
                                                  launcher="art"), LAUNCHER)
        result = review.cancel_runs([started.uuid, created.uuid, ended.uuid], user_id, ACTOR)
        assert sorted(result.done) == sorted([started.uuid, created.uuid])
        assert ended.uuid in result.conflicts
        assert (_run_row(started).state, _run_row(created).state) == (RunState.CANCELED, RunState.CLOSED)
        # a person's cancel is a transition, not a launcher call
        assert not [e for e in _events(started, RunEventKind.LAUNCHER_CALL) if "cancel" in (e.details or "")]

    def test_closing_an_ended_run_needs_a_reason(self, user_id):
        run = _run()
        alert_uuid = _alert(run)
        run = _ended(run)
        result = review.close_runs([run.uuid], user_id, ACTOR)
        assert "needs a reason" in result.conflicts[run.uuid]

        result = review.close_runs([run.uuid], user_id, ACTOR, reason="the test VM was rebuilt mid-run")
        assert result.done == [run.uuid]
        closed = _run_row(run)
        assert (closed.state, closed.close_reason) == (RunState.CLOSED, "the test VM was rebuilt mid-run")
        assert _row(alert_uuid).disposition == DISPOSITION_SIMULATED

    def test_a_run_someone_else_owns_needs_confirmation(self, user_id, bob):
        run = _run()
        runs.cancel(run.uuid, LAUNCHER)
        _set_owner(run, bob.id)
        assert review.close_runs([run.uuid], user_id, ACTOR).left_alone == {run.uuid: "bob"}
        result = review.close_runs([run.uuid], user_id, ACTOR, confirmed_takes={run.uuid: bob.id})
        assert result.done == [run.uuid]
        assert (_run_row(run).state, _run_row(run).owner_id) == (RunState.CLOSED, user_id)


class TestTakingWhileActing:
    """A run someone takes while another person acts on it: the take waits for the action."""

    @pytest.mark.parametrize("action", ["close", "review"])
    def test_the_take_waits_for_the_action(self, user_id, bob, monkeypatch, action):
        run = _ended(_run())
        taken = threading.Event()
        threads = []

        def take():
            review.take_ownership([run.uuid], bob.id, "bob")
            get_db().remove()
            taken.set()

        claim = review._claim

        def bob_takes_it_meanwhile(*args, **kwargs):
            claim(*args, **kwargs)
            threads.append(threading.Thread(target=take))
            threads[0].start()
            # with the run's row no longer locked, bob's take would go through here, before the action
            assert not taken.wait(1)

        monkeypatch.setattr(review, "_claim", bob_takes_it_meanwhile)
        if action == "close":
            review.close_runs([run.uuid], user_id, ACTOR, reason="not needed")
        else:
            review.review(run.uuid, user_id, ACTOR)
        threads[0].join(10)
        assert taken.is_set()

        db = get_db()
        db.expire_all()
        kinds = [(e.kind, e.actor) for e in db.execute(select(SVSRunEvent).where(SVSRunEvent.run_id == run.id)
                                                       .order_by(SVSRunEvent.id)).scalars()
                 if e.kind in (RunEventKind.OWNERSHIP_TAKEN.value, RunEventKind.REVIEWED.value)
                 or (e.kind == RunEventKind.TRANSITION.value and e.to_state == RunState.CLOSED.value)]
        if action == "close":
            # the close came first, and bob took the closed run
            assert kinds[-1] == (RunEventKind.OWNERSHIP_TAKEN.value, "bob")
            assert ACTOR in [actor for _, actor in kinds[:-1]]
        else:
            # the review took the run first, so bob, who never confirmed taking it from them, is refused
            assert (RunEventKind.OWNERSHIP_TAKEN.value, "bob") not in kinds
            assert _run_row(run).owner_id == user_id


class TestReview:
    def test_review(self, user_id):
        run = _run()
        alert_uuid = _alert(run, RULE)
        run = _ended(run)
        expectations.set_expectation(GUID, RULE, "expected", user_id, platform="windows")
        results.recompute_stale_results()

        result = review.review(run.uuid, user_id, ACTOR)
        assert (result.re_review, result.counts, result.alerts_closed) == (False, {"hit": 1}, 1)
        reviewed = _run_row(run)
        assert (reviewed.state, reviewed.reviewer_id, reviewed.owner_id) == (RunState.REVIEWED, user_id, user_id)
        assert reviewed.reviewed_at is not None and reviewed.changed_since_review is False

        (row,) = get_db().execute(select(SVSRunResult).where(SVSRunResult.run_id == run.id)).scalars()
        assert (row.reviewed_status, row.reviewed_alert_count) == ("hit", 1)
        alert = _row(alert_uuid)
        assert alert.disposition == DISPOSITION_SIMULATED
        assert f"reviewed with SVS test run {run.uuid} by {ACTOR}" in get_db().execute(
            select(Comment.comment).where(Comment.uuid == alert_uuid)).scalars().all()
        (event,) = _events(run, RunEventKind.REVIEWED)
        assert (event.from_state, event.to_state) == ("ended", "reviewed")
        assert json.loads(event.details) == {"counts": {"hit": 1}, "re_review": False}

    def test_blocked_by_candidates_and_a_stale_result(self, user_id):
        run = _run()
        _alert(run, RULE)
        run = _ended(run)
        with pytest.raises(review.ReviewBlocked) as e:
            review.review(run.uuid, user_id, ACTOR)
        assert e.value.blockers == {"candidates": [RULE]}

        expectations.set_expectation(GUID, RULE, "rejected", user_id, platform="windows")
        with pytest.raises(review.ReviewBlocked) as e:
            review.review(run.uuid, user_id, ACTOR)
        # the stale result still shows the candidate; the recompute settles it
        assert e.value.blockers["stale"] is True
        assert _run_row(run).state == RunState.ENDED

        results.recompute_stale_results()
        assert review.review(run.uuid, user_id, ACTOR).counts == {"rejected": 1}

    def test_a_blocked_review_takes_nothing(self, user_id):
        run = _run()
        _alert(run, RULE)
        run = _ended(run)
        with pytest.raises(review.ReviewBlocked):
            review.review(run.uuid, user_id, ACTOR)
        assert _run_row(run).owner_id is None
        assert _events(run, RunEventKind.OWNERSHIP_TAKEN) == []

    def test_blocked_by_a_context_alert_neither_kept_nor_rejected(self, user_id):
        run = _run()
        context = _alert(run, marker=False)
        run = _ended(run)
        with pytest.raises(review.ReviewBlocked) as e:
            review.review(run.uuid, user_id, ACTOR)
        assert e.value.blockers == {"context_alerts": [context]}

        association.keep(run.uuid, context, user_id, ACTOR)
        assert review.review(run.uuid, user_id, ACTOR).alerts_closed == 1

    def test_a_result_never_computed_is_marked_stale(self, user_id):
        run = _ended(_run())
        db = get_db()
        db.execute(SVSRunResultState.__table__.delete().where(SVSRunResultState.run_id == run.id))
        db.commit()
        with pytest.raises(review.ReviewBlocked):
            review.review(run.uuid, user_id, ACTOR)
        db.expire_all()
        assert db.get(SVSRunResultState, run.id).stale

    def test_ignored_detections_get_an_fp_verdict(self, user_id):
        run = _run()
        alert_uuid = _alert(run, RULE, NOISE)
        expectations.set_expectation(GUID, RULE, "expected", user_id, platform="windows")
        expectations.set_ignore(NOISE, user_id, test_guid=GUID)
        run = _ended(run)

        assert review.review(run.uuid, user_id, ACTOR).fp_verdicts == 1
        db = get_db()
        db.expire_all()
        verdicts = db.execute(select(DetectionPointVerdict.signature_uuid, DetectionPointVerdict.verdict,
                                     DetectionPointVerdict.user_id)
                              .join(Alert, Alert.id == DetectionPointVerdict.alert_id)
                              .where(Alert.uuid == alert_uuid)).all()
        assert verdicts == [(NOISE, "fp", user_id)]

    def test_a_verdict_someone_set_is_left_alone(self, user_id):
        run = _run()
        alert_uuid = _alert(run, NOISE)
        expectations.set_ignore(NOISE, user_id, test_guid=GUID)
        run = _ended(run)
        alert_id = _row(alert_uuid).id
        targets = review.ignored_detections(get_db(), run)
        # an analyst graded the detection TP (a verdict needs a tp alert; it is reopened after)
        db = get_db()
        db.execute(update(Alert).where(Alert.id == alert_id).values(disposition="DELIVERY"))
        db.commit()
        set_verdicts(targets, "tp", user_id)
        db.execute(update(Alert).where(Alert.id == alert_id).values(disposition=DISPOSITION_OPEN))
        db.commit()

        assert review.review(run.uuid, user_id, ACTOR).fp_verdicts == 0
        db.expire_all()
        assert db.execute(select(DetectionPointVerdict.verdict).where(
            DetectionPointVerdict.alert_id == alert_id)).scalars().all() == ["tp"]

    def test_review_again(self, user_id):
        run = _run()
        _alert(run, RULE)
        run = _ended(run)
        expectations.set_expectation(GUID, RULE, "expected", user_id, platform="windows")
        results.recompute_stale_results()
        review.review(run.uuid, user_id, ACTOR)

        # a late alert after the review, of a signature since rejected
        late = _alert(run, NOISE)
        assert _run_row(run).changed_since_review is True
        expectations.set_expectation(GUID, NOISE, "rejected", user_id, platform="windows")
        results.recompute_stale_results()
        # an older reviewed row that left the live result is dropped with the old sign-off
        with private_transaction() as session:
            session.add(SVSRunResult(run_id=run.id, signature_uuid=str(uuid.uuid4()), status=None,
                                     reviewed_status="missing"))

        result = review.review(run.uuid, user_id, ACTOR)
        assert (result.re_review, result.counts, result.alerts_closed) == (True, {"hit": 1, "rejected": 1}, 1)
        assert _row(late).disposition == DISPOSITION_SIMULATED
        assert _run_row(run).changed_since_review is False
        statuses = sorted(get_db().execute(select(SVSRunResult.reviewed_status).where(
            SVSRunResult.run_id == run.id)).scalars())
        assert statuses == ["hit", "rejected"]
        assert [json.loads(e.details)["re_review"] for e in _events(run, RunEventKind.REVIEWED)] == [False, True]

    def test_refused(self, user_id, bob):
        started = _run()
        with pytest.raises(runs.RunStateConflict):
            review.review(started.uuid, user_id, ACTOR)
        with pytest.raises(runs.UnknownRun):
            review.review(str(uuid.uuid4()), user_id, ACTOR)

        run = _ended(_run())
        _set_owner(run, bob.id)
        with pytest.raises(review.RunOwned) as e:
            review.review(run.uuid, user_id, ACTOR)
        assert e.value.owner == "bob"
        result = review.review(run.uuid, user_id, ACTOR, confirmed_from=bob.id)
        assert _run_row(run).owner_id == user_id and result.counts == {}

    def test_a_failure_after_the_sign_off_keeps_it(self, user_id, monkeypatch):
        run = _run()
        alert_uuid = _alert(run)
        run = _ended(run)
        monkeypatch.setattr("saq.error.reporting.write_error_report", lambda *a, **k: None)

        def down(*args, **kwargs):
            raise RuntimeError("database down")

        close_reviewed_run_alerts = runs.close_reviewed_run_alerts
        monkeypatch.setattr(runs, "close_reviewed_run_alerts", down)
        review.review(run.uuid, user_id, ACTOR)
        assert _run_row(run).state == RunState.REVIEWED
        assert _row(alert_uuid).disposition == DISPOSITION_OPEN

        # reviewing again finishes the job
        monkeypatch.setattr(runs, "close_reviewed_run_alerts", close_reviewed_run_alerts)
        assert review.review(run.uuid, user_id, ACTOR).alerts_closed == 1


class TestComments:
    def test_comments(self, user_id, bob):
        run = _run()
        comment = run_comments.add_comment(run.uuid, user_id, ACTOR, "  rerun after the agent update\r\n")
        assert comment.comment == "rerun after the agent update"
        run_comments.update_comment(run.uuid, comment.id, user_id, ACTOR, "rerun tomorrow")
        assert [c.comment for c in run_comments.list_comments(run.uuid)] == ["rerun tomorrow"]

        with pytest.raises(run_comments.NotTheAuthor):
            run_comments.update_comment(run.uuid, comment.id, bob.id, "bob", "mine now")
        with pytest.raises(run_comments.NotTheAuthor):
            run_comments.delete_comment(run.uuid, comment.id, bob.id, "bob")
        with pytest.raises(run_comments.InvalidComment):
            run_comments.add_comment(run.uuid, user_id, ACTOR, "   ")
        with pytest.raises(run_comments.UnknownComment):
            run_comments.delete_comment(run.uuid, 999999, user_id, ACTOR)

        run_comments.delete_comment(run.uuid, comment.id, user_id, ACTOR)
        assert run_comments.list_comments(run.uuid) == []


def test_stale_marking_does_not_wait_on_a_review_forever(user_id):
    """mark_runs_stale and a review lock the run's result state in the same order as the router."""
    run = _ended(_run())
    with private_transaction() as session:
        mark_runs_stale(session, run_ids=[run.id])
    results.recompute_stale_results()
    review.review(run.uuid, user_id, ACTOR)
    assert _run_row(run).state == RunState.REVIEWED
