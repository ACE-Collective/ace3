"""A person's changes to which alerts belong to a run (saq.svs.association, docs/SVS_RUNS.md,
*Associating alerts by hand*), and how the marker router respects them (saq.svs.routing,
saq.svs.attribution)."""

import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest
from sqlalchemy import select, update

from saq.alert_routing import reset_alert_routers
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_OPEN,
    DISPOSITION_SIMULATED,
    F_HOSTNAME,
    F_TEST,
    QUEUE_DEFAULT,
)
from saq.database.model import (
    Alert,
    AlertQueueChange,
    Comment,
    SVSAttribution,
    SVSRun,
    SVSRunEvent,
    SVSRunResultState,
    User,
)
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.database.util.alert import ALERT, set_dispositions
from saq.database.util.user_management import add_user
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.svs import association, attribution, runs
from saq.svs.association import AssociationConflict, InvalidAssociation, UnknownAlert
from saq.svs.attribution import evaluate, write_attributions
from saq.svs.constants import SVS_MANUAL_ROUTER, RunEventKind, RunState
from tests.saq.helpers import create_root_analysis, insert_alert
from tests.saq.svs.conftest import LAUNCHER, add_catalog_test, add_test_host, started_run

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
ACTOR = "unittest"


@pytest.fixture(autouse=True)
def setup(no_hunts, monkeypatch):
    reset_alert_routers()
    monkeypatch.setattr("saq.database.util.alert.submit_payload_task", lambda alert_uuid: None)
    monkeypatch.setattr("saq.database.util.alert.submit_index_task", lambda alert_uuid: None)
    add_catalog_test(GUID)
    add_test_host("win10-01")
    yield
    reset_alert_routers()


@pytest.fixture
def user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == ACTOR)).scalar_one()


@pytest.fixture
def run() -> SVSRun:
    return started_run(GUID, now=datetime.now() - timedelta(minutes=1))


def _alert(*, marker=None, host="win10-01", analysis_mode=None) -> RootAnalysis:
    """An alert inserted through ALERT(), which the marker router judges."""
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now(), analysis_mode=analysis_mode)
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    if marker:
        root.details = {"events": [{"command_line": f"whoami & REM {marker}"}]}
    root.add_detection_point("hunt hit")
    root.save()
    ALERT(root)
    return root


def _row(alert_uuid: str) -> Alert:
    db = get_db()
    db.expire_all()
    return db.execute(select(Alert).where(Alert.uuid == alert_uuid)).unique().scalar_one()


def _attributions(alert_uuid: str, run_id: int) -> list[SVSAttribution]:
    db = get_db()
    db.expire_all()
    return list(db.execute(select(SVSAttribution).where(
        SVSAttribution.alert_uuid == alert_uuid, SVSAttribution.run_id == run_id).order_by(SVSAttribution.id)).scalars())


def _last_change(alert_uuid: str) -> tuple:
    db = get_db()
    db.expire_all()
    return tuple(db.execute(
        select(AlertQueueChange.from_queue, AlertQueueChange.to_queue, AlertQueueChange.router)
        .join(Alert, Alert.id == AlertQueueChange.alert_id).where(Alert.uuid == alert_uuid)
        .order_by(AlertQueueChange.id.desc()).limit(1)).one())


def _events(run: SVSRun, kind: RunEventKind) -> list[dict]:
    db = get_db()
    db.expire_all()
    return [json.loads(e.details) for e in db.execute(select(SVSRunEvent).where(
        SVSRunEvent.run_id == run.id, SVSRunEvent.kind == kind.value).order_by(SVSRunEvent.id)).scalars()]


def _sync(root: RootAnalysis):
    """The engine's POST_ANALYSIS stage for an existing alert."""
    config_manager = Mock(spec=ConfigurationManager)
    config_manager.config = Mock()
    orchestrator = AnalysisOrchestrator(configuration_manager=config_manager,
                                        analysis_executor=Mock(spec=AnalysisExecutor),
                                        workload_manager=Mock(), lock_manager=Mock())
    context = Mock(spec=EngineExecutionContext)
    context.root = root
    context.analysis_skipped = False
    context.analysis_aborted = False
    orchestrator._sync_alert_to_database(context)


class TestAssociate:
    def test_an_unattributed_alert(self, run, user_id):
        root = _alert(host="srv-01")
        assert _row(root.uuid).queue == QUEUE_DEFAULT

        result = association.associate(run.uuid, root.uuid, user_id, ACTOR, "seen on the test VM's console")
        assert (result.svs_status, result.queue, result.moved) == ("test", get_config().svs.queue, True)

        (row,) = _attributions(root.uuid, run.id)
        assert (row.source, row.confidence, row.scan_point, row.late, row.actor, row.actor_user_id) == (
            "manual", "marker", None, False, ACTOR, user_id)
        assert _last_change(root.uuid) == (QUEUE_DEFAULT, get_config().svs.queue, SVS_MANUAL_ROUTER)
        (event,) = _events(run, RunEventKind.ASSOCIATED)
        assert event["alert_uuid"] == root.uuid and event["reason"] == "seen on the test VM's console"
        assert get_db().get(SVSRunResultState, run.id).stale

    def test_over_the_routers_rows(self, run, user_id):
        root = _alert(marker=run.marker)
        assert [r.source for r in _attributions(root.uuid, run.id)] == ["router"]

        result = association.associate(run.uuid, root.uuid, user_id, ACTOR)
        assert result.moved is False and result.svs_status == "test"
        (row,) = _attributions(root.uuid, run.id)
        assert (row.source, row.scan_point) == ("manual", None)

    def test_a_late_alert(self, user_id):
        early = started_run(GUID, now=datetime.now() - timedelta(hours=3))
        root = _alert(host="srv-01")
        association.associate(early.uuid, root.uuid, user_id, ACTOR)
        assert _attributions(root.uuid, early.id)[0].late is True

    def test_a_reviewed_run_changes_since_review(self, run, user_id):
        db = get_db()
        db.execute(update(SVSRun).where(SVSRun.id == run.id).values(state=RunState.REVIEWED.value))
        db.commit()
        association.associate(run.uuid, _alert(host="srv-01").uuid, user_id, ACTOR)
        db.expire_all()
        assert db.get(SVSRun, run.id).changed_since_review is True

    def test_a_dispositioned_alert_is_not_moved(self, run, user_id):
        root = _alert(host="srv-01")
        set_dispositions([root.uuid], DISPOSITION_FALSE_POSITIVE, user_id)
        result = association.associate(run.uuid, root.uuid, user_id, ACTOR)
        assert (result.svs_status, result.moved, result.queue) == ("test", False, QUEUE_DEFAULT)

    def test_an_alert_taken_meanwhile_is_not_moved(self, run, user_id, monkeypatch):
        """associate reads the alert, then moves it: an analyst who takes it in between keeps it."""
        root = _alert(host="srv-01")
        analyst = add_user("bob", "bob@localhost", "Bob", "bob").id
        movable = association._movable

        def taken_first(alert, user):
            with private_transaction() as session:
                session.execute(update(Alert).where(Alert.uuid == root.uuid).values(owner_id=analyst))
            return movable(alert, user)

        monkeypatch.setattr(association, "_movable", taken_first)
        result = association.associate(run.uuid, root.uuid, user_id, ACTOR)
        assert (result.svs_status, result.moved, result.queue) == ("test", False, QUEUE_DEFAULT)

    def test_refused(self, user_id):
        created = runs.register(runs.Registration(test_guid=GUID, targets=[runs.TargetSpec("win10-01")],
                                                  launcher="art"), LAUNCHER)
        root = _alert(host="srv-01")
        with pytest.raises(AssociationConflict):
            association.associate(created.uuid, root.uuid, user_id, ACTOR)

        run = started_run(GUID)
        with pytest.raises(InvalidAssociation):
            association.associate(run.uuid, insert_alert().uuid, user_id, ACTOR)
        with pytest.raises(UnknownAlert):
            association.associate(run.uuid, str(uuid.uuid4()), user_id, ACTOR)
        with pytest.raises(runs.UnknownRun):
            association.associate(str(uuid.uuid4()), root.uuid, user_id, ACTOR)


class TestDisassociate:
    def test_a_routed_alert_goes_back(self, run, user_id):
        root = _alert(marker=run.marker)
        assert _row(root.uuid).queue == get_config().svs.queue

        result = association.disassociate(run.uuid, root.uuid, user_id, ACTOR, "the analyst ran this by hand")
        assert (result.svs_status, result.queue, result.moved, result.reopened) == (None, QUEUE_DEFAULT, True, False)
        (row,) = _attributions(root.uuid, run.id)
        assert (row.removed_by, row.removed_by_user_id, row.removal_reason) == (
            ACTOR, user_id, "the analyst ran this by hand")
        assert _last_change(root.uuid) == (get_config().svs.queue, QUEUE_DEFAULT, SVS_MANUAL_ROUTER)
        (event,) = _events(run, RunEventKind.DISASSOCIATED)
        assert event["not_a_test"] is False

    def test_a_simulated_alert_is_given_back_open(self, run, user_id):
        root = _alert(marker=run.marker)
        runs.cancel(run.uuid, LAUNCHER)
        runs.run_timers(now=run.attribution_ends_at + timedelta(seconds=1))
        assert _row(root.uuid).disposition == DISPOSITION_SIMULATED

        result = association.disassociate(run.uuid, root.uuid, user_id, ACTOR)
        assert (result.reopened, result.moved, result.queue) == (True, True, QUEUE_DEFAULT)
        alert = _row(root.uuid)
        assert alert.disposition == DISPOSITION_OPEN
        assert alert.disposition_user_id == get_config().global_settings.automation_user_id
        # given up by the automation user that owned it as SIMULATED
        assert alert.owner_id is None
        comments = get_db().execute(select(Comment.comment).where(Comment.uuid == root.uuid)).scalars().all()
        assert f"disassociated from SVS test run {run.uuid} by {ACTOR}" in comments

    def test_an_analyst_who_takes_the_reopened_alert_keeps_it(self, run, user_id, monkeypatch):
        root = _alert(marker=run.marker)
        runs.cancel(run.uuid, LAUNCHER)
        runs.run_timers(now=run.attribution_ends_at + timedelta(seconds=1))
        bob = add_user("bob", "bob@localhost", "Bob", "bob").id
        give_up = association.change_alert_owner

        def bob_takes_it_first(alert_uuids, owner_id, acting_user_id):
            with private_transaction() as session:
                session.execute(update(Alert).where(Alert.uuid == root.uuid).values(owner_id=bob))
            return give_up(alert_uuids, owner_id, acting_user_id)

        monkeypatch.setattr(association, "change_alert_owner", bob_takes_it_first)
        assert association.disassociate(run.uuid, root.uuid, user_id, ACTOR).reopened
        assert _row(root.uuid).owner_id == bob

    def test_an_alert_still_fully_attributed_to_another_run_stays(self, run, user_id):
        root = _alert(marker=run.marker)
        other = started_run(GUID)
        association.associate(other.uuid, root.uuid, user_id, ACTOR)

        result = association.disassociate(run.uuid, root.uuid, user_id, ACTOR)
        assert (result.svs_status, result.queue, result.moved) == ("test", get_config().svs.queue, False)

    def test_an_alert_submitted_to_the_test_queue_stays_there(self, run, user_id):
        root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now(), queue=get_config().svs.queue)
        root.initialize_storage()
        root.add_observable_by_spec(F_HOSTNAME, "srv-01")
        root.add_detection_point("hunt hit")
        root.save()
        ALERT(root)
        association.associate(run.uuid, root.uuid, user_id, ACTOR)
        result = association.disassociate(run.uuid, root.uuid, user_id, ACTOR)
        assert (result.moved, result.queue) == (False, get_config().svs.queue)

    def test_it_is_reversible(self, run, user_id):
        root = _alert(marker=run.marker)
        association.disassociate(run.uuid, root.uuid, user_id, ACTOR)
        result = association.associate(run.uuid, root.uuid, user_id, ACTOR)
        assert (result.svs_status, result.queue) == ("test", get_config().svs.queue)
        (row,) = _attributions(root.uuid, run.id)
        assert (row.source, row.removed_at, row.removed_by_user_id) == ("manual", None, None)

    def test_nothing_to_disassociate(self, run, user_id):
        with pytest.raises(AssociationConflict):
            association.disassociate(run.uuid, _alert(host="srv-01").uuid, user_id, ACTOR)


class TestNotATestAndKeep:
    def test_not_a_test_on_a_context_alert(self, run, user_id):
        root = _alert()
        assert [r.confidence for r in _attributions(root.uuid, run.id)] == ["context"]
        result = association.disassociate(run.uuid, root.uuid, user_id, ACTOR, not_a_test=True)
        assert (result.svs_status, result.queue) == (None, QUEUE_DEFAULT)
        assert _attributions(root.uuid, run.id)[0].removal_reason == "not a test"

    def test_not_a_test_on_a_marker_alert_is_refused(self, run, user_id):
        root = _alert(marker=run.marker)
        with pytest.raises(AssociationConflict):
            association.disassociate(run.uuid, root.uuid, user_id, ACTOR, not_a_test=True)

    def test_keep(self, run, user_id):
        root = _alert()
        result = association.keep(run.uuid, root.uuid, user_id, ACTOR)
        assert result.svs_status == "test?"
        (row,) = _attributions(root.uuid, run.id)
        assert row.kept_by_user_id == user_id and row.kept_at is not None
        assert _events(run, RunEventKind.CONTEXT_KEPT) == [{"alert_uuid": root.uuid}]

        with pytest.raises(AssociationConflict):
            association.keep(run.uuid, _alert(marker=run.marker).uuid, user_id, ACTOR)


class TestFromTheAlertsSide:
    def test_every_run_lets_the_alert_go(self, run, user_id):
        root = _alert(marker=run.marker)
        other = started_run(GUID)
        association.associate(other.uuid, root.uuid, user_id, ACTOR)

        result = association.disassociate_alert(root.uuid, user_id, ACTOR, "a real attack")
        assert result.runs == (run.uuid, other.uuid)
        assert (result.svs_status, result.queue, result.moved, result.reopened) == (None, QUEUE_DEFAULT, True, False)
        for held_by in (run, other):
            (row,) = _attributions(root.uuid, held_by.id)
            assert (row.removed_by_user_id, row.removal_reason) == (user_id, "a real attack")
            assert _events(held_by, RunEventKind.DISASSOCIATED)[0]["not_a_test"] is False

    def test_a_simulated_alert_is_given_back_open(self, run, user_id):
        root = _alert(marker=run.marker)
        runs.cancel(run.uuid, LAUNCHER)
        runs.run_timers(now=run.attribution_ends_at + timedelta(seconds=1))
        assert _row(root.uuid).disposition == DISPOSITION_SIMULATED

        result = association.disassociate_alert(root.uuid, user_id, ACTOR)
        assert (result.runs, result.reopened, result.moved) == ((run.uuid,), True, True)
        assert (_row(root.uuid).disposition, _row(root.uuid).owner_id) == (DISPOSITION_OPEN, None)

    def test_not_a_test(self, run, user_id):
        root = _alert()
        result = association.disassociate_alert(root.uuid, user_id, ACTOR, not_a_test=True)
        assert (result.runs, result.svs_status, result.queue) == ((run.uuid,), None, QUEUE_DEFAULT)
        assert _attributions(root.uuid, run.id)[0].removal_reason == "not a test"

    def test_not_a_test_only_for_a_context_alert(self, run, user_id):
        root = _alert(marker=run.marker)
        with pytest.raises(AssociationConflict):
            association.disassociate_alert(root.uuid, user_id, ACTOR, not_a_test=True)
        assert _attributions(root.uuid, run.id)[0].removed_at is None

    def test_nothing_holds_it(self, run, user_id):
        with pytest.raises(AssociationConflict):
            association.disassociate_alert(_alert(host="srv-01").uuid, user_id, ACTOR)
        with pytest.raises(UnknownAlert):
            association.disassociate_alert(str(uuid.uuid4()), user_id, ACTOR)


class TestTheRouterRespectsAPerson:
    def test_a_disassociated_run_never_takes_the_alert_back(self, run, user_id):
        # the engine stage below ends the session the run was read in
        run_id, marker = run.id, run.marker
        root = _alert(marker=marker, analysis_mode=ANALYSIS_MODE_CORRELATION)
        association.disassociate(run.uuid, root.uuid, user_id, ACTOR)

        # a later pass finds another detection on the marker's branch
        root.add_observable_by_spec(F_TEST, f"ran {marker}").add_detection_point("test detection")
        _sync(root)
        assert all(r.removed_at is not None for r in _attributions(root.uuid, run_id))
        assert _row(root.uuid).queue == QUEUE_DEFAULT

    def test_another_runs_marker_is_attributed_but_the_queue_is_held(self, run, user_id):
        root = _alert(marker=run.marker, analysis_mode=ANALYSIS_MODE_CORRELATION)
        association.disassociate(run.uuid, root.uuid, user_id, ACTOR)

        other = started_run(GUID, now=datetime.now() - timedelta(minutes=1))
        other_id = other.id
        root.details = {"events": [{"command_line": f"whoami & REM {other.marker}"}]}
        _sync(root)
        assert [r.source for r in _attributions(root.uuid, other_id)] == ["router"]
        assert _row(root.uuid).queue == QUEUE_DEFAULT

    def test_a_hand_associated_alert_is_never_moved_back(self, run, user_id):
        root = _alert(host="srv-01", analysis_mode=ANALYSIS_MODE_CORRELATION)
        association.associate(run.uuid, root.uuid, user_id, ACTOR)

        # a later pass finds a detection the association doesn't cover: the alert is partial
        root.add_observable_by_spec(F_TEST, "unrelated").add_detection_point("real detection")
        _sync(root)
        assert _row(root.uuid).queue == get_config().svs.queue
        assert _last_change(root.uuid)[2] == SVS_MANUAL_ROUTER

    def test_the_router_never_overwrites_a_row_a_person_took_meanwhile(self, run, user_id, monkeypatch):
        root = _alert(marker=run.marker)
        (row,) = _attributions(root.uuid, run.id)
        update_own_row = attribution._update_own_row

        def a_person_first(session, row_id, *conditions, **values):
            with private_transaction() as other:
                other.execute(update(SVSAttribution).where(SVSAttribution.id == row_id).values(
                    source="manual", actor=ACTOR, actor_user_id=user_id))
            return update_own_row(session, row_id, *conditions, **values)

        monkeypatch.setattr(attribution, "_update_own_row", a_person_first)
        # the marker is gone from the tree: the router would remove its row
        root.details = {}
        result = write_attributions(root.uuid, evaluate(root, datetime.now()))
        assert result.removed == []
        (row,) = _attributions(root.uuid, run.id)
        assert (row.source, row.removed_at) == ("manual", None)
