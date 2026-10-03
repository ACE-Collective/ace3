"""Routing in use: ALERT() (PRE_INSERT), move_alert_to_queue(), and the engine's POST_ANALYSIS
stage and queue reconcile."""

import logging
import uuid
from unittest.mock import Mock

import pytest

from saq.alert_routing import AlertRouter, RouteDecision, RouteStage, register_alert_router
from saq.analysis.root import RootAnalysis, load_root
from saq.constants import ANALYSIS_MODE_CORRELATION, DISPOSITION_FALSE_POSITIVE, QUEUE_DEFAULT
from saq.database.model import Alert, AlertQueueChange, User, load_alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT, get_last_queue_change, move_alert_to_queue
from saq.database.util.automation_user import lookup_automation_user_id
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration


class StageRouter(AlertRouter):
    def __init__(self, name: str, priority: int, queue: str, stage: RouteStage):
        super().__init__(name=name, priority=priority)
        self.queue = queue
        self.stage = stage

    def route(self, root, stage):
        if stage != self.stage:
            return None
        return RouteDecision(queue=self.queue, reason="test routing")


def _saved_root(**kwargs) -> RootAnalysis:
    root = create_root_analysis(uuid=str(uuid.uuid4()), **kwargs)
    root.initialize_storage()
    root.save()
    return root


def _changes(alert_id: int) -> list[AlertQueueChange]:
    get_db().expire_all()
    return get_db().query(AlertQueueChange).filter(AlertQueueChange.alert_id == alert_id).order_by(AlertQueueChange.id).all()


def _stored_queue(alert_uuid: str) -> str:
    # a column query reads the database, not the session's identity map
    get_db().commit()
    return get_db().query(Alert.queue).filter(Alert.uuid == alert_uuid).scalar()


@pytest.fixture
def submitted_payloads(monkeypatch):
    calls = []
    monkeypatch.setattr("saq.database.util.alert.submit_payload_task", lambda alert_uuid: calls.append(alert_uuid))
    return calls


class TestPreInsert:
    def test_a_decision_becomes_the_queue_in_the_row_and_the_tree(self):
        register_alert_router(StageRouter("pre", 100, "routed", RouteStage.PRE_INSERT))
        root = _saved_root()

        alert = ALERT(root)

        assert _stored_queue(root.uuid) == "routed"
        # ALERT() saved the caller's root, routed queue included
        assert load_root(root.storage_dir).queue == "routed"

        (change,) = _changes(alert.id)
        assert (change.from_queue, change.to_queue, change.router, change.actor_user_id) == (
            QUEUE_DEFAULT, "routed", "pre", None)
        assert change.reason == "test routing"
        assert get_last_queue_change(alert.id).id == change.id

    def test_no_decision_no_change_row(self):
        root = _saved_root()
        alert = ALERT(root)

        assert _stored_queue(root.uuid) == QUEUE_DEFAULT
        assert _changes(alert.id) == []
        assert get_last_queue_change(alert.id) is None

    def test_the_detection_queue_router_runs_for_every_insert_path(self):
        """It used to run only when the engine converted a root; now any ALERT() call routes."""
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        root.add_detection_point("yara hit", queue="experimental")
        root.save()

        alert = ALERT(root)
        assert _stored_queue(root.uuid) == "experimental"
        assert _changes(alert.id)[0].router == "detection_queue"

    def test_a_raising_router_never_breaks_the_insert(self, monkeypatch):
        class Broken(AlertRouter):
            def route(self, root, stage):
                raise RuntimeError("broken router")

        monkeypatch.setattr("saq.alert_routing.registry.report_exception", lambda *a, **k: None)
        register_alert_router(Broken("broken", 100))
        root = _saved_root()

        ALERT(root)
        assert _stored_queue(root.uuid) == QUEUE_DEFAULT


class TestMoveAlertToQueue:
    def test_moves_the_row_and_records_who(self, submitted_payloads, caplog):
        root = _saved_root()
        alert = ALERT(root)
        version = alert.version
        user = get_db().query(User).filter(User.username == "unittest").one()

        with caplog.at_level(logging.INFO):
            assert move_alert_to_queue(alert, "triage", "analyst moved it", actor_user_id=user.id) is True

        assert alert.queue == "triage"
        assert alert.version != version
        assert _stored_queue(root.uuid) == "triage"
        assert submitted_payloads == [root.uuid]

        change = get_last_queue_change(alert.id)
        assert (change.from_queue, change.to_queue, change.router, change.actor_user_id, change.reason) == (
            QUEUE_DEFAULT, "triage", None, user.id, "analyst moved it")

        (record,) = [r for r in caplog.records if r.getMessage() == "AUDIT: alert moved to queue"]
        assert (record.alert_uuid, record.from_queue, record.to_queue) == (root.uuid, QUEUE_DEFAULT, "triage")

    def test_moving_back_restores_through_the_record(self, submitted_payloads):
        """The newest change row says what queue the alert came from, which is how a move is
        reversed."""
        alert = ALERT(_saved_root())
        move_alert_to_queue(alert, "svs", "attributed to a test run", router="svs_marker")

        previous = get_last_queue_change(alert.id)
        assert previous.router == "svs_marker"
        move_alert_to_queue(alert, previous.from_queue, "disassociated", actor_user_id=None)

        assert _stored_queue(alert.uuid) == QUEUE_DEFAULT
        assert [c.to_queue for c in _changes(alert.id)] == ["svs", QUEUE_DEFAULT]

    def test_the_same_queue_is_not_a_move(self, submitted_payloads):
        alert = ALERT(_saved_root())
        assert move_alert_to_queue(alert, QUEUE_DEFAULT, "no-op") is False
        assert _changes(alert.id) == []
        assert submitted_payloads == []

    def test_a_given_root_carries_the_queue(self, submitted_payloads):
        root = _saved_root()
        alert = ALERT(root)
        move_alert_to_queue(alert, "triage", "moved", root=root)
        assert root.queue == "triage"

    @pytest.mark.parametrize("queue", ["", "q" * 65])
    def test_a_bad_queue_is_refused(self, queue):
        alert = ALERT(_saved_root())
        with pytest.raises(ValueError):
            move_alert_to_queue(alert, queue, "bad")


def _orchestrator() -> AnalysisOrchestrator:
    config_manager = Mock(spec=ConfigurationManager)
    config_manager.config = Mock()
    return AnalysisOrchestrator(
        configuration_manager=config_manager,
        analysis_executor=Mock(spec=AnalysisExecutor),
        workload_manager=Mock(),
        lock_manager=Mock(),
    )


def _context(root: RootAnalysis) -> EngineExecutionContext:
    context = Mock(spec=EngineExecutionContext)
    context.root = root
    context.analysis_skipped = False
    context.analysis_aborted = False
    return context


class TestPostAnalysis:
    @pytest.fixture
    def correlation_alert(self, submitted_payloads):
        register_alert_router(StageRouter("post", 100, "post_queue", RouteStage.POST_ANALYSIS))
        root = _saved_root(analysis_mode=ANALYSIS_MODE_CORRELATION)
        alert = ALERT(root)
        return root, alert

    def _sync(self, root):
        _orchestrator()._sync_alert_to_database(_context(root))

    def test_an_open_unowned_alert_is_moved(self, correlation_alert, submitted_payloads):
        root, alert = correlation_alert
        self._sync(root)

        assert _stored_queue(root.uuid) == "post_queue"
        assert load_root(root.storage_dir).queue == "post_queue"
        assert get_last_queue_change(alert.id).router == "post"
        assert root.uuid in submitted_payloads

    def test_an_alert_an_analyst_owns_is_not_moved(self, correlation_alert):
        root, alert = correlation_alert
        user = get_db().query(User).filter(User.username == "unittest").one()
        get_db().execute(Alert.__table__.update().where(Alert.id == alert.id).values(owner_id=user.id))
        get_db().commit()

        self._sync(root)
        assert _stored_queue(root.uuid) == QUEUE_DEFAULT

    def test_the_automation_user_counts_as_nobody(self, correlation_alert):
        """Setting a disposition as automation makes it the owner; a re-review must still be able
        to move the alert."""
        root, alert = correlation_alert
        get_db().execute(Alert.__table__.update().where(Alert.id == alert.id).values(
            owner_id=lookup_automation_user_id()))
        get_db().commit()

        self._sync(root)
        assert _stored_queue(root.uuid) == "post_queue"

    def test_a_dispositioned_alert_is_not_moved(self, correlation_alert):
        root, alert = correlation_alert
        get_db().execute(Alert.__table__.update().where(Alert.id == alert.id).values(
            disposition=DISPOSITION_FALSE_POSITIVE))
        get_db().commit()

        self._sync(root)
        assert _stored_queue(root.uuid) == QUEUE_DEFAULT


class TestReconcile:
    def test_a_queue_changed_elsewhere_reaches_the_tree_before_analysis(self, submitted_payloads):
        """The alerts row owns the queue once the alert exists; modules that check the queue
        during the next pass see where the alert is now."""
        root = _saved_root(analysis_mode=ANALYSIS_MODE_CORRELATION)
        alert = ALERT(root)
        move_alert_to_queue(alert, "elsewhere", "moved without the tree")
        assert root.queue == QUEUE_DEFAULT

        _orchestrator()._check_disposition(_context(root))
        assert root.queue == "elsewhere"


class TestEngine:
    def test_a_detection_queue_routes_the_alert_the_engine_creates(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode="test_single")
        root.initialize_storage()
        root.add_detection_point("yara hit", queue="experimental")
        root.save()
        root.schedule()

        engine = Engine()
        engine.configuration_manager.config.alerting_enabled = True
        engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

        alert = load_alert(root.uuid)
        assert alert.queue == "experimental"
        assert load_root(alert.storage_dir).queue == "experimental"
        (change,) = _changes(alert.id)
        assert (change.from_queue, change.to_queue, change.router) == (QUEUE_DEFAULT, "experimental", "detection_queue")
