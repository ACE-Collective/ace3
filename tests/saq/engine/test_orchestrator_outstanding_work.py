# vim: sw=4:ts=4:et:cc=120
#
# tests for AnalysisOrchestrator._check_for_outstanding_work and the post-analysis
# decisions it gates (see docs/ENGINE.md 13.1, 19.8).
#
# The defect: _handle_post_analysis_logic evaluated the "is anything else still
# working on this root?" predicate up to three separate times -- once to gate
# detection handling, once to gate storage cleanup, once to gate embedding
# submission -- each in its own get_db_connection(). Besides the cost, the three
# answers are not atomic with respect to each other, so a single pass could act on
# contradictory answers. The damaging ordering is True then False: detections are
# skipped (so a root carrying detection points never becomes an alert) and then
# cleanup deletes its storage directory anyway.
#
# Most of these are unit tests because the defect is in the control flow of one
# method, not in the SQL it runs; the two integration tests pin the resulting
# round-trip count against a real engine pass.
#

import os
import uuid

import pytest
from unittest.mock import MagicMock, Mock, patch

from saq.constants import ANALYSIS_MODE_CORRELATION, F_TEST
from saq.database.util.alert import get_alert_by_uuid
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.util.uuid import get_storage_dir, workload_storage_dir
from tests.saq.helpers import create_root_analysis

#
# unit tests
#

def _make_orchestrator(non_detectable_modes=None, alerting_enabled=True) -> AnalysisOrchestrator:
    """An AnalysisOrchestrator with every collaborator mocked out."""
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.non_detectable_modes = non_detectable_modes if non_detectable_modes else []
    configuration_manager.config.alerting_enabled = alerting_enabled

    lock_manager = Mock()
    lock_manager.lock_uuid = str(uuid.uuid4())

    return AnalysisOrchestrator(
        configuration_manager=configuration_manager,
        analysis_executor=Mock(spec=AnalysisExecutor),
        workload_manager=Mock(),
        lock_manager=lock_manager,
    )

def _make_context(analysis_mode="test_single") -> EngineExecutionContext:
    """A real execution context over a real (unsaved) RootAnalysis."""
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode=analysis_mode)
    return EngineExecutionContext(work_item=root)

def _cleanup_mode(cleanup: bool):
    """Patches get_config() so the root's analysis mode reports the given cleanup setting."""
    config = MagicMock()
    config.get_analysis_mode_config.return_value.cleanup = cleanup
    return patch("saq.engine.analysis_orchestrator.get_config", return_value=config)

@pytest.mark.unit
def test_outstanding_work_queried_once_per_pass():
    """all three post-analysis decisions must share a single evaluation of the predicate

    The root is in correlation mode with cleanup forced on, so every consumer of the
    predicate is live in this pass. Before the fix this cost three connections and
    three evaluations."""
    orchestrator = _make_orchestrator()
    context = _make_context(analysis_mode=ANALYSIS_MODE_CORRELATION)

    with patch.object(orchestrator, "_check_for_outstanding_work", return_value=False) as mock_check, \
         patch("saq.engine.analysis_orchestrator.get_db_connection") as mock_connection, \
         patch("saq.engine.analysis_orchestrator.get_db"), \
         patch("saq.llm.embedding.service.submit_embedding_task") as mock_submit, \
         patch("shutil.rmtree") as mock_rmtree, \
         _cleanup_mode(True):

        orchestrator._handle_post_analysis_logic(context)

    assert mock_check.call_count == 1
    assert mock_connection.call_count == 1

    # and the single answer (no outstanding work) still drove both consumers
    mock_rmtree.assert_called_once()
    mock_submit.assert_called_once_with(context.root.uuid)

@pytest.mark.unit
def test_inconsistent_answers_do_not_delete_an_unalerted_root():
    """a root whose detections were skipped because of outstanding work must not then be cleaned up

    This is the harmful ordering: the first evaluation says there is outstanding
    work (so _handle_detection_points never runs and the root never becomes an
    alert) and by the time cleanup asks again the answer has flipped, deleting the
    storage directory along with the detections nobody acted on."""
    orchestrator = _make_orchestrator()
    context = _make_context(analysis_mode="test_single")
    context.root.add_detection_point("something bad")

    with patch.object(orchestrator, "_check_for_outstanding_work", side_effect=[True, False, False]), \
         patch("saq.engine.analysis_orchestrator.get_db_connection"), \
         patch("saq.engine.analysis_orchestrator.get_db"), \
         patch("saq.llm.embedding.service.submit_embedding_task") as mock_submit, \
         patch("shutil.rmtree") as mock_rmtree, \
         _cleanup_mode(True):

        orchestrator._handle_post_analysis_logic(context)

    # the detections were not acted on ...
    assert context.root.analysis_mode == "test_single"
    # ... so the tree that still carries them must survive
    mock_rmtree.assert_not_called()
    mock_submit.assert_not_called()

@pytest.mark.unit
def test_rescheduled_root_is_never_cleaned_up():
    """a mode change re-queues the root, which is itself outstanding work

    _handle_analysis_mode_changes runs between the old check #1 and checks #2/#3 and
    calls root.schedule(), so the later queries saw the new workload row. With a
    single up-front evaluation that row does not exist yet, so the reschedule has to
    promote the answer to True explicitly -- otherwise cleanup deletes a root that
    was just queued for another pass."""
    orchestrator = _make_orchestrator()
    context = _make_context(analysis_mode="test_single")
    # the mode changed during analysis to one that cleans up after itself
    context.root.analysis_mode = "test_cleanup"
    assert context.root.original_analysis_mode == "test_single"

    with patch.object(orchestrator, "_check_for_outstanding_work", return_value=False), \
         patch("saq.engine.analysis_orchestrator.get_db_connection"), \
         patch("saq.engine.analysis_orchestrator.get_db"), \
         patch.object(context.root, "schedule") as mock_schedule, \
         patch("saq.llm.embedding.service.submit_embedding_task") as mock_submit, \
         patch("shutil.rmtree") as mock_rmtree, \
         _cleanup_mode(True):

        orchestrator._handle_post_analysis_logic(context)

    mock_schedule.assert_called_once()
    mock_rmtree.assert_not_called()
    mock_submit.assert_not_called()

@pytest.mark.unit
def test_failed_reschedule_still_blocks_cleanup():
    """if root.schedule() fails the root is not queued anywhere -- deleting it would lose it"""
    orchestrator = _make_orchestrator()
    context = _make_context(analysis_mode="test_single")
    context.root.analysis_mode = "test_cleanup"

    with patch.object(orchestrator, "_check_for_outstanding_work", return_value=False), \
         patch("saq.engine.analysis_orchestrator.get_db_connection"), \
         patch("saq.engine.analysis_orchestrator.get_db"), \
         patch.object(context.root, "schedule", side_effect=RuntimeError("workload insert failed")), \
         patch("shutil.rmtree") as mock_rmtree, \
         _cleanup_mode(True):

        orchestrator._handle_post_analysis_logic(context)

    mock_rmtree.assert_not_called()

@pytest.mark.unit
def test_database_failure_is_fail_safe():
    """when the predicate cannot be evaluated at all, none of the decisions it gates are taken"""
    orchestrator = _make_orchestrator()
    context = _make_context(analysis_mode=ANALYSIS_MODE_CORRELATION)
    context.root.add_detection_point("something bad")

    with patch("saq.engine.analysis_orchestrator.get_db_connection", side_effect=RuntimeError("no database")), \
         patch("saq.engine.analysis_orchestrator.get_db"), \
         patch("saq.llm.embedding.service.submit_embedding_task") as mock_submit, \
         patch("shutil.rmtree") as mock_rmtree, \
         _cleanup_mode(True):

        orchestrator._handle_post_analysis_logic(context)

    mock_rmtree.assert_not_called()
    mock_submit.assert_not_called()

#
# integration tests: the round-trip count against a real engine pass
#

def _count_outstanding_work_checks(monkeypatch) -> list:
    """Records one entry per _check_for_outstanding_work evaluation, keeping the real behavior."""
    calls = []
    original = AnalysisOrchestrator._check_for_outstanding_work

    def counting(self, cursor, execution_context):
        calls.append(execution_context.root.uuid)
        return original(self, cursor, execution_context)

    monkeypatch.setattr(AnalysisOrchestrator, "_check_for_outstanding_work", counting)
    return calls

@pytest.mark.integration
def test_single_check_for_a_cleaned_up_root(monkeypatch):
    """a root in a cleanup mode is evaluated once, and is still cleaned up"""
    calls = _count_outstanding_work_checks(monkeypatch)

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, analysis_mode="test_cleanup",
                                storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    root.save()
    root.schedule()

    engine = Engine()
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    # detections and cleanup shared one evaluation (two before the fix)
    assert calls == [root_uuid]
    assert not os.path.isdir(workload_storage_dir(root_uuid))

@pytest.mark.integration
def test_single_check_for_a_root_that_becomes_an_alert(monkeypatch):
    """a root that alerts is evaluated once, and is still converted and preserved"""
    calls = _count_outstanding_work_checks(monkeypatch)

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, analysis_mode="test_single")
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, "test_detection")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.config.alerting_enabled = True
    engine.configuration_manager.enable_module("basic_test", "test_single")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    # detections and the embedding check shared one evaluation (two before the fix)
    assert calls == [root_uuid]
    assert get_alert_by_uuid(root_uuid) is not None
    assert os.path.isdir(get_storage_dir(root_uuid))
