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
# The predicate runs against real workload/locks/delayed_analysis rows; the
# race it guards against is reproduced by releasing another worker's lock right
# after the first evaluation.
#

import os
import uuid

import pytest
from unittest.mock import patch

from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, F_TEST
from saq.database.model import Workload
from saq.database.pool import get_db, get_db_connection
from saq.database.util.alert import ALERT, get_alert_by_uuid
from saq.database.util.locking import acquire_lock, release_lock
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.engine.execution_context import EngineExecutionContext
from saq.util.uuid import get_storage_dir, workload_storage_dir
from tests.saq.helpers import create_root_analysis, create_test_orchestrator

#
# a single post-analysis pass
#

def _make_context(tmp_path, analysis_mode="test_single") -> EngineExecutionContext:
    """A real execution context over a RootAnalysis saved under tmp_path."""
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, analysis_mode=analysis_mode, storage_dir=str(tmp_path / root_uuid))
    root.initialize_storage()
    root.save()
    return EngineExecutionContext(work_item=root)

def _make_alert_context(tmp_path, monkeypatch) -> EngineExecutionContext:
    """A context over an alert whose correlation mode is set to clean up, so that every consumer
    of the predicate is live in the pass."""
    monkeypatch.setattr(get_config().get_analysis_mode_config(ANALYSIS_MODE_CORRELATION), "cleanup", True)
    context = _make_context(tmp_path, analysis_mode=ANALYSIS_MODE_CORRELATION)
    ALERT(context.root)
    return context

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
def test_outstanding_work_queried_once_per_pass(tmp_path, monkeypatch):
    """all three post-analysis decisions must share a single evaluation of the predicate

    The root is an alert in correlation mode with cleanup turned on, so every consumer
    of the predicate is live in this pass. Before the fix this cost three connections
    and three evaluations."""
    orchestrator = create_test_orchestrator()
    context = _make_alert_context(tmp_path, monkeypatch)
    calls = _count_outstanding_work_checks(monkeypatch)

    with patch("saq.engine.analysis_orchestrator.get_db_connection", wraps=get_db_connection) as connection:
        orchestrator._handle_post_analysis_logic(context)

    assert calls == [context.root.uuid]
    assert connection.call_count == 1

    # and the single answer (no outstanding work) still drove both consumers
    assert not os.path.isdir(context.root.storage_dir)
    assert context.search_index_requested is True

@pytest.mark.integration
def test_inconsistent_answers_do_not_delete_an_unalerted_root(tmp_path, monkeypatch):
    """a root whose detections were skipped because of outstanding work must not then be cleaned up

    This is the harmful ordering: the first evaluation says there is outstanding
    work (another worker holds the lock, so _handle_detection_points never runs and
    the root never becomes an alert) and by the time cleanup could ask again the
    other worker is gone, which would delete the storage directory along with the
    detections nobody acted on."""
    orchestrator = create_test_orchestrator()
    context = _make_context(tmp_path, analysis_mode="test_cleanup")
    context.root.add_detection_point("something bad")

    other_lock_uuid = str(uuid.uuid4())
    assert acquire_lock(context.root.uuid, other_lock_uuid, lock_owner="another worker")

    original = AnalysisOrchestrator._check_for_outstanding_work

    def other_worker_finishes_after_the_check(self, cursor, execution_context):
        result = original(self, cursor, execution_context)
        release_lock(context.root.uuid, other_lock_uuid)
        return result

    monkeypatch.setattr(AnalysisOrchestrator, "_check_for_outstanding_work", other_worker_finishes_after_the_check)

    orchestrator._handle_post_analysis_logic(context)

    # the detections were not acted on ...
    assert context.root.analysis_mode == "test_cleanup"
    # ... so the tree that still carries them must survive
    assert os.path.isdir(context.root.storage_dir)
    assert context.search_index_requested is False

@pytest.mark.integration
def test_rescheduled_root_is_never_cleaned_up(tmp_path):
    """a mode change re-queues the root, which is itself outstanding work

    _handle_analysis_mode_changes runs between the old check #1 and checks #2/#3 and
    calls root.schedule(), so the later queries saw the new workload row. With a
    single up-front evaluation that row does not exist yet, so the reschedule has to
    promote the answer to True explicitly -- otherwise cleanup deletes a root that
    was just queued for another pass."""
    orchestrator = create_test_orchestrator()
    context = _make_context(tmp_path, analysis_mode="test_single")
    # the mode changed during analysis to one that cleans up after itself
    context.root.analysis_mode = "test_cleanup"
    assert context.root.original_analysis_mode == "test_single"

    orchestrator._handle_post_analysis_logic(context)

    workload = get_db().query(Workload).filter(Workload.uuid == context.root.uuid).one()
    assert workload.analysis_mode == "test_cleanup"
    assert os.path.isdir(context.root.storage_dir)
    assert context.search_index_requested is False

@pytest.mark.integration
def test_failed_reschedule_still_blocks_cleanup(tmp_path):
    """if root.schedule() fails the root is not queued anywhere -- deleting it would lose it"""
    orchestrator = create_test_orchestrator()
    context = _make_context(tmp_path, analysis_mode="test_single")
    context.root.analysis_mode = "test_cleanup"

    with patch.object(context.root, "schedule", side_effect=RuntimeError("workload insert failed")):
        orchestrator._handle_post_analysis_logic(context)

    assert os.path.isdir(context.root.storage_dir)

@pytest.mark.integration
def test_database_failure_is_fail_safe(tmp_path, monkeypatch):
    """when the predicate cannot be evaluated at all, none of the decisions it gates are taken"""
    orchestrator = create_test_orchestrator()
    context = _make_alert_context(tmp_path, monkeypatch)
    context.root.add_detection_point("something bad")

    with patch("saq.engine.analysis_orchestrator.get_db_connection", side_effect=RuntimeError("no database")):
        orchestrator._handle_post_analysis_logic(context)

    assert os.path.isdir(context.root.storage_dir)
    assert context.search_index_requested is False

#
# integration tests: the round-trip count against a real engine pass
#

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
