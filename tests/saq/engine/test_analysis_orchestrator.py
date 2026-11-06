import os
import shutil
import uuid
from datetime import datetime

import pytest
from unittest.mock import Mock, patch

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_engine_config
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    ANALYSIS_MODE_DISPOSITIONED,
    DISPOSITION_FALSE_POSITIVE,
    F_TEST,
    STATE_ANALYST_REQUESTED_ANALYSIS,
)
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.database.util.workload import request_analyst_analysis
from saq.database.util.alert import ALERT, get_alert_by_uuid
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.execution_context import EngineExecutionContext
from saq.environment import get_global_runtime_settings
from saq.modules.test import BasicTestAnalysis
from tests.saq.helpers import create_root_analysis, create_test_orchestrator


def _alert_root(delayed: bool = False) -> RootAnalysis:
    """A saved correlation mode root with its alerts row. With delayed, one of its analyses is
    still waiting on delayed analysis."""
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode=ANALYSIS_MODE_CORRELATION)
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, "initial_obs")
    if delayed:
        analysis = BasicTestAnalysis()
        analysis.delayed = True
        observable.add_analysis(analysis)
    root.save()
    ALERT(root)
    return root


def _set_disposition(root_uuid: str, disposition: str):
    get_db().query(Alert).filter(Alert.uuid == root_uuid).update({Alert.disposition: disposition})
    get_db().commit()


def _indexed_values(root_uuid: str) -> set[str]:
    """The observable values the alert's index holds."""
    alert = get_alert_by_uuid(root_uuid)
    alert.load()
    # Observable.value comes back as bytes from the DB; normalize to str
    return {v.decode() if isinstance(v, bytes) else v for v in (o.value for o in alert.get_observables())}


@pytest.mark.unit
class TestAnalysisOrchestratorHandleDetectionPoints:
    """Test cases for AnalysisOrchestrator._handle_detection_points method."""

    @pytest.fixture
    def orchestrator(self):
        return create_test_orchestrator()

    @pytest.fixture
    def execution_context(self):
        """Create an execution context with a test root analysis."""
        return EngineExecutionContext(work_item=create_root_analysis(analysis_mode="test_groups"))

    @staticmethod
    def _add_detection(root: RootAnalysis):
        root.add_observable_by_spec(F_TEST, "test").add_detection_point("test detection")

    def test_handle_detection_points_non_detectable_mode(self, orchestrator, execution_context, monkeypatch):
        """Test that function returns early for non-detectable analysis modes."""
        assert ANALYSIS_MODE_DISPOSITIONED in orchestrator.config.non_detectable_modes
        execution_context.root.analysis_mode = ANALYSIS_MODE_DISPOSITIONED
        self._add_detection(execution_context.root)
        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", False)

        orchestrator._handle_detection_points(execution_context)

        assert execution_context.root.analysis_mode == ANALYSIS_MODE_DISPOSITIONED

    @pytest.mark.parametrize("forced_alerts,expected_mode", [
        (False, "test_groups"),
        (True, ANALYSIS_MODE_CORRELATION)
    ])
    def test_handle_detection_points_whitelisted_analysis(self, orchestrator, execution_context, monkeypatch, forced_alerts, expected_mode):
        """Test whitelisted analysis behavior with and without forced alerts."""
        # a detection the whitelist has to override, or the mode stays put without it
        self._add_detection(execution_context.root)
        execution_context.root.add_tag("whitelisted")

        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", forced_alerts)

        orchestrator._handle_detection_points(execution_context)

        assert execution_context.root.analysis_mode == expected_mode

    def test_handle_detection_points_with_detections(self, orchestrator, execution_context, monkeypatch):
        """Test analysis with detections changes to correlation mode."""
        assert execution_context.root.analysis_mode == "test_groups"
        self._add_detection(execution_context.root)
        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", False)

        orchestrator._handle_detection_points(execution_context)

        assert execution_context.root.analysis_mode == ANALYSIS_MODE_CORRELATION

    @pytest.mark.parametrize("forced_alerts,expected_mode", [
        (False, "test_groups"),
        (True, ANALYSIS_MODE_CORRELATION)
    ])
    def test_handle_detection_points_no_detections_forced_alerts_behavior(self, orchestrator, execution_context, monkeypatch, forced_alerts, expected_mode):
        """Test behavior with no detections and varying forced alerts settings."""
        assert not execution_context.root.has_detections()
        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", forced_alerts)

        orchestrator._handle_detection_points(execution_context)

        assert execution_context.root.analysis_mode == expected_mode

    @pytest.mark.parametrize("has_detections,forced_alerts", [
        (True, False),
        (False, True)
    ])
    def test_handle_detection_points_alerting_disabled_no_change(self, orchestrator, execution_context, monkeypatch, has_detections, forced_alerts):
        """Test that no mode changes occur when alerting is disabled."""
        orchestrator.config.alerting_enabled = False
        if has_detections:
            self._add_detection(execution_context.root)
        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", forced_alerts)

        orchestrator._handle_detection_points(execution_context)

        assert execution_context.root.analysis_mode == "test_groups"


@pytest.mark.integration
class TestAnalysisOrchestratorFinallyBlock:
    """Test cases to validate that _handle_post_analysis_logic is called in the finally block."""

    @pytest.fixture
    def orchestrator(self):
        return create_test_orchestrator()

    @pytest.fixture
    def execution_context(self, tmpdir):
        """create an execution context with a test root analysis"""
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode="test_groups", storage_dir=str(tmpdir))
        root.save()
        return EngineExecutionContext(work_item=root)

    def test_post_analysis_logic_called_on_success(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is called when analysis succeeds"""
        with patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is True
            mock_post_analysis.assert_called_once_with(execution_context)

        assert not execution_context.analysis_aborted

    def test_post_analysis_logic_called_on_execute_analysis_exception(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is called even when _execute_analysis raises an exception"""
        with patch.object(orchestrator, '_execute_analysis', side_effect=RuntimeError("analysis failed")), \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            mock_post_analysis.assert_called_once_with(execution_context)

    def test_post_analysis_logic_skipped_when_process_work_item_fails(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is skipped when _process_work_item returns False"""
        # a delayed analysis request for an observable the saved root does not have cannot be loaded
        root = execution_context.root
        request = DelayedAnalysisRequest(root.uuid, str(uuid.uuid4()), "basic_test", datetime.now(), root.storage_dir)
        execution_context = EngineExecutionContext(work_item=request)

        with patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            # the work item was never loaded for analysis - there is nothing to clean up
            mock_post_analysis.assert_not_called()

    def test_post_analysis_logic_skipped_when_root_is_none(self, orchestrator):
        """test that _handle_post_analysis_logic is skipped when root is None after processing work item"""
        # a real context always has a root once its work item is processed; this guards the defensive branch
        execution_context = Mock(spec=EngineExecutionContext)
        execution_context.work_item = Mock()
        execution_context.root = None

        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            # the root was never loaded - there is nothing to clean up
            mock_post_analysis.assert_not_called()

    def test_post_analysis_logic_skipped_when_storage_dir_missing(self, orchestrator, execution_context, caplog):
        """regression: a re-picked-up work item whose storage dir is gone must not run cleanup

        this reproduces the production scenario where an orphaned workload row is
        re-dispatched after its analysis already completed and its storage directory
        was cleaned up - post-analysis logic must not attempt to rmtree a missing dir"""
        # simulate the production scenario: the analysis already completed and its
        # work storage directory was cleaned up before this orphaned workload row
        # was re-dispatched
        shutil.rmtree(execution_context.root.storage_dir)
        assert not os.path.isdir(execution_context.root.storage_dir)

        with patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis, \
             caplog.at_level("WARNING"):
            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            mock_post_analysis.assert_not_called()

        # an expected leftover, not an error: without the check the load fails, and that is
        # logged at ERROR with a traceback (an error report)
        assert any("missing - already processed?" in r.getMessage() for r in caplog.records)
        assert not [r for r in caplog.records if r.levelname == "ERROR"]

    def test_post_analysis_logic_called_when_check_disposition_returns_true(self, orchestrator, monkeypatch):
        """test that _handle_post_analysis_logic is called when _check_disposition returns True (skipping analysis)"""
        monkeypatch.setattr(get_engine_config(), "stop_analysis_on_any_alert_disposition", True)
        root = _alert_root()
        _set_disposition(root.uuid, DISPOSITION_FALSE_POSITIVE)
        execution_context = EngineExecutionContext(work_item=root)

        with patch.object(orchestrator, '_execute_analysis') as mock_execute, \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is True
            assert execution_context.analysis_skipped is True
            mock_execute.assert_not_called()
            mock_post_analysis.assert_called_once_with(execution_context)

    def test_post_analysis_logic_exception_is_caught(self, orchestrator, execution_context):
        """test that exceptions in _handle_post_analysis_logic are caught and logged"""
        with patch.object(orchestrator, '_handle_post_analysis_logic', side_effect=RuntimeError("post-analysis failed")), \
             patch('saq.engine.analysis_orchestrator.logging') as mock_logging:

            result = orchestrator.orchestrate_analysis(execution_context)

            # analysis should still return True because the exception was in the finally block
            assert result is True
            # verify error was logged
            mock_logging.exception.assert_called()
            error_call_args = str(mock_logging.exception.call_args)
            assert "post-analysis logic" in error_call_args

    def test_multiple_exceptions_in_try_and_finally(self, orchestrator, execution_context):
        """test behavior when exceptions occur in both try and finally blocks"""
        with patch.object(orchestrator, '_execute_analysis', side_effect=RuntimeError("execute failed")), \
             patch.object(orchestrator, '_handle_post_analysis_logic', side_effect=RuntimeError("post-analysis failed")), \
             patch('saq.engine.analysis_orchestrator.logging') as mock_logging:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            # verify both errors were logged
            assert mock_logging.exception.call_count >= 2


@pytest.mark.integration
class TestSyncAlertToDatabaseBuildIndex:
    """When _sync_alert_to_database syncs an alert at all. Whether it rebuilds the observable
    index is checked against the index itself, in TestSyncAlertToDatabaseRebuildIndexIntegration
    (delayed, then aborted) and test_live_tree_is_attached_when_the_storage_dir_matches (neither)."""

    @pytest.fixture
    def orchestrator(self):
        return create_test_orchestrator()

    @pytest.mark.parametrize("analysis_aborted,expected_sync", [
        # nothing ran because the alert was already dispositioned -- nothing to write
        (False, False),
        # belt and braces: an aborted pass syncs even if something also marked it skipped
        (True, True),
    ])
    def test_skipped_analysis_does_not_sync(self, orchestrator, analysis_aborted, expected_sync):
        context = EngineExecutionContext(work_item=_alert_root())
        context.analysis_aborted = analysis_aborted
        context.analysis_skipped = True

        with patch.object(Alert, "sync", autospec=True, side_effect=Alert.sync) as sync:
            orchestrator._sync_alert_to_database(context)

        assert sync.called is expected_sync

    def test_a_missing_alerts_row_is_an_error(self, orchestrator, caplog):
        """A correlation-mode root with no alerts row is an alert no analyst will see; it used
        to be skipped without a word (FR-6)."""
        root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode=ANALYSIS_MODE_CORRELATION)
        root.initialize_storage()
        root.save()
        context = EngineExecutionContext(work_item=root)

        with caplog.at_level("ERROR"):
            orchestrator._sync_alert_to_database(context)

        (record,) = [r for r in caplog.records if "has no alerts row" in r.getMessage()]
        assert record.levelname == "ERROR"
        assert record.alert_uuid == context.root.uuid


@pytest.mark.integration
class TestSyncAlertToDatabaseAvoidsRereadingTheTree:
    """_sync_alert_to_database used to make Alert.sync() read the tree back off disk.

    alert.load() parses the whole data.json into a *second* RootAnalysis, which sync() then
    re-serializes straight back out -- immediately after _convert_to_alert had already saved
    the live tree. On a large alert that is two full round trips of a multi-megabyte document
    for nothing. The engine is holding the tree it just analyzed, so it hands that over
    instead (see docs/ENGINE.md §19.7)."""

    @pytest.fixture
    def orchestrator(self):
        return create_test_orchestrator()

    def test_live_tree_is_attached_when_the_storage_dir_matches(self, orchestrator):
        root = _alert_root()
        root.add_observable_by_spec(F_TEST, "discovered_during_analysis")
        context = EngineExecutionContext(work_item=root)

        with patch.object(Alert, "attach_root_analysis", autospec=True, side_effect=Alert.attach_root_analysis) as attach, \
             patch.object(Alert, "load", autospec=True, side_effect=Alert.load) as load:
            orchestrator._sync_alert_to_database(context)

        attach.assert_called_once()
        assert attach.call_args.args[1] is root
        load.assert_not_called()
        # the live tree (never saved since the observable was added) is what was synced
        assert "discovered_during_analysis" in _indexed_values(root.uuid)

    def test_falls_back_to_loading_when_the_storage_dir_does_not_match(self, orchestrator, tmp_path):
        """The alert and the root must actually be the same thing before we substitute one
        for the other -- otherwise sync() would write the wrong tree to the alert."""
        root = _alert_root()
        other_dir = str(tmp_path / root.uuid)
        shutil.copytree(root.storage_dir, other_dir)
        other = RootAnalysis(storage_dir=other_dir)
        other.load()
        other.add_observable_by_spec(F_TEST, "only_in_the_other_tree")
        context = EngineExecutionContext(work_item=other)

        with patch.object(Alert, "attach_root_analysis", autospec=True, side_effect=Alert.attach_root_analysis) as attach, \
             patch.object(Alert, "load", autospec=True, side_effect=Alert.load) as load:
            orchestrator._sync_alert_to_database(context)

        load.assert_called_once()
        attach.assert_not_called()
        values = _indexed_values(root.uuid)
        assert "initial_obs" in values
        assert "only_in_the_other_tree" not in values


@pytest.mark.integration
class TestSyncAlertToDatabaseRebuildIndexIntegration:
    """_sync_alert_to_database must rebuild the observable index whenever analysis was aborted,
    even while root.delayed is still True: an observable discovered during a delayed, then
    aborted, analysis must become searchable (present in observable_mapping).

    Regression: an alert that timed out with outstanding delayed analysis had its delayed
    requests cleared and abandoned, but root.delayed (computed from the in-memory tree) stayed
    True, so alert.sync(build_index=False) skipped the rebuild and the alert's observables never
    reached observable_mapping. Since the delayed analysis was abandoned, no later pass ever
    rebuilt the index."""

    @pytest.fixture
    def orchestrator(self):
        return create_test_orchestrator()

    def test_aborted_delayed_alert_rebuilds_observable_index(self, orchestrator):
        # 1. an existing alert in CORRELATION mode with outstanding delayed analysis:
        # only 'initial_obs' is indexed at creation
        root = _alert_root(delayed=True)
        assert root.delayed

        # 2. an observable discovered later, during analysis, and persisted to the tree
        root.add_observable_by_spec(F_TEST, "discovered_during_analysis")
        root.save()

        context = EngineExecutionContext(work_item=root)

        # not aborted + delayed -> index deliberately NOT rebuilt yet
        context.analysis_aborted = False
        orchestrator._sync_alert_to_database(context)
        values = _indexed_values(root.uuid)
        assert "initial_obs" in values
        assert "discovered_during_analysis" not in values

        # aborted (timeout / exception) while delayed -> rebuild is forced despite root.delayed
        context.analysis_aborted = True
        orchestrator._sync_alert_to_database(context)
        assert "discovered_during_analysis" in _indexed_values(root.uuid)


class TestCheckDispositionAnalystOverride:
    """Analyst-initiated observable actions (sandbox upload, crawl, render, ...) re-queue an alert
    in correlation mode. If that alert was already dispositioned, _check_disposition would normally
    short-circuit the analysis and the action would silently do nothing — so the action sets the
    STATE_ANALYST_REQUESTED_ANALYSIS flag, which grants exactly one pass."""

    @pytest.fixture
    def orchestrator(self):
        return create_test_orchestrator()

    @pytest.fixture
    def stop_on_false_positive(self, monkeypatch):
        monkeypatch.setattr(get_engine_config(), "stop_analysis_on_any_alert_disposition", True)
        monkeypatch.setattr(get_engine_config(), "stop_analysis_on_dispositions", [DISPOSITION_FALSE_POSITIVE])

    def _context(self, analysis_mode=ANALYSIS_MODE_CORRELATION):
        return EngineExecutionContext(work_item=create_root_analysis(analysis_mode=analysis_mode))

    @pytest.mark.integration
    def test_flag_is_consumed_only_once(self, orchestrator, stop_on_false_positive):
        """after the granted pass, the same alert is short-circuited again"""
        root = _alert_root()
        _set_disposition(root.uuid, DISPOSITION_FALSE_POSITIVE)
        context = EngineExecutionContext(work_item=root)
        request_analyst_analysis(context.root)

        assert orchestrator._check_disposition(context) is False   # granted
        assert orchestrator._check_disposition(context) is True    # back to normal
        assert context.analysis_skipped is True

    @pytest.mark.unit
    def test_flag_ignored_outside_correlation_mode(self, orchestrator):
        """the mode check comes first, so a non-correlation mode is unaffected and keeps the flag"""
        context = self._context(analysis_mode="dispositioned")
        request_analyst_analysis(context.root)
        context.root.analysis_mode = "dispositioned"

        assert orchestrator._check_disposition(context) is False
        assert context.root.state[STATE_ANALYST_REQUESTED_ANALYSIS] is True

    @pytest.mark.unit
    def test_request_analyst_analysis_sets_mode_and_flag(self):
        """the helper must set the mode on the RootAnalysis, which is what add_workload reads"""
        root = create_root_analysis(analysis_mode="dispositioned")
        request_analyst_analysis(root)

        assert root.analysis_mode == ANALYSIS_MODE_CORRELATION
        assert root.state[STATE_ANALYST_REQUESTED_ANALYSIS] is True
