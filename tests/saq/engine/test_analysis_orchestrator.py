import pytest
from unittest.mock import Mock

from saq.constants import ANALYSIS_MODE_CORRELATION, G_FORCED_ALERTS
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from tests.saq.helpers import create_root_analysis


@pytest.mark.unit
class TestAnalysisOrchestratorHandleDetectionPoints:
    """Test cases for AnalysisOrchestrator._handle_detection_points method."""

    @pytest.fixture
    def mock_config_manager(self):
        """Create a mock configuration manager."""
        config_manager = Mock(spec=ConfigurationManager)
        config_manager.config = Mock()
        config_manager.config.non_detectable_modes = ["analysis"]
        config_manager.config.alerting_enabled = True
        return config_manager

    @pytest.fixture
    def mock_analysis_executor(self):
        """Create a mock analysis executor."""
        return Mock(spec=AnalysisExecutor)

    @pytest.fixture
    def mock_workload_manager(self):
        """Create a mock workload manager."""
        return Mock()

    @pytest.fixture
    def mock_lock_manager(self):
        """Create a mock lock manager."""
        return Mock()

    @pytest.fixture
    def orchestrator(self, mock_config_manager, mock_analysis_executor, mock_workload_manager, mock_lock_manager):
        """Create an AnalysisOrchestrator instance for testing."""
        return AnalysisOrchestrator(
            configuration_manager=mock_config_manager,
            analysis_executor=mock_analysis_executor,
            workload_manager=mock_workload_manager,
            lock_manager=mock_lock_manager
        )

    @pytest.fixture
    def execution_context(self):
        """Create an execution context with a test root analysis."""
        root = create_root_analysis(analysis_mode="test_mode")
        context = Mock(spec=EngineExecutionContext)
        context.root = root
        return context

    def test_handle_detection_points_non_detectable_mode(self, orchestrator, execution_context):
        """Test that function returns early for non-detectable analysis modes."""
        execution_context.root.analysis_mode = "analysis"
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == "analysis"

    @pytest.mark.parametrize("forced_alerts,expected_mode", [
        (False, "test_mode"),
        (True, ANALYSIS_MODE_CORRELATION)
    ])
    def test_handle_detection_points_whitelisted_analysis(self, orchestrator, execution_context, monkeypatch, forced_alerts, expected_mode):
        """Test whitelisted analysis behavior with and without forced alerts."""
        execution_context.root.analysis_mode = "test_mode"
        execution_context.root.add_tag("whitelisted")
        
        monkeypatch.setattr("saq.engine.analysis_orchestrator.g_boolean", lambda x: forced_alerts and x == G_FORCED_ALERTS)
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == expected_mode

    @pytest.mark.parametrize("initial_mode,expected_mode", [
        ("test_mode", ANALYSIS_MODE_CORRELATION),
        (ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_CORRELATION)
    ])
    def test_handle_detection_points_with_detections(self, orchestrator, execution_context, monkeypatch, initial_mode, expected_mode):
        """Test analysis with detections changes to or stays in correlation mode."""
        execution_context.root.analysis_mode = initial_mode
        
        # Mock has_detections to return True and all_detection_points property
        monkeypatch.setattr(execution_context.root, 'has_detections', Mock(return_value=True))
        mock_detection_points = ["detection1", "detection2"]
        monkeypatch.setattr(type(execution_context.root), 'all_detection_points', property(lambda self: mock_detection_points))
        monkeypatch.setattr("saq.engine.analysis_orchestrator.g_boolean", lambda x: False)
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == expected_mode

    @pytest.mark.parametrize("forced_alerts,expected_mode", [
        (False, "test_mode"),
        (True, ANALYSIS_MODE_CORRELATION)
    ])
    def test_handle_detection_points_no_detections_forced_alerts_behavior(self, orchestrator, execution_context, monkeypatch, forced_alerts, expected_mode):
        """Test behavior with no detections and varying forced alerts settings."""
        execution_context.root.analysis_mode = "test_mode"
        
        # Mock has_detections to return False
        monkeypatch.setattr(execution_context.root, 'has_detections', Mock(return_value=False))
        monkeypatch.setattr("saq.engine.analysis_orchestrator.g_boolean", lambda x: forced_alerts and x == G_FORCED_ALERTS)
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == expected_mode

    @pytest.mark.parametrize("has_detections,forced_alerts", [
        (True, False),
        (False, True)
    ])
    def test_handle_detection_points_alerting_disabled_no_change(self, orchestrator, execution_context, monkeypatch, has_detections, forced_alerts):
        """Test that no mode changes occur when alerting is disabled."""
        orchestrator.config.alerting_enabled = False
        execution_context.root.analysis_mode = "test_mode"
        
        # Mock has_detections and forced alerts behavior
        monkeypatch.setattr(execution_context.root, 'has_detections', Mock(return_value=has_detections))
        if has_detections:
            mock_detection_points = ["detection1"]
            monkeypatch.setattr(type(execution_context.root), 'all_detection_points', property(lambda self: mock_detection_points))
        monkeypatch.setattr("saq.engine.analysis_orchestrator.g_boolean", lambda x: forced_alerts and x == G_FORCED_ALERTS)
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == "test_mode"

