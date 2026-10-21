from datetime import datetime, timedelta
import pytest
from unittest.mock import Mock

from saq.constants import F_IP
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineType
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.environment import get_global_runtime_settings
from saq.modules.base_module import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.util.time import local_time
from tests.saq.helpers import create_root_analysis


class MockAnalysisModule(AnalysisModule):
    """Mock analysis module for testing."""
    def __init__(self, *args, **kwargs):
        super().__init__(AnalysisModuleConfig(
            name="test_module",
            python_module="placeholdder",
            python_class="placeholder",
            enabled=True
        ), *args, **kwargs)

@pytest.mark.unit
class TestWorkerDelayedAnalysisFunctions:
    """Test cases for Worker delayed analysis functions."""
    
    @pytest.fixture
    def worker(self):
        """Create a worker instance for testing."""
        return Worker(
            name="test_worker",
            configuration_manager=ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=True)),
            node_manager=Mock(spec=NodeManagerInterface),
        )

    def test_get_delayed_analysis_timeout_hours_only(self, worker):
        """Test get_delayed_analysis_timeout with hours parameter only."""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        timeout_hours = 2
        
        result = worker.get_delayed_analysis_timeout(
            start_time=start_time,
            timeout_hours=timeout_hours
        )
        
        expected = start_time + timedelta(hours=2)
        assert result == expected
    
    def test_get_delayed_analysis_timeout_minutes_only(self, worker):
        """Test get_delayed_analysis_timeout with minutes parameter only."""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        timeout_minutes = 30
        
        result = worker.get_delayed_analysis_timeout(
            start_time=start_time,
            timeout_minutes=timeout_minutes
        )
        
        expected = start_time + timedelta(minutes=30)
        assert result == expected
    
    def test_get_delayed_analysis_timeout_seconds_only(self, worker):
        """Test get_delayed_analysis_timeout with seconds parameter only."""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        timeout_seconds = 45
        
        result = worker.get_delayed_analysis_timeout(
            start_time=start_time,
            timeout_seconds=timeout_seconds
        )
        
        expected = start_time + timedelta(seconds=45)
        assert result == expected
    
    def test_get_delayed_analysis_timeout_all_parameters(self, worker):
        """Test get_delayed_analysis_timeout with all timeout parameters."""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        timeout_hours = 1
        timeout_minutes = 30
        timeout_seconds = 45
        
        result = worker.get_delayed_analysis_timeout(
            start_time=start_time,
            timeout_hours=timeout_hours,
            timeout_minutes=timeout_minutes,
            timeout_seconds=timeout_seconds
        )
        
        expected = start_time + timedelta(hours=1, minutes=30, seconds=45)
        assert result == expected
    
    def test_get_delayed_analysis_timeout_no_timeout_parameters(self, worker):
        """Test get_delayed_analysis_timeout with no timeout parameters (all None)."""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        
        result = worker.get_delayed_analysis_timeout(start_time=start_time)
        
        # When all timeout parameters are None, they default to 0
        expected = start_time + timedelta(hours=0, minutes=0, seconds=0)
        assert result == expected
        assert result == start_time
    
    def test_get_delayed_analysis_timeout_zero_values(self, worker):
        """Test get_delayed_analysis_timeout with explicit zero values."""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        
        result = worker.get_delayed_analysis_timeout(
            start_time=start_time,
            timeout_hours=0,
            timeout_minutes=0,
            timeout_seconds=0
        )
        
        expected = start_time
        assert result == expected
    
    def test_get_delayed_analysis_timeout_mixed_none_and_values(self, worker):
        """Test get_delayed_analysis_timeout with mix of None and actual values."""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        
        result = worker.get_delayed_analysis_timeout(
            start_time=start_time,
            timeout_hours=None,
            timeout_minutes=15,
            timeout_seconds=None
        )
        
        expected = start_time + timedelta(hours=0, minutes=15, seconds=0)
        assert result == expected

    def test_is_delayed_analysis_timed_out_no_timeout_set(self, worker, tmpdir):
        """Test is_delayed_analysis_timed_out when no timeout is set."""
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        analysis_module = MockAnalysisModule()
        
        result = worker.is_delayed_analysis_timed_out(
            root=root,
            observable=observable,
            analysis_module=analysis_module
        )
        
        assert result is False
    
    def test_is_delayed_analysis_timed_out_not_expired(self, worker, tmpdir):
        """Test is_delayed_analysis_timed_out when timeout has not expired."""
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        analysis_module = MockAnalysisModule()
        
        # Set a timeout in the future (2 hours from now)
        result = worker.is_delayed_analysis_timed_out(
            root=root,
            observable=observable,
            analysis_module=analysis_module,
            timeout_hours=2
        )
        
        assert result is False
    
    def test_is_delayed_analysis_timed_out_expired_hours(self, worker, tmpdir, monkeypatch):
        """Test is_delayed_analysis_timed_out when timeout has expired (hours)."""
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        analysis_module = MockAnalysisModule()
        
        # Mock the start time to be in the past
        past_time = datetime.now().replace(tzinfo=None) - timedelta(hours=3)
        past_time_utc = past_time.replace(tzinfo=local_time().tzinfo)
        
        def mock_initialize_delayed_analysis_start_time(obs, module):
            return past_time_utc
        
        monkeypatch.setattr(root, "initialize_delayed_analysis_start_time", mock_initialize_delayed_analysis_start_time)
        
        result = worker.is_delayed_analysis_timed_out(
            root=root,
            observable=observable,
            analysis_module=analysis_module,
            timeout_hours=2  # 2 hours timeout, but started 3 hours ago
        )
        
        assert result is True
    
    def test_is_delayed_analysis_timed_out_expired_minutes(self, worker, tmpdir, monkeypatch):
        """Test is_delayed_analysis_timed_out when timeout has expired (minutes)."""
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        analysis_module = MockAnalysisModule()
        
        # Mock the start time to be in the past
        past_time = datetime.now().replace(tzinfo=None) - timedelta(minutes=45)
        past_time_utc = past_time.replace(tzinfo=local_time().tzinfo)
        
        def mock_initialize_delayed_analysis_start_time(obs, module):
            return past_time_utc
        
        monkeypatch.setattr(root, "initialize_delayed_analysis_start_time", mock_initialize_delayed_analysis_start_time)
        
        result = worker.is_delayed_analysis_timed_out(
            root=root,
            observable=observable,
            analysis_module=analysis_module,
            timeout_minutes=30  # 30 minutes timeout, but started 45 minutes ago
        )
        
        assert result is True
    
    def test_is_delayed_analysis_timed_out_expired_seconds(self, worker, tmpdir, monkeypatch):
        """Test is_delayed_analysis_timed_out when timeout has expired (seconds)."""
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        analysis_module = MockAnalysisModule()
        
        # Mock the start time to be in the past
        past_time = datetime.now().replace(tzinfo=None) - timedelta(seconds=120)
        past_time_utc = past_time.replace(tzinfo=local_time().tzinfo)
        
        def mock_initialize_delayed_analysis_start_time(obs, module):
            return past_time_utc
        
        monkeypatch.setattr(root, "initialize_delayed_analysis_start_time", mock_initialize_delayed_analysis_start_time)
        
        result = worker.is_delayed_analysis_timed_out(
            root=root,
            observable=observable,
            analysis_module=analysis_module,
            timeout_seconds=60  # 60 seconds timeout, but started 120 seconds ago
        )
        
        assert result is True
    
    def test_is_delayed_analysis_timed_out_combined_timeout_expired(self, worker, tmpdir, monkeypatch):
        """Test is_delayed_analysis_timed_out with combined timeout parameters that have expired."""
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        analysis_module = MockAnalysisModule()
        
        # Mock the start time to be in the past (2 hours ago)
        past_time = datetime.now().replace(tzinfo=None) - timedelta(hours=2)
        past_time_utc = past_time.replace(tzinfo=local_time().tzinfo)
        
        def mock_initialize_delayed_analysis_start_time(obs, module):
            return past_time_utc
        
        monkeypatch.setattr(root, "initialize_delayed_analysis_start_time", mock_initialize_delayed_analysis_start_time)
        
        result = worker.is_delayed_analysis_timed_out(
            root=root,
            observable=observable,
            analysis_module=analysis_module,
            timeout_hours=1,
            timeout_minutes=30,  # Total timeout: 1.5 hours, but started 2 hours ago
            timeout_seconds=0
        )
        
        assert result is True
    
    def test_is_delayed_analysis_timed_out_combined_timeout_not_expired(self, worker, tmpdir, monkeypatch):
        """Test is_delayed_analysis_timed_out with combined timeout parameters that have not expired."""
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        analysis_module = MockAnalysisModule()
        
        # Mock the start time to be in the recent past (30 minutes ago)
        past_time = datetime.now().replace(tzinfo=None) - timedelta(minutes=30)
        past_time_utc = past_time.replace(tzinfo=local_time().tzinfo)
        
        def mock_initialize_delayed_analysis_start_time(obs, module):
            return past_time_utc
        
        monkeypatch.setattr(root, "initialize_delayed_analysis_start_time", mock_initialize_delayed_analysis_start_time)
        
        result = worker.is_delayed_analysis_timed_out(
            root=root,
            observable=observable,
            analysis_module=analysis_module,
            timeout_hours=1,
            timeout_minutes=30,  # Total timeout: 1.5 hours, started only 30 minutes ago
            timeout_seconds=0
        )
        
        assert result is False
    
    def test_is_delayed_analysis_timed_out_exactly_at_timeout(self, worker, tmpdir, monkeypatch):
        """Test is_delayed_analysis_timed_out when current time is exactly at timeout."""
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        analysis_module = MockAnalysisModule()
        
        # Mock the start time to be exactly 1 hour ago
        past_time = datetime.now().replace(tzinfo=None) - timedelta(hours=1)
        past_time_utc = past_time.replace(tzinfo=local_time().tzinfo)
        
        def mock_initialize_delayed_analysis_start_time(obs, module):
            return past_time_utc
        
        monkeypatch.setattr(root, "initialize_delayed_analysis_start_time", mock_initialize_delayed_analysis_start_time)
        
        result = worker.is_delayed_analysis_timed_out(
            root=root,
            observable=observable,
            analysis_module=analysis_module,
            timeout_hours=1  # Exactly 1 hour timeout
        )
        
        # Should be True since local_time() >= timeout (>= condition in the code)
        assert result is True


@pytest.mark.unit
@pytest.mark.parametrize("engine_type", [EngineType.LOCAL, EngineType.DISTRIBUTED])
def test_worker_lock_owner_is_node_prefixed(engine_type):
    """The worker lock_owner must start with this node's name so that
    DistributedNodeManager.initialize_node() can clear leftover locks on restart
    (it deletes locks WHERE lock_owner LIKE '<node_name>-%'). If the prefix is
    missing, locks held at restart are orphaned until they expire."""
    worker = Worker(
        name="email-0",
        configuration_manager=ConfigurationManager(EngineConfiguration(engine_type=engine_type, single_threaded_mode=True)),
        node_manager=Mock(spec=NodeManagerInterface),
    )

    saq_node = get_global_runtime_settings().saq_node
    assert worker.lock_manager.lock_owner == f"{saq_node}-worker-email-0"
    assert worker.lock_manager.lock_owner.startswith(f"{saq_node}-")