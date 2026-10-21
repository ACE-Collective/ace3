from datetime import datetime
import pytest
from uuid import uuid4

from saq.constants import F_IP
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.engine_configuration import EngineConfiguration
from saq.modules.test import BasicTestAnalysis
from tests.saq.helpers import create_root_analysis


@pytest.fixture
def configuration_manager() -> ConfigurationManager:
    configuration_manager = ConfigurationManager(EngineConfiguration())
    configuration_manager.enable_module("basic_test", "test_groups")
    configuration_manager.load_modules()
    return configuration_manager


@pytest.mark.unit
class TestDelayedAnalysisRequest:
    """Test cases for DelayedAnalysisRequest class."""
    
    def test_initialization_valid_params(self):
        """Test successful initialization with valid parameters."""
        uuid_str = str(uuid4())
        observable_uuid_str = str(uuid4())
        analysis_module = "test_module"
        next_analysis = datetime.now()
        storage_dir = "/test/storage"
        database_id = 123
        
        request = DelayedAnalysisRequest(
            uuid=uuid_str,
            observable_uuid=observable_uuid_str,
            analysis_module_str=analysis_module,
            next_analysis=next_analysis,
            storage_dir=storage_dir,
            database_id=database_id
        )
        
        assert request.uuid == uuid_str
        assert request.observable_uuid == observable_uuid_str
        assert request.analysis_module_str == analysis_module
        assert request.next_analysis == next_analysis
        assert request.storage_dir == storage_dir
        assert request.database_id == database_id
        
        # Check initial state
        assert request.root is None
        assert request.observable is None
        assert request.analysis is None
    
    def test_initialization_without_database_id(self):
        """Test initialization without database_id parameter."""
        uuid_str = str(uuid4())
        observable_uuid_str = str(uuid4())
        analysis_module = "test_module"
        next_analysis = datetime.now()
        storage_dir = "/test/storage"
        
        request = DelayedAnalysisRequest(
            uuid=uuid_str,
            observable_uuid=observable_uuid_str,
            analysis_module_str=analysis_module,
            next_analysis=next_analysis,
            storage_dir=storage_dir
        )
        
        assert request.database_id is None
    
    @pytest.mark.parametrize("invalid_uuid", [None, "", 123, []])
    def test_initialization_invalid_uuid(self, invalid_uuid):
        """Test that invalid uuid values raise AssertionError."""
        with pytest.raises(AssertionError):
            DelayedAnalysisRequest(
                uuid=invalid_uuid,
                observable_uuid="valid_uuid",
                analysis_module_str="test_module",
                next_analysis=datetime.now(),
                storage_dir="/test/storage"
            )
    
    @pytest.mark.parametrize("invalid_observable_uuid", [None, "", 123, []])
    def test_initialization_invalid_observable_uuid(self, invalid_observable_uuid):
        """Test that invalid observable_uuid values raise AssertionError."""
        with pytest.raises(AssertionError):
            DelayedAnalysisRequest(
                uuid="valid_uuid",
                observable_uuid=invalid_observable_uuid,
                analysis_module_str="test_module",
                next_analysis=datetime.now(),
                storage_dir="/test/storage"
            )
    
    @pytest.mark.parametrize("invalid_analysis_module", [None, "", 123, []])
    def test_initialization_invalid_analysis_module(self, invalid_analysis_module):
        """Test that invalid analysis_module values raise AssertionError."""
        with pytest.raises(AssertionError):
            DelayedAnalysisRequest(
                uuid="valid_uuid",
                observable_uuid="valid_observable_uuid",
                analysis_module_str=invalid_analysis_module,
                next_analysis=datetime.now(),
                storage_dir="/test/storage"
            )
    
    @pytest.mark.parametrize("invalid_storage_dir", [None, "", 123, []])
    def test_initialization_invalid_storage_dir(self, invalid_storage_dir):
        """Test that invalid storage_dir values raise AssertionError."""
        with pytest.raises(AssertionError):
            DelayedAnalysisRequest(
                uuid="valid_uuid",
                observable_uuid="valid_observable_uuid",
                analysis_module_str="test_module",
                next_analysis=datetime.now(),
                storage_dir=invalid_storage_dir
            )
    
    def test_str_representation(self):
        """Test string representation of DelayedAnalysisRequest."""
        uuid_str = str(uuid4())
        analysis_module = "test_module"
        next_analysis = datetime(2023, 1, 1, 12, 0, 0)
        
        request = DelayedAnalysisRequest(
            uuid=uuid_str,
            observable_uuid=str(uuid4()),
            analysis_module_str=analysis_module,
            next_analysis=next_analysis,
            storage_dir="/test/storage"
        )
        
        expected_str = f"DelayedAnalysisRequest for {uuid_str} by {analysis_module} @ {next_analysis}"
        assert str(request) == expected_str
    
    def test_load_success(self, tmpdir, configuration_manager):
        """Test successful load operation."""
        # Create a test root analysis
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        
        # Add an observable
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        
        # the analysis the module delayed
        analysis = BasicTestAnalysis()
        observable.add_analysis(analysis)
        
        # Save the root
        root.save()

        # Create delayed analysis request
        request = DelayedAnalysisRequest(
            uuid=root.uuid,
            observable_uuid=observable.uuid,
            analysis_module_str="basic_test",
            next_analysis=datetime.now(),
            storage_dir=str(tmpdir)
        )
        
        # Test the load method
        result = request.load(configuration_manager)
        
        assert result is True
        assert request.root is not None
        assert request.root.uuid == root.uuid
        assert request.observable is not None
        assert request.observable.uuid == observable.uuid
        assert request.analysis_module is configuration_manager.get_analysis_module_by_name("basic_test")
        assert isinstance(request.analysis, BasicTestAnalysis)
        assert request.analysis.uuid == analysis.uuid
    
    def test_load_missing_observable(self, tmpdir, configuration_manager):
        """Test load when observable cannot be found."""
        # Create a test root analysis
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        root.save()
        
        # Create delayed analysis request with non-existent observable
        request = DelayedAnalysisRequest(
            uuid=root.uuid,
            observable_uuid="non-existent-uuid",
            analysis_module_str="basic_test",
            next_analysis=datetime.now(),
            storage_dir=str(tmpdir)
        )
        
        result = request.load(configuration_manager)
        
        assert result is False
        assert request.root is not None
        assert request.observable is None
    
    def test_load_missing_analysis_module(self, tmpdir, configuration_manager):
        """Test load when analysis module cannot be found in configuration."""
        # Create a test root analysis
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        
        # Add an observable
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        root.save()
        
        # Create delayed analysis request
        request = DelayedAnalysisRequest(
            uuid=root.uuid,
            observable_uuid=observable.uuid,
            analysis_module_str="missing_module",
            next_analysis=datetime.now(),
            storage_dir=str(tmpdir)
        )
        
        result = request.load(configuration_manager)
        
        assert result is False
        assert request.root is not None
        assert request.observable is not None
        assert request.analysis_module is None
    
    def test_load_missing_analysis(self, tmpdir, configuration_manager):
        """Test load when analysis cannot be found on observable."""
        # Create a test root analysis
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        
        # Add an observable without analysis
        observable = root.add_observable_by_spec(F_IP, "192.168.1.1")
        root.save()
        
        # Create delayed analysis request
        request = DelayedAnalysisRequest(
            uuid=root.uuid,
            observable_uuid=observable.uuid,
            analysis_module_str="basic_test",
            next_analysis=datetime.now(),
            storage_dir=str(tmpdir)
        )
        
        result = request.load(configuration_manager)
        
        assert result is False
        assert request.root is not None
        assert request.observable is not None
        assert request.analysis_module is configuration_manager.get_analysis_module_by_name("basic_test")
        assert request.analysis is None
    
    def test_load_all_failures(self, tmpdir, configuration_manager):
        """Test load when all components fail to load."""
        # Create a test root analysis
        root = create_root_analysis(storage_dir=str(tmpdir))
        root.initialize_storage()
        root.save()
        
        # Create delayed analysis request with non-existent observable
        request = DelayedAnalysisRequest(
            uuid=root.uuid,
            observable_uuid="non-existent-uuid",
            analysis_module_str="missing_module",
            next_analysis=datetime.now(),
            storage_dir=str(tmpdir)
        )
        
        result = request.load(configuration_manager)
        
        # Should still return False even with multiple failures
        assert result is False
        assert request.root is not None
        assert request.observable is None
        assert request.analysis_module is None
        assert request.analysis is None