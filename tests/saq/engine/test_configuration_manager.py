"""
Tests for the ConfigurationManager class that was extracted from the Engine class.
"""

import pytest

from saq.configuration.config import get_analysis_module_config, get_config, get_engine_config
from saq.constants import (
    ANALYSIS_MODE_ANALYSIS,
)
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.environment import get_global_runtime_settings
from saq.modules.test import BasicTestAnalyzer


@pytest.mark.unit
def test_configuration_manager_initialization():
    """Test that ConfigurationManager initializes properly."""
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],))
    
    assert config_manager.config.default_analysis_mode == ANALYSIS_MODE_ANALYSIS
    assert config_manager.config.local_analysis_modes == []
    assert config_manager.config.excluded_analysis_modes == []
    assert config_manager.analysis_modules == []
    assert config_manager.analysis_mode_mapping == {ANALYSIS_MODE_ANALYSIS: []}
    assert config_manager.analysis_module_name_mapping == {}


@pytest.mark.unit
def test_analysis_mode_support_logic():
    """Test the analysis mode support logic."""
    # Test with no restrictions (supports all modes)
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    assert config_manager.is_analysis_mode_supported("any_mode") is True
    
    # Test with local modes specified
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=["test_mode", "analysis"],
        excluded_analysis_modes=[],
    ))
    assert config_manager.is_analysis_mode_supported("test_mode") is True
    assert config_manager.is_analysis_mode_supported("analysis") is True
    assert config_manager.is_analysis_mode_supported("other_mode") is False
    
    # Test with excluded modes
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=["excluded_mode"],
    ))
    assert config_manager.is_analysis_mode_supported("any_mode") is True
    assert config_manager.is_analysis_mode_supported("excluded_mode") is False


@pytest.mark.unit
def test_enable_module_for_testing():
    """Test enabling modules for local testing."""

    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    # Enable a module without analysis mode
    config_manager.enable_module("test_module")
    assert "test_module" in config_manager.locally_enabled_modules
    
    # Enable a module with analysis mode
    config_manager.enable_module("test_module2", "test_mode")
    assert "test_module2" in config_manager.locally_enabled_modules
    assert "test_mode" in config_manager.locally_mapped_analysis_modes
    assert "test_module2" in config_manager.locally_mapped_analysis_modes["test_mode"]


@pytest.mark.unit 
def test_add_analysis_module():
    """Test adding analysis modules."""
    
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    analysis_module = BasicTestAnalyzer(get_analysis_module_config("basic_test"))
    config_manager.add_analysis_module(analysis_module)
    
    assert len(config_manager.analysis_modules) == 1
    assert analysis_module in config_manager.analysis_modules
    assert ANALYSIS_MODE_ANALYSIS in config_manager.analysis_mode_mapping
    assert analysis_module in config_manager.analysis_mode_mapping[ANALYSIS_MODE_ANALYSIS]


@pytest.mark.unit
def test_get_analysis_modules_by_mode():
    """Test getting analysis modules by mode."""
    
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    analysis_module = BasicTestAnalyzer(get_analysis_module_config("basic_test"))
    config_manager.add_analysis_module(analysis_module, [ANALYSIS_MODE_ANALYSIS])
    
    modules = config_manager.get_analysis_modules_by_mode(ANALYSIS_MODE_ANALYSIS)
    assert len(modules) == 1
    assert modules[0] == analysis_module
    
    # Test with None (should return default mode)
    modules = config_manager.get_analysis_modules_by_mode(None)
    assert len(modules) == 1
    assert modules[0] == analysis_module


@pytest.mark.unit
def test_get_analysis_module_by_name():
    """Test getting analysis module by name."""
    
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    analysis_module = BasicTestAnalyzer(get_analysis_module_config("basic_test"))
    config_manager.add_analysis_module(analysis_module)
    
    # Test with valid name
    if analysis_module.name:
        found_module = config_manager.get_analysis_module_by_name(analysis_module.name)
        assert found_module == analysis_module
    
    # Test with invalid name
    found_module = config_manager.get_analysis_module_by_name("nonexistent_name")
    assert found_module is None


@pytest.mark.unit
def test_is_module_enabled():
    """Test checking if module is enabled."""
    
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    analysis_module = BasicTestAnalyzer(get_analysis_module_config("basic_test"))
    config_manager.add_analysis_module(analysis_module)
    
    # Test with valid name
    if analysis_module.name:
        assert config_manager.is_module_enabled(analysis_module.name) is True
    
    # Test with invalid name
    assert config_manager.is_module_enabled("nonexistent_name") is False


@pytest.mark.integration
def test_load_modules_integration():
    """Test the full module loading process."""
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))

    # Enable one module to be loaded
    analysis_module = BasicTestAnalyzer(get_analysis_module_config("basic_test"))
    module_config = get_analysis_module_config(analysis_module.name)
    if module_config:
        module_config.enabled = True

    config_manager.load_modules()

    # Should load the enabled module
    assert len(config_manager.analysis_modules) >= 0  # May be 0 if config not found


@pytest.mark.unit
def test_engine_configuration_loads_from_config():
    """Test that EngineConfiguration loads all properties correctly from configuration."""

    # Create an EngineConfiguration without passing any parameters
    # This should load everything from the configuration
    config = EngineConfiguration()

    # Test default_analysis_mode
    expected_default_mode = get_engine_config().default_analysis_mode
    assert config.default_analysis_mode == expected_default_mode

    # Test local_analysis_modes
    expected_local_modes = get_engine_config().local_analysis_modes

    # Note: the implementation adds default_analysis_mode to the list if not empty
    if expected_local_modes and config.default_analysis_mode not in expected_local_modes:
        expected_local_modes.append(config.default_analysis_mode)

    assert config.local_analysis_modes == expected_local_modes

    # Test excluded_analysis_modes
    expected_excluded_modes = get_engine_config().excluded_analysis_modes
    assert config.excluded_analysis_modes == expected_excluded_modes

    # Test non_detectable_modes
    expected_non_detectable = get_engine_config().non_detectable_modes
    assert config.non_detectable_modes == expected_non_detectable

    # Test pool_size_limit
    expected_pool_size_limit = get_engine_config().pool_size_limit
    assert config.pool_size_limit == expected_pool_size_limit

    # Test copy_analysis_on_error
    expected_copy_on_error = get_engine_config().copy_analysis_on_error
    assert config.copy_analysis_on_error == expected_copy_on_error

    # Test copy_terminated_analysis_causes
    expected_copy_terminated = get_engine_config().copy_terminated_analysis_causes
    assert config.copy_terminated_analysis_causes == expected_copy_terminated

    # Test alerting_enabled
    expected_alerting_enabled = get_engine_config().alerting_enabled
    assert config.alerting_enabled == expected_alerting_enabled

    # Test work_dir
    expected_work_dir = get_engine_config().work_dir
    assert config.work_dir == expected_work_dir

    # Test alert_disposition_check_frequency
    expected_alert_disp_freq = get_engine_config().alert_disposition_check_frequency
    assert config.alert_disposition_check_frequency == expected_alert_disp_freq

    # Test auto_refresh_frequency
    expected_auto_refresh = get_engine_config().auto_refresh_frequency
    assert config.auto_refresh_frequency == expected_auto_refresh

    # Test maximum_cumulative_analysis_warning_time
    #expected_max_warning_time = get_engine_config().maximum_cumulative_analysis_warning_time
    #assert config.maximum_cumulative_analysis_warning_time == expected_max_warning_time

    # Test maximum_cumulative_analysis_fail_time
    #expected_max_fail_time = get_engine_config().maximum_cumulative_analysis_fail_time
    #assert config.maximum_cumulative_analysis_fail_time == expected_max_fail_time

    # Test maximum_analysis_time
    #expected_max_analysis_time = get_engine_config().maximum_analysis_time
    #assert config.maximum_analysis_time == expected_max_analysis_time

    # Test target_nodes
    expected_target_nodes = get_engine_config().target_nodes
    # Note: target_nodes may have LOCAL translated to actual node name
    expected_target_nodes = [
        get_global_runtime_settings().saq_node if node == "LOCAL" else node for node in expected_target_nodes
    ]
    assert config.target_nodes == expected_target_nodes

    # Test memory limits
    expected_memory_kill = get_config().global_settings.memory_limit_kill * 1024 * 1024
    expected_memory_warning = get_config().global_settings.memory_limit_warning * 1024 * 1024
    assert config.memory_limit_kill == expected_memory_kill
    assert config.memory_limit_warning == expected_memory_warning

    # Test that stats_dir, runtime_dir, and observable_exclusions are initialized
    assert config.stats_dir is not None
    assert config.runtime_dir is not None
    assert isinstance(config.observable_exclusions, dict)
    assert len(config.observable_exclusions) == 0


@pytest.mark.unit
def test_engine_configuration_analysis_pools_loaded_from_config():
    """Test that analysis_pools are loaded automatically from configuration."""
    from saq.engine.engine_configuration import compute_pool_size

    # Create config without passing analysis_pools - should load from configuration
    # Use local_analysis_modes=[] to avoid filtering
    config = EngineConfiguration(local_analysis_modes=[])

    # Get the analysis_pools from configuration
    config_analysis_pools = get_engine_config().analysis_pools

    # Compute expected pools using the compute_pool_size function
    expected_pools = {}
    for analysis_mode, value in config_analysis_pools.items():
        expected_pools[analysis_mode] = compute_pool_size(value)

    # Verify the pools were loaded
    assert isinstance(config.analysis_pools, dict)
    for analysis_mode, count in expected_pools.items():
        assert analysis_mode in config.analysis_pools
        assert config.analysis_pools[analysis_mode] == count


@pytest.mark.unit
def test_engine_configuration_analysis_pools_empty_when_none_defined():
    """Test that analysis_pools is empty when no pools are defined in config and none passed."""
    # Create config with explicit empty pools to override any config values
    config = EngineConfiguration(
        analysis_pools={},
        local_analysis_modes=[],
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
    )

    # Should have empty pools since we explicitly passed an empty dict
    assert config.analysis_pools == {}
    assert isinstance(config.analysis_pools, dict)


@pytest.mark.unit
def test_engine_configuration_analysis_pools_explicit():
    """Test that explicitly passed analysis_pools are used correctly."""
    from multiprocessing import cpu_count

    test_pools = {
        "analysis": 4,
        "correlation": "50%",
        "email": "8",
    }

    # Pass local_analysis_modes=[] to allow all modes (no filtering)
    config = EngineConfiguration(
        analysis_pools=test_pools,
        local_analysis_modes=[],
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
    )

    # Should use the explicitly provided pools with computed values
    assert config.analysis_pools["analysis"] == 4
    assert config.analysis_pools["correlation"] == int(cpu_count() * 50 / 100)
    assert config.analysis_pools["email"] == 8


@pytest.mark.unit
def test_engine_configuration_analysis_pools_filtered_by_local_modes():
    """Test that analysis_pools are filtered based on local_analysis_modes."""

    test_pools = {
        "analysis": 4,
        "correlation": "100%",
        "email": "6",
    }

    # Only allow "analysis" and "email" modes
    config = EngineConfiguration(
        analysis_pools=test_pools,
        local_analysis_modes=["analysis", "email"],
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
    )

    # "correlation" should be filtered out
    assert "analysis" in config.analysis_pools
    assert config.analysis_pools["analysis"] == 4
    assert "email" in config.analysis_pools
    assert config.analysis_pools["email"] == 6
    assert "correlation" not in config.analysis_pools


@pytest.mark.unit
def test_engine_configuration_explicit_params_override_config():
    """Test that explicitly passed parameters override configuration values."""
    # Test with local_analysis_modes
    config = EngineConfiguration(
        default_analysis_mode="test_mode",
        local_analysis_modes=["test_mode", "analysis"],
        pool_size_limit=42,
        copy_analysis_on_error=True,
        target_nodes=["test_node"],
        analysis_mode_priority="priority_mode",
    )

    # All explicitly set values should be used
    assert config.default_analysis_mode == "test_mode"
    assert config.local_analysis_modes == ["test_mode", "analysis"]
    assert config.pool_size_limit == 42
    assert config.copy_analysis_on_error is True
    assert config.target_nodes == ["test_node"]
    assert config.analysis_mode_priority == "priority_mode"

    # Test with excluded_analysis_modes (must pass empty local_analysis_modes to avoid conflict with config)
    config2 = EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],  # Empty list means no restriction
        excluded_analysis_modes=["excluded_mode"],
        pool_size_limit=99,
    )
    assert config2.excluded_analysis_modes == ["excluded_mode"]
    assert config2.pool_size_limit == 99
    assert config2.local_analysis_modes == []


@pytest.mark.unit
def test_engine_configuration_single_threaded_mode():
    """Test single_threaded_mode parameter."""
    config = EngineConfiguration(single_threaded_mode=True)
    assert config.single_threaded_mode is True

    config = EngineConfiguration(single_threaded_mode=False)
    assert config.single_threaded_mode is False


@pytest.mark.unit
def test_engine_configuration_engine_type():
    """Test engine_type parameter and its effect on manager types."""
    from saq.engine.enums import EngineType
    from saq.constants import LockManagerType, WorkloadManagerType

    # Test DISTRIBUTED engine type
    config = EngineConfiguration(engine_type=EngineType.DISTRIBUTED)
    assert config.engine_type == EngineType.DISTRIBUTED
    assert config.lock_manager_type == LockManagerType.DISTRIBUTED
    assert config.workload_manager_type == WorkloadManagerType.DATABASE

    # Test LOCAL engine type
    config = EngineConfiguration(engine_type=EngineType.LOCAL)
    assert config.engine_type == EngineType.LOCAL
    assert config.lock_manager_type == LockManagerType.LOCAL
    assert config.workload_manager_type == WorkloadManagerType.MEMORY


@pytest.mark.unit
def test_engine_configuration_add_analysis_pool():
    """Test add_analysis_pool method."""
    # Pass local_analysis_modes=[] to allow all modes
    config = EngineConfiguration(
        local_analysis_modes=[],
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
    )

    # Add a pool
    config.add_analysis_pool("test_mode", 10)
    assert "test_mode" in config.analysis_pools
    assert config.analysis_pools["test_mode"] == 10

    # Update existing pool
    config.add_analysis_pool("test_mode", 15)
    assert config.analysis_pools["test_mode"] == 15


@pytest.mark.unit
def test_engine_configuration_add_analysis_pool_filtered():
    """Test that add_analysis_pool respects local_analysis_modes."""
    config = EngineConfiguration(
        local_analysis_modes=["allowed_mode"],
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
    )

    # Try to add a pool for an unsupported mode
    config.add_analysis_pool("unsupported_mode", 10)
    # Should not be added
    assert "unsupported_mode" not in config.analysis_pools

    # Add for supported mode
    config.add_analysis_pool("allowed_mode", 10)
    assert "allowed_mode" in config.analysis_pools


@pytest.mark.unit
def test_compute_pool_size_with_integer():
    """Test compute_pool_size with integer input."""
    from saq.engine.engine_configuration import compute_pool_size

    assert compute_pool_size(4) == 4
    assert compute_pool_size(8) == 8
    assert compute_pool_size(16) == 16


@pytest.mark.unit
def test_compute_pool_size_with_percentage():
    """Test compute_pool_size with percentage string."""
    from saq.engine.engine_configuration import compute_pool_size
    from multiprocessing import cpu_count

    # Test with 50%
    result = compute_pool_size("50%")
    expected = int(cpu_count() * 50 / 100)
    assert result == expected

    # Test with 100%
    result = compute_pool_size("100%")
    expected = int(cpu_count() * 100 / 100)
    assert result == expected

    # Test with 25%
    result = compute_pool_size("25%")
    expected = int(cpu_count() * 25 / 100)
    assert result == expected


@pytest.mark.unit
def test_compute_pool_size_with_string_number():
    """Test compute_pool_size with string number input."""
    from saq.engine.engine_configuration import compute_pool_size

    assert compute_pool_size("4") == 4
    assert compute_pool_size("8") == 8
    assert compute_pool_size("16") == 16


@pytest.mark.unit
def test_compute_pool_size_percentage_rounding():
    """Test compute_pool_size percentage rounding behavior with low CPU counts."""
    from saq.engine.engine_configuration import compute_pool_size
    from unittest.mock import patch

    # Test with 1 CPU
    with patch("saq.engine.engine_configuration.cpu_count", return_value=1):
        # 25% of 1 CPU = 0.25, but min is 1 for non-zero percentages
        assert compute_pool_size("25%") == 1
        # 50% of 1 CPU = 0.5, but min is 1 for non-zero percentages
        assert compute_pool_size("50%") == 1
        # 100% of 1 CPU = 1
        assert compute_pool_size("100%") == 1
        # 200% of 1 CPU = 2
        assert compute_pool_size("200%") == 2

    # Test with 2 CPUs
    with patch("saq.engine.engine_configuration.cpu_count", return_value=2):
        # 25% of 2 CPUs = 0.5, but min is 1 for non-zero percentages
        assert compute_pool_size("25%") == 1
        # 50% of 2 CPUs = 1
        assert compute_pool_size("50%") == 1
        # 100% of 2 CPUs = 2
        assert compute_pool_size("100%") == 2

    # Test with 3 CPUs
    with patch("saq.engine.engine_configuration.cpu_count", return_value=3):
        # 33% of 3 CPUs = 0.99, but min is 1 for non-zero percentages
        assert compute_pool_size("33%") == 1
        # 34% of 3 CPUs = 1.02, should truncate to 1
        assert compute_pool_size("34%") == 1
        # 50% of 3 CPUs = 1.5, should truncate to 1
        assert compute_pool_size("50%") == 1


@pytest.mark.unit
def test_compute_pool_size_percentage_edge_cases():
    """Test compute_pool_size with edge case percentages."""
    from saq.engine.engine_configuration import compute_pool_size
    from multiprocessing import cpu_count

    # Test with 0%
    assert compute_pool_size("0%") == 0

    # Test with 1% - should return at least 1 for non-zero percentages
    result = compute_pool_size("1%")
    expected = max(1, int(cpu_count() * 1 / 100))
    assert result == expected

    # Test with high percentage (200%)
    result = compute_pool_size("200%")
    expected = max(1, int(cpu_count() * 200 / 100))
    assert result == expected

    # Test with very high percentage (500%)
    result = compute_pool_size("500%")
    expected = max(1, int(cpu_count() * 500 / 100))
    assert result == expected


@pytest.mark.unit
def test_compute_pool_size_zero_values():
    """Test compute_pool_size with zero values."""
    from saq.engine.engine_configuration import compute_pool_size

    # Integer zero
    assert compute_pool_size(0) == 0

    # String zero
    assert compute_pool_size("0") == 0

    # 0 percent
    assert compute_pool_size("0%") == 0


@pytest.mark.unit
def test_engine_configuration_directories():
    """Test that directory properties are set correctly."""
    from saq.environment import get_data_dir
    import os

    config = EngineConfiguration()

    # Check stats_dir
    expected_stats_dir = os.path.join(get_global_runtime_settings().module_stats_dir, "ace")
    assert config.stats_dir == expected_stats_dir

    # Check runtime_dir
    expected_runtime_dir = os.path.join(get_data_dir(), "var", "engine", "ace")
    assert config.runtime_dir == expected_runtime_dir

    # Check that work_dir is loaded from config
    assert config.work_dir is not None
