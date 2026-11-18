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
    
    assert config_manager.get_analysis_module_by_name("basic_test") is analysis_module
    assert config_manager.is_module_enabled("basic_test") is True

    assert config_manager.get_analysis_module_by_name("nonexistent_name") is None
    assert config_manager.is_module_enabled("nonexistent_name") is False


@pytest.mark.integration
def test_load_modules_integration():
    """Every enabled module is loaded and mapped to the modes that name it, and a supported
    mode that names no module still gets an (empty) entry."""
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))

    get_analysis_module_config("basic_test").enabled = True

    config_manager.load_modules()

    basic_test = config_manager.get_analysis_module_by_name("basic_test")
    assert basic_test is not None
    # test_single enables it, test_groups and test_queues name it through a module group, and
    # test_disabled names it through a group but disables it
    assert sorted(
        mode for mode, modules in config_manager.analysis_mode_mapping.items() if basic_test in modules
    ) == ["test_groups", "test_queues", "test_single"]
    assert config_manager.analysis_mode_mapping["test_empty"] == []


@pytest.mark.unit
def test_engine_configuration_loads_from_config(monkeypatch):
    """With no arguments, EngineConfiguration reads the engine section of the configuration."""
    engine_config = get_engine_config()
    monkeypatch.setattr(engine_config, "default_analysis_mode", "test_single")
    # the default mode is added to a non-empty list of local modes
    monkeypatch.setattr(engine_config, "local_analysis_modes", ["test_groups"])
    monkeypatch.setattr(engine_config, "excluded_analysis_modes", [])
    monkeypatch.setattr(engine_config, "non_detectable_modes", ["test_empty"])
    monkeypatch.setattr(engine_config, "pool_size_limit", 7)
    monkeypatch.setattr(engine_config, "alerting_enabled", False)
    monkeypatch.setattr(engine_config, "work_dir", "/opt/work")
    monkeypatch.setattr(engine_config, "alert_disposition_check_frequency", 11)
    monkeypatch.setattr(engine_config, "auto_refresh_frequency", 13)
    # LOCAL stands for this node
    monkeypatch.setattr(engine_config, "target_nodes", ["LOCAL", "node-2"])
    monkeypatch.setattr(get_global_runtime_settings(), "saq_node", "node-1")
    monkeypatch.setattr(get_config().global_settings, "memory_limit_kill", 3)
    monkeypatch.setattr(get_config().global_settings, "memory_limit_warning", 2)

    config = EngineConfiguration()

    assert config.default_analysis_mode == "test_single"
    assert config.local_analysis_modes == ["test_groups", "test_single"]
    assert config.excluded_analysis_modes == []
    assert config.non_detectable_modes == ["test_empty"]
    assert config.pool_size_limit == 7
    assert config.alerting_enabled is False
    assert config.work_dir == "/opt/work"
    assert config.alert_disposition_check_frequency == 11
    assert config.auto_refresh_frequency == 13
    assert config.target_nodes == ["node-1", "node-2"]
    # megabytes in the configuration, bytes on the engine
    assert config.memory_limit_kill == 3145728
    assert config.memory_limit_warning == 2097152


@pytest.mark.unit
def test_engine_configuration_observable_exclusions():
    """The global observable_exclusions: config is parsed into the {o_type: [o_value]}
    shape the engine reads (docs/ENGINE.md §7.5)."""
    get_config().observable_exclusions = {
        "exclude_loopback": "ipv4:127.0.0.1",
        "exclude_invalid_ipv4": "ipv4:0.0.0.0",
        "exclude_google": "fqdn:google.com",
        # values split on the first colon only, so this url keeps its scheme
        "exclude_url": "url:https://google.com/evil",
        # blank values are legitimate (office365 journaling)
        "exclude_user": "user:-",
    }

    config = EngineConfiguration()

    assert config.observable_exclusions == {
        "ipv4": ["127.0.0.1", "0.0.0.0"],
        "fqdn": ["google.com"],
        "url": ["https://google.com/evil"],
        "user": ["-"],
    }


@pytest.mark.unit
def test_engine_configuration_observable_exclusions_deduplicated():
    """The same type:value listed twice under different names collapses."""
    get_config().observable_exclusions = {
        "exclude_google": "fqdn:google.com",
        "exclude_google_again": "fqdn:google.com",
    }

    assert EngineConfiguration().observable_exclusions == {"fqdn": ["google.com"]}


@pytest.mark.unit
def test_engine_configuration_observable_exclusions_malformed():
    """A spec with no type separator is skipped, not fatal -- one bad entry must
    not take the engine down."""
    get_config().observable_exclusions = {
        "bad": "no_separator_here",
        "exclude_google": "fqdn:google.com",
    }

    assert EngineConfiguration().observable_exclusions == {"fqdn": ["google.com"]}


@pytest.mark.unit
def test_engine_configuration_observable_exclusions_empty():
    get_config().observable_exclusions = None

    assert EngineConfiguration().observable_exclusions == {}


@pytest.mark.unit
def test_engine_configuration_observable_exclusions_override():
    """An explicit dict passed to the constructor wins over the config."""
    get_config().observable_exclusions = {"exclude_google": "fqdn:google.com"}

    config = EngineConfiguration(observable_exclusions={"ipv4": ["127.0.0.1"]})

    assert config.observable_exclusions == {"ipv4": ["127.0.0.1"]}


@pytest.mark.unit
def test_engine_configuration_shipped_observable_exclusions_are_live():
    """The exclusions shipped in etc/saq.default.yaml actually reach the engine.
    This is the specific defect recorded in docs/ENGINE.md §19.2: the config was
    validated and then dropped on the floor."""
    config = EngineConfiguration()

    assert "127.0.0.1" in config.observable_exclusions["ipv4"]
    assert "google.com" in config.observable_exclusions["fqdn"]


@pytest.mark.unit
def test_engine_configuration_analysis_pools_loaded_from_config(monkeypatch):
    """Test that analysis_pools are loaded automatically from configuration."""
    # the unittest configuration defines no pools
    monkeypatch.setattr(get_engine_config(), "analysis_pools", {"analysis": 3, "correlation": "2"})

    # Use local_analysis_modes=[] to avoid filtering
    config = EngineConfiguration(local_analysis_modes=[])

    assert config.analysis_pools == {"analysis": 3, "correlation": 2}


@pytest.mark.unit
def test_engine_configuration_analysis_pools_empty_when_none_defined(monkeypatch):
    """An explicitly empty analysis_pools wins over the pools the configuration defines."""
    monkeypatch.setattr(get_engine_config(), "analysis_pools", {"analysis": 3})

    config = EngineConfiguration(
        analysis_pools={},
        local_analysis_modes=[],
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
    )

    assert config.analysis_pools == {}


@pytest.mark.unit
def test_engine_configuration_analysis_pools_explicit(monkeypatch):
    """Test that explicitly passed analysis_pools are used correctly."""
    monkeypatch.setattr("saq.engine.engine_configuration.cpu_count", lambda: 6)

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
    assert config.analysis_pools["correlation"] == 3
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
        target_nodes=["test_node"],
        analysis_mode_priority="priority_mode",
    )

    # All explicitly set values should be used
    assert config.default_analysis_mode == "test_mode"
    assert config.local_analysis_modes == ["test_mode", "analysis"]
    assert config.pool_size_limit == 42
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
    """0% is the one percentage that does not get the minimum of 1 worker."""
    from saq.engine.engine_configuration import compute_pool_size

    assert compute_pool_size("0%") == 0


@pytest.mark.unit
def test_engine_configuration_directories(monkeypatch):
    """Test that directory properties are set correctly."""
    monkeypatch.setattr(get_global_runtime_settings(), "module_stats_dir", "/opt/stats")
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", "/opt/data")

    config = EngineConfiguration()

    assert config.stats_dir == "/opt/stats/ace"
    assert config.runtime_dir == "/opt/data/var/engine/ace"
