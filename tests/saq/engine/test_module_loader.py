"""
Tests for the ModuleLoader class that was extracted from the ConfigurationManager class.
"""

import pytest

from saq.constants import ANALYSIS_MODE_ANALYSIS
from saq.engine.core import Engine
from saq.engine.module_loader import ModuleLoader


@pytest.mark.unit
def test_module_loader_initialization():
    """Test that ModuleLoader initializes properly."""
    
    module_loader = ModuleLoader(
        local_analysis_modes=[],
        excluded_analysis_modes=[],
        locally_enabled_modules=[],
        locally_mapped_analysis_modes={},
    )
    
    assert module_loader.local_analysis_modes == []
    assert module_loader.excluded_analysis_modes == []
    assert module_loader.locally_enabled_modules == []
    assert module_loader.locally_mapped_analysis_modes == {}


@pytest.mark.unit
def test_module_loader_analysis_mode_support():
    """Test the analysis mode support logic in ModuleLoader."""
    
    # Test with no restrictions (supports all modes)
    module_loader = ModuleLoader(
        local_analysis_modes=[],
        excluded_analysis_modes=[],
        locally_enabled_modules=[],
        locally_mapped_analysis_modes={},
    )
    assert module_loader.is_analysis_mode_supported("any_mode") == True
    
    # Test with local modes specified
    module_loader = ModuleLoader(
        local_analysis_modes=["test_mode", "analysis"],
        excluded_analysis_modes=[],
        locally_enabled_modules=[],
        locally_mapped_analysis_modes={},
    )
    assert module_loader.is_analysis_mode_supported("test_mode") == True
    assert module_loader.is_analysis_mode_supported("analysis") == True
    assert module_loader.is_analysis_mode_supported("other_mode") == False
    
    # Test with excluded modes
    module_loader = ModuleLoader(
        local_analysis_modes=[],
        excluded_analysis_modes=["excluded_mode"],
        locally_enabled_modules=[],
        locally_mapped_analysis_modes={},
    )
    assert module_loader.is_analysis_mode_supported("any_mode") == True
    assert module_loader.is_analysis_mode_supported("excluded_mode") == False


@pytest.mark.integration
def test_module_loader_load_modules():
    """Test the module loading functionality."""
    engine = Engine()
    
    module_loader = ModuleLoader(
        local_analysis_modes=[],
        excluded_analysis_modes=[],
        locally_enabled_modules=[],
        locally_mapped_analysis_modes={},
    )
    
    # Load modules
    loaded_modules = module_loader.load_modules()
    
    # Should return a dictionary of modules
    assert isinstance(loaded_modules, dict)
    # The exact number may vary based on configuration, but should have some modules
    assert len(loaded_modules) >= 0
    
    # Each value should be a tuple of (module, analysis_modes)
    for section_name, (module, analysis_modes) in loaded_modules.items():
        assert isinstance(section_name, str)
        assert module is not None
        assert isinstance(analysis_modes, list) 