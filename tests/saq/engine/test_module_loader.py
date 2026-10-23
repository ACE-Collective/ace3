"""
Tests for the ModuleLoader class that was extracted from the ConfigurationManager class.
"""

import logging

import pytest

from saq.configuration.config import get_config
from saq.configuration.schema import AnalysisModeConfig, AnalysisModuleGroupConfig
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

def _module_loader(analysis_mode: str) -> ModuleLoader:
    return ModuleLoader(
        local_analysis_modes=[analysis_mode],
        excluded_analysis_modes=[],
        locally_enabled_modules=[],
        locally_mapped_analysis_modes={},
    )


def _removed_module_warnings(caplog, module_name: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno == logging.WARNING and getattr(r, "analysis_module", None) == module_name]


@pytest.mark.unit
def test_module_group_reference_to_removed_module_is_skipped(caplog):
    configured_module = get_config().analysis_modules[0].name
    get_config().add_module_group_config(
        "test_removed_ref",
        AnalysisModuleGroupConfig(name="test_removed_ref", modules=[configured_module, "removed_module"]),
    )
    get_config().add_analysis_mode_config(
        "test_removed_ref",
        AnalysisModeConfig(name="test_removed_ref", module_groups=["test_removed_ref"], cleanup=True),
    )

    with caplog.at_level(logging.WARNING):
        mapping = _module_loader("test_removed_ref")._build_analysis_mode_mapping()

    assert mapping == {"test_removed_ref": {configured_module}}
    (record,) = _removed_module_warnings(caplog, "removed_module")
    assert record.analysis_mode == "test_removed_ref"
    assert record.module_group == "test_removed_ref"


@pytest.mark.unit
def test_enabled_and_disabled_reference_to_removed_module_is_skipped(caplog):
    configured_module = get_config().analysis_modules[0].name
    get_config().add_analysis_mode_config(
        "test_removed_ref",
        AnalysisModeConfig(
            name="test_removed_ref",
            module_groups=[],
            enabled_modules=[configured_module, "removed_enabled"],
            disabled_modules=["removed_disabled"],
            cleanup=True,
        ),
    )

    with caplog.at_level(logging.WARNING):
        mapping = _module_loader("test_removed_ref")._build_analysis_mode_mapping()

    assert mapping == {"test_removed_ref": {configured_module}}
    for module_name in ("removed_enabled", "removed_disabled"):
        (record,) = _removed_module_warnings(caplog, module_name)
        assert record.analysis_mode == "test_removed_ref"
        assert record.module_group is None


@pytest.mark.unit
def test_has_analysis_module_config():
    assert get_config().has_analysis_module_config(get_config().analysis_modules[0].name)
    assert not get_config().has_analysis_module_config("removed_module")
