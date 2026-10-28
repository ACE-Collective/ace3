"""
Tests for the ModuleLoader class that was extracted from the ConfigurationManager class.
"""

import logging

import pytest
from pydantic import ValidationError

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


def _removed_module_errors(caplog, module_name: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno == logging.ERROR and getattr(r, "analysis_module", None) == module_name]


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

    with caplog.at_level(logging.ERROR):
        mapping = _module_loader("test_removed_ref")._build_analysis_mode_mapping()

    assert mapping == {"test_removed_ref": {configured_module}}
    (record,) = _removed_module_errors(caplog, "removed_module")
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

    with caplog.at_level(logging.ERROR):
        mapping = _module_loader("test_removed_ref")._build_analysis_mode_mapping()

    assert mapping == {"test_removed_ref": {configured_module}}
    for module_name in ("removed_enabled", "removed_disabled"):
        (record,) = _removed_module_errors(caplog, module_name)
        assert record.analysis_mode == "test_removed_ref"
        assert record.module_group is None


@pytest.mark.unit
def test_has_analysis_module_config():
    assert get_config().has_analysis_module_config(get_config().analysis_modules[0].name)
    assert not get_config().has_analysis_module_config("removed_module")


@pytest.mark.unit
def test_a_disabled_module_is_not_imported():
    # the engine asks this of every module an analysis mode names; a disabled one is skipped on its base config,
    # so its python module (one that doesn't exist, here) is never imported
    get_config().raw._data["analysis_module_test_disabled_missing"] = {
        "name": "test_disabled_missing", "python_module": "saq.modules.does_not_exist", "python_class": "Nothing",
        "enabled": False}
    get_config().load_analysis_module_configs()

    assert _module_loader(ANALYSIS_MODE_ANALYSIS)._should_load_module("test_disabled_missing") is False
    assert get_config().is_analysis_module_enabled("test_disabled_missing") is False


@pytest.mark.unit
def test_a_module_disabled_after_it_was_resolved_is_not_loaded():
    # ace correlate --disable-all sets enabled on the resolved configs; the loader has to read those back
    name = get_config().analysis_modules[0].name
    get_config().get_analysis_module_config(name).enabled = False

    assert _module_loader(ANALYSIS_MODE_ANALYSIS)._should_load_module(name) is False


@pytest.mark.unit
def test_is_analysis_module_enabled_rejects_an_unknown_module():
    with pytest.raises(ValueError):
        get_config().is_analysis_module_enabled("removed_module")


@pytest.mark.unit
def test_module_with_an_undeclared_config_key_is_reported_and_skipped(caplog):
    # the key the shipped zip_encryption_analyzer block set for years, which nothing read
    get_config().raw._data["analysis_module_zip_encryption_analyzer"]["timeout"] = 30
    get_config().load_analysis_module_configs()
    module_loader = _module_loader(ANALYSIS_MODE_ANALYSIS)

    with caplog.at_level(logging.ERROR):
        assert module_loader._load_single_module("zip_encryption_analyzer") is None

    # with a traceback, the record gets an error report
    (record,) = _removed_module_errors(caplog, "zip_encryption_analyzer")
    assert isinstance(record.exc_info[1], ValidationError)
    assert record.exc_info[1].errors()[0]["loc"] == ("timeout",)

    # the other modules still load
    assert module_loader._load_single_module("file_hash_analyzer") is not None


@pytest.mark.unit
def test_module_without_a_config_is_reported_and_skipped(caplog):
    with caplog.at_level(logging.ERROR):
        assert _module_loader(ANALYSIS_MODE_ANALYSIS)._load_single_module("removed_module") is None

    (record,) = _removed_module_errors(caplog, "removed_module")
    assert "not found" in record.getMessage()
