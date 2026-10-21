import pytest

from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import CONFIG_ANALYSIS_MODE_CLEANUP, CONFIG_ANALYSIS_MODE_PREFIX, CONFIG_ANALYSIS_MODULE_ENABLED, CONFIG_ANALYSIS_MODULE_MODULE_GROUPS, CONFIG_DISABLED_MODULES, F_TEST
from saq.engine.core import Engine, EngineState
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker_manager import WorkerManager
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.test import BasicTestAnalysis, BasicTestAnalyzer

ANALYIS_MODE_TEST = "test"

@pytest.mark.parametrize("included, excluded, mode, expected_result", [
    ([], [], "test_1", True), # any mode supported
    (["test_1"], [], "test_1", True), # directly supported
    (["test_1"], [], "test_2", False), # not specifically supported
    ([], ["test_1"], "test_1", False), # specifically excluded
    ([], ["test_1"], "test_2", True), # outside exclusion
])
@pytest.mark.unit
def test_is_analysis_mode_supported(included, excluded, mode, expected_result):
    engine = Engine(config=EngineConfiguration(local_analysis_modes=included, excluded_analysis_modes=excluded))
    assert engine.configuration_manager.is_analysis_mode_supported(mode) == expected_result

@pytest.mark.unit
def test_default_engine():
    engine = Engine()
    assert engine.state == EngineState.INITIALIZING
    assert isinstance(engine.config, EngineConfiguration)
    assert isinstance(engine.configuration_manager, ConfigurationManager)
    assert isinstance(engine.node_manager, NodeManagerInterface)
    assert isinstance(engine.worker_manager, WorkerManager)

@pytest.mark.unit
def test_add_analysis_module(monkeypatch, test_context):
    engine = Engine()

    analysis_module = AnalysisModuleAdapter(BasicTestAnalyzer(get_analysis_module_config("basic_test")))
    engine.configuration_manager.add_analysis_module(analysis_module)

    assert engine.configuration_manager.analysis_modules == [analysis_module]
    assert engine.configuration_manager.analysis_module_name_mapping == { analysis_module.name: analysis_module }
    assert engine.configuration_manager.analysis_mode_mapping == { engine.config.default_analysis_mode: [analysis_module] }

    # verification failure
    def mock_verify_environment(*args, **kwargs):
        raise RuntimeError()

    engine.configuration_manager._initialize_mappings()
    with monkeypatch.context() as context:
        context.setattr(analysis_module, "verify_environment", mock_verify_environment)
        with pytest.raises(RuntimeError):
            engine.configuration_manager.add_analysis_module(analysis_module)


@pytest.mark.integration
def test_initialize_modules(test_context):
    engine = Engine()

    # by default all modules are disabled in the config so nothing should be loaded
    assert not engine.configuration_manager.analysis_modules
    assert not engine.configuration_manager.analysis_module_name_mapping
    assert engine.configuration_manager.analysis_mode_mapping == { engine.config.default_analysis_mode: [] }

    # enable one of them to be loaded
    get_analysis_module_config("basic_test").enabled = True
    #engine.configuration_manager._get_analysis_module_config(AnalysisModuleAdapter(BasicTestAnalyzer(get_analysis_module_config("basic_test")))).enabled = True

    engine.configuration_manager.load_modules()

    assert len(engine.configuration_manager.analysis_modules) == 1
    assert len(engine.configuration_manager.analysis_module_name_mapping) == 1
    # this one is mapped to three different groups
    map_count = 0
    for mode, module_adapters in engine.configuration_manager.analysis_mode_mapping.items():
        for module_adapter in module_adapters:
            if module_adapter.name == "basic_test":
                map_count += 1
                break

    assert map_count == 3

@pytest.mark.integration
def test_initialize_modules_invalid_references(test_context):
    config = get_analysis_module_config("basic_test")
    config.enabled = True

    engine = Engine()
    mode_config = get_config().get_analysis_mode_config(engine.config.default_analysis_mode)
    mode_config.module_groups = ["invalid_group_name"]
    mode_config.enabled_modules = ["invalid_module_name"]
    
    get_config().get_module_group_config("unittest").modules = ["invalid_module_name"]

    # should raise an error because the module group is invalid
    with pytest.raises(ValueError):
        engine.configuration_manager.load_modules()

    #assert len(engine.configuration_manager.analysis_modules) == 1

@pytest.mark.integration
def test_initialize_modules_disabled_module(test_context):
    config = get_analysis_module_config("basic_test")
    config.enabled = True

    # disable this module globally
    get_config().disabled_modules = [config.name]

    engine = Engine()
    engine.configuration_manager.load_modules()
    assert len(engine.configuration_manager.analysis_modules) == 0

@pytest.mark.integration
def test_initialize_modules_module_load_failure(monkeypatch, test_context, caplog):
    config = get_analysis_module_config("basic_test")
    assert config is not None
    config.enabled = True
    monkeypatch.setattr(config, "python_module", "tests.saq.does_not_exist")

    engine = Engine()
    engine.configuration_manager.load_modules()
    # module fails to load
    assert len(engine.configuration_manager.analysis_modules) == 0
    assert any("unable to import module tests.saq.does_not_exist" in record.getMessage() for record in caplog.records)
