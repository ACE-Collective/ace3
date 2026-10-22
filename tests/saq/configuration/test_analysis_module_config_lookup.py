import logging

import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.module_path import MODULE_PATH
from saq.configuration.loader import load_configuration
from saq.configuration.schema import ACEConfig
from saq.modules.base_module import AnalysisModule
from saq.modules.config import AnalysisModuleConfig

#
# several analysis modules hosted by this one python module, the way saq.modules.test,
# saq.modules.email and others host theirs
#

class FirstAnalysis(Analysis):
    pass


class SecondAnalysis(Analysis):
    pass


class FirstAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return FirstAnalysis


class SecondAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return SecondAnalysis


class InitStateAnalyzer(AnalysisModule):
    """Reads instance state that only __init__ sets, so it cannot be asked before it is built."""

    @property
    def generated_analysis_type(self):
        return self._analysis_type


class NoAnalysisAnalyzer(AnalysisModule):
    pass


def module_config(name: str, python_class: str, instance: str | None = None) -> AnalysisModuleConfig:
    return AnalysisModuleConfig(name=name, python_module=__name__, python_class=python_class,
                                enabled=True, instance=instance)


@pytest.fixture
def config() -> ACEConfig:
    # a private config, not get_config(), so the modules added here go nowhere else
    raw_config = load_configuration(config_paths=[])
    result = ACEConfig.model_validate(raw_config._data)
    result.raw = raw_config
    return result


@pytest.mark.unit
def test_each_module_of_one_python_module_resolves_to_its_own_config(config):
    config.add_analysis_module_config("first", module_config("first", "FirstAnalyzer"))
    config.add_analysis_module_config("second", module_config("second", "SecondAnalyzer"))

    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(FirstAnalysis)).name == "first"
    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(SecondAnalysis)).name == "second"

    # registered the other way around, which used to decide which one both resolved to
    config.load_analysis_module_configs()
    config.add_analysis_module_config("second", module_config("second", "SecondAnalyzer"))
    config.add_analysis_module_config("first", module_config("first", "FirstAnalyzer"))

    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(FirstAnalysis)).name == "first"
    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(SecondAnalysis)).name == "second"


@pytest.mark.unit
def test_instances_of_one_module_resolve_to_their_own_config(config):
    config.add_analysis_module_config("first", module_config("first", "FirstAnalyzer"))
    config.add_analysis_module_config("first_a", module_config("first_a", "FirstAnalyzer", instance="a"))
    config.add_analysis_module_config("second_a", module_config("second_a", "SecondAnalyzer", instance="a"))

    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(FirstAnalysis)).name == "first"
    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(FirstAnalysis, instance="a")).name == "first_a"
    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(SecondAnalysis, instance="a")).name == "second_a"
    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(SecondAnalysis)) is None
    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(FirstAnalysis, instance="b")) is None


@pytest.mark.unit
def test_module_path_no_module_generates_resolves_to_nothing(config):
    config.add_analysis_module_config("first", module_config("first", "FirstAnalyzer"))
    config.add_analysis_module_config("none", module_config("none", "NoAnalysisAnalyzer"))

    # a class in a python module that hosts modules, but that none of them generates (an
    # Analysis class renamed since the analysis was saved, say)
    assert config.get_analysis_module_config_by_module_path(f"{__name__}:RenamedAnalysis") is None
    # a python module with no modules configured at all
    assert config.get_analysis_module_config_by_module_path("saq.modules.missing:MissingAnalysis") is None
    assert config.get_analysis_module_config_by_module_path("not a module path") is None


@pytest.mark.unit
def test_lookup_is_resolved_once_per_module_path(config, monkeypatch):
    config.add_analysis_module_config("first", module_config("first", "FirstAnalyzer"))
    config.add_analysis_module_config("second", module_config("second", "SecondAnalyzer"))

    reads = []
    original = SecondAnalyzer.generated_analysis_type

    def _counting(self):
        reads.append(self)
        return original.fget(self)

    monkeypatch.setattr(SecondAnalyzer, "generated_analysis_type", property(_counting))

    for _ in range(3):
        assert config.get_analysis_module_config_by_module_path(MODULE_PATH(SecondAnalysis)).name == "second"
        assert config.get_analysis_module_config_by_module_path(f"{__name__}:RenamedAnalysis") is None

    # once for each module path, the miss included
    assert len(reads) == 2


@pytest.mark.unit
def test_module_added_after_a_lookup_is_found(config):
    config.add_analysis_module_config("first", module_config("first", "FirstAnalyzer"))
    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(SecondAnalysis)) is None

    config.add_analysis_module_config("second", module_config("second", "SecondAnalyzer"))
    assert config.get_analysis_module_config_by_module_path(MODULE_PATH(SecondAnalysis)).name == "second"


@pytest.mark.unit
def test_module_whose_analysis_type_cannot_be_read_is_logged_and_skipped(config, caplog):
    config.add_analysis_module_config("init_state", module_config("init_state", "InitStateAnalyzer"))
    config.add_analysis_module_config("second", module_config("second", "SecondAnalyzer"))

    with caplog.at_level(logging.ERROR):
        assert config.get_analysis_module_config_by_module_path(MODULE_PATH(SecondAnalysis)).name == "second"

    records = [r for r in caplog.records if "unable to read the generated analysis type" in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None
    assert records[0].analysis_module == "init_state"
    assert records[0].module_path == MODULE_PATH(SecondAnalysis)
