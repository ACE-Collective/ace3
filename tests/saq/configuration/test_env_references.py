"""A process needs the environment variables of the configuration sections it reads, and no others.

Every env: reference in the merged configuration used to be resolved when it was loaded, so a
container needed the variables of every service and integration in its configuration chain,
including the ones it never runs (#1009).
"""

import importlib
import logging
import re
import sys
import textwrap

import pytest
from pydantic import BaseModel, ValidationError

from app.application import initialize_presenters
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.presenter import analysis_presenter
from saq.configuration import config as config_module
from saq.configuration.config import (
    get_config,
    get_service_config,
    register_integration_configuration,
    resolve_configuration,
)
from saq.configuration.schema import ServiceConfig
from saq.configuration.yaml_parser import MissingEnvironmentVariable

MISSING = "ACE_TEST_ENV_REFERENCE_NOT_SET"


class EnvReferenceServiceConfig(ServiceConfig):
    api_key: str


class EnvReferenceService:
    @classmethod
    def get_config_class(cls):
        return EnvReferenceServiceConfig


class EnvReferenceIntegrationConfig(BaseModel):
    env_reference_integration: dict


@pytest.fixture(autouse=True)
def missing_variable(monkeypatch):
    monkeypatch.delenv(MISSING, raising=False)


def _set_section(monkeypatch, key: str, value):
    monkeypatch.setitem(get_config().raw._data, key, value)


def _add_service(monkeypatch, api_key: str):
    _set_section(monkeypatch, "service_env_reference", {
        "name": "env_reference",
        "python_module": __name__,
        "python_class": "EnvReferenceService",
        "description": "a service whose block references an environment variable",
        "enabled": False,
        "api_key": api_key,
    })


@pytest.mark.unit
def test_a_service_needs_its_variables_only_when_its_config_is_read(monkeypatch):
    _add_service(monkeypatch, f"env:{MISSING}")

    # loading the configuration does not read the service's block
    resolve_configuration(get_config())

    with pytest.raises(MissingEnvironmentVariable, match=f"{MISSING} at service_env_reference.api_key"):
        get_service_config("env_reference")


@pytest.mark.unit
def test_a_service_reference_resolves_when_the_variable_is_set(monkeypatch):
    _add_service(monkeypatch, f"env:{MISSING}")
    monkeypatch.setenv(MISSING, "the key")
    resolve_configuration(get_config())

    assert get_service_config("env_reference").api_key == "the key"
    # the parsed configuration keeps the reference
    assert get_config().raw._data["service_env_reference"]["api_key"] == f"env:{MISSING}"


@pytest.mark.unit
def test_a_section_the_process_validates_at_load_still_needs_its_variables(monkeypatch):
    _set_section(monkeypatch, "global", {**get_config().raw._data["global"], "instance_name": f"env:{MISSING}"})

    with pytest.raises(MissingEnvironmentVariable, match=f"{MISSING} at global.instance_name"):
        resolve_configuration(get_config())


@pytest.mark.unit
def test_a_section_nothing_validates_needs_no_variables(monkeypatch):
    _set_section(monkeypatch, "unread_section", {"password": f"env:{MISSING}"})

    resolve_configuration(get_config())

    assert get_config().raw._data["unread_section"] == {"password": f"env:{MISSING}"}


@pytest.mark.unit
def test_an_integration_needs_its_variables_only_when_its_config_is_read(monkeypatch, caplog):
    _set_section(monkeypatch, "env_reference_integration", {"api_key": f"env:{MISSING}"})
    register_integration_configuration("env_reference", EnvReferenceIntegrationConfig)

    with caplog.at_level(logging.INFO):
        # every process imports every integration
        resolve_configuration(get_config())

    assert "env_reference" not in config_module.INTEGRATION_CONFIGURATIONS
    assert any(record.getMessage().startswith("integration env_reference configuration is not loaded")
               and MISSING in record.getMessage() for record in caplog.records)

    with pytest.raises(MissingEnvironmentVariable, match=f"{MISSING} at env_reference_integration.api_key"):
        get_config("env_reference")

    monkeypatch.setenv(MISSING, "the key")
    assert get_config("env_reference").env_reference_integration == {"api_key": "the key"}
    assert get_config("env_reference") is get_config("env_reference")


@pytest.mark.unit
def test_an_integration_registered_late_is_deferred_too(monkeypatch):
    _set_section(monkeypatch, "env_reference_integration", {"api_key": f"env:{MISSING}"})
    resolve_configuration(get_config())

    # an integration package imported after the configuration was resolved
    register_integration_configuration("env_reference_late", EnvReferenceIntegrationConfig)

    with pytest.raises(MissingEnvironmentVariable):
        get_config("env_reference_late")


@pytest.mark.unit
def test_an_integration_reads_only_the_sections_its_model_declares(monkeypatch):
    _set_section(monkeypatch, "env_reference_integration", {"api_key": "literal"})
    _set_section(monkeypatch, "unread_section", {"password": f"env:{MISSING}"})
    register_integration_configuration("env_reference_only_its_own", EnvReferenceIntegrationConfig)

    resolve_configuration(get_config())

    assert get_config("env_reference_only_its_own").env_reference_integration == {"api_key": "literal"}


@pytest.mark.unit
def test_an_ai_query_backend_needs_its_variables_only_when_it_is_loaded(monkeypatch):
    _set_section(monkeypatch, "ai_query_backend_env_reference", {
        "name": "env_reference",
        "python_module": "saq.ai_query.interface",
        "python_class": "AIQueryBackend",
        "token": f"env:{MISSING}",
    })

    resolve_configuration(get_config())

    # the base config carries only the fields it declares, never the unresolved reference
    assert not hasattr(get_config().get_ai_query_backend_config("env_reference"), "token")
    with pytest.raises(MissingEnvironmentVariable, match=f"{MISSING} at ai_query_backend_env_reference.token"):
        get_config().get_ai_query_backend_raw("env_reference")


ANALYZER_MODULE = "env_reference_analyzer"


@pytest.fixture
def env_reference_analyzer(monkeypatch, tmp_path):
    """An analysis module whose own config field references a missing variable, in a python module
    nothing has imported, which registers a presenter when it is."""
    (tmp_path / f"{ANALYZER_MODULE}.py").write_text(textwrap.dedent("""
        from saq.analysis.analysis import Analysis
        from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
        from saq.modules.base_module import AnalysisModule
        from saq.modules.config import AnalysisModuleConfig

        class EnvReferenceAnalysis(Analysis):
            pass

        class EnvReferenceAnalysisPresenter(AnalysisPresenter):
            pass

        class EnvReferenceAnalyzerConfig(AnalysisModuleConfig):
            api_key: str

        class EnvReferenceAnalyzer(AnalysisModule):
            @classmethod
            def get_config_class(cls):
                return EnvReferenceAnalyzerConfig

            @property
            def generated_analysis_type(self):
                return EnvReferenceAnalysis

        register_analysis_presenter(EnvReferenceAnalysis, EnvReferenceAnalysisPresenter)
    """))
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(analysis_presenter, "_ANALYSIS_PRESENTER_REGISTRY",
                        dict(analysis_presenter._ANALYSIS_PRESENTER_REGISTRY))

    _set_section(monkeypatch, "analysis_module_env_reference", {
        "name": "env_reference",
        "python_module": ANALYZER_MODULE,
        "python_class": "EnvReferenceAnalyzer",
        "enabled": True,
        "default_collapsed": True,
        "api_key": f"env:{MISSING}",
    })
    unittest_group = get_config().raw._data["module_group_unittest"]
    _set_section(monkeypatch, "module_group_unittest",
                 {**unittest_group, "modules": [*unittest_group["modules"], "env_reference"]})
    resolve_configuration(get_config())

    yield
    sys.modules.pop(ANALYZER_MODULE, None)


@pytest.mark.unit
def test_the_gui_registers_a_modules_presenters_without_its_variables(env_reference_analyzer, caplog):
    with caplog.at_level(logging.ERROR):
        initialize_presenters()

    analyzer_module = sys.modules[ANALYZER_MODULE]
    assert analysis_presenter._ANALYSIS_PRESENTER_REGISTRY[analyzer_module.EnvReferenceAnalysis] \
        is analyzer_module.EnvReferenceAnalysisPresenter
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]


@pytest.mark.unit
def test_the_gui_logs_an_analysis_module_it_cannot_import(env_reference_analyzer, monkeypatch, caplog):
    _set_section(monkeypatch, "analysis_module_env_reference", {
        **get_config().raw._data["analysis_module_env_reference"],
        "python_module": "env_reference_no_such_module",
    })
    resolve_configuration(get_config())

    with caplog.at_level(logging.ERROR):
        initialize_presenters()

    [record] = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert record.analysis_module == "env_reference"
    assert record.python_module == "env_reference_no_such_module"
    assert record.exc_info[0] is ModuleNotFoundError

@pytest.mark.unit
def test_the_alert_tree_reads_a_modules_base_config_without_its_variables(env_reference_analyzer, caplog):
    analyzer_module = importlib.import_module(ANALYZER_MODULE)

    with caplog.at_level(logging.ERROR):
        module_config = get_config().get_analysis_module_config_by_module_path(
            MODULE_PATH(analyzer_module.EnvReferenceAnalysis))

    assert module_config.name == "env_reference"
    assert module_config.default_collapsed
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]


# every family of sections ACEConfig validates at load, each by its own loader: a block with an
# env: reference in one field, and how the process reads that field
REFERENCE = f"env:{MISSING}"
LOADED_SECTIONS = [
    ("database_env_reference",
     {"name": "env_reference", "hostname": REFERENCE, "database": "ace", "username": "ace", "password": "ace"},
     "hostname", lambda config: config.get_database_config("env_reference").hostname),
    ("integration_env_reference",
     {"name": "env_reference", "description": REFERENCE, "enabled": False, "python_module": "env_reference"},
     "description",
     lambda config: next(i for i in config.integrations if i.name == "env_reference").description),
    ("analysis_mode_env_reference",
     {"name": "env_reference", "cleanup": False, "module_groups": [], "disabled_modules": [REFERENCE]},
     "disabled_modules[0]", lambda config: config.get_analysis_mode_config("env_reference").disabled_modules[0]),
    ("module_group_env_reference", {"name": "env_reference", "modules": [REFERENCE]},
     "modules[0]", lambda config: config.get_module_group_config("env_reference").modules[0]),
    ("collection_group_env_reference",
     {"name": REFERENCE, "enabled": False, "coverage": 100, "full_delivery": True, "company_id": 1},
     "name", lambda config: config.get_collection_group_config("env_reference").name),
    ("proxy_env_reference", {"name": "env_reference", "transport": "http", "host": REFERENCE, "port": 3128},
     "host", lambda config: config.get_proxy_config("env_reference").host),
    ("splunk_config_env_reference",
     {"name": "env_reference", "enabled": False, "host": REFERENCE, "port": 8089, "timezone": "UTC",
      "performance_logging_dir": "splunk_perf"},
     "host", lambda config: config.get_splunk_config("env_reference").host),
    ("api_query_defaults_env_reference",
     {"name": "env_reference", "wide_duration_before": REFERENCE, "wide_duration_after": "00:00:00",
      "narrow_duration_before": "00:00:00", "narrow_duration_after": "00:00:00", "max_result_count": 1,
      "query_timeout": 1, "async_delay": 1, "use_index_time": False},
     "wide_duration_before",
     lambda config: config.get_api_query_defaults_config("env_reference").wide_duration_before),
    ("hunt_type_env_reference",
     {"name": "env_reference", "python_module": REFERENCE, "python_class": "Hunt", "update_frequency": 60,
      "schedulable": False},
     "python_module", lambda config: config.get_hunt_type_config("env_reference").python_module),
    ("git_repo_env_reference",
     {"name": "env_reference", "description": "a repo", "local_path": "repo", "git_url": REFERENCE,
      "update_frequency": 60, "branch": "main"},
     "git_url", lambda config: config.get_git_repo_config("env_reference").git_url),
    ("remediator_env_reference",
     {"name": "env_reference", "display_name": "a remediator", "description": REFERENCE,
      "observable_type": "email_address", "python_module": "env_reference", "python_class": "Remediator"},
     "description", lambda config: config.get_remediator_config("env_reference").description),
    ("file_collector_env_reference",
     {"name": "env_reference", "display_name": "a collector", "description": REFERENCE,
      "observable_type": "file_location", "python_module": "env_reference", "python_class": "Collector"},
     "description", lambda config: config.get_file_collector_config("env_reference").description),
    ("external_remediation_probe_env_reference",
     {"name": "env_reference", "observable_type": REFERENCE, "python_module": "env_reference",
      "python_class": "Probe", "enabled": False},
     "observable_type",
     lambda config: config.get_external_remediation_probe_config("env_reference").observable_type),
]


@pytest.mark.unit
@pytest.mark.parametrize("key, block, field, read", LOADED_SECTIONS, ids=[case[0] for case in LOADED_SECTIONS])
def test_a_section_validated_at_load_resolves_its_references(monkeypatch, key, block, field, read):
    _set_section(monkeypatch, key, block)

    with pytest.raises(MissingEnvironmentVariable, match=rf"{MISSING} at {key}\.{re.escape(field)}$"):
        resolve_configuration(get_config())

    monkeypatch.setenv(MISSING, "env_reference")
    resolve_configuration(get_config())

    assert read(get_config()) == "env_reference"


# what an integration's section can get wrong besides naming a missing variable
BROKEN_INTEGRATION_SECTIONS = [
    pytest.param("not a section", ValidationError, id="invalid"),
    pytest.param({"api_key": "file:/nonexistent/env_reference_secret"}, FileNotFoundError, id="unreadable-file"),
]


@pytest.mark.unit
@pytest.mark.parametrize("section, error", BROKEN_INTEGRATION_SECTIONS)
def test_an_integrations_other_errors_still_fail_at_load(monkeypatch, caplog, section, error):
    _set_section(monkeypatch, "env_reference_integration", section)
    # registered by an integration package imported before the configuration is resolved
    monkeypatch.setattr(config_module, "CONFIG_RESOLVED", False)
    register_integration_configuration("env_reference_broken", EnvReferenceIntegrationConfig)

    with caplog.at_level(logging.INFO), pytest.raises(error):
        resolve_configuration(get_config())

    assert not [record for record in caplog.records if "is not loaded" in record.getMessage()]


@pytest.mark.unit
@pytest.mark.parametrize("section, error", BROKEN_INTEGRATION_SECTIONS)
def test_an_integration_registered_late_still_fails_on_its_other_errors(monkeypatch, caplog, section, error):
    _set_section(monkeypatch, "env_reference_integration", section)
    resolve_configuration(get_config())

    with caplog.at_level(logging.INFO), pytest.raises(error):
        register_integration_configuration("env_reference_broken_late", EnvReferenceIntegrationConfig)

    assert not [record for record in caplog.records if "is not loaded" in record.getMessage()]
