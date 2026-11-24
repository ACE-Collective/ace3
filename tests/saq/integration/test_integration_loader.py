import logging
from logging.handlers import BufferingHandler
import os
import sys
import uuid
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import saq.environment
from saq.configuration.schema import IntegrationConfig
from saq.environment import get_base_dir, get_data_dir, get_global_runtime_settings, get_temp_dir, initialize_environment
from saq.error.reporting import ErrorReportHandler
from saq.integration.integration_loader import (
    initialize_integrations,
    load_integrations,
    load_integration_component_src,
    load_integration_component_bin,
    load_integration_component_etc,
    load_integration_from_directory,
)
from saq.integration.integration_util import (
    get_integration_var_base_dir,
    validate_integration_dir,
    _recurse_integration_dirs,
)
from tests.saq.helpers import configure_integrations, unconfigured_logging


@pytest.mark.unit
class TestValidateIntegrationDir:
    
    def test_validate_integration_dir_missing_integration_md(self, tmpdir):
        """Test validation fails when integration.md is missing."""
        result = validate_integration_dir(str(tmpdir))
        assert result is False

@pytest.mark.unit
class TestRecurseIntegrationDirs:
    
    def test_recurse_integration_dirs_nested_integrations(self, tmpdir):
        """Test recursion finds nested integrations."""
        # Create nested structure
        level1 = tmpdir.mkdir("level1")
        level1_integration = level1.mkdir("integration1")
        level1_integration.join("integration.md").write("# Integration")
        
        level2 = level1.mkdir("level2")
        level2_integration = level2.mkdir("integration2")
        level2_integration.join("integration.md").write("# Integration")
        
        result = _recurse_integration_dirs(str(tmpdir))
        assert len(result) == 2
        assert str(level1_integration) in result
        assert str(level2_integration) in result

    def test_recurse_integration_dirs_mixed_valid_invalid(self, tmpdir):
        """Test recursion only returns valid integrations."""
        # Valid integration
        valid_integration = tmpdir.mkdir("valid")
        valid_integration.join("integration.md").write("# Integration")
        
        # Invalid integration (missing integration.md)
        tmpdir.mkdir("invalid")
        
        # Regular directory with valid integration inside
        nested_dir = tmpdir.mkdir("nested")
        nested_integration = nested_dir.mkdir("nested_integration")
        nested_integration.join("integration.md").write("# Integration")
        
        result = _recurse_integration_dirs(str(tmpdir))
        assert len(result) == 2
        assert str(valid_integration) in result
        assert str(nested_integration) in result


@pytest.fixture
def integration_env(tmp_path, monkeypatch):
    """Points the integration base and var dirs at tmp_path and restores what loading changes.

    Returns a function that creates an integration directory the way integrations.example/ lays
    one out: integration.md, src/<package>/, bin/ and etc/saq.integration.yaml, which declares
    integration_<name>: with the given enabled.
    """
    base_dir = tmp_path / "base"
    data_dir = tmp_path / "data"
    (base_dir / "integrations").mkdir(parents=True)
    data_dir.mkdir()
    monkeypatch.setattr("saq.integration.integration_util.get_base_dir", lambda: str(base_dir))
    monkeypatch.setattr("saq.integration.integration_util.get_data_dir", lambda: str(data_dir))
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])

    def create(name: str, enabled: bool = True) -> str:
        integration_dir = base_dir / "integrations" / name
        (integration_dir / "src" / name).mkdir(parents=True)
        (integration_dir / "src" / name / "__init__.py").write_text("")
        (integration_dir / "bin").mkdir()
        (integration_dir / "etc").mkdir()
        (integration_dir / "etc" / "saq.integration.yaml").write_text(
            f"integration_{name}:\n  name: {name}\n  enabled: {str(enabled).lower()}\n"
            f"  description: {name}\n  python_module: {name}\n")
        (integration_dir / "integration.md").write_text(f"# {name}")
        return str(integration_dir)

    return create


def _on_path(integration_dir: str) -> bool:
    return os.path.join(integration_dir, "bin") in os.environ["PATH"].split(":")


@pytest.mark.unit
class TestLoadIntegrations:

    def test_every_integration_is_on_sys_path_and_merged(self, integration_env):
        """The configuration loader leaves a disabled integration's file out, but its src/ stays on
        sys.path so that alerts saved while it was enabled still load their analysis."""
        enabled = integration_env("enabled_integration")
        disabled = integration_env("disabled_integration", enabled=False)

        load_integrations()

        for integration_dir in (enabled, disabled):
            assert os.path.join(integration_dir, "src") in sys.path
            # the configuration decides who goes on PATH, so nobody does before it is loaded
            assert not _on_path(integration_dir)
        assert sorted(get_global_runtime_settings().integration_config_paths) == sorted(
            os.path.join(integration_dir, "etc", "saq.integration.yaml") for integration_dir in (enabled, disabled))

    def test_load_integrations_component_raises(self, integration_env, monkeypatch, caplog):
        """A component that raises fails that integration, is logged with its traceback, and the rest still load."""
        healthy = integration_env("healthy")
        broken = integration_env("broken")
        real_load_etc = load_integration_component_etc

        def load_etc(dir_path: str):
            if dir_path == broken:
                raise KeyError("broken")
            real_load_etc(dir_path)

        monkeypatch.setattr("saq.integration.integration_loader.load_integration_component_etc", load_etc)

        load_integrations()

        assert os.path.join(healthy, "src") in sys.path
        assert get_global_runtime_settings().integration_config_paths == [
            os.path.join(healthy, "etc", "saq.integration.yaml")]

        failures = [r for r in caplog.records if r.message.startswith(f"failed to load integration from {broken}")]
        assert len(failures) == 1
        assert failures[0].levelname == "ERROR"
        assert failures[0].exc_info[0] is KeyError


@pytest.mark.unit
class TestInitializeIntegrations:

    def test_only_an_integration_that_is_on_goes_on_path(self, integration_env, monkeypatch):
        enabled = integration_env("enabled_integration")
        disabled = integration_env("disabled_integration", enabled=False)
        load_integrations()
        configure_integrations(monkeypatch)
        # neither package exists to import, and that is not what this is about
        monkeypatch.setattr("saq.integration.integration_loader.importlib.import_module", Mock())

        initialize_integrations()

        assert _on_path(enabled)
        assert not _on_path(disabled)

    def test_a_failure_putting_bin_on_path_is_logged(self, integration_env, monkeypatch, caplog):
        broken = integration_env("broken")
        load_integrations()
        configure_integrations(monkeypatch)
        monkeypatch.setattr("saq.integration.integration_loader.importlib.import_module", Mock())
        # the bin component raises KeyError reading PATH
        monkeypatch.delenv("PATH")

        initialize_integrations()

        failures = [r for r in caplog.records if r.message.startswith(f"failed to initialize integration from {broken}")]
        assert len(failures) == 1
        assert failures[0].levelname == "ERROR"
        assert failures[0].exc_info[0] is KeyError

    @pytest.mark.parametrize("enabled, advice", [
        (True, "so it is enabled. To disable it set integration_vendor.enabled: false in the configuration"),
        (False, "and its configuration already disables it: remove the file")])
    def test_the_file_ace_integration_disable_left_is_reported(self, integration_env, monkeypatch, caplog, enabled, advice):
        """Nothing reads the file any more, so the integration it turned off is back on unless its
        configuration turns it off. It is logged at every start until someone removes it."""
        integration_dir = integration_env("vendor", enabled=enabled)
        marker = os.path.join(get_integration_var_base_dir(), "vendor", "disabled")
        os.makedirs(os.path.dirname(marker))
        open(marker, "w").close()
        load_integrations()
        configure_integrations(monkeypatch)
        monkeypatch.setattr("saq.integration.integration_loader.importlib.import_module", Mock())

        initialize_integrations()

        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1
        assert errors[0].message.startswith(
            f"integration vendor ({integration_dir}) has the file {marker}, which ace integration disable wrote")
        assert advice in errors[0].message
        assert errors[0].integration == "vendor"
        assert errors[0].path == marker

    def test_no_file_no_report(self, integration_env, monkeypatch, caplog):
        integration_env("vendor")
        load_integrations()
        configure_integrations(monkeypatch)
        monkeypatch.setattr("saq.integration.integration_loader.importlib.import_module", Mock())

        initialize_integrations()

        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_import_failure_is_logged_at_error(self, integration_env, monkeypatch, caplog):
        """An integration package that fails to import is logged at ERROR with its traceback."""
        config = SimpleNamespace(integrations=[IntegrationConfig(
            name="broken", description="broken", enabled=True, python_module="no_such_integration_package")])
        monkeypatch.setattr("saq.integration.integration_loader.get_config", lambda: config)

        initialize_integrations()

        failures = [r for r in caplog.records if r.message.startswith("failed to import integration module broken")]
        assert len(failures) == 1
        assert failures[0].levelname == "ERROR"
        assert failures[0].exc_info[0] is ModuleNotFoundError

    def test_a_disabled_integration_is_not_imported(self, integration_env, monkeypatch, caplog):
        """Its hooks would register observable actions whose templates live in the GUI blueprint
        apply_integration_hooks() leaves out for it. It is declared, so it is not warned about either."""
        token = uuid.uuid4().hex
        names = {True: f"switched_on_{token}", False: f"switched_off_{token}"}
        for name in names.values():
            load_integration_from_directory(integration_env(name))
            monkeypatch.delitem(sys.modules, name, raising=False)
        monkeypatch.setattr("saq.integration.integration_loader.get_config", lambda: SimpleNamespace(integrations=[
            IntegrationConfig(name=name, description=name, enabled=enabled, python_module=name)
            for enabled, name in names.items()]))

        with caplog.at_level(logging.WARNING):
            initialize_integrations()

        assert names[True] in sys.modules
        assert names[False] not in sys.modules
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_undeclared_integration_is_logged_at_warning(self, integration_env, monkeypatch, caplog):
        """An integration directory with no integration_*: block is logged at WARNING."""
        undeclared = integration_env("undeclared")
        monkeypatch.setattr("saq.integration.integration_loader.get_config", lambda: SimpleNamespace(integrations=[]))

        initialize_integrations()

        warnings = [r for r in caplog.records if r.message.startswith(f"integration undeclared ({undeclared}) declares no")]
        assert len(warnings) == 1
        assert warnings[0].levelname == "WARNING"


class _Stop(Exception):
    pass


@pytest.mark.unit
def test_startup_failures_reach_the_configured_handlers(integration_env, monkeypatch, capsys):
    """What initialize_environment() logs before it has configured logging reaches the handlers
    initialize_logging() installs, and a failure with a traceback writes its error report (#817)."""
    broken = integration_env("broken")
    monkeypatch.setattr("saq.integration.integration_loader.load_integration_from_directory",
                        Mock(side_effect=RuntimeError("load failed")))
    # nothing declares the integration, so initialize_integrations() warns about it too
    monkeypatch.setattr("saq.integration.integration_loader.get_config", lambda: SimpleNamespace(integrations=[]))

    # keep the session's configuration and runtime settings
    monkeypatch.setattr("saq.configuration.initialize_configuration", lambda config_paths: None)
    monkeypatch.setattr(saq.environment, "GLOBAL_RUNTIME_SETTINGS", get_global_runtime_settings().model_copy(deep=True))

    collector = BufferingHandler(capacity=100)
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

    def initialize_logging(*args, **kwargs):
        logging_root = logging.getLogger()
        logging_root.addHandler(collector)
        logging_root.addHandler(ErrorReportHandler())

    monkeypatch.setattr("saq.logging.initialize_logging", initialize_logging)
    # logging is configured by the time encryption is initialized, so stop there
    monkeypatch.setattr("saq.crypto.initialize_encryption", Mock(side_effect=_Stop))

    with unconfigured_logging():
        with pytest.raises(_Stop):
            initialize_environment(saq_home=get_base_dir(), data_dir=get_data_dir(), temp_dir=get_temp_dir(), config_paths=[])

    failures = [r for r in collector.buffer if r.getMessage().startswith(f"failed to load integration from {broken}")]
    assert len(failures) == 1
    assert failures[0].levelname == "ERROR"
    assert failures[0].exc_info[0] is RuntimeError
    write_error_report.assert_called_once()
    assert write_error_report.call_args.args[0][0] is RuntimeError

    assert any(r.levelname == "WARNING" and r.getMessage().startswith("integration broken") for r in collector.buffer)

    # nothing went to an implicit stderr handler first
    assert "failed to load integration" not in capsys.readouterr().err


@pytest.mark.unit
class TestLoadIntegrationComponentSrc:
    
    def test_load_integration_component_src_no_src_dir(self, tmpdir):
        """Test loading src component when src directory doesn't exist."""
        original_path = list(sys.path)
        load_integration_component_src(str(tmpdir))
        assert sys.path == original_path

    def test_load_integration_component_src_already_in_path(self, tmpdir):
        """Test loading src component when src directory already in sys.path."""
        src_dir = tmpdir.mkdir("src")
        src_path = str(src_dir)
        
        # Add to sys.path first
        sys.path.append(src_path)
        original_path_length = len(sys.path)
        
        load_integration_component_src(str(tmpdir))
        # Should not be added again
        assert len(sys.path) == original_path_length
        
        # Clean up
        if src_path in sys.path:
            sys.path.remove(src_path)


@pytest.mark.unit
class TestLoadIntegrationComponentBin:
    
    def test_load_integration_component_bin_already_in_path(self, monkeypatch, tmpdir):
        """Test loading bin component when bin directory already in PATH."""
        bin_dir = tmpdir.mkdir("bin")
        bin_path = str(bin_dir)

        # monkeypatch restores PATH even when the assertion fails
        path_with_bin = f"{os.environ['PATH']}:{bin_path}"
        monkeypatch.setenv("PATH", path_with_bin)

        load_integration_component_bin(str(tmpdir))
        # Should not be added again
        assert os.environ["PATH"] == path_with_bin


@pytest.mark.unit
class TestLoadIntegrationComponentEtc:
    
    def test_load_integration_component_etc_non_ini_files_ignored(self, monkeypatch, tmpdir):
        """Test loading etc component ignores non-ini files."""
        etc_dir = tmpdir.mkdir("etc")
        txt_file = etc_dir.join("test.txt")
        txt_file.write("some content")
        
        monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
        
        load_integration_component_etc(str(tmpdir))
        assert get_global_runtime_settings().integration_config_paths == []

    def test_load_integration_component_etc_multiple_ini_files(self, monkeypatch, tmpdir):
        """Test loading etc component with multiple ini files."""
        etc_dir = tmpdir.mkdir("etc")
        config1 = etc_dir.join("saq.integration.yaml")
        config1.write("section1:\n  key1: value1")
        config2 = etc_dir.join("config2.yaml")
        config2.write("section2:\n  key2: value2")
        
        monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
        
        load_integration_component_etc(str(tmpdir))
        assert get_global_runtime_settings().integration_config_paths == [str(config1)]


@pytest.mark.unit
def test_the_tests_load_this_checkouts_integrations():
    # tests/harness.py puts every integration's source on sys.path before ACE is initialized, and the loader
    # appends, so whatever it adds first wins. Run from a checkout other than /opt/ace (a worktree), it used to add
    # /opt/ace's integrations, and every test imported that checkout's integration code instead of this one's
    own = os.path.realpath(get_base_dir())

    def other_checkout(path: str) -> bool:
        # under <checkout>/integrations/, where <checkout> is an ACE checkout (it has saq/) other than this one
        marker = f"{os.sep}integrations{os.sep}"
        if marker not in path:
            return False
        checkout = path.split(marker, 1)[0]
        return os.path.isdir(os.path.join(checkout, "saq")) and os.path.realpath(checkout) != own

    others = [path for path in sys.path if other_checkout(path)]
    loaded = [module.__file__ for module in list(sys.modules.values())
              if other_checkout(getattr(module, "__file__", None) or "")]
    assert not others, others
    assert not loaded, loaded[:5]
