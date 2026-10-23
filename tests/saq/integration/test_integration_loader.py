import logging
from logging.handlers import BufferingHandler
import os
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

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
    load_integration_from_directory
)
from saq.integration.integration_manager import disable_integration
from saq.integration.integration_util import (
    validate_integration_dir,
    _recurse_integration_dirs,
    get_valid_integration_dirs,
)
from tests.saq.helpers import unconfigured_logging


@pytest.mark.unit
class TestValidateIntegrationDir:
    
    def test_validate_integration_dir_nonexistent_path(self):
        """Test validation fails for non-existent path."""
        result = validate_integration_dir("/nonexistent/path")
        assert result is False

    def test_validate_integration_dir_not_directory(self, tmpdir):
        """Test validation fails for non-directory path."""
        file_path = tmpdir.join("not_a_dir")
        file_path.write("content")
        
        result = validate_integration_dir(str(file_path))
        assert result is False

    def test_validate_integration_dir_missing_integration_md(self, tmpdir):
        """Test validation fails when integration.md is missing."""
        result = validate_integration_dir(str(tmpdir))
        assert result is False

    def test_validate_integration_dir_valid(self, tmpdir):
        """Test validation passes for valid integration directory."""
        integration_md = tmpdir.join("integration.md")
        integration_md.write("# Integration")
        
        result = validate_integration_dir(str(tmpdir))
        assert result is True


@pytest.mark.unit
class TestRecurseIntegrationDirs:
    
    def test_recurse_integration_dirs_empty_directory(self, tmpdir):
        """Test recursion returns empty list for empty directory."""
        result = _recurse_integration_dirs(str(tmpdir))
        assert result == []

    def test_recurse_integration_dirs_single_valid_integration(self, tmpdir):
        """Test recursion finds single valid integration."""
        integration_dir = tmpdir.mkdir("integration1")
        integration_dir.join("integration.md").write("# Integration")
        
        result = _recurse_integration_dirs(str(tmpdir))
        assert len(result) == 1
        assert str(integration_dir) in result

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


@pytest.mark.unit
class TestGetValidIntegrationDirs:
    
    @patch('saq.integration.integration_util.get_integration_base_dir')
    def test_get_valid_integration_dirs(self, mock_get_base_dir, tmpdir):
        """Test getting valid integration directories."""
        mock_get_base_dir.return_value = str(tmpdir)
        
        # Create valid integration
        integration = tmpdir.mkdir("test_integration")
        integration.join("integration.md").write("# Test Integration")
        
        result = get_valid_integration_dirs()
        assert len(result) == 1
        assert str(integration) in result


@pytest.fixture
def integration_env(tmp_path, monkeypatch):
    """Points the integration base and var dirs at tmp_path and restores what loading changes.

    Returns a function that creates an integration directory the way integrations.example/ lays
    one out: integration.md, src/<package>/, bin/ and etc/saq.integration.yaml.
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

    def create(name: str, disabled: bool = False) -> str:
        integration_dir = base_dir / "integrations" / name
        (integration_dir / "src" / name).mkdir(parents=True)
        (integration_dir / "src" / name / "__init__.py").write_text("")
        (integration_dir / "bin").mkdir()
        (integration_dir / "etc").mkdir()
        (integration_dir / "etc" / "saq.integration.yaml").write_text(f"integration_{name}:\n  name: {name}\n")
        (integration_dir / "integration.md").write_text(f"# {name}")
        if disabled:
            disable_integration(name)
        return str(integration_dir)

    return create


def _assert_loaded(integration_dir: str):
    assert os.path.join(integration_dir, "src") in sys.path
    assert os.path.join(integration_dir, "bin") in os.environ["PATH"].split(":")
    assert os.path.join(integration_dir, "etc", "saq.integration.yaml") in get_global_runtime_settings().integration_config_paths


@pytest.mark.unit
class TestLoadIntegrations:

    def test_load_integrations_all_enabled_success(self, integration_env):
        """Test loading all enabled integrations successfully."""
        integration1 = integration_env("integration1")
        integration2 = integration_env("integration2")

        load_integrations()
        _assert_loaded(integration1)
        _assert_loaded(integration2)

    def test_load_integrations_disabled_integration(self, integration_env):
        """Test disabled integrations are skipped."""
        enabled = integration_env("enabled_integration")
        disabled = integration_env("disabled_integration", disabled=True)

        load_integrations()
        _assert_loaded(enabled)
        assert os.path.join(disabled, "src") not in sys.path
        assert os.path.join(disabled, "bin") not in os.environ["PATH"].split(":")
        assert get_global_runtime_settings().integration_config_paths == [
            os.path.join(enabled, "etc", "saq.integration.yaml")]

    @patch('saq.integration.integration_loader.is_integration_enabled')
    @patch('saq.error.reporting.write_error_report')
    def test_load_integrations_exception_handling(self, mock_write_error_report, mock_is_enabled, integration_env):
        """Test exception handling during integration loading."""
        integration_env("integration1")
        mock_is_enabled.side_effect = Exception("Test exception")

        load_integrations()
        mock_write_error_report.assert_called_once()

    def test_load_integrations_component_raises(self, integration_env, monkeypatch, caplog):
        """A component that raises fails that integration, is logged with its traceback, and the rest still load."""
        healthy = integration_env("healthy")
        # without a bin/ the bin component never reads PATH, so only the other integration fails
        os.rmdir(os.path.join(healthy, "bin"))
        broken = integration_env("broken")
        # the bin component raises KeyError reading PATH
        monkeypatch.delenv("PATH")

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

    def test_load_integration_component_src_with_src_dir(self, tmpdir):
        """Test loading src component with existing src directory."""
        src_dir = tmpdir.mkdir("src")
        src_path = str(src_dir)
        
        # Ensure src_path is not in sys.path initially
        if src_path in sys.path:
            sys.path.remove(src_path)
            
        load_integration_component_src(str(tmpdir))
        assert src_path in sys.path
        
        # Clean up
        if src_path in sys.path:
            sys.path.remove(src_path)

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
    
    def test_load_integration_component_bin_no_bin_dir(self, tmpdir):
        """Test loading bin component when bin directory doesn't exist."""
        original_path = os.environ["PATH"]
        load_integration_component_bin(str(tmpdir))
        assert os.environ["PATH"] == original_path

    def test_load_integration_component_bin_with_bin_dir(self, tmpdir):
        """Test loading bin component with existing bin directory."""
        bin_dir = tmpdir.mkdir("bin")
        bin_path = str(bin_dir)
        
        # Store original PATH
        original_path = os.environ.get("PATH", "")
        
        load_integration_component_bin(str(tmpdir))
        assert bin_path in os.environ["PATH"]
        
        # Restore original PATH
        os.environ["PATH"] = original_path

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
    
    def test_load_integration_component_etc_no_etc_dir(self, monkeypatch, tmpdir):
        """Test loading etc component when etc directory doesn't exist."""
        monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
        load_integration_component_etc(str(tmpdir))
        assert get_global_runtime_settings().integration_config_paths == []

    def test_load_integration_component_etc_with_ini_files(self, monkeypatch, tmpdir):
        """Test loading etc component with ini files."""
        etc_dir = tmpdir.mkdir("etc")
        config_file = etc_dir.join("saq.integration.yaml")
        config_file.write("section:\n  key: value")
        monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
        load_integration_component_etc(str(tmpdir))
        assert get_global_runtime_settings().integration_config_paths == [str(config_file)]

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
class TestLoadIntegrationFromDirectory:

    def test_load_integration_from_directory_all_components(self, integration_env):
        """Test loading integration from directory wires src, bin and etc."""
        integration_dir = integration_env("integration1")

        load_integration_from_directory(integration_dir)
        _assert_loaded(integration_dir)
