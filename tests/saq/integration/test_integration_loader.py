import os
import sys
from unittest.mock import patch

import pytest

from saq.environment import get_global_runtime_settings
from saq.integration.integration_loader import (
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

        result = load_integrations()
        assert result is True
        _assert_loaded(integration1)
        _assert_loaded(integration2)

    def test_load_integrations_disabled_integration(self, integration_env):
        """Test disabled integrations are skipped."""
        enabled = integration_env("enabled_integration")
        disabled = integration_env("disabled_integration", disabled=True)

        result = load_integrations()
        assert result is True
        _assert_loaded(enabled)
        assert os.path.join(disabled, "src") not in sys.path
        assert os.path.join(disabled, "bin") not in os.environ["PATH"].split(":")
        assert get_global_runtime_settings().integration_config_paths == [
            os.path.join(enabled, "etc", "saq.integration.yaml")]

    @patch('saq.integration.integration_loader.is_integration_enabled')
    @patch('saq.error.reporting.write_error_report')
    def test_load_integrations_exception_handling(self, mock_report_exception, mock_is_enabled, integration_env):
        """Test exception handling during integration loading."""
        integration_env("integration1")
        mock_is_enabled.side_effect = Exception("Test exception")

        result = load_integrations()
        assert result is False
        mock_report_exception.assert_called_once()


@pytest.mark.unit
class TestLoadIntegrationComponentSrc:
    
    def test_load_integration_component_src_no_src_dir(self, tmpdir):
        """Test loading src component when src directory doesn't exist."""
        result = load_integration_component_src(str(tmpdir))
        assert result is True

    def test_load_integration_component_src_with_src_dir(self, tmpdir):
        """Test loading src component with existing src directory."""
        src_dir = tmpdir.mkdir("src")
        src_path = str(src_dir)
        
        # Ensure src_path is not in sys.path initially
        if src_path in sys.path:
            sys.path.remove(src_path)
            
        result = load_integration_component_src(str(tmpdir))
        assert result is True
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
        
        result = load_integration_component_src(str(tmpdir))
        assert result is True
        # Should not be added again
        assert len(sys.path) == original_path_length
        
        # Clean up
        if src_path in sys.path:
            sys.path.remove(src_path)


@pytest.mark.unit
class TestLoadIntegrationComponentBin:
    
    def test_load_integration_component_bin_no_bin_dir(self, tmpdir):
        """Test loading bin component when bin directory doesn't exist."""
        result = load_integration_component_bin(str(tmpdir))
        assert result is True

    def test_load_integration_component_bin_with_bin_dir(self, tmpdir):
        """Test loading bin component with existing bin directory."""
        bin_dir = tmpdir.mkdir("bin")
        bin_path = str(bin_dir)
        
        # Store original PATH
        original_path = os.environ.get("PATH", "")
        
        result = load_integration_component_bin(str(tmpdir))
        assert result is True
        assert bin_path in os.environ["PATH"]
        
        # Restore original PATH
        os.environ["PATH"] = original_path

    def test_load_integration_component_bin_already_in_path(self, tmpdir):
        """Test loading bin component when bin directory already in PATH."""
        bin_dir = tmpdir.mkdir("bin")
        bin_path = str(bin_dir)
        
        # Add to PATH first
        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{original_path}:{bin_path}"
        
        result = load_integration_component_bin(str(tmpdir))
        assert result is True
        
        # Restore original PATH
        os.environ["PATH"] = original_path


@pytest.mark.unit
class TestLoadIntegrationComponentEtc:
    
    def test_load_integration_component_etc_no_etc_dir(self, tmpdir):
        """Test loading etc component when etc directory doesn't exist."""
        result = load_integration_component_etc(str(tmpdir))
        assert result is True

    def test_load_integration_component_etc_with_ini_files(self, monkeypatch, tmpdir):
        """Test loading etc component with ini files."""
        etc_dir = tmpdir.mkdir("etc")
        config_file = etc_dir.join("saq.integration.yaml")
        config_file.write("section:\n  key: value")
        monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
        result = load_integration_component_etc(str(tmpdir))
        assert result is True
        assert get_global_runtime_settings().integration_config_paths == [str(config_file)]

    def test_load_integration_component_etc_non_ini_files_ignored(self, monkeypatch, tmpdir):
        """Test loading etc component ignores non-ini files."""
        etc_dir = tmpdir.mkdir("etc")
        txt_file = etc_dir.join("test.txt")
        txt_file.write("some content")
        
        monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
        
        result = load_integration_component_etc(str(tmpdir))
        assert result is True
        assert get_global_runtime_settings().integration_config_paths == []

    def test_load_integration_component_etc_multiple_ini_files(self, monkeypatch, tmpdir):
        """Test loading etc component with multiple ini files."""
        etc_dir = tmpdir.mkdir("etc")
        config1 = etc_dir.join("saq.integration.yaml")
        config1.write("section1:\n  key1: value1")
        config2 = etc_dir.join("config2.yaml")
        config2.write("section2:\n  key2: value2")
        
        monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
        
        result = load_integration_component_etc(str(tmpdir))
        assert result is True
        assert get_global_runtime_settings().integration_config_paths == [str(config1)]


@pytest.mark.unit
class TestLoadIntegrationFromDirectory:

    def test_load_integration_from_directory_all_components(self, integration_env):
        """Test loading integration from directory wires src, bin and etc."""
        integration_dir = integration_env("integration1")

        result = load_integration_from_directory(integration_dir)
        assert result is True
        _assert_loaded(integration_dir)
