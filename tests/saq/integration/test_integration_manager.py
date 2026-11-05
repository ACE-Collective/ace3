import os
import pytest

from saq.integration.integration_manager import (
    _create_symlink_name,
    install_integration,
    uninstall_integration,
    is_integration_installed,
    _ensure_var_dir_exists,
    _get_disabled_path,
    enable_integration,
    disable_integration,
    is_integration_enabled
)
from saq.integration.integration_util import (
    get_integration_var_base_dir
)


@pytest.mark.unit
class TestIntegrationManager:
    
    def test_create_symlink_name(self):
        """Test _create_symlink_name creates correct symlink names."""
        assert _create_symlink_name("test_integration") == "test_external_integration_test_integration"
        assert _create_symlink_name("my-integration") == "test_external_integration_my-integration"
        assert _create_symlink_name("integration.with.dots") == "test_external_integration_integration.with.dots"
    
    def test_get_disabled_path(self):
        """Test _get_disabled_path returns correct disabled file path."""
        test_var_dir = "/var/integrations/test"
        result = _get_disabled_path(test_var_dir)
        
        expected = os.path.join(test_var_dir, "disabled")
        assert result == expected
    
    def test_ensure_var_dir_exists_creates_nested_directories(self, tmpdir):
        """Test _ensure_var_dir_exists creates nested directories."""
        test_dir = os.path.join(str(tmpdir), "level1", "level2", "level3")
        
        # Directory should not exist initially
        assert not os.path.exists(test_dir)
        
        _ensure_var_dir_exists(test_dir)
        
        # All nested directories should exist
        assert os.path.exists(test_dir)
        assert os.path.isdir(test_dir)


@pytest.mark.integration
class TestIntegrationManagerIntegration:
    """Integration tests that use temporary filesystem structures."""
    
    @pytest.fixture
    def temp_integration_structure(self, tmpdir):
        """Create a temporary integration directory structure for testing."""
        # Create temporary base directories
        temp_base = tmpdir.mkdir("temp_ace")
        integrations_dir = temp_base.mkdir("integrations")
        tests_dir = temp_base.mkdir("tests")
        var_dir = temp_base.mkdir("var").mkdir("integrations")
        
        # Create a test integration
        test_integration = integrations_dir.mkdir("test_integration")
        test_integration.join("integration.md").write("# test integration")
        test_integration_tests = test_integration.mkdir("tests")
        test_integration_tests.join("test_example.py").write("# test file")
        
        return {
            "base_dir": str(temp_base),
            "integrations_dir": str(integrations_dir),
            "tests_dir": str(tests_dir),
            "var_dir": str(var_dir),
            "integration_name": "test_integration",
            "integration_path": str(test_integration),
            "integration_tests_path": str(test_integration_tests)
        }
    
    def test_install_integration_success(self, temp_integration_structure, monkeypatch):
        """Test successful integration installation."""
        # Mock the environment functions to use our temporary structure
        monkeypatch.setattr("saq.integration.integration_manager.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        monkeypatch.setattr("saq.integration.integration_util.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        integration_name = temp_integration_structure["integration_name"]
        
        # Install should succeed
        result = install_integration(integration_name)
        assert result is True
        
        # Check that symlink was created
        symlink_name = _create_symlink_name(integration_name)
        symlink_path = os.path.join(temp_integration_structure["tests_dir"], symlink_name)
        assert os.path.exists(symlink_path)
        assert os.path.islink(symlink_path)
    
    def test_install_integration_nonexistent_integration(self, temp_integration_structure, monkeypatch):
        """Test installing non-existent integration returns False."""
        monkeypatch.setattr("saq.integration.integration_manager.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        monkeypatch.setattr("saq.integration.integration_util.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        result = install_integration("nonexistent_integration")
        assert result is False
    
    def test_install_integration_no_tests_directory(self, temp_integration_structure, monkeypatch):
        """Test installing integration without tests directory returns False."""
        monkeypatch.setattr("saq.integration.integration_manager.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        monkeypatch.setattr("saq.integration.integration_util.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        # Create integration without tests directory
        integration_without_tests = os.path.join(temp_integration_structure["integrations_dir"], "no_tests_integration")
        os.makedirs(integration_without_tests)
        with open(os.path.join(integration_without_tests, "integration.md"), "w") as f:
            f.write("# integration")

        result = install_integration("no_tests_integration")
        assert result is False
    
    def test_install_integration_already_installed(self, temp_integration_structure, monkeypatch):
        """Test installing already installed integration returns False."""
        monkeypatch.setattr("saq.integration.integration_manager.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        monkeypatch.setattr("saq.integration.integration_util.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        integration_name = temp_integration_structure["integration_name"]
        
        # Install first time
        result1 = install_integration(integration_name)
        assert result1 is True
        
        # Try to install again
        result2 = install_integration(integration_name)
        assert result2 is False
    
    def test_uninstall_integration_success(self, temp_integration_structure, monkeypatch):
        """Test successful integration uninstallation."""
        monkeypatch.setattr("saq.integration.integration_manager.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        monkeypatch.setattr("saq.integration.integration_util.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        integration_name = temp_integration_structure["integration_name"]
        
        # Install first
        install_result = install_integration(integration_name)
        assert install_result is True
        
        # Verify symlink exists
        symlink_name = _create_symlink_name(integration_name)
        symlink_path = os.path.join(temp_integration_structure["tests_dir"], symlink_name)
        assert os.path.exists(symlink_path)
        
        # Uninstall
        uninstall_result = uninstall_integration(integration_name)
        assert uninstall_result is True
        
        # Verify symlink is gone
        assert not os.path.exists(symlink_path)
    
    def test_uninstall_integration_not_installed(self, temp_integration_structure, monkeypatch):
        """Test uninstalling non-installed integration returns False."""
        monkeypatch.setattr("saq.integration.integration_manager.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        result = uninstall_integration("not_installed_integration")
        assert result is False
    
    def test_is_integration_installed(self, temp_integration_structure, monkeypatch):
        """Test is_integration_installed correctly identifies installation status."""
        monkeypatch.setattr("saq.integration.integration_manager.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        monkeypatch.setattr("saq.integration.integration_util.get_base_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        integration_name = temp_integration_structure["integration_name"]
        
        # Should not be installed initially
        assert is_integration_installed(integration_name) is False
        
        # Install
        install_integration(integration_name)
        
        # Should be installed now
        assert is_integration_installed(integration_name) is True
        
        # Uninstall
        uninstall_integration(integration_name)
        
        # Should not be installed again
        assert is_integration_installed(integration_name) is False
    
    def test_enable_integration_success(self, temp_integration_structure, monkeypatch):
        """Test successful integration enabling."""
        monkeypatch.setattr("saq.integration.integration_util.get_data_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        integration_name = "test_enable_integration"
        
        # First disable the integration
        disable_integration(integration_name)
        
        # Verify it's disabled
        assert is_integration_enabled(integration_name) is False
        
        # Enable it
        result = enable_integration(integration_name)
        assert result is True
        
        # Verify it's enabled
        assert is_integration_enabled(integration_name) is True
    
    def test_enable_integration_already_enabled(self, temp_integration_structure, monkeypatch):
        """Test enabling already enabled integration."""
        monkeypatch.setattr("saq.integration.integration_util.get_data_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        integration_name = "test_already_enabled"
        
        # Should be enabled by default (no disabled file)
        assert is_integration_enabled(integration_name) is True
        
        # Enable again
        result = enable_integration(integration_name)
        assert result is True
        
        # Should still be enabled
        assert is_integration_enabled(integration_name) is True
    
    def test_disable_integration_success(self, temp_integration_structure, monkeypatch):
        """Test successful integration disabling."""
        monkeypatch.setattr("saq.integration.integration_util.get_data_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        integration_name = "test_disable_integration"
        
        # Should be enabled initially
        assert is_integration_enabled(integration_name) is True
        
        # Disable it
        result = disable_integration(integration_name)
        assert result is True
        
        # Verify it's disabled
        assert is_integration_enabled(integration_name) is False
        
        # Verify disabled file exists
        var_dir = os.path.join(get_integration_var_base_dir(), integration_name)
        disabled_path = _get_disabled_path(var_dir)
        assert os.path.exists(disabled_path)
    
    def test_disable_integration_already_disabled(self, temp_integration_structure, monkeypatch):
        """Test disabling already disabled integration."""
        monkeypatch.setattr("saq.integration.integration_util.get_data_dir", 
                           lambda: temp_integration_structure["base_dir"])
        
        integration_name = "test_already_disabled"
        
        # Disable first time
        result1 = disable_integration(integration_name)
        assert result1 is True
        assert is_integration_enabled(integration_name) is False
        
        # Disable again
        result2 = disable_integration(integration_name)
        assert result2 is True
        assert is_integration_enabled(integration_name) is False
