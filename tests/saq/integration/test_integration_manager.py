import os
import pytest

from saq.integration.integration_manager import (
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
        var_dir = temp_base.mkdir("var").mkdir("integrations")
        
        # Create a test integration
        test_integration = integrations_dir.mkdir("test_integration")
        test_integration.join("integration.md").write("# test integration")
        
        return {
            "base_dir": str(temp_base),
            "integrations_dir": str(integrations_dir),
            "var_dir": str(var_dir),
            "integration_name": "test_integration",
            "integration_path": str(test_integration),
        }
    
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
