import os
import sys

import pytest

from saq.configuration.yaml_parser import (
    YAMLConfig,
)
from saq.environment import get_global_runtime_settings, get_base_dir


@pytest.mark.unit
def test_yaml_config_initialization():
    """Test YAMLConfig initialization."""
    config = YAMLConfig()
    
    assert isinstance(config._data, dict)
    assert len(config._data) == 0
    assert isinstance(config.encrypted_password_cache, dict)
    assert isinstance(config.loaded_files, set)
    assert len(config.loaded_files) == 0


@pytest.mark.unit
def test_yaml_config_environment_variable_resolution():
    """Test environment variable resolution in YAMLConfig."""
    # Set up test environment variables
    os.environ["TEST_YAML_VAR1"] = "env_value_1"
    os.environ["TEST_YAML_VAR2"] = "env_value_2"
    
    try:
        config = YAMLConfig()
        
        # Test env: prefix resolution
        assert config._resolve_value("env:TEST_YAML_VAR2") == "env_value_2"
        
        # Test error for unknown environment variable
        with pytest.raises(RuntimeError, match="configuration referenced unknown environment variable"):
            config._resolve_value("env:NONEXISTENT_VAR")
        
        # Test regular strings are not modified
        assert config._resolve_value("regular_string") == "regular_string"
        assert config._resolve_value("prefix:but_not_env") == "prefix:but_not_env"
        
    finally:
        del os.environ["TEST_YAML_VAR1"]
        del os.environ["TEST_YAML_VAR2"]


@pytest.mark.unit
def test_yaml_config_encrypted_password_resolution(monkeypatch):
    """Test encrypted password resolution in YAMLConfig."""
    config = YAMLConfig()
    
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_initialized", False)
        
    # Test encrypted: prefix when encryption not initialized
    result = config._resolve_value("encrypted:test_key")
    assert result == "encrypted:test_key"


@pytest.mark.unit
def test_yaml_config_load_file_basic(tmpdir):
    """Test basic YAML file loading."""
    yaml_file = tmpdir.join("test.yaml")
    yaml_content = """
section1:
  key1: value1
  key2: value2

section2:
  key3: value3
  key4: 42
"""
    yaml_file.write(yaml_content)
    
    config = YAMLConfig()
    result = config.load_file(str(yaml_file))
    
    assert result is True  # File was loaded
    data = config._data
    assert "section1" in data
    assert "section2" in data
    
    assert data["section1"]["key1"] == "value1"
    assert data["section1"]["key2"] == "value2"
    assert data["section2"]["key3"] == "value3"
    assert data["section2"]["key4"] == 42
    
    assert str(yaml_file) in config.loaded_files
    
    # Test loading same file again returns False
    result = config.load_file(str(yaml_file))
    assert result is False


@pytest.mark.unit
def test_yaml_config_load_file_invalid_yaml(tmpdir):
    """Test YAML file loading with invalid content."""
    yaml_file = tmpdir.join("invalid.yaml")
    yaml_content = "not_a_mapping"
    yaml_file.write(yaml_content)
    
    config = YAMLConfig()
    
    with pytest.raises(ValueError, match="YAML configuration root must be a mapping"):
        config.load_file(str(yaml_file))


@pytest.mark.unit
def test_yaml_config_merge():
    """Test the merge method for merging configurations."""
    config = YAMLConfig()
    config._data["section1"] = {"key1": "value1", "key2": "value2"}
    config._data["section2"] = {"key3": "value3"}
    
    # Apply another configuration
    other_config = {
        "section1": {"key1": "updated_value1", "key4": "value4"},  # Update and add
        "section3": {"key5": "value5"}  # New section
    }
    
    config.merge(other_config)
    
    # Check that existing values were updated
    assert config._data["section1"]["key1"] == "updated_value1"
    # Check that existing values not in other_config remain
    assert config._data["section1"]["key2"] == "value2"
    # Check that new values were added
    assert config._data["section1"]["key4"] == "value4"
    # Check that untouched sections remain
    assert config._data["section2"]["key3"] == "value3"
    # Check that new sections were added
    assert config._data["section3"]["key5"] == "value5"


@pytest.mark.unit
def test_yaml_config_resolve_references_list(tmpdir):
    """Test resolve_references with list of includes."""
    # Create include files
    include1 = tmpdir.join("include1.yaml")
    include1.write("""
included_section1:
  inc_key1: inc_value1
""")
    
    include2 = tmpdir.join("include2.yaml")
    include2.write("""
included_section2:
  inc_key2: inc_value2
""")
    
    # Create main file with config list
    main_file = tmpdir.join("main.yaml")
    main_file.write(f"""
config:
  - {include1}
  - {include2}

main_section:
  main_key: main_value
""")
    
    config = YAMLConfig()
    config.load_file(str(main_file))
    
    # Check that all sections are loaded
    assert "main_section" in config._data
    assert "included_section1" in config._data
    assert "included_section2" in config._data
    
    assert config._data["main_section"]["main_key"] == "main_value"
    assert config._data["included_section1"]["inc_key1"] == "inc_value1"
    assert config._data["included_section2"]["inc_key2"] == "inc_value2"
    
    # Check that all files are in loaded_files
    assert str(main_file) in config.loaded_files
    assert str(include1) in config.loaded_files
    assert str(include2) in config.loaded_files


@pytest.mark.unit
def test_yaml_config_resolve_references_mapping(tmpdir):
    """Test resolve_references with mapping of includes."""
    # Create include files
    include1 = tmpdir.join("db.yaml")
    include1.write("""
database:
  host: localhost
  port: 3306
""")
    
    include2 = tmpdir.join("cache.yaml")
    include2.write("""
redis:
  host: redis-server
  port: 6379
""")
    
    # Create main file with config mapping
    main_file = tmpdir.join("main.yaml")
    main_file.write(f"""
config:
  database: {include1}
  cache: {include2}

app:
  name: test_app
""")
    
    config = YAMLConfig()
    config.load_file(str(main_file))
    
    # Check that all sections are loaded
    assert "app" in config._data
    assert "database" in config._data
    assert "redis" in config._data
    
    assert config._data["app"]["name"] == "test_app"
    assert config._data["database"]["host"] == "localhost"
    assert config._data["database"]["port"] == 3306
    assert config._data["redis"]["host"] == "redis-server"


@pytest.mark.unit
def test_yaml_config_resolve_references_non_yaml_skipped(tmpdir):
    """Test that non-YAML includes are skipped with warning."""
    # Create a non-YAML file
    txt_file = tmpdir.join("config.txt")
    txt_file.write("some config text")
    
    # Create main file
    main_file = tmpdir.join("main.yaml")
    main_file.write(f"""
config:
  - {txt_file}

main_section:
  key: value
""")
    
    config = YAMLConfig()
    
    # This should not raise an error, but should log a warning
    config.load_file(str(main_file))
    
    # Main section should still be loaded
    assert "main_section" in config._data
    assert config._data["main_section"]["key"] == "value"
    
    # txt file should not be in loaded_files
    assert str(txt_file) not in config.loaded_files


@pytest.mark.unit
def test_yaml_config_apply_path_references():
    """Test apply_path_references method."""
    # Save original sys.path
    original_path = sys.path.copy()
    
    try:
        config = YAMLConfig()
        test_path1 = "/test/path1"
        test_path2 = "/test/path2"
        
        # Set up path section with various value types
        config._data["path"] = {
            "path1": test_path1,
            "path2": test_path2,
            "not_string": 42,  # Should be ignored
        }
        
        config.apply_path_references()
        
        # Check that string paths were added to sys.path
        assert test_path1 in sys.path
        assert test_path2 in sys.path
        
    finally:
        # Restore original sys.path
        sys.path[:] = original_path


@pytest.mark.unit
def test_yaml_config_apply_path_references_with_env_var():
    """Test apply_path_references with environment variable."""
    os.environ["TEST_PATH_VAR"] = "/env/test/path"
    original_path = sys.path.copy()
    
    try:
        config = YAMLConfig()
        config._data["path"] = {"env_path": "env:TEST_PATH_VAR"}
        
        config.apply_path_references()
        
        # Check that resolved path was added
        assert "/env/test/path" in sys.path
        
    finally:
        del os.environ["TEST_PATH_VAR"]
        sys.path[:] = original_path


@pytest.mark.unit
def test_yaml_config_apply_path_references_no_path_section():
    """Test apply_path_references when no path section exists."""
    original_path = sys.path.copy()
    
    try:
        config = YAMLConfig()
        config._data["other_section"] = {"key": "value"}
        
        # Should not raise an error
        config.apply_path_references()
        
        # sys.path should be unchanged
        assert sys.path == original_path
        
    finally:
        sys.path[:] = original_path


@pytest.mark.unit
def test_yaml_config_apply_path_references_non_dict_path_section():
    """Test apply_path_references when path section is not a dict."""
    original_path = sys.path.copy()
    
    try:
        config = YAMLConfig()
        # This would happen if someone puts 'path: some_string' at top level
        config._data["path"] = "not_a_dict"
        
        # Should not raise an error
        config.apply_path_references()
        
        # sys.path should be unchanged
        assert sys.path == original_path
        
    finally:
        sys.path[:] = original_path


@pytest.mark.unit
def test_yaml_config_recursive_includes(tmpdir):
    """Test recursive includes and circular reference handling."""
    # Create files that include each other
    file1 = tmpdir.join("file1.yaml")
    file2 = tmpdir.join("file2.yaml")
    
    file1.write(f"""
config:
  - {file2}

section1:
  key1: value1
""")
    
    file2.write(f"""
config:
  - {file1}  # This creates a circular reference

section2:
  key2: value2
""")
    
    config = YAMLConfig()
    config.load_file(str(file1))
    
    # Should handle circular references gracefully
    assert "section1" in config._data
    assert "section2" in config._data
    assert config._data["section1"]["key1"] == "value1"
    assert config._data["section2"]["key2"] == "value2"
    
    # Both files should be in loaded_files (loaded only once each)
    assert str(file1) in config.loaded_files
    assert str(file2) in config.loaded_files


@pytest.mark.unit
def test_yaml_config_get_decrypted_password_cached():
    """Test _get_decrypted_password with cached value."""
    config = YAMLConfig()
    
    # Pre-populate cache
    config.encrypted_password_cache["test_key"] = "cached_password"
    
    result = config._get_decrypted_password("test_key")
    assert result == "cached_password"


@pytest.mark.unit
def test_yaml_config_merge_scalars():
    """Test merge with scalar values - scalars should be replaced."""
    config = YAMLConfig()
    config._data = {
        "section1": {"key1": "original_value", "key2": 42, "key3": True}
    }

    # Merge with updated scalar values
    other_config = {
        "section1": {"key1": "new_value", "key2": 99}
    }

    config.merge(other_config)

    # Scalars should be replaced
    assert config._data["section1"]["key1"] == "new_value"
    assert config._data["section1"]["key2"] == 99
    # Unmodified values should remain
    assert config._data["section1"]["key3"] is True


@pytest.mark.unit
def test_yaml_config_merge_lists():
    """Test merge with lists - lists should be appended."""
    config = YAMLConfig()
    config._data = {
        "section1": {"items": ["item1", "item2", "item3"]}
    }

    # Merge with list containing new items
    other_config = {
        "section1": {"items": ["item2", "item4", "item5"]}
    }

    config.merge(other_config)

    # List should be appended, not replaced
    result = config._data["section1"]["items"]
    assert result == ["item1", "item2", "item3", "item2", "item4", "item5"]
    assert "item1" in result
    assert "item2" in result
    assert "item3" in result
    assert "item4" in result
    assert "item5" in result


@pytest.mark.unit
def test_yaml_config_merge_nested_dicts():
    """Test merge with nested dictionaries - should merge recursively."""
    config = YAMLConfig()
    config._data = {
        "section1": {
            "level1": {
                "level2": {
                    "key1": "value1",
                    "key2": "value2"
                },
                "other_key": "other_value"
            }
        }
    }

    # Merge with nested structure
    other_config = {
        "section1": {
            "level1": {
                "level2": {
                    "key2": "updated_value2",  # Update nested value
                    "key3": "value3"  # Add new nested value
                },
                "new_key": "new_value"  # Add new key at level1
            }
        }
    }

    config.merge(other_config)

    # Check recursive merge
    assert config._data["section1"]["level1"]["level2"]["key1"] == "value1"  # Preserved
    assert config._data["section1"]["level1"]["level2"]["key2"] == "updated_value2"  # Updated
    assert config._data["section1"]["level1"]["level2"]["key3"] == "value3"  # Added
    assert config._data["section1"]["level1"]["other_key"] == "other_value"  # Preserved
    assert config._data["section1"]["level1"]["new_key"] == "new_value"  # Added


@pytest.mark.unit
def test_yaml_config_merge_complex_mixed():
    """Test merge with complex structure containing scalars, lists, and dicts."""
    config = YAMLConfig()
    config._data = {
        "app": {
            "name": "original_app",
            "version": 1,
            "features": ["feature1", "feature2"],
            "database": {
                "host": "localhost",
                "port": 3306,
                "options": ["opt1", "opt2"]
            }
        }
    }

    # Merge complex structure
    other_config = {
        "app": {
            "name": "updated_app",  # Scalar replacement
            "features": ["feature3"],  # List append
            "database": {
                "port": 5432,  # Nested scalar replacement
                "username": "admin",  # New nested scalar
                "options": ["opt3"]  # Nested list append
            },
            "new_section": {  # New nested dict
                "key": "value"
            }
        }
    }

    config.merge(other_config)

    # Check scalar replacement
    assert config._data["app"]["name"] == "updated_app"
    assert config._data["app"]["version"] == 1  # Preserved

    # Check list append
    features = config._data["app"]["features"]
    assert features == ["feature1", "feature2", "feature3"]
    assert "feature1" in features
    assert "feature2" in features
    assert "feature3" in features

    # Check nested dict merging
    assert config._data["app"]["database"]["host"] == "localhost"  # Preserved
    assert config._data["app"]["database"]["port"] == 5432  # Replaced
    assert config._data["app"]["database"]["username"] == "admin"  # Added

    # Check nested list append
    options = config._data["app"]["database"]["options"]
    assert options == ["opt1", "opt2", "opt3"]
    assert "opt1" in options
    assert "opt2" in options
    assert "opt3" in options

    # Check new section added
    assert config._data["app"]["new_section"]["key"] == "value"


@pytest.mark.unit
def test_yaml_config_merge_sections_on_multiple_loads(tmpdir):
    """Test that sections are merged when loading multiple files with same sections."""
    file1 = tmpdir.join("file1.yaml")
    file1.write("""
section1:
  key1: value1
  key2: value2
""")
    
    file2 = tmpdir.join("file2.yaml")
    file2.write("""
section1:
  key2: updated_value2  # This should override
  key3: value3          # This should be added
""")
    
    config = YAMLConfig()
    config.load_file(str(file1))
    config.load_file(str(file2))
    
    # Check that sections were merged
    assert config._data["section1"]["key1"] == "value1"  # Original value preserved
    assert config._data["section1"]["key2"] == "updated_value2"  # Value updated
    assert config._data["section1"]["key3"] == "value3"  # New value added


@pytest.mark.unit
def test_yaml_config_file_prefix_absolute_path(tmpdir):
    """Test file: prefix resolution with an absolute path."""
    secret_file = tmpdir.join("secret.txt")
    secret_file.write("my_secret_value")

    config = YAMLConfig()
    result = config._resolve_value(f"file:{secret_file}")
    assert result == "my_secret_value"


@pytest.mark.unit
def test_yaml_config_file_prefix_relative_path(tmpdir, monkeypatch):
    """Test file: prefix resolution with a relative path."""
    sub = tmpdir.mkdir("secrets")
    secret_file = sub.join("db_password.txt")
    secret_file.write("relative_secret")

    monkeypatch.setattr(get_global_runtime_settings(), "saq_home", str(tmpdir))

    config = YAMLConfig()
    result = config._resolve_value("file:secrets/db_password.txt")
    assert result == "relative_secret"


@pytest.mark.unit
def test_yaml_config_file_prefix_missing_file():
    """Test file: prefix raises FileNotFoundError for missing files."""
    config = YAMLConfig()
    with pytest.raises(FileNotFoundError):
        config._resolve_value("file:/nonexistent/path/to/secret.txt")


@pytest.mark.unit
def test_yaml_config_file_prefix_strips_trailing_whitespace(tmpdir):
    """Test file: prefix strips trailing whitespace from file contents."""
    secret_file = tmpdir.join("secret_with_newlines.txt")
    secret_file.write("secret\n\n")

    config = YAMLConfig()
    result = config._resolve_value(f"file:{secret_file}")
    assert result == "secret"


@pytest.mark.unit
def test_yaml_config_resolve_all_values_file_prefix(tmpdir, monkeypatch):
    """Test resolve_all_values handles file: prefix in dict values and list items."""
    secret1 = tmpdir.join("secret1.txt")
    secret1.write("dict_secret\n")
    secret2 = tmpdir.join("secret2.txt")
    secret2.write("list_secret\n")

    monkeypatch.setattr(get_global_runtime_settings(), "saq_home", str(tmpdir))

    config = YAMLConfig()
    config._data = {
        "section": {
            "password": f"file:{secret1}",
            "tokens": [f"file:{secret2}", "plain_value"],
        }
    }

    config.resolve_all_values()

    assert config._data["section"]["password"] == "dict_secret"
    assert config._data["section"]["tokens"][0] == "list_secret"
    assert config._data["section"]["tokens"][1] == "plain_value"