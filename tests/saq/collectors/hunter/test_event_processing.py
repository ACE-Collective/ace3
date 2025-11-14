import pytest

from saq.collectors.hunter.event_processing import (
    _build_path_components,
    interpolate_event_value,
)


@pytest.mark.unit
def test_build_path_components_simple_path():
    """test simple dotted path is converted to list of string components"""
    result = _build_path_components("field_name")
    assert result == ["field_name"]


@pytest.mark.unit
def test_build_path_components_nested_path():
    """test nested dotted path is converted to list of components"""
    result = _build_path_components("device.hostname")
    assert result == ["device", "hostname"]


@pytest.mark.unit
def test_build_path_components_with_integer():
    """test path with integer index is converted to list with int component"""
    result = _build_path_components("items.0.name")
    assert result == ["items", 0, "name"]


@pytest.mark.unit
def test_build_path_components_multiple_integers():
    """test path with multiple integer indices"""
    result = _build_path_components("data.0.items.1.value")
    assert result == ["data", 0, "items", 1, "value"]


@pytest.mark.unit
def test_build_path_components_empty_part():
    """test path with empty part returns None"""
    result = _build_path_components("device..hostname")
    assert result is None


@pytest.mark.unit
def test_build_path_components_trailing_dot():
    """test path with trailing dot returns None"""
    result = _build_path_components("device.hostname.")
    assert result is None


@pytest.mark.unit
def test_build_path_components_leading_dot():
    """test path with leading dot returns None"""
    result = _build_path_components(".device.hostname")
    assert result is None


@pytest.mark.unit
def test_build_path_components_whitespace_handling():
    """test path components with whitespace are trimmed"""
    result = _build_path_components("device . hostname")
    assert result == ["device", "hostname"]


@pytest.mark.unit
def test_interpolate_observable_value_non_string():
    """test non-string values are returned unchanged"""
    event = {"field": "value"}
    result = interpolate_event_value(123, event)
    assert result == 123

    result = interpolate_event_value(None, event)
    assert result is None

    result = interpolate_event_value(["list"], event)
    assert result == ["list"]


@pytest.mark.unit
def test_interpolate_observable_value_no_pattern():
    """test string without interpolation pattern is returned unchanged"""
    event = {"field": "value"}
    result = interpolate_event_value("plain string", event)
    assert result == "plain string"


@pytest.mark.unit
def test_interpolate_observable_value_non_dict_event():
    """test interpolation with non-dict event returns original value"""
    result = interpolate_event_value("${field}", "not a dict")
    assert result == "${field}"

    result = interpolate_event_value("${field}", None)
    assert result == "${field}"


@pytest.mark.unit
def test_interpolate_observable_value_simple_field():
    """test simple field interpolation"""
    event = {"technique_id": "T1234"}
    result = interpolate_event_value("${technique_id}", event)
    assert result == "T1234"


@pytest.mark.unit
def test_interpolate_observable_value_key_with_dot():
    """test that ${} defaults to key lookup, not dot notation"""
    event = {
        "device": {
            "hostname": "workstation-01",
            "device_id": "abc123"
        }
    }
    # ${device.hostname} tries to lookup "device.hostname" as a key (not nested)
    result = interpolate_event_value("${device.hostname}", event)
    assert result == "${device.hostname}"  # key doesn't exist

    result = interpolate_event_value("${device.device_id}", event)
    assert result == "${device.device_id}"  # key doesn't exist


@pytest.mark.unit
def test_interpolate_observable_value_dot_syntax():
    """test $dot{} syntax for nested field interpolation"""
    event = {
        "device": {
            "hostname": "workstation-01",
            "device_id": "abc123"
        }
    }
    result = interpolate_event_value("$dot{device.hostname}", event)
    assert result == "workstation-01"

    result = interpolate_event_value("$dot{device.device_id}", event)
    assert result == "abc123"


@pytest.mark.unit
def test_interpolate_observable_value_key_syntax():
    """test $key{} syntax for direct key lookup"""
    event = {
        "technique_id": "T1234",
        "device.hostname": "literal-key-with-dot"
    }
    # $key{} does direct key lookup
    result = interpolate_event_value("$key{technique_id}", event)
    assert result == "T1234"

    # $key{} with a literal key that contains a dot
    result = interpolate_event_value("$key{device.hostname}", event)
    assert result == "literal-key-with-dot"


@pytest.mark.unit
def test_interpolate_observable_value_multiple_interpolations():
    """test multiple field interpolations in single value"""
    event = {
        "device": {"hostname": "workstation-01"},
        "file_path": "/tmp/malware.exe"
    }
    # use $dot{} for nested access and ${} for top-level key
    result = interpolate_event_value("$dot{device.hostname}@${file_path}", event)
    assert result == "workstation-01@/tmp/malware.exe"


@pytest.mark.unit
def test_interpolate_observable_value_with_surrounding_text():
    """test interpolation with surrounding text"""
    event = {"user": "john.doe"}
    result = interpolate_event_value("User: ${user} logged in", event)
    assert result == "User: john.doe logged in"


@pytest.mark.unit
def test_interpolate_observable_value_missing_field():
    """test interpolation with missing field returns original placeholder"""
    event = {"existing_field": "value"}
    result = interpolate_event_value("${missing_field}", event)
    assert result == "${missing_field}"


@pytest.mark.unit
def test_interpolate_observable_value_nested_missing_field():
    """test interpolation with missing nested field returns original placeholder"""
    event = {"device": {"hostname": "workstation-01"}}
    # use $dot{} for nested access
    result = interpolate_event_value("$dot{device.missing}", event)
    assert result == "$dot{device.missing}"


@pytest.mark.unit
def test_interpolate_observable_value_partial_path_missing():
    """test interpolation with partially missing path returns original placeholder"""
    event = {"device": {"hostname": "workstation-01"}}
    # use $dot{} for nested access
    result = interpolate_event_value("$dot{missing.hostname}", event)
    assert result == "$dot{missing.hostname}"


@pytest.mark.unit
def test_interpolate_observable_value_none_field_value():
    """test interpolation with None field value returns empty string"""
    event = {"field": None}
    result = interpolate_event_value("${field}", event)
    assert result == ""


@pytest.mark.unit
def test_interpolate_observable_value_empty_placeholder():
    """test interpolation with empty placeholder returns original placeholder"""
    event = {"field": "value"}
    result = interpolate_event_value("${}", event)
    assert result == "${}"


@pytest.mark.unit
def test_interpolate_observable_value_whitespace_placeholder():
    """test interpolation with whitespace-only placeholder returns original placeholder"""
    event = {"field": "value"}
    result = interpolate_event_value("${   }", event)
    assert result == "${   }"


@pytest.mark.unit
def test_interpolate_observable_value_array_access():
    """test interpolation with array index access"""
    event = {
        "items": ["first", "second", "third"]
    }
    # use $dot{} for array access
    result = interpolate_event_value("$dot{items.0}", event)
    assert result == "first"

    result = interpolate_event_value("$dot{items.2}", event)
    assert result == "third"


@pytest.mark.unit
def test_interpolate_observable_value_nested_array_access():
    """test interpolation with nested array and object access"""
    event = {
        "data": [
            {"name": "item1", "value": 10},
            {"name": "item2", "value": 20}
        ]
    }
    # use $dot{} for nested array access
    result = interpolate_event_value("$dot{data.0.name}", event)
    assert result == "item1"

    result = interpolate_event_value("$dot{data.1.value}", event)
    assert result == "20"


@pytest.mark.unit
def test_interpolate_observable_value_invalid_array_index():
    """test interpolation with out of bounds array index returns original placeholder"""
    event = {
        "items": ["first", "second"]
    }
    # use $dot{} for array access
    result = interpolate_event_value("$dot{items.5}", event)
    assert result == "$dot{items.5}"


@pytest.mark.unit
def test_interpolate_observable_value_numeric_value():
    """test interpolation with numeric field value converts to string"""
    event = {
        "port": 443,
        "severity": 7.5
    }
    result = interpolate_event_value("Port ${port}", event)
    assert result == "Port 443"

    result = interpolate_event_value("Severity: ${severity}", event)
    assert result == "Severity: 7.5"


@pytest.mark.unit
def test_interpolate_observable_value_boolean_value():
    """test interpolation with boolean field value converts to string"""
    event = {
        "enabled": True,
        "disabled": False
    }
    result = interpolate_event_value("${enabled}", event)
    assert result == "True"

    result = interpolate_event_value("${disabled}", event)
    assert result == "False"


@pytest.mark.unit
def test_interpolate_observable_value_crowdstrike_example():
    """test interpolation with example from crowdstrike_alerts.yaml"""
    event = {
        "technique_id": "T1566.001",
        "device": {
            "hostname": "DESKTOP-ABC123",
            "device_id": "1234567890abcdef"
        },
        "file_path": "C:\\Users\\user\\Downloads\\malware.exe",
        "falcon_host_link": "https://falcon.crowdstrike.com/hosts/1234567890abcdef"
    }

    # test tag interpolation (top-level key)
    result = interpolate_event_value("mitre:${technique_id}", event)
    assert result == "mitre:T1566.001"

    # test file_location interpolation (nested + top-level key)
    result = interpolate_event_value("$dot{device.hostname}@${file_path}", event)
    assert result == "DESKTOP-ABC123@C:\\Users\\user\\Downloads\\malware.exe"

    # test pivot link URL interpolation (top-level key)
    result = interpolate_event_value("${falcon_host_link}", event)
    assert result == "https://falcon.crowdstrike.com/hosts/1234567890abcdef"


@pytest.mark.unit
def test_interpolate_observable_value_malformed_placeholder():
    """test interpolation with malformed placeholder syntax"""
    event = {"field": "value"}

    # missing closing brace
    result = interpolate_event_value("${field", event)
    assert result == "${field"

    # missing opening brace
    result = interpolate_event_value("$field}", event)
    assert result == "$field}"

    # no dollar sign
    result = interpolate_event_value("{field}", event)
    assert result == "{field}"


@pytest.mark.unit
def test_interpolate_observable_value_invalid_path():
    """test interpolation with invalid path syntax returns original placeholder"""
    event = {"field": "value"}

    # path with empty components due to dots (use $dot{} for path lookup)
    result = interpolate_event_value("$dot{field..name}", event)
    assert result == "$dot{field..name}"


@pytest.mark.unit
def test_interpolate_observable_value_complex_crowdstrike_event():
    """test interpolation with complex crowdstrike event structure"""
    event = {
        "composite_id": "ldt:abc123:1234567890",
        "device": {
            "device_id": "abc123",
            "hostname": "WIN-SERVER-01",
            "platform_name": "Windows"
        },
        "filename": "malware.exe",
        "file_path": "\\Device\\HarddiskVolume2\\Windows\\Temp\\malware.exe",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "user_name": "SYSTEM",
        "user_principal": "admin@company.com",
        "cmdline": "malware.exe --payload",
        "severity_name": "High",
        "description": "Malware Detected"
    }

    # test various observable mappings from the YAML (top-level keys use ${}, nested use $dot{})
    assert interpolate_event_value("${cmdline}", event) == "malware.exe --payload"
    assert interpolate_event_value("${composite_id}", event) == "ldt:abc123:1234567890"
    assert interpolate_event_value("$dot{device.device_id}", event) == "abc123"
    assert interpolate_event_value("${filename}", event) == "malware.exe"
    assert interpolate_event_value("${file_path}", event) == "\\Device\\HarddiskVolume2\\Windows\\Temp\\malware.exe"
    assert interpolate_event_value("$dot{device.hostname}@${file_path}", event) == "WIN-SERVER-01@\\Device\\HarddiskVolume2\\Windows\\Temp\\malware.exe"
    assert interpolate_event_value("${sha256}", event) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert interpolate_event_value("${user_name}", event) == "SYSTEM"
    assert interpolate_event_value("${user_principal}", event) == "admin@company.com"


@pytest.mark.unit
def test_interpolate_observable_value_invalid_type():
    """test interpolation with invalid TYPE returns original placeholder"""
    event = {"field": "value"}

    # invalid type name
    result = interpolate_event_value("$invalid{field}", event)
    assert result == "$invalid{field}"

    result = interpolate_event_value("$foo{field}", event)
    assert result == "$foo{field}"


@pytest.mark.unit
def test_interpolate_observable_value_mixed_syntax():
    """test interpolation with mixed syntax types in same value"""
    event = {
        "top_level": "value1",
        "nested": {"field": "value2"}
    }

    # mix of ${} and $dot{}
    result = interpolate_event_value("${top_level}:$dot{nested.field}", event)
    assert result == "value1:value2"

    # mix of $key{} and $dot{}
    result = interpolate_event_value("$key{top_level}:$dot{nested.field}", event)
    assert result == "value1:value2"
