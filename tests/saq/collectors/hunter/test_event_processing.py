import pytest

from saq.collectors.hunter.event_processing import (
    _build_path_components,
    interpolate_event_value,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "path,expected",
    [
        ("field_name", ["field_name"]),
        ("device.hostname", ["device", "hostname"]),
        ("items.0.name", ["items", 0, "name"]),
        ("data.0.items.1.value", ["data", 0, "items", 1, "value"]),
        ("device . hostname", ["device", "hostname"]),
    ],
)
def test_build_path_components_valid_paths(path, expected):
    """test various valid dotted paths are converted to lists of components"""
    result = _build_path_components(path)
    assert result == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "path",
    [
        "device..hostname",
        "device.hostname.",
        ".device.hostname",
    ],
)
def test_build_path_components_invalid_paths(path):
    """test paths with invalid components return None"""
    result = _build_path_components(path)
    assert result is None


@pytest.mark.unit
@pytest.mark.parametrize("value", [123, None, ["list"]])
def test_interpolate_observable_value_non_string(value):
    """test non-string values raise assertion error (value must be str)"""
    event = {"field": "value"}
    with pytest.raises(AssertionError):
        interpolate_event_value(value, event)


@pytest.mark.unit
def test_interpolate_observable_value_no_pattern():
    """test string without interpolation pattern is returned unchanged"""
    event = {"field": "value"}
    result = interpolate_event_value("plain string", event)
    assert result == ["plain string"]


@pytest.mark.unit
@pytest.mark.parametrize("event", ["not a dict", None])
def test_interpolate_observable_value_non_dict_event(event):
    """test interpolation with non-dict event raises assertion error"""
    with pytest.raises(AssertionError):
        interpolate_event_value("${field}", event)


@pytest.mark.unit
def test_interpolate_observable_value_simple_field():
    """test simple field interpolation"""
    event = {"technique_id": "T1234"}
    result = interpolate_event_value("${technique_id}", event)
    assert result == ["T1234"]


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
    assert result == ["${device.hostname}"]  # key doesn't exist

    result = interpolate_event_value("${device.device_id}", event)
    assert result == ["${device.device_id}"]  # key doesn't exist


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
    assert result == ["workstation-01"]

    result = interpolate_event_value("$dot{device.device_id}", event)
    assert result == ["abc123"]


@pytest.mark.unit
def test_interpolate_observable_value_key_syntax():
    """test $key{} syntax for direct key lookup"""
    event = {
        "technique_id": "T1234",
        "device.hostname": "literal-key-with-dot"
    }
    # $key{} does direct key lookup
    result = interpolate_event_value("$key{technique_id}", event)
    assert result == ["T1234"]

    # $key{} with a literal key that contains a dot
    result = interpolate_event_value("$key{device.hostname}", event)
    assert result == ["literal-key-with-dot"]


@pytest.mark.unit
def test_interpolate_observable_value_with_escaped_braces_in_lookup():
    """test interpolation when lookup contains literal brace characters"""
    event = {
        "field}name": "closing-brace-key",
        "field{start": "opening-brace-key",
        "device": {"id}value": "nested-closing"}
    }

    assert interpolate_event_value("${field\\}name}", event) == ["closing-brace-key"]
    assert interpolate_event_value("$key{field\\{start}", event) == ["opening-brace-key"]
    assert interpolate_event_value("$dot{device.id\\}value}", event) == ["nested-closing"]


@pytest.mark.unit
def test_interpolate_observable_value_multiple_interpolations():
    """test multiple field interpolations in single value"""
    event = {
        "device": {"hostname": "workstation-01"},
        "file_path": "/tmp/malware.exe"
    }
    # use $dot{} for nested access and ${} for top-level key
    result = interpolate_event_value("$dot{device.hostname}@${file_path}", event)
    assert result == ["workstation-01@/tmp/malware.exe"]


@pytest.mark.unit
def test_interpolate_observable_value_with_surrounding_text():
    """test interpolation with surrounding text"""
    event = {"user": "john.doe"}
    result = interpolate_event_value("User: ${user} logged in", event)
    assert result == ["User: john.doe logged in"]


@pytest.mark.unit
def test_interpolate_observable_value_missing_field():
    """test interpolation with missing field returns original placeholder"""
    event = {"existing_field": "value"}
    result = interpolate_event_value("${missing_field}", event)
    assert result == ["${missing_field}"]


@pytest.mark.unit
def test_interpolate_observable_value_nested_missing_field():
    """test interpolation with missing nested field returns original placeholder"""
    event = {"device": {"hostname": "workstation-01"}}
    # use $dot{} for nested access
    result = interpolate_event_value("$dot{device.missing}", event)
    assert result == ["$dot{device.missing}"]


@pytest.mark.unit
def test_interpolate_observable_value_partial_path_missing():
    """test interpolation with partially missing path returns original placeholder"""
    event = {"device": {"hostname": "workstation-01"}}
    # use $dot{} for nested access
    result = interpolate_event_value("$dot{missing.hostname}", event)
    assert result == ["$dot{missing.hostname}"]


@pytest.mark.unit
def test_interpolate_observable_value_none_field_value():
    """test interpolation with None field value returns empty string"""
    event = {"field": None}
    result = interpolate_event_value("${field}", event)
    assert result == [""]


@pytest.mark.unit
def test_interpolate_observable_value_empty_placeholder():
    """test interpolation with empty placeholder returns original placeholder"""
    event = {"field": "value"}
    result = interpolate_event_value("${}", event)
    assert result == ["${}"]


@pytest.mark.unit
def test_interpolate_observable_value_whitespace_placeholder():
    """test interpolation with whitespace-only placeholder returns original placeholder"""
    event = {"field": "value"}
    result = interpolate_event_value("${   }", event)
    assert result == ["${   }"]


@pytest.mark.unit
def test_interpolate_observable_value_array_access():
    """test interpolation with array index access"""
    event = {
        "items": ["first", "second", "third"]
    }
    # use $dot{} for array access
    result = interpolate_event_value("$dot{items.0}", event)
    assert result == ["first"]

    result = interpolate_event_value("$dot{items.2}", event)
    assert result == ["third"]


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
    assert result == ["item1"]

    result = interpolate_event_value("$dot{data.1.value}", event)
    assert result == ["20"]


@pytest.mark.unit
def test_interpolate_observable_value_invalid_array_index():
    """test interpolation with out of bounds array index returns original placeholder"""
    event = {
        "items": ["first", "second"]
    }
    # use $dot{} for array access
    result = interpolate_event_value("$dot{items.5}", event)
    assert result == ["$dot{items.5}"]


@pytest.mark.unit
def test_interpolate_observable_value_numeric_value():
    """test interpolation with numeric field value converts to string"""
    event = {
        "port": 443,
        "severity": 7.5
    }
    result = interpolate_event_value("Port ${port}", event)
    assert result == ["Port 443"]

    result = interpolate_event_value("Severity: ${severity}", event)
    assert result == ["Severity: 7.5"]


@pytest.mark.unit
def test_interpolate_observable_value_boolean_value():
    """test interpolation with boolean field value converts to string"""
    event = {
        "enabled": True,
        "disabled": False
    }
    result = interpolate_event_value("${enabled}", event)
    assert result == ["True"]

    result = interpolate_event_value("${disabled}", event)
    assert result == ["False"]


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
    assert result == ["mitre:T1566.001"]

    # test file_location interpolation (nested + top-level key)
    result = interpolate_event_value("$dot{device.hostname}@${file_path}", event)
    assert result == ["DESKTOP-ABC123@C:\\Users\\user\\Downloads\\malware.exe"]

    # test pivot link URL interpolation (top-level key)
    result = interpolate_event_value("${falcon_host_link}", event)
    assert result == ["https://falcon.crowdstrike.com/hosts/1234567890abcdef"]


@pytest.mark.unit
def test_interpolate_observable_value_malformed_placeholder():
    """test interpolation with malformed placeholder syntax"""
    event = {"field": "value"}

    # missing closing brace
    result = interpolate_event_value("${field", event)
    assert result == ["${field"]

    # missing opening brace
    result = interpolate_event_value("$field}", event)
    assert result == ["$field}"]

    # no dollar sign
    result = interpolate_event_value("{field}", event)
    assert result == ["{field}"]


@pytest.mark.unit
def test_interpolate_observable_value_invalid_path():
    """test interpolation with invalid path syntax returns original placeholder"""
    event = {"field": "value"}

    # path with empty components due to dots (use $dot{} for path lookup)
    result = interpolate_event_value("$dot{field..name}", event)
    assert result == ["$dot{field..name}"]


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
    assert interpolate_event_value("${cmdline}", event) == ["malware.exe --payload"]
    assert interpolate_event_value("${composite_id}", event) == ["ldt:abc123:1234567890"]
    assert interpolate_event_value("$dot{device.device_id}", event) == ["abc123"]
    assert interpolate_event_value("${filename}", event) == ["malware.exe"]
    assert interpolate_event_value("${file_path}", event) == ["\\Device\\HarddiskVolume2\\Windows\\Temp\\malware.exe"]
    assert interpolate_event_value("$dot{device.hostname}@${file_path}", event) == ["WIN-SERVER-01@\\Device\\HarddiskVolume2\\Windows\\Temp\\malware.exe"]
    assert interpolate_event_value("${sha256}", event) == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    assert interpolate_event_value("${user_name}", event) == ["SYSTEM"]
    assert interpolate_event_value("${user_principal}", event) == ["admin@company.com"]


@pytest.mark.unit
def test_interpolate_observable_value_invalid_type():
    """test interpolation with invalid TYPE returns original placeholder"""
    event = {"field": "value"}

    # invalid type name
    result = interpolate_event_value("$invalid{field}", event)
    assert result == ["$invalid{field}"]

    result = interpolate_event_value("$foo{field}", event)
    assert result == ["$foo{field}"]


@pytest.mark.unit
def test_interpolate_observable_value_mixed_syntax():
    """test interpolation with mixed syntax types in same value"""
    event = {
        "top_level": "value1",
        "nested": {"field": "value2"}
    }

    # mix of ${} and $dot{}
    result = interpolate_event_value("${top_level}:$dot{nested.field}", event)
    assert result == ["value1:value2"]

    # mix of $key{} and $dot{}
    result = interpolate_event_value("$key{top_level}:$dot{nested.field}", event)
    assert result == ["value1:value2"]


@pytest.mark.unit
def test_interpolate_observable_value_list_single_field():
    """test interpolation when field value is a list of scalars"""
    event = {"url": ["test.com", "other.com"]}
    result = interpolate_event_value("${url}", event)
    assert result == ["test.com", "other.com"]


@pytest.mark.unit
def test_interpolate_observable_value_list_multiple_fields_cartesian_product():
    """test interpolation when multiple fields are lists (cartesian product)"""
    event = {
        "url": ["test.com", "other.com"],
        "user": ["user1", "user2"],
    }
    result = interpolate_event_value("${url}-${user}", event)
    assert result == [
        "test.com-user1",
        "test.com-user2",
        "other.com-user1",
        "other.com-user2",
    ]


@pytest.mark.unit
def test_interpolate_observable_value_list_and_scalar_mix():
    """test interpolation when one field is a list and the other is a scalar"""
    event = {
        "url": ["test.com", "other.com"],
        "user": "user1",
    }
    result = interpolate_event_value("${url}-${user}", event)
    assert result == ["test.com-user1", "other.com-user1"]


@pytest.mark.unit
def test_interpolate_observable_value_empty_list_yields_no_results():
    """test interpolation when a placeholder resolves to an empty list returns no results"""
    event = {"url": []}
    result = interpolate_event_value("${url}", event)
    assert result == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "event,value_template,expected",
    [
        # list with None values (None becomes empty string)
        (
            {"values": ["first", None, "third", None, "fifth"]},
            "${values}",
            ["first", "", "third", "", "fifth"]
        ),
        # list with numeric values (converted to strings)
        (
            {"ports": [80, 443, 8080, 8443]},
            "Port ${ports}",
            ["Port 80", "Port 443", "Port 8080", "Port 8443"]
        ),
        # list with boolean values (converted to strings)
        (
            {"flags": [True, False, True]},
            "Flag: ${flags}",
            ["Flag: True", "Flag: False", "Flag: True"]
        ),
        # list with mixed types (all converted to strings)
        (
            {"mixed": ["string", 123, True, None, 45.67]},
            "${mixed}",
            ["string", "123", "True", "", "45.67"]
        ),
    ],
)
def test_interpolate_observable_value_list_with_various_element_types(event, value_template, expected):
    """test interpolation when list contains various element types (converted to strings, None becomes empty)"""
    result = interpolate_event_value(value_template, event)
    assert result == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "event,value_template,expected",
    [
        # nested field using $dot{} resolves to a list
        (
            {
                "device": {
                    "urls": ["test.com", "other.com", "example.org"]
                }
            },
            "$dot{device.urls}",
            ["test.com", "other.com", "example.org"]
        ),
        # $key{} resolves to a list
        (
            {
                "url.list": ["test.com", "other.com"]
            },
            "$key{url.list}",
            ["test.com", "other.com"]
        ),
        # deeply nested path using $dot{} resolves to a list
        (
            {
                "level1": {
                    "level2": {
                        "level3": {
                            "items": ["item1", "item2", "item3"]
                        }
                    }
                }
            },
            "$dot{level1.level2.level3.items}",
            ["item1", "item2", "item3"]
        ),
    ],
)
def test_interpolate_observable_value_list_with_various_syntax(event, value_template, expected):
    """test interpolation when list is accessed using various syntax options ($dot{}, $key{}, nested paths)"""
    result = interpolate_event_value(value_template, event)
    assert result == expected


@pytest.mark.unit
def test_interpolate_observable_value_list_mixed_dot_and_key_syntax():
    """test interpolation when mixing $dot{} and ${} with both resolving to lists"""
    event = {
        "top_level_list": ["a", "b"],
        "nested": {
            "list": ["1", "2"]
        }
    }
    result = interpolate_event_value("${top_level_list}-$dot{nested.list}", event)
    assert result == [
        "a-1",
        "a-2",
        "b-1",
        "b-2",
    ]


@pytest.mark.unit
def test_interpolate_observable_value_list_multiple_dot_notation_fields():
    """test interpolation when multiple $dot{} fields resolve to lists"""
    event = {
        "device": {
            "ips": ["192.168.1.1", "192.168.1.2"]
        },
        "network": {
            "ports": [80, 443]
        }
    }
    result = interpolate_event_value("$dot{device.ips}:$dot{network.ports}", event)
    assert result == [
        "192.168.1.1:80",
        "192.168.1.1:443",
        "192.168.1.2:80",
        "192.168.1.2:443",
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    "event,value_template,expected",
    [
        # $dot{} list is mixed with scalar values
        (
            {
                "device": {
                    "hostnames": ["host1", "host2", "host3"]
                },
                "domain": "example.com"
            },
            "$dot{device.hostnames}.${domain}",
            [
                "host1.example.com",
                "host2.example.com",
                "host3.example.com",
            ]
        ),
        # list field has surrounding literal text
        (
            {
                "domains": ["example.com", "test.com", "demo.org"]
            },
            "Visit ${domains} for more info",
            [
                "Visit example.com for more info",
                "Visit test.com for more info",
                "Visit demo.org for more info",
            ]
        ),
    ],
)
def test_interpolate_observable_value_list_with_surrounding_content(event, value_template, expected):
    """test interpolation when list is combined with surrounding text or scalar values"""
    result = interpolate_event_value(value_template, event)
    assert result == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "event,value_template,expected",
    [
        # multiple placeholders resolve to empty lists returns empty result
        (
            {
                "list1": [],
                "list2": []
            },
            "${list1}-${list2}",
            []
        ),
        # one placeholder is empty list and another has values returns empty
        (
            {
                "empty": [],
                "non_empty": ["value1", "value2"]
            },
            "${empty}-${non_empty}",
            []
        ),
    ],
)
def test_interpolate_observable_value_list_with_empty_lists(event, value_template, expected):
    """test interpolation when placeholders resolve to empty lists (returns empty result)"""
    result = interpolate_event_value(value_template, event)
    assert result == expected


@pytest.mark.unit
def test_interpolate_observable_value_list_three_fields_cartesian_product():
    """test interpolation when three fields are lists (3-way cartesian product)"""
    event = {
        "a": ["a1", "a2"],
        "b": ["b1", "b2"],
        "c": ["c1", "c2"]
    }
    result = interpolate_event_value("${a}-${b}-${c}", event)
    assert result == [
        "a1-b1-c1",
        "a1-b1-c2",
        "a1-b2-c1",
        "a1-b2-c2",
        "a2-b1-c1",
        "a2-b1-c2",
        "a2-b2-c1",
        "a2-b2-c2",
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    "value_template,expected",
    [
        ("$dot{data.0.items}", ["item1", "item2"]),
        ("$dot{data.1.items}", ["item3", "item4"]),
    ],
)
def test_interpolate_observable_value_list_with_array_index_in_path(value_template, expected):
    """test interpolation when path contains array index but final value is a list"""
    event = {
        "data": [
            {"items": ["item1", "item2"]},
            {"items": ["item3", "item4"]}
        ]
    }
    result = interpolate_event_value(value_template, event)
    assert result == expected


@pytest.mark.unit
def test_interpolate_observable_value_list_single_element():
    """test interpolation when list contains only one element"""
    event = {
        "url": ["only-one.com"]
    }
    result = interpolate_event_value("${url}", event)
    assert result == ["only-one.com"]
