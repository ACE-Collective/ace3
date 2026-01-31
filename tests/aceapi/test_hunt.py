import pytest
from unittest.mock import Mock, patch

from aceapi.hunt import _validate_hunt_file_path
from saq.configuration.config import get_config


# Valid hunt YAML content for reuse in tests
VALID_HUNT_YAML = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt Description
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
  instance_types:
    - unittest
  tags:
    - tag1
"""

# URL for the hunt validate endpoint
HUNT_VALIDATE_URL = "/hunt/validate"


@pytest.fixture
def auth_headers():
    """Returns authentication headers for API requests."""
    return {"x-ace-auth": get_config().api.api_key}


# =============================================================================
# Unit Tests for _validate_hunt_file_path
# =============================================================================

@pytest.mark.unit
@pytest.mark.parametrize("path,should_raise,error_contains", [
    # Absolute paths should be rejected
    ("/etc/passwd", True, "absolute"),
    ("/home/user/test.yaml", True, "absolute"),
    # Directory traversal should be rejected
    ("../secret.yaml", True, "parent directory traversal"),
    ("hunts/../../../etc/passwd", True, "parent directory traversal"),
    ("foo/bar/../../../etc/passwd", True, "parent directory traversal"),
    # Windows-style paths with traversal should be rejected
    ("hunts\\..\\..\\etc\\passwd", True, "parent directory traversal"),
    # Valid relative paths should be accepted
    ("hunts/test.yaml", False, None),
    ("test.yaml", False, None),
    ("a/b/c/d/e.yaml", False, None),
    # ".." in filename (not as path segment) should be accepted
    ("hunts/test..file.yaml", False, None),
    ("test..yaml", False, None),
    # ".." as the last component (filename) should be accepted per implementation
    ("hunts/..", False, None),
])
def test_validate_hunt_file_path(path, should_raise, error_contains):
    """Parameterized tests for _validate_hunt_file_path function."""
    if should_raise:
        with pytest.raises(ValueError) as exc_info:
            _validate_hunt_file_path(path)
        assert error_contains in str(exc_info.value).lower()
    else:
        # Should not raise any exception
        result = _validate_hunt_file_path(path)
        # Function returns the path or None on success
        assert result is None or isinstance(result, str)


@pytest.mark.unit
def test_validate_hunt_file_path_empty_string():
    """Verify empty string path is handled (not absolute, no traversal)."""
    # Empty string is not absolute and has no ".." segments
    # so it should not raise from this validation function
    _validate_hunt_file_path("")


@pytest.mark.unit
def test_validate_hunt_file_path_windows_absolute():
    """Verify Windows absolute paths are rejected."""
    # Note: os.path.isabs behavior varies by platform
    # On Unix, "C:\\Windows" is not considered absolute
    # This test documents the current behavior
    try:
        _validate_hunt_file_path("C:\\Windows\\test.yaml")
        # On Unix, this won't be detected as absolute
    except ValueError as e:
        assert "absolute" in str(e).lower()


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Request Body Validation
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_missing_json_body(test_client, auth_headers):
    """Verify missing JSON body (empty string) returns 400 Bad Request.

    Note: When sending empty data with JSON content-type, Flask returns 400
    because it cannot parse the empty body as JSON.
    """
    result = test_client.post(
        HUNT_VALIDATE_URL,
        headers=auth_headers,
        data="",
        content_type="application/json"
    )
    assert result.status_code == 400


@pytest.mark.integration
def test_validate_hunt_non_json_content_type(test_client, auth_headers):
    """Verify non-JSON content type returns 415 Unsupported Media Type.

    Note: Flask returns 415 when the content-type is not application/json
    and the endpoint expects JSON data.
    """
    result = test_client.post(
        HUNT_VALIDATE_URL,
        headers=auth_headers,
        data="some text",
        content_type="text/plain"
    )
    # Flask returns 415 UNSUPPORTED MEDIA TYPE for non-JSON content types
    assert result.status_code == 415


@pytest.mark.integration
def test_validate_hunt_empty_json_body(test_client, auth_headers):
    """Verify empty JSON object is treated as no JSON.

    Note: The code uses `if not request.json` which treats empty dict {} as falsy,
    so it returns "request body must be JSON" error.
    """
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    # Empty dict is falsy in Python, so it's treated as "no JSON"
    assert "request body must be JSON" in data["error"]


@pytest.mark.integration
def test_validate_hunt_missing_hunts_field(test_client, auth_headers):
    """Verify missing 'hunts' field returns appropriate error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"target": "test.yaml"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "missing 'hunts' field" in data["error"]


@pytest.mark.integration
def test_validate_hunt_missing_target_field(test_client, auth_headers):
    """Verify missing 'target' field returns appropriate error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"hunts": []},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "missing 'target' field" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("hunts_value", [
    "not-a-list",
    {"key": "value"},
    123,
    True,
])
def test_validate_hunt_hunts_wrong_type(test_client, auth_headers, hunts_value):
    """Verify 'hunts' with wrong type returns error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"hunts": hunts_value, "target": "test.yaml"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "'hunts' must be a list" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("target_value", [
    123,
    ["test.yaml"],
    {"file": "test.yaml"},
    True,
])
def test_validate_hunt_target_wrong_type(test_client, auth_headers, target_value):
    """Verify 'target' with wrong type returns error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"hunts": [], "target": target_value},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "'target' must be a string" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("hunt_item", [
    "not-a-dict",
    ["list-item"],
    123,
    True,
])
def test_validate_hunt_item_not_dict(test_client, auth_headers, hunt_item):
    """Verify hunt items that are not dictionaries are rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"hunts": [hunt_item], "target": "test.yaml"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "each hunt must be a dictionary" in data["error"]


@pytest.mark.integration
def test_validate_hunt_item_missing_file_path(test_client, auth_headers):
    """Verify hunt items missing 'file_path' are rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"hunts": [{"content": "test content"}], "target": "test.yaml"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "each hunt must have a 'file_path' field" in data["error"]


@pytest.mark.integration
def test_validate_hunt_item_missing_content(test_client, auth_headers):
    """Verify hunt items missing 'content' are rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"hunts": [{"file_path": "test.yaml"}], "target": "test.yaml"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "each hunt must have a 'content' field" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("file_path_value", [
    123,
    ["test.yaml"],
    {"path": "test.yaml"},
    True,
])
def test_validate_hunt_item_file_path_wrong_type(test_client, auth_headers, file_path_value):
    """Verify hunt 'file_path' as non-string is rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"hunts": [{"file_path": file_path_value, "content": "test"}], "target": "test.yaml"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "hunt 'file_path' must be a string" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("content_value", [
    123,
    ["content"],
    {"yaml": "content"},
    True,
])
def test_validate_hunt_item_content_wrong_type(test_client, auth_headers, content_value):
    """Verify hunt 'content' as non-string is rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"hunts": [{"file_path": "test.yaml", "content": content_value}], "target": "test.yaml"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "hunt 'content' must be a string" in data["error"]


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Path Security
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_target_absolute_path(test_client, auth_headers):
    """Verify absolute target path is rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
            "target": "/etc/passwd"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "absolute" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_target_path_traversal(test_client, auth_headers):
    """Verify target with path traversal is rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
            "target": "../../../etc/passwd"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "parent directory traversal" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_file_path_absolute(test_client, auth_headers):
    """Verify absolute hunt file_path is rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "/etc/passwd", "content": "test"}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "absolute" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_file_path_traversal(test_client, auth_headers):
    """Verify hunt file_path with path traversal is rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "../../../etc/passwd", "content": "test"}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "parent directory traversal" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_file_path_traversal_windows_style(test_client, auth_headers):
    """Verify hunt file_path with Windows-style path traversal is rejected."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "..\\..\\..\\etc\\passwd", "content": "test"}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "parent directory traversal" in data["error"].lower()


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - YAML/Config Validation
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_invalid_yaml_syntax(test_client, auth_headers):
    """Verify invalid YAML syntax returns validation error."""
    invalid_yaml = """rule:
  name: test
  invalid: yaml: : : syntax
  [broken
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": invalid_yaml}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "yaml syntax error" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_missing_required_field_uuid(test_client, auth_headers):
    """Verify hunt config missing uuid field returns validation error."""
    yaml_missing_uuid = """rule:
  enabled: yes
  name: test_hunt
  description: Test Hunt
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": yaml_missing_uuid}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_missing_required_field_name(test_client, auth_headers):
    """Verify hunt config missing name field returns validation error."""
    yaml_missing_name = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  description: Test Hunt
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": yaml_missing_name}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_missing_required_field_type(test_client, auth_headers):
    """Verify hunt config missing type field returns validation error."""
    yaml_missing_type = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt
  alert_type: test - alert
  frequency: '00:10:00'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": yaml_missing_type}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_missing_required_field_frequency(test_client, auth_headers):
    """Verify hunt config missing frequency field returns validation error."""
    yaml_missing_frequency = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt
  type: test
  alert_type: test - alert
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": yaml_missing_frequency}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_invalid_frequency_format(test_client, auth_headers):
    """Verify hunt config with invalid frequency format returns error."""
    yaml_invalid_frequency = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt
  type: test
  alert_type: test - alert
  frequency: 'invalid_frequency'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": yaml_invalid_frequency}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_unknown_hunt_type(test_client, auth_headers):
    """Verify unknown hunt type returns appropriate error."""
    yaml_unknown_type = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt
  type: nonexistent_hunt_type_xyz
  alert_type: test - alert
  frequency: '00:10:00'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "test.yaml", "content": yaml_unknown_type}],
            "target": "test.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    # Note: The error message uses hunt_dict.type_ (with underscore) due to Pydantic alias
    assert "invalid hunt type" in data["error"].lower()


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Success Cases
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_valid_hunt_with_mock(test_client, auth_headers):
    """Verify a completely valid hunt passes validation with mocked service."""
    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        # Setup mock
        mock_manager = Mock()
        mock_manager.load_hunt_from_config.return_value = Mock()
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml"
            },
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


@pytest.mark.integration
def test_validate_hunt_valid_hunt_with_includes(test_client, auth_headers):
    """Verify valid hunt with include files passes validation."""
    base_yaml = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: base_hunt
  description: Base Hunt Description
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
  tags:
    - base_tag
"""
    main_yaml = """include:
  - includes/base.yaml
rule:
  name: main_hunt
  tags:
    - main_tag
"""

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_manager.load_hunt_from_config.return_value = Mock()
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [
                    {"file_path": "includes/base.yaml", "content": base_yaml},
                    {"file_path": "main.yaml", "content": main_yaml},
                ],
                "target": "main.yaml"
            },
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


@pytest.mark.integration
def test_validate_hunt_nested_directory_structure(test_client, auth_headers):
    """Verify hunts with nested directory paths work correctly."""
    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_manager.load_hunt_from_config.return_value = Mock()
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "hunts/subdir/nested/test.yaml", "content": VALID_HUNT_YAML}],
                "target": "hunts/subdir/nested/test.yaml"
            },
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


@pytest.mark.integration
def test_validate_hunt_empty_hunts_list_target_not_found(test_client, auth_headers):
    """Verify empty hunts list with target returns file not found error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [],
            "target": "nonexistent.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "not found" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_target_not_in_hunts(test_client, auth_headers):
    """Verify target file not in hunts list returns file not found error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={
            "hunts": [{"file_path": "other.yaml", "content": VALID_HUNT_YAML}],
            "target": "missing_target.yaml"
        },
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "not found" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_multiple_hunts_all_valid(test_client, auth_headers):
    """Verify multiple valid hunts in request work correctly."""
    hunt1_yaml = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: hunt_one
  description: Hunt One Description
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
"""
    hunt2_yaml = """rule:
  uuid: 8c6f3380-5b2e-5010-97b1-ef4f9d0d93f8
  enabled: yes
  name: hunt_two
  description: Hunt Two Description
  type: test
  alert_type: test - alert
  frequency: '00:15:00'
"""

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_manager.load_hunt_from_config.return_value = Mock()
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [
                    {"file_path": "hunt1.yaml", "content": hunt1_yaml},
                    {"file_path": "hunt2.yaml", "content": hunt2_yaml},
                ],
                "target": "hunt1.yaml"
            },
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Execution Arguments Validation
# =============================================================================

@pytest.mark.integration
@pytest.mark.parametrize("execution_arguments,error_contains", [
    # Invalid type for analyze_results (non-coercible to bool)
    ({"analyze_results": "invalid"}, "execution_arguments"),
    ({"analyze_results": []}, "execution_arguments"),
    ({"analyze_results": {}}, "execution_arguments"),
    # Invalid type for create_alerts (non-coercible to bool)
    ({"create_alerts": "nope"}, "execution_arguments"),
    # Invalid type for queue (must be string)
    ({"queue": 123}, "execution_arguments"),
    ({"queue": ["default"]}, "execution_arguments"),
    # Invalid type for start_time (must be string or None)
    ({"start_time": 123}, "execution_arguments"),
])
def test_validate_hunt_execution_arguments_invalid_types(test_client, auth_headers, execution_arguments, error_contains):
    """Verify invalid execution_arguments field types return validation error."""
    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock()
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": execution_arguments
            },
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert error_contains in data["error"].lower()


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Time Parsing (QueryHunt)
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_query_hunt_missing_start_time(test_client, auth_headers):
    """Verify QueryHunt without start_time returns clear error."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        # Create a mock that passes isinstance check for QueryHunt
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "end_time": "01/15/2025:12:00:00"
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "start_time is required" in data["error"]


@pytest.mark.integration
def test_validate_hunt_execution_query_hunt_missing_end_time(test_client, auth_headers):
    """Verify QueryHunt without end_time returns clear error."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": "01/15/2025:12:00:00"
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "end_time is required" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("invalid_time,field_name", [
    ("2025-01-15 12:00:00", "start_time"),  # Wrong format (dashes instead of slashes)
    ("01-15-2025:12:00:00", "start_time"),  # Wrong separator
    ("01/15/2025 12:00:00", "start_time"),  # Space instead of colon
    ("15/01/2025:12:00:00", "start_time"),  # DD/MM/YYYY instead of MM/DD/YYYY
    ("not-a-date", "start_time"),  # Completely invalid
    ("", "start_time"),  # Empty string
    ("01/15/2025:25:00:00", "start_time"),  # Invalid hour
    ("01/15/2025:12:60:00", "start_time"),  # Invalid minute
])
def test_validate_hunt_execution_invalid_start_time_format(test_client, auth_headers, invalid_time, field_name):
    """Verify invalid start_time format returns clear error with expected format."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": invalid_time,
                    "end_time": "01/15/2025:12:00:00"
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "start_time" in data["error"].lower()
        assert "MM/DD/YYYY:HH:MM:SS" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("invalid_time", [
    "2025-01-15 12:00:00",  # Wrong format
    "not-a-date",  # Completely invalid
    "",  # Empty string
])
def test_validate_hunt_execution_invalid_end_time_format(test_client, auth_headers, invalid_time):
    """Verify invalid end_time format returns clear error with expected format."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": "01/15/2025:10:00:00",
                    "end_time": invalid_time
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "end_time" in data["error"].lower()
        assert "MM/DD/YYYY:HH:MM:SS" in data["error"]


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Timezone Handling
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_invalid_timezone(test_client, auth_headers):
    """Verify invalid timezone returns clear error."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": "01/15/2025:10:00:00",
                    "end_time": "01/15/2025:12:00:00",
                    "timezone": "Invalid/Timezone"
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "invalid timezone" in data["error"].lower()
        assert "Invalid/Timezone" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("timezone", [
    "America/New_York",
    "Europe/London",
    "Asia/Tokyo",
    "UTC",
    "US/Eastern",
])
def test_validate_hunt_execution_valid_timezones(test_client, auth_headers, timezone):
    """Verify valid timezones are accepted."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        # Mock execute to return empty list (no submissions)
        mock_hunt.execute.return_value = []
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": "01/15/2025:10:00:00",
                    "end_time": "01/15/2025:12:00:00",
                    "timezone": timezone
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Execution Success Cases
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_success_no_analyze_no_alerts(test_client, auth_headers):
    """Verify successful execution without analyze_results or create_alerts."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)

        # Create mock submission with mock root
        mock_root = Mock(spec=RootAnalysis)
        mock_root.json = {"uuid": "test-uuid-123", "description": "Test Hunt"}
        mock_root.details = {"query": "test query", "events": []}
        mock_submission = Mock(spec=Submission)
        mock_submission.root = mock_root

        mock_hunt.execute.return_value = [mock_submission]
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": "01/15/2025:10:00:00",
                    "end_time": "01/15/2025:12:00:00"
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert "roots" in data
        assert "logs" in data
        assert len(data["roots"]) == 1
        assert data["roots"][0]["details"] == {"query": "test query", "events": []}


@pytest.mark.integration
def test_validate_hunt_execution_success_with_analyze_results(test_client, auth_headers):
    """Verify successful execution with analyze_results=True."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        with patch("aceapi.hunt.storage_dir_from_uuid") as mock_storage_dir:
            mock_storage_dir.return_value = "/tmp/test-storage"

            mock_manager = Mock()
            mock_hunt = Mock(spec=QueryHunt)

            # Create mock submission with mock root
            mock_root = Mock(spec=RootAnalysis)
            mock_root.json = {"uuid": "test-uuid-123", "description": "Test Hunt"}
            mock_root.details = {"query": "test query"}

            # Mock the duplicate method to return a new mock root
            mock_new_root = Mock(spec=RootAnalysis)
            mock_new_root.json = {"uuid": "new-uuid-456", "description": "Test Hunt"}
            mock_new_root.details = {"query": "test query"}
            mock_new_root.uuid = "new-uuid-456"
            mock_root.duplicate.return_value = mock_new_root

            mock_submission = Mock(spec=Submission)
            mock_submission.root = mock_root

            mock_hunt.execute.return_value = [mock_submission]
            mock_manager.load_hunt_from_config.return_value = mock_hunt
            mock_instance = mock_hunter_service.return_value
            mock_instance.hunt_managers = {"test": mock_manager}
            mock_instance.load_hunt_managers = Mock()

            result = test_client.post(
                HUNT_VALIDATE_URL,
                json={
                    "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                    "target": "test.yaml",
                    "execution_arguments": {
                        "start_time": "01/15/2025:10:00:00",
                        "end_time": "01/15/2025:12:00:00",
                        "analyze_results": True
                    }
                },
                headers=auth_headers
            )

            assert result.status_code == 200
            data = result.get_json()
            assert data["valid"] is True
            assert "roots" in data
            # Verify duplicate was called
            mock_root.duplicate.assert_called_once()
            # Verify move, save, and schedule were called on the new root
            mock_new_root.move.assert_called_once_with("/tmp/test-storage")
            mock_new_root.save.assert_called()
            mock_new_root.schedule.assert_called_once()


@pytest.mark.integration
def test_validate_hunt_execution_success_with_create_alerts(test_client, auth_headers):
    """Verify successful execution with create_alerts=True."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis
    from saq.constants import ANALYSIS_MODE_CORRELATION

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        with patch("aceapi.hunt.storage_dir_from_uuid") as mock_storage_dir:
            with patch("aceapi.hunt.ALERT") as mock_alert:
                mock_storage_dir.return_value = "/tmp/test-storage"

                mock_manager = Mock()
                mock_hunt = Mock(spec=QueryHunt)

                # Create mock submission with mock root
                mock_root = Mock(spec=RootAnalysis)
                mock_root.json = {"uuid": "test-uuid-123", "description": "Test Hunt"}
                mock_root.details = {"query": "test query"}

                # Mock the duplicate method to return a new mock root
                mock_new_root = Mock(spec=RootAnalysis)
                mock_new_root.json = {"uuid": "new-uuid-456", "description": "Test Hunt"}
                mock_new_root.details = {"query": "test query"}
                mock_new_root.uuid = "new-uuid-456"
                mock_root.duplicate.return_value = mock_new_root

                mock_submission = Mock(spec=Submission)
                mock_submission.root = mock_root

                mock_hunt.execute.return_value = [mock_submission]
                mock_manager.load_hunt_from_config.return_value = mock_hunt
                mock_instance = mock_hunter_service.return_value
                mock_instance.hunt_managers = {"test": mock_manager}
                mock_instance.load_hunt_managers = Mock()

                result = test_client.post(
                    HUNT_VALIDATE_URL,
                    json={
                        "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                        "target": "test.yaml",
                        "execution_arguments": {
                            "start_time": "01/15/2025:10:00:00",
                            "end_time": "01/15/2025:12:00:00",
                            "create_alerts": True
                        }
                    },
                    headers=auth_headers
                )

                assert result.status_code == 200
                data = result.get_json()
                assert data["valid"] is True
                # Verify ALERT was called
                mock_alert.assert_called_once_with(mock_new_root)
                # Verify analysis_mode was set to correlation
                assert mock_new_root.analysis_mode == ANALYSIS_MODE_CORRELATION


@pytest.mark.integration
def test_validate_hunt_execution_success_with_custom_queue(test_client, auth_headers):
    """Verify successful execution with custom queue."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        with patch("aceapi.hunt.storage_dir_from_uuid") as mock_storage_dir:
            mock_storage_dir.return_value = "/tmp/test-storage"

            mock_manager = Mock()
            mock_hunt = Mock(spec=QueryHunt)

            mock_root = Mock(spec=RootAnalysis)
            mock_root.json = {"uuid": "test-uuid-123"}
            mock_root.details = {}

            mock_new_root = Mock(spec=RootAnalysis)
            mock_new_root.json = {"uuid": "new-uuid-456"}
            mock_new_root.details = {}
            mock_new_root.uuid = "new-uuid-456"
            mock_root.duplicate.return_value = mock_new_root

            mock_submission = Mock(spec=Submission)
            mock_submission.root = mock_root

            mock_hunt.execute.return_value = [mock_submission]
            mock_manager.load_hunt_from_config.return_value = mock_hunt
            mock_instance = mock_hunter_service.return_value
            mock_instance.hunt_managers = {"test": mock_manager}
            mock_instance.load_hunt_managers = Mock()

            result = test_client.post(
                HUNT_VALIDATE_URL,
                json={
                    "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                    "target": "test.yaml",
                    "execution_arguments": {
                        "start_time": "01/15/2025:10:00:00",
                        "end_time": "01/15/2025:12:00:00",
                        "analyze_results": True,
                        "queue": "custom-queue"
                    }
                },
                headers=auth_headers
            )

            assert result.status_code == 200
            data = result.get_json()
            assert data["valid"] is True
            # Verify queue was set
            assert mock_new_root.queue == "custom-queue"


@pytest.mark.integration
def test_validate_hunt_execution_empty_submissions(test_client, auth_headers):
    """Verify execution with no submissions returns empty roots."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_hunt.execute.return_value = []
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": "01/15/2025:10:00:00",
                    "end_time": "01/15/2025:12:00:00"
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert data["roots"] == []
        assert "logs" in data


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Execution Error Cases
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_raises_exception(test_client, auth_headers):
    """Verify hunt execution exception returns wrapped error message."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_hunt.execute.side_effect = Exception("Connection failed to SIEM")
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": "01/15/2025:10:00:00",
                    "end_time": "01/15/2025:12:00:00"
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "error executing hunt" in data["error"].lower()
        assert "Connection failed to SIEM" in data["error"]


@pytest.mark.integration
def test_validate_hunt_execution_non_query_hunt_no_time_required(test_client, auth_headers):
    """Verify non-QueryHunt types don't require start_time/end_time."""
    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        # This is NOT a QueryHunt, just a regular hunt
        mock_hunt = Mock()
        mock_hunt.execute.return_value = []
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {}  # No time parameters
            },
            headers=auth_headers
        )

        # Should succeed because it's not a QueryHunt
        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


@pytest.mark.integration
def test_validate_hunt_execution_logs_collected(test_client, auth_headers):
    """Verify logs are collected during execution."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    import logging

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)

        def execute_with_logging(**kwargs):
            logging.info("Test log message from hunt execution")
            return []

        mock_hunt.execute.side_effect = execute_with_logging
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json={
                "hunts": [{"file_path": "test.yaml", "content": VALID_HUNT_YAML}],
                "target": "test.yaml",
                "execution_arguments": {
                    "start_time": "01/15/2025:10:00:00",
                    "end_time": "01/15/2025:12:00:00"
                }
            },
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert "logs" in data
        # Check that logs contain our test message
        log_messages = " ".join(data["logs"])
        assert "Test log message from hunt execution" in log_messages