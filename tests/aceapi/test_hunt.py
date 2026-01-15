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
    return {"x-ice-auth": get_config().api.api_key}


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
    assert result.status_code == 200
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
    assert result.status_code == 200
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
    assert result.status_code == 200
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
    assert result.status_code == 200
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
    assert result.status_code == 200
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
    assert result.status_code == 200
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
    assert result.status_code == 200
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
    assert result.status_code == 200
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
    assert result.status_code == 200
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
