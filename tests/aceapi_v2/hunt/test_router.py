import copy
import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Optional
from uuid import uuid4

import pytest
import pytz
import yaml
from pydantic import BaseModel
from sqlalchemy import text

from hunt_compiler.models import CompiledHunt, EmbeddedFile
from saq.analysis.root import RootAnalysis, Submission, load_root
from saq.collectors.hunter.base_hunter import Hunt
from saq.collectors.hunter.correlation.command_types import (
    CorrelationCommand,
    clear_command_types,
    reset_command_types_loaded_flag,
)
from saq.collectors.hunter.loader import get_compiled_hunt_dir
from saq.collectors.hunter.query_hunter import QueryHunt
from saq.collectors.hunter.service import HunterService
from saq.configuration.config import get_config
from saq.configuration.schema import CommandTypeConfig, HuntTypeConfig
from saq.constants import ANALYSIS_MODE_CORRELATION, QUEUE_DEFAULT, TAG_HUNT_VALIDATION
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, create_api_key, delete_user
from saq.error.remote import RemoteApiError
from saq.logging import ThreadSuppressionFilter, audit_actor
from saq.permissions.user import add_user_permission
from saq.util.uuid import storage_dir_from_uuid
from tests.saq.helpers import workload_count


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
  query: index=proxy | stats count by src
  time_range: '00:10:00'
  full_coverage: no
  use_index_time: no
"""

# URL for the hunt validate endpoint
HUNT_VALIDATE_URL = "/hunt/validate"

# the time range every executing test asks for
EXECUTION_TIMES = {"start_time": "01/15/2025:10:00:00", "end_time": "01/15/2025:12:00:00"}


def _make_compiled_payload(yaml_content, target="test.yaml", **kwargs):
    """Build a compiled_hunt request payload from raw YAML content."""
    compiled = CompiledHunt(
        target=target,
        package_root="/tmp/test",
        assets=[EmbeddedFile(kind="yaml", path=target, content=yaml_content)],
        **kwargs,
    )
    return {"compiled_hunt": compiled.model_dump()}


def _hunt_yaml(rule: Optional[dict] = None, without: Optional[str] = None, **top_level) -> str:
    """VALID_HUNT_YAML with rule fields added or replaced, one rule field removed, and top-level
    keys added."""
    hunt = yaml.safe_load(VALID_HUNT_YAML)
    hunt["rule"].update(rule or {})
    if without is not None:
        del hunt["rule"][without]
    hunt.update(top_level)
    return yaml.safe_dump(hunt)


class _DataSource:
    """What the data source of a "test" hunt (Splunk, in production) answers, and what it was asked."""

    def __init__(self):
        self.events: Optional[list[dict]] = []
        self.error: Optional[Exception] = None
        self.searches: list[dict] = []


class ValidationQueryHunt(QueryHunt):
    """The "test" hunt type: a real query hunt whose search alone is answered by the test."""

    data_source = _DataSource()

    def execute_query(self, start_time, end_time, *args, **kwargs):
        logging.info("test data source searched by hunt %s", self.name)
        self.data_source.searches.append(
            {"start_time": start_time, "end_time": end_time, "manual_hunt": self.manual_hunt, **kwargs})
        if self.data_source.error is not None:
            raise self.data_source.error

        return copy.deepcopy(self.data_source.events)

    def cancel(self):
        pass


class ValidationHunt(Hunt):
    """The "test_plain" hunt type, which is not a query hunt: every execution submits one root."""

    def execute(self):
        root_uuid = str(uuid4())
        root = RootAnalysis(
            uuid=root_uuid,
            storage_dir=self.manager.file_manager.get_staging_tmp_path(root_uuid),
            desc=self.name,
            analysis_mode=self.analysis_mode,
            tool="test_tool",
            tool_instance="test_tool_instance",
            alert_type=self.alert_type)
        root.initialize_storage()
        return [Submission(root)]

    def cancel(self):
        pass


@pytest.fixture(autouse=True)
def data_source(monkeypatch):
    """Configures the "test" and "test_plain" hunt types and returns what a "test" hunt's search
    answers."""
    source = _DataSource()
    monkeypatch.setattr(ValidationQueryHunt, "data_source", source)
    for hunt_type, python_class in (("test", "ValidationQueryHunt"), ("test_plain", "ValidationHunt")):
        get_config().add_hunt_type_config(hunt_type, HuntTypeConfig(
            name=hunt_type,
            python_module=__name__,
            python_class=python_class,
            update_frequency=60,
            schedulable=False,
        ))
    yield source
    get_config().load_hunt_type_configs()


@pytest.fixture
def auth_headers():
    """Returns authentication headers for API requests."""
    return {"x-ace-auth": get_config().api.api_key}


class _V2Response:
    def __init__(self, response):
        self._response = response
        self.status_code = response.status_code

    def get_json(self):
        return self._response.json()


class _V2HuntApi:
    """POST /api/v2/hunt/validate, with the request built from the keyword arguments these tests
    pass. Run on the loop the cached async database engine is bound to (see
    tests/conftest.py::mock_api_call)."""

    def __init__(self, raise_app_exceptions: bool = True):
        # Starlette re-raises an unhandled exception after its handler has answered 500; False
        # returns that answer instead
        self.raise_app_exceptions = raise_app_exceptions

    def post(self, path, json=None, data=None, content_type=None, headers=None):
        from httpx import ASGITransport, AsyncClient
        from aceapi_v2.application import app as fastapi_app
        from aceapi_v2.sync import run_async

        request_headers = dict(headers or {})
        kwargs = {}
        if json is not None:
            kwargs["json"] = json
        elif data is not None:
            kwargs["content"] = data
            if content_type:
                request_headers["content-type"] = content_type

        async def _send():
            transport = ASGITransport(app=fastapi_app, raise_app_exceptions=self.raise_app_exceptions)
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.post(path, headers=request_headers, **kwargs)

        return _V2Response(run_async(_send()))


@pytest.fixture
def hunt_api():
    return _V2HuntApi()


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Request Body Validation
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_missing_json_body(hunt_api, auth_headers):
    """Verify missing JSON body (empty string) returns 400 Bad Request."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        headers=auth_headers,
        data="",
        content_type="application/json"
    )
    assert result.status_code == 400


@pytest.mark.integration
def test_validate_hunt_non_json_content_type(hunt_api, auth_headers):
    """Verify non-JSON content type returns 415 Unsupported Media Type."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        headers=auth_headers,
        data="some text",
        content_type="text/plain"
    )
    assert result.status_code == 415


@pytest.mark.integration
def test_validate_hunt_empty_json_body(hunt_api, auth_headers):
    """Verify empty JSON object returns error about missing compiled_hunt."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json={},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "request body must be JSON" in data["error"]


@pytest.mark.integration
def test_validate_hunt_missing_compiled_hunt_field(hunt_api, auth_headers):
    """Verify missing 'compiled_hunt' field returns appropriate error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json={"other_field": "value"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "missing 'compiled_hunt' field" in data["error"]


@pytest.mark.integration
def test_validate_hunt_invalid_compiled_hunt_format(hunt_api, auth_headers):
    """Verify invalid compiled_hunt format returns validation error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json={"compiled_hunt": "not-a-dict"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid compiled_hunt" in data["error"]


@pytest.mark.integration
def test_validate_hunt_compiled_hunt_missing_required_fields(hunt_api, auth_headers):
    """Verify compiled_hunt missing required fields returns validation error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json={"compiled_hunt": {"version": 1}},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid compiled_hunt" in data["error"]


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - YAML/Config Validation
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_invalid_yaml_syntax(hunt_api, auth_headers):
    """Verify invalid YAML syntax returns validation error."""
    invalid_yaml = """rule:
  name: test
  invalid: yaml: : : syntax
  [broken
"""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(invalid_yaml),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False


@pytest.mark.integration
def test_validate_hunt_missing_required_field_uuid(hunt_api, auth_headers):
    """Verify hunt config missing uuid field returns validation error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(_hunt_yaml(without="uuid")),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid hunt config" in data["error"]
    assert "uuid" in data["error"]


@pytest.mark.integration
def test_validate_hunt_missing_required_field_name(hunt_api, auth_headers):
    """Verify hunt config missing name field returns validation error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(_hunt_yaml(without="name")),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid hunt config" in data["error"]
    assert "name" in data["error"]


@pytest.mark.integration
def test_validate_hunt_missing_required_field_type(hunt_api, auth_headers):
    """Verify hunt config missing type field returns validation error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(_hunt_yaml(without="type")),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "missing 'rule.type'" in data["error"]


@pytest.mark.integration
def test_validate_hunt_missing_required_field_frequency(hunt_api, auth_headers):
    """Verify hunt config missing frequency field returns validation error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(_hunt_yaml(without="frequency")),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid hunt config" in data["error"]
    assert "frequency" in data["error"]


@pytest.mark.integration
def test_validate_hunt_invalid_frequency_format(hunt_api, auth_headers):
    """Verify hunt config with invalid frequency format returns error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(_hunt_yaml({"frequency": "invalid_frequency"})),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "frequency must be a timedelta string or a valid cron expression" in data["error"]


@pytest.mark.integration
def test_validate_hunt_unknown_hunt_type(hunt_api, auth_headers):
    """Verify unknown hunt type returns appropriate error."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(_hunt_yaml({"type": "nonexistent_hunt_type_xyz"})),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid hunt type" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_invalid_query_hunt_config(hunt_api, auth_headers):
    """The hunt is validated by its own type's config class, so a field only a query hunt
    requires is enforced."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(_hunt_yaml(without="time_range")),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid hunt config" in data["error"]
    assert "time_range" in data["error"]


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Success Cases
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_valid_hunt(hunt_api, auth_headers, data_source):
    """Verify a completely valid hunt passes validation, without running it."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(VALID_HUNT_YAML),
        headers=auth_headers
    )

    assert result.status_code == 200
    assert result.get_json() == {"valid": True}
    assert data_source.searches == []


@pytest.mark.integration
def test_validate_hunt_valid_hunt_with_includes(hunt_api, auth_headers, hunt_audit_records):
    """Verify valid hunt with include files passes validation."""
    base_yaml = _hunt_yaml({"name": "base_hunt", "tags": ["base_tag"]})
    main_yaml = """include:
  - includes/base.yaml
rule:
  name: main_hunt
  tags:
    - main_tag
"""

    payload = {
        "compiled_hunt": CompiledHunt(
            target="main.yaml",
            package_root="/tmp/test",
            assets=[
                EmbeddedFile(kind="yaml", path="includes/base.yaml", content=base_yaml),
                EmbeddedFile(kind="yaml", path="main.yaml", content=main_yaml),
            ],
        ).model_dump()
    }

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    # the hunt loaded is the merge of the two files
    assert hunt_audit_records[0]["hunt"]["name"] == "main_hunt"


@pytest.mark.integration
def test_validate_hunt_nested_directory_structure(hunt_api, auth_headers):
    """Verify hunts with nested directory paths work correctly."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(VALID_HUNT_YAML, target="hunts/subdir/nested/test.yaml"),
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
def test_validate_hunt_execution_arguments_invalid_types(hunt_api, auth_headers, execution_arguments, error_contains):
    """Verify invalid execution_arguments field types return validation error."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = execution_arguments

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
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
def test_validate_hunt_execution_query_hunt_missing_start_time(hunt_api, auth_headers):
    """Verify QueryHunt without start_time returns clear error."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {"end_time": "01/15/2025:12:00:00"}

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "start_time is required" in data["error"]


@pytest.mark.integration
def test_validate_hunt_execution_query_hunt_missing_end_time(hunt_api, auth_headers):
    """Verify QueryHunt without end_time returns clear error."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {"start_time": "01/15/2025:12:00:00"}

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "end_time is required" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("invalid_time,field_name", [
    ("2025-01-15 12:00:00", "start_time"),
    ("01-15-2025:12:00:00", "start_time"),
    ("01/15/2025 12:00:00", "start_time"),
    ("15/01/2025:12:00:00", "start_time"),
    ("not-a-date", "start_time"),
    ("", "start_time"),
    ("01/15/2025:25:00:00", "start_time"),
    ("01/15/2025:12:60:00", "start_time"),
])
def test_validate_hunt_execution_invalid_start_time_format(hunt_api, auth_headers, invalid_time, field_name):
    """Verify invalid start_time format returns clear error with expected format."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {
        "start_time": invalid_time,
        "end_time": "01/15/2025:12:00:00"
    }

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "start_time" in data["error"].lower()
    assert "MM/DD/YYYY:HH:MM:SS" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("invalid_time", [
    "2025-01-15 12:00:00",
    "not-a-date",
    "",
])
def test_validate_hunt_execution_invalid_end_time_format(hunt_api, auth_headers, invalid_time):
    """Verify invalid end_time format returns clear error with expected format."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {
        "start_time": "01/15/2025:10:00:00",
        "end_time": invalid_time
    }

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
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
def test_validate_hunt_execution_invalid_timezone(hunt_api, auth_headers):
    """Verify invalid timezone returns clear error."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {**EXECUTION_TIMES, "timezone": "Invalid/Timezone"}

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
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
def test_validate_hunt_execution_valid_timezones(hunt_api, auth_headers, data_source, timezone):
    """Verify valid timezones are accepted, and the times are searched in that zone."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {**EXECUTION_TIMES, "timezone": timezone}

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    tz = pytz.timezone(timezone)
    assert len(data_source.searches) == 1
    assert data_source.searches[0]["start_time"] == tz.localize(datetime(2025, 1, 15, 10))
    assert data_source.searches[0]["end_time"] == tz.localize(datetime(2025, 1, 15, 12))


@pytest.mark.integration
def test_validate_hunt_execution_defaults_to_utc(hunt_api, auth_headers, data_source):
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 200
    assert data_source.searches[0]["start_time"] == pytz.utc.localize(datetime(2025, 1, 15, 10))
    assert data_source.searches[0]["end_time"] == pytz.utc.localize(datetime(2025, 1, 15, 12))


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Execution Success Cases
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_success_no_analyze_no_alerts(hunt_api, auth_headers, data_source):
    """Verify successful execution without analyze_results or create_alerts."""
    data_source.events = [{"src": "1.2.3.4"}]

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert "roots" in data
    assert "logs" in data
    assert len(data["roots"]) == 1
    assert data["roots"][0]["details"]["events"] == [{"src": "1.2.3.4"}]
    # nothing is analyzed or alerted, so the root never leaves the hunt's staging directory
    uuid = data["roots"][0]["uuid"]
    assert not os.path.exists(storage_dir_from_uuid(uuid))
    assert workload_count(uuid) == 0


@pytest.mark.integration
def test_validate_hunt_execution_serializes_detection_points(hunt_api, auth_headers, data_source):
    """A submitted root carries DetectionPoint objects in its json (correlation-mode
    hunts always attach one). The endpoint must serialize them via the ACE encoder
    rather than failing with 'Object of type DetectionPoint is not JSON serializable'."""
    data_source.events = [{"src": "1.2.3.4"}]

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert len(data["roots"]) == 1
    assert data["roots"][0]["detections"][0]["description"] == "hunt test_hunt (test) matched"


@pytest.mark.integration
def test_validate_hunt_execution_sets_manual_hunt(hunt_api, auth_headers, data_source):
    """The validate endpoint must set manual_hunt=True on the hunt before executing it.
       manual_hunt causes suppression to be ignored so the analyst sees the hunt's true
       output, unaffected by production alert history."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 200
    assert data_source.searches[0]["manual_hunt"] is True


@pytest.mark.integration
def test_validate_hunt_execution_forwards_time_range_overrides(hunt_api, auth_headers, data_source):
    """Verify execution_arguments.time_range_overrides reach the hunt's search."""
    overrides = {"TIMESPEC": "00:10:00", "TIMESPEC2": "02:00:00"}
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {**EXECUTION_TIMES, "time_range_overrides": overrides}

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 200
    assert data_source.searches[0].get("time_range_overrides") == overrides


@pytest.mark.integration
def test_validate_hunt_execution_omits_time_range_overrides_when_not_set(hunt_api, auth_headers, data_source):
    """When time_range_overrides is absent, the search is not given one."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 200
    assert "time_range_overrides" not in data_source.searches[0]


@pytest.mark.integration
def test_validate_hunt_execution_success_with_analyze_results(hunt_api, auth_headers, data_source):
    """Verify successful execution with analyze_results=True."""
    data_source.events = [{"src": "1.2.3.4"}]

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {**EXECUTION_TIMES, "analyze_results": True}

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert len(data["roots"]) == 1
    uuid = data["roots"][0]["uuid"]

    # the copy is where the engine looks for it, queued for analysis but not an alert
    root = load_root(storage_dir_from_uuid(uuid))
    assert root.queue == QUEUE_DEFAULT
    # whatever the validation run submits is marked as such
    assert root.has_tag(TAG_HUNT_VALIDATION)
    assert root.details["events"] == [{"src": "1.2.3.4"}]
    assert workload_count(uuid) == 1
    assert get_db().query(Alert).filter(Alert.uuid == uuid).count() == 0


@pytest.mark.integration
def test_validate_hunt_execution_success_with_create_alerts(hunt_api, auth_headers, data_source):
    """Verify successful execution with create_alerts=True."""
    data_source.events = [{"src": "1.2.3.4"}]

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {**EXECUTION_TIMES, "create_alerts": True}

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert len(data["roots"]) == 1
    uuid = data["roots"][0]["uuid"]

    alert = get_db().query(Alert).filter(Alert.uuid == uuid).one()
    # a config key belongs to no analyst, so the alert has no owner
    assert alert.owner_id is None
    assert alert.queue == QUEUE_DEFAULT
    root = load_root(storage_dir_from_uuid(uuid))
    assert root.analysis_mode == ANALYSIS_MODE_CORRELATION
    assert root.has_tag(TAG_HUNT_VALIDATION)
    assert workload_count(uuid) == 1


@pytest.mark.integration
def test_validate_hunt_execution_create_alerts_owned_by_key_holder(hunt_api, data_source):
    """An alert created with an analyst's own API key belongs to that analyst."""
    data_source.events = [{"src": "1.2.3.4"}]

    user = add_user("hunt_tuner", "hunt_tuner@localhost", "Hunt Tuner", "password")
    add_user_permission(user.id, "hunt", "write")
    api_key = create_api_key(user.id, "tuning", inherit=True)

    try:
        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {**EXECUTION_TIMES, "create_alerts": True}

        result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers={"x-ace-auth": api_key})

        assert result.status_code == 200
        uuid = result.get_json()["roots"][0]["uuid"]
        alert = get_db().query(Alert).filter(Alert.uuid == uuid).one()
        assert alert.owner_id == user.id
        assert alert.owner_time is not None
    finally:
        delete_user("hunt_tuner")


@pytest.mark.integration
def test_validate_hunt_execution_success_with_custom_queue(hunt_api, auth_headers, data_source):
    """Verify successful execution with custom queue."""
    data_source.events = [{"src": "1.2.3.4"}]

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {**EXECUTION_TIMES, "analyze_results": True, "queue": "custom-queue"}

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert data["roots"][0]["queue"] == "custom-queue"
    assert load_root(storage_dir_from_uuid(data["roots"][0]["uuid"])).queue == "custom-queue"


@pytest.mark.integration
def test_validate_hunt_execution_empty_submissions(hunt_api, auth_headers, data_source):
    """Verify execution with no submissions returns empty roots."""
    data_source.events = []

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert data["roots"] == []
    assert "logs" in data


@pytest.mark.integration
def test_validate_hunt_execution_returns_none(hunt_api, auth_headers, data_source):
    """Verify a search that returns nothing at all (the hunt submits None) is handled."""
    data_source.events = None

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
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
def test_validate_hunt_execution_raises_exception(hunt_api, auth_headers, data_source):
    """Verify hunt execution exception returns wrapped error message."""
    data_source.error = Exception("Connection failed to SIEM")

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error executing hunt" in data["error"].lower()
    assert "Connection failed to SIEM" in data["error"]


@pytest.mark.integration
def test_validate_hunt_execution_remote_api_error(hunt_api, auth_headers, data_source):
    """Verify RemoteApiError propagates status code and message from remote API."""
    data_source.error = RemoteApiError(403, "Forbidden")

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert data["error"] == "Forbidden"
    assert data["remote_status_code"] == 403


@pytest.mark.integration
def test_validate_hunt_execution_non_query_hunt_no_time_required(hunt_api, auth_headers):
    """Verify non-QueryHunt types don't require start_time/end_time."""
    hunt = yaml.safe_load(VALID_HUNT_YAML)
    rule = {key: value for key, value in hunt["rule"].items()
            if key not in ("query", "time_range", "full_coverage", "use_index_time")}
    rule["type"] = "test_plain"
    payload = _make_compiled_payload(yaml.safe_dump({"rule": rule}))
    payload["execution_arguments"] = {"analyze_results": False}

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert len(data["roots"]) == 1
    assert data["original_events"] is None


@pytest.mark.integration
def test_validate_hunt_execution_logs_collected(hunt_api, auth_headers):
    """Verify logs are collected during execution."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=payload,
        headers=auth_headers
    )

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert "logs" in data
    log_messages = " ".join(data["logs"])
    assert "test data source searched by hunt test_hunt" in log_messages


@pytest.mark.integration
def test_validate_hunt_logs_suppressed_from_production_handlers(hunt_api, auth_headers):
    """Logs generated during a /hunt/validate call must not reach the production
    root-logger handlers (which carry the ThreadSuppressionFilter), while the caller
    still receives them in the response."""
    marker = "test data source searched by hunt"
    received = []

    class ProbeHandler(logging.Handler):
        def emit(self, record):
            received.append(record.getMessage())

    # the probe stands in for a production sink: it carries the ThreadSuppressionFilter
    # exactly as initialize_logging installs it on the real root handlers
    probe = ProbeHandler()
    probe.addFilter(ThreadSuppressionFilter())
    root_logger = logging.getLogger()
    root_logger.addHandler(probe)

    try:
        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = EXECUTION_TIMES

        result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        # the caller still receives the log line
        assert any(marker in line for line in data["logs"])
        # ... but the production-style handler did not
        assert not any(marker in m for m in received)

        # negative control: a log emitted outside the suppression context still
        # reaches the production-style handler (suppression is not a global silence)
        logging.error("%s outside validation", marker)
        assert any(marker in m for m in received)
    finally:
        root_logger.removeHandler(probe)


@pytest.mark.integration
def test_validate_hunt_load_phase_logs_suppressed(hunt_api, auth_headers):
    """Log records emitted during the load phase of a /hunt/validate call (before hunt
    execution) must also be kept off the production handlers."""
    received = []

    class ProbeHandler(logging.Handler):
        def emit(self, record):
            received.append(record.getMessage())

    probe = ProbeHandler()
    probe.setLevel(logging.DEBUG)
    probe.addFilter(ThreadSuppressionFilter())
    root_logger = logging.getLogger()
    root_logger.addHandler(probe)

    try:
        payload = _make_compiled_payload(VALID_HUNT_YAML)
        result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)
        assert result.status_code == 200
        # the "loading compiled hunt" debug line is emitted during the wrapped call
        assert not any("loading compiled hunt" in m for m in received)
        # and so are the hunt manager's own records
        assert not any("loading hunt managers" in m for m in received)
    finally:
        root_logger.removeHandler(probe)


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Original (pre-correlation) Events
# =============================================================================

# drops every event whose tag is "drop"
CORRELATE_DROP = {"logic": [{
    "when": {"type": "equals", "property": "tag", "value": "drop"},
    "execute": [{"action": {"type": "filter"}}],
}]}


@pytest.mark.integration
def test_validate_hunt_response_includes_original_events(hunt_api, auth_headers, data_source):
    """When the executed hunt captured original_query_results (i.e. correlate ran),
    the validate response should expose them at the top level."""
    captured = [{"src": "1.2.3.4", "tag": "keep"}, {"src": "5.6.7.8", "tag": "drop"}]
    data_source.events = captured

    payload = _make_compiled_payload(_hunt_yaml({"correlate": CORRELATE_DROP}))
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert data["original_events"] == captured
    # correlation filtered one event out
    assert len(data["roots"]) == 1
    assert data["roots"][0]["details"]["events"] == [{"src": "1.2.3.4", "tag": "keep"}]
    # the per-root details also carry the originals (set by process_query_results)
    assert data["roots"][0]["details"]["original_events"] == captured
    assert data["correlation_trace"] is not None


@pytest.mark.integration
def test_validate_hunt_response_original_events_non_correlate(hunt_api, auth_headers, data_source):
    """A non-correlate hunt run through the validate API (a manual run) snapshots the raw
    query results, so original_events is exposed at the top level. The per-root details are
    NOT bloated with a copy — those events already live in details["events"]."""
    captured = [{"src": "1.2.3.4"}, {"src": "5.6.7.8"}]
    data_source.events = captured

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert data["original_events"] == captured
    # ungrouped, so each event is a root of its own
    assert [root["details"]["events"] for root in data["roots"]] == [[event] for event in captured]
    assert all("original_events" not in root["details"] for root in data["roots"])


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - query_results override
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_query_results_override(hunt_api, auth_headers, data_source):
    """When execution_arguments.query_results is set, those events are processed as the
    query's results and the data source is never searched."""
    override_events = [{"src": "1.2.3.4"}, {"src": "5.6.7.8"}]
    data_source.events = [{"src": "9.9.9.9"}]

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = {"query_results": override_events}

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    # The override path must not re-run the data-source query.
    assert data_source.searches == []
    assert data["original_events"] == override_events
    assert [root["details"]["events"] for root in data["roots"]] == [[event] for event in override_events]


@pytest.mark.integration
def test_validate_hunt_query_results_override_without_times(hunt_api, auth_headers, data_source):
    """The override path should NOT require start_time/end_time — those are only
    needed when actually querying the data source."""
    payload = _make_compiled_payload(VALID_HUNT_YAML)
    # No start_time or end_time at all
    payload["execution_arguments"] = {"query_results": [{"src": "1.1.1.1"}]}

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    # Without the override this would 400 with "start_time is required"
    assert result.status_code == 200
    data = result.get_json()
    assert data["valid"] is True
    assert len(data["roots"]) == 1
    assert data_source.searches == []


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - hunts have no access to secrets
# =============================================================================

def _hunt_with_predefined_env(env_value):
    """A hunt package whose hunt defines one predefined command with the given env value."""
    hunt_yaml = _hunt_yaml(commands=[{
        "name": "get_r7_investigation_comments",
        "type": "executable",
        "path": "__pkg__/r7_get_comments.py",
        "env": {"R7_API_KEY": env_value},
    }])
    return {
        "compiled_hunt": CompiledHunt(
            target="test.yaml",
            package_root="/tmp/test",
            assets=[
                EmbeddedFile(kind="yaml", path="test.yaml", content=hunt_yaml),
                EmbeddedFile(kind="executable", path="r7_get_comments.py", content="#!/bin/sh\n", permissions=0o755),
            ],
        ).model_dump()
    }


@pytest.mark.integration
@pytest.mark.parametrize("env_value", [
    "{{ _secrets['rapid7.api_key'] }}",
    "{{ _config['rapid7']['api_key'] }}",
])
def test_validate_hunt_rejects_env_reading_secrets_or_config(hunt_api, auth_headers, env_value):
    """Hunts have no access to secrets or configuration; say so at authoring time rather than
    letting the step fail on every event in production."""
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_hunt_with_predefined_env(env_value),
        headers=auth_headers
    )

    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "get_r7_investigation_comments" in data["error"]
    assert "no access to secrets or configuration" in data["error"]


@pytest.mark.integration
def test_validate_hunt_accepts_env_reading_event_data(hunt_api, auth_headers):
    result = hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_hunt_with_predefined_env("{{ _event.user }}"),
        headers=auth_headers
    )

    assert result.status_code == 200
    assert result.get_json()["valid"] is True


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - custom correlation command types
# =============================================================================

class _EchoOptions(BaseModel):
    model_config = {"extra": "forbid"}
    message: str


class EchoCommand(CorrelationCommand):
    config_class = _EchoOptions

    def execute(self, context, options):
        return options.message


def _validate_hunt_with_custom_command(hunt_api, auth_headers, command: dict):
    """Validates a hunt whose correlate block runs one command."""
    correlate = {"logic": [{"transform": {"method": "property", "property_name": "p", "command": command}}]}
    return hunt_api.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(_hunt_yaml({"correlate": correlate})),
        headers=auth_headers
    )


@pytest.fixture
def registered_echo_command_type(monkeypatch):
    """Configures an `echo` command type, which the endpoint's own loader then registers."""
    monkeypatch.setattr(get_config().hunter.correlation, "command_types", [
        CommandTypeConfig(name="echo", python_module=__name__, python_class="EchoCommand"),
    ])
    reset_command_types_loaded_flag()
    yield
    # the next load registers what the real configuration declares
    clear_command_types()
    reset_command_types_loaded_flag()


@pytest.mark.integration
def test_validate_hunt_rejects_unregistered_custom_command_type(hunt_api, auth_headers, registered_echo_command_type):
    """A typo'd or missing custom type would otherwise error (and so alert) on every event."""
    result = _validate_hunt_with_custom_command(hunt_api, auth_headers, {"type": "ecoh"})

    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "unknown command type 'ecoh'" in data["error"]


@pytest.mark.integration
def test_validate_hunt_rejects_bad_custom_command_options(hunt_api, auth_headers, registered_echo_command_type):
    result = _validate_hunt_with_custom_command(
        hunt_api, auth_headers, {"type": "echo", "options": {"mesage": "typo"}})

    assert result.status_code == 400
    assert "options.mesage" in result.get_json()["error"]


@pytest.mark.integration
def test_validate_hunt_accepts_registered_custom_command_type(hunt_api, auth_headers, registered_echo_command_type):
    result = _validate_hunt_with_custom_command(
        hunt_api, auth_headers, {"type": "echo", "options": {"message": "{{ _event.user }}"}})

    assert result.status_code == 200
    assert result.get_json()["valid"] is True


@pytest.mark.integration
def test_validate_hunt_runs_registered_custom_command_type(hunt_api, auth_headers, registered_echo_command_type):
    correlate = {"logic": [{"transform": {"method": "property", "property_name": "greeting",
                                          "command": {"type": "echo", "options": {"message": "hi {{ _event.user }}"}}}}]}
    payload = _make_compiled_payload(_hunt_yaml({"correlate": correlate}))
    payload["execution_arguments"] = {"query_results": [{"user": "alice"}]}

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 200
    assert result.get_json()["roots"][0]["details"]["events"] == [{"user": "alice", "greeting": "hi alice"}]


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Package Confinement
# =============================================================================

@pytest.mark.integration
@pytest.mark.parametrize("asset_path", ["../escaped.yaml", "/tmp/escaped.yaml"])
def test_validate_hunt_rejects_asset_outside_package(hunt_api, auth_headers, asset_path):
    """An asset path is client-supplied; one that leaves the package is refused before any write."""
    # each request's package directory is created inside the compiled hunt dir
    escaped = asset_path if os.path.isabs(asset_path) else os.path.join(get_compiled_hunt_dir(), "escaped.yaml")
    payload = {
        "compiled_hunt": CompiledHunt(
            target="test.yaml",
            package_root="/tmp/test",
            assets=[
                EmbeddedFile(kind="yaml", path="test.yaml", content=VALID_HUNT_YAML),
                EmbeddedFile(kind="yaml", path=asset_path, content="rule: {}\n"),
            ],
        ).model_dump()
    }

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 400
    error = result.get_json()["error"]
    assert f"asset path '{asset_path}'" in error and "package root" in error
    assert not os.path.exists(escaped)


@pytest.mark.integration
def test_validate_hunt_rejects_include_outside_package(hunt_api, auth_headers, tmp_path, hunt_audit_records):
    """An include outside the package is refused before the hunt is parsed or loaded."""
    outside = tmp_path / "outside.yaml"
    outside.write_text(VALID_HUNT_YAML)
    payload = _make_compiled_payload(f"include:\n  - {outside}\nrule:\n  name: included\n")

    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 400
    assert str(outside) in result.get_json()["error"]
    assert "outside" in result.get_json()["error"]
    # the hunt was never loaded
    assert "hunt" not in hunt_audit_records[0]


@pytest.mark.integration
def test_validate_hunt_rejects_executable_outside_package(hunt_api, auth_headers, hunt_audit_records):
    hunt_yaml = _hunt_yaml({"correlate": {"logic": [
        {"transform": {"command": {"type": "executable", "path": "/usr/bin/env"}}},
    ]}})
    result = hunt_api.post(HUNT_VALIDATE_URL, json=_make_compiled_payload(hunt_yaml), headers=auth_headers)

    assert result.status_code == 400
    assert "executable /usr/bin/env is outside the submitted hunt" in result.get_json()["error"]
    # the hunt was never loaded
    assert "hunt" not in hunt_audit_records[0]


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Audit Trail
# =============================================================================

@pytest.fixture
def hunt_audit_records():
    """HUNT_AUDIT records as a production handler receives them (it drops suppressed records)."""
    records = []

    class ProbeHandler(logging.Handler):
        def emit(self, record):
            message = record.getMessage()
            if message.startswith("HUNT_AUDIT "):
                # the actor fields every AUDIT record has, from extra={}, under a key the JSON never uses
                actor = {key: getattr(record, key, "missing") for key in audit_actor(None)}
                records.append({**json.loads(message[len("HUNT_AUDIT "):]), "_actor": actor})

    probe = ProbeHandler()
    probe.addFilter(ThreadSuppressionFilter())
    audit_logger = logging.getLogger("ace.hunt_audit")
    previous_level = audit_logger.level
    audit_logger.setLevel(logging.INFO)
    audit_logger.addHandler(probe)
    try:
        yield records
    finally:
        audit_logger.removeHandler(probe)
        audit_logger.setLevel(previous_level)


@pytest.mark.integration
def test_validate_hunt_audits_execution_with_the_key_that_ran_it(hunt_api, hunt_audit_records, data_source):
    data_source.events = [{"src": "1.2.3.4"}]

    user = add_user("hunt_auditor", "hunt_auditor@localhost", "Hunt Auditor", "password")
    add_user_permission(user.id, "hunt", "write")
    api_key = create_api_key(user.id, "hunt-ai", scope=[("hunt", "write")])

    try:
        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {**EXECUTION_TIMES, "create_alerts": True}

        result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers={"x-ace-auth": api_key})

        assert result.status_code == 200
        alert_uuid = result.get_json()["roots"][0]["uuid"]
        assert get_db().query(Alert).filter(Alert.uuid == alert_uuid).count() == 1
        assert len(hunt_audit_records) == 1
        record = hunt_audit_records[0]
        assert record["event"] == "hunt_validate"
        assert record["status"] == 200
        assert record["detail"] is None
        assert record["user"] == "hunt_auditor"
        assert record["user_id"] == user.id
        assert record["key_name"] == "hunt-ai"
        assert isinstance(record["key_id"], int)
        assert record["_actor"] == {"actor": "hunt_auditor", "actor_user_id": user.id, "actor_key_id": record["key_id"],
                                    "actor_key_name": "hunt-ai", "auth_type": "user"}
        assert record["hunt"] == {"type": "test", "name": "test_hunt", "uuid": "7b5f2270-4a1d-4009-86a0-de3f8c9c82e7"}
        assert record["query"] == "index=proxy | stats count by src"
        assert record["execution"]["create_alerts"] is True
        assert record["execution"]["start_time"] == "01/15/2025:10:00:00"
        assert record["result"] == {"roots": 1, "events": 1, "alert_uuids": [alert_uuid]}
        assert record["package"]["target"] == "test.yaml"
        assert record["package"]["assets"][0]["sha256"] == hashlib.sha256(VALID_HUNT_YAML.encode()).hexdigest()
        assert isinstance(record["duration_ms"], int)
    finally:
        delete_user("hunt_auditor")


@pytest.mark.integration
def test_validate_hunt_audits_a_rejected_request(hunt_api, auth_headers, hunt_audit_records):
    result = hunt_api.post(HUNT_VALIDATE_URL, json=_make_compiled_payload("rule: [unclosed\n"), headers=auth_headers)

    assert result.status_code == 400
    assert len(hunt_audit_records) == 1
    record = hunt_audit_records[0]
    assert record["event"] == "hunt_rejected"
    assert record["status"] == 400
    assert "YAML syntax error" in record["detail"]
    # a config key has a name but no key row
    assert record["key_name"] == record["user"]
    assert record["key_id"] is None
    assert "hunt" not in record


@pytest.mark.integration
def test_validate_hunt_audits_a_body_that_is_not_json(hunt_audit_records, auth_headers):
    """A body that is not JSON is answered 415 and audited as refused."""
    response = _V2HuntApi().post(HUNT_VALIDATE_URL, data="some text", content_type="text/plain", headers=auth_headers)

    assert response.status_code == 415
    assert response.get_json() == {"valid": False, "error": "request body must be JSON"}
    assert [(record["event"], record["status"]) for record in hunt_audit_records] == [("hunt_rejected", 415)]


@pytest.mark.integration
def test_validate_hunt_audits_an_execution_error(hunt_api, auth_headers, hunt_audit_records, data_source):
    data_source.error = Exception("Connection failed to SIEM")

    payload = _make_compiled_payload(VALID_HUNT_YAML)
    payload["execution_arguments"] = EXECUTION_TIMES
    result = hunt_api.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

    assert result.status_code == 400
    assert [record["event"] for record in hunt_audit_records] == ["hunt_error"]
    assert "Connection failed to SIEM" in hunt_audit_records[0]["detail"]
    assert "result" not in hunt_audit_records[0]


def _query_and_leave_open():
    # what Persistable.register_persistence_source() does: a SELECT through get_db() and no commit
    get_db().execute(text("SELECT 1"))


def _query_then_lose_connection():
    # MySQL server has gone away mid-request: the connection is invalidated inside the
    # transaction, and the session refuses every later statement with PendingRollbackError
    get_db().execute(text("SELECT 1"))
    get_db().connection().invalidate()
    get_db().execute(text("SELECT 1"))


@pytest.mark.integration
@pytest.mark.parametrize("database_use,expected_status", [
    (_query_and_leave_open, 200),
    (_query_then_lose_connection, 500),
])
def test_validate_hunt_v2_resets_the_thread_session(monkeypatch, auth_headers, hunt_audit_records, database_use, expected_status):
    """The worker thread's get_db() session is removed after every request, so one left in a
    transaction, or holding a dropped connection, cannot fail later requests on that thread."""
    sessions = []
    load_hunt_managers = HunterService.load_hunt_managers

    def _load_hunt_managers(self, *args, **kwargs):
        load_hunt_managers(self, *args, **kwargs)
        sessions.append(get_db()())
        database_use()

    monkeypatch.setattr(HunterService, "load_hunt_managers", _load_hunt_managers)

    result = _V2HuntApi(raise_app_exceptions=False).post(
        HUNT_VALIDATE_URL, json=_make_compiled_payload(VALID_HUNT_YAML), headers=auth_headers)

    assert result.status_code == expected_status
    assert len(sessions) == 1
    assert not sessions[0].in_transaction()
    if expected_status == 500:
        assert [record["event"] for record in hunt_audit_records] == ["hunt_rejected"]
        assert "PendingRollbackError" in hunt_audit_records[0]["detail"]
