from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from splunklib.results import Message

import saq.ai_query.backends.splunk as splunk_backend_module
from saq.ai_query.interface import AIBackendError, AIQueryRejected, AIQueryRequest
from saq.ai_query.registry import load_backend
from saq.configuration.config import get_config
from saq.configuration.secret_ref import SecretRef
from saq.error.remote import RemoteApiError


@pytest.fixture
def backend():
    return load_backend("splunk")


@pytest.fixture
def mock_client(monkeypatch):
    client = MagicMock()
    client.query.return_value = [{"_time": "2026-01-01T00:00:00", "host": "a"}]
    client.encoded_query_link.return_value = "https://splunk/link"
    factory = MagicMock(return_value=client)
    monkeypatch.setattr(splunk_backend_module, "SplunkClient", factory)
    return client


def make_request(**kwargs) -> AIQueryRequest:
    end = datetime.now(timezone.utc)
    defaults = {"query": "search index=main", "start_time": end - timedelta(hours=1), "end_time": end}
    defaults.update(kwargs)
    return AIQueryRequest(**defaults)


@pytest.mark.unit
def test_config_revalidated_against_backend_model(backend):
    assert backend.config.splunk_config == "test_api"
    assert backend.config.auto_append == "| fields *"


@pytest.mark.unit
def test_validate_request_rejections(backend):
    with pytest.raises(AIQueryRejected):
        backend.validate_request(make_request(query="  "))

    end = datetime.now(timezone.utc)
    with pytest.raises(AIQueryRejected):
        backend.validate_request(make_request(start_time=end, end_time=end - timedelta(hours=1)))

    # one day past the configured max_window, whatever it is set to
    from saq.util import create_timedelta
    too_wide = create_timedelta(backend.config.limits.max_window) + timedelta(days=1)
    with pytest.raises(AIQueryRejected):
        backend.validate_request(make_request(start_time=end - too_wide, end_time=end))

    with pytest.raises(AIQueryRejected):
        backend.validate_request(make_request(limit=backend.config.limits.max_limit + 1))

    # a valid request passes
    backend.validate_request(make_request())


@pytest.mark.unit
def test_execute_builds_client_per_request_and_appends_fields(backend, mock_client, monkeypatch):
    request = make_request(limit=50, timeout_seconds=60)
    result = backend.execute(request)

    factory = splunk_backend_module.SplunkClient
    factory.assert_called_once_with("test_api")

    query_arg = mock_client.query.call_args.args[0]
    assert query_arg == "search index=main | fields *"
    assert mock_client.query.call_args.kwargs["limit"] == 50
    assert mock_client.query.call_args.kwargs["timeout"] == timedelta(seconds=60)

    assert result.row_count == 1
    assert not result.truncated
    assert result.window_start == request.start_time
    assert result.meta["search_link"] == "https://splunk/link"


@pytest.mark.unit
def test_execute_applies_config_defaults(backend, mock_client):
    backend.execute(make_request())
    assert mock_client.query.call_args.kwargs["limit"] == backend.config.limits.default_limit
    assert mock_client.query.call_args.kwargs["timeout"] == timedelta(seconds=backend.config.limits.default_query_timeout)


@pytest.mark.unit
def test_execute_truncation_at_limit(backend, mock_client):
    mock_client.query.return_value = [{"n": str(i)} for i in range(3)]
    result = backend.execute(make_request(limit=3))
    assert result.truncated
    assert result.truncation_reason == "limit"


@pytest.mark.unit
def test_execute_filters_splunk_messages(backend, mock_client):
    mock_client.query.return_value = [Message("INFO", "some server message"), {"n": "1"}]
    result = backend.execute(make_request())
    assert result.rows == [{"n": "1"}]
    assert result.row_count == 1


@pytest.mark.unit
@pytest.mark.parametrize("remote_status,expected_status", [(401, 502), (504, 504), (502, 502), (500, 502)])
def test_execute_maps_remote_errors(backend, mock_client, remote_status, expected_status):
    mock_client.query.side_effect = RemoteApiError(remote_status, "boom")
    with pytest.raises(AIBackendError) as exc_info:
        backend.execute(make_request())
    assert exc_info.value.status_code == expected_status


@pytest.mark.unit
def test_validate_startup_rejects_encrypted_ref(backend, monkeypatch):
    splunk_config = get_config().get_splunk_config("test_api")
    monkeypatch.setattr(splunk_config, "token", SecretRef(key="splunk_token"))
    with pytest.raises(RuntimeError, match="encrypted"):
        backend.validate_startup()


@pytest.mark.unit
def test_validate_startup_rejects_missing_credential(backend):
    # the unittest splunk config carries no credential at all
    with pytest.raises(RuntimeError, match="token is not set"):
        backend.validate_startup()


@pytest.mark.unit
def test_validate_startup_returns_owned_paths(backend, monkeypatch):
    splunk_config = get_config().get_splunk_config("test_api")
    monkeypatch.setattr(splunk_config, "token", SecretRef(literal="readonly-token"))
    assert backend.validate_startup() == ["splunk_config_test_api.token"]
