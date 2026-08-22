from datetime import datetime, timedelta, timezone

import pytest

from saq.ai_query.backends.testing import FakeAIQueryBackend
from saq.ai_query.interface import AIBackendError, AIQueryRejected, AIQueryRequest
from saq.ai_query.registry import build_backend_registry, load_backend
from saq.configuration.config import get_ai_query_backend_config, get_config
from saq.configuration.schema import AIQueryBackendConfig


@pytest.mark.unit
def test_ai_query_backend_config_loaded_from_prefix_scan():
    config = get_ai_query_backend_config("fake")
    assert config.name == "fake"
    assert config.enabled
    assert config.python_module == "saq.ai_query.backends.testing"
    assert config.python_class == "FakeAIQueryBackend"
    # defaults applied
    assert config.limits.max_concurrency == 2
    assert config.limits.default_limit == 1000


@pytest.mark.unit
def test_unknown_backend_config_raises():
    with pytest.raises(ValueError):
        get_ai_query_backend_config("does_not_exist")


@pytest.mark.unit
def test_config_parse_does_not_import_backend_module():
    # a section pointing at a nonexistent module validates fine at config-parse time --
    # class import is deferred to the registry, which is the only place it may fail
    section = {
        "name": "bogus",
        "enabled": True,
        "python_module": "saq.ai_query.backends.does_not_exist",
        "python_class": "Nope",
    }
    config = AIQueryBackendConfig.model_validate(section)
    assert config.python_module == "saq.ai_query.backends.does_not_exist"


@pytest.mark.unit
def test_registry_builds_enabled_backends():
    registry = build_backend_registry()
    assert "fake" in registry
    assert isinstance(registry["fake"], FakeAIQueryBackend)


@pytest.mark.unit
def test_load_backend_rejects_non_backend_class(monkeypatch):
    base = get_config().get_ai_query_backend_config("fake")
    monkeypatch.setattr(base, "python_class", "FakeQueryExtras")
    with pytest.raises(TypeError):
        load_backend("fake")


def make_request(**kwargs) -> AIQueryRequest:
    end = datetime.now(timezone.utc)
    defaults = dict(query="search", start_time=end - timedelta(hours=1), end_time=end)
    defaults.update(kwargs)
    return AIQueryRequest(**defaults)


@pytest.mark.unit
def test_fake_backend_execute_returns_canned_rows():
    backend = load_backend("fake")
    request = make_request()
    result = backend.execute(request)
    assert result.row_count == len(result.rows) == 2
    assert not result.truncated
    assert result.window_start == request.start_time
    assert result.window_end == request.end_time
    assert backend.last_request is request


@pytest.mark.unit
def test_fake_backend_truncation_signal():
    backend = load_backend("fake")
    result = backend.execute(make_request(extras={"simulate": "truncated"}))
    assert result.truncated
    assert result.truncation_reason == "backend_cap"
    assert result.row_count == 1


@pytest.mark.unit
def test_fake_backend_rejection_and_error():
    backend = load_backend("fake")

    with pytest.raises(AIQueryRejected):
        backend.validate_request(make_request(extras={"simulate": "rejected"}))

    with pytest.raises(AIQueryRejected):
        backend.validate_request(make_request(query="   "))

    with pytest.raises(AIBackendError) as exc_info:
        backend.execute(make_request(extras={"simulate": "backend_error", "error_status_code": 504}))
    assert exc_info.value.status_code == 504


@pytest.mark.unit
def test_fake_backend_describe():
    backend = load_backend("fake")
    described = backend.describe()
    assert described["name"] == "fake"
    assert described["limits"]["max_limit"] == 5000
    assert "simulate" in described["extras_schema"]["properties"]
