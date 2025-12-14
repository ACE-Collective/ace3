import os

import pytest

from aceapi.auth import (
    ApiAuthResult,
    _get_config_api_key_match,
    _get_user_api_key_match,
    set_user_api_key,
    get_user_api_key,
    verify_api_key,
    clear_user_api_key,
    API_AUTH_TYPE_CONFIG,
    API_AUTH_TYPE_USER,
)

from saq.configuration.config import get_config
from saq.environment import get_global_runtime_settings
from saq.util import sha256_str, is_uuid

API_KEY = "0c89aad4-c942-4275-8282-5772aedb6bcd"

@pytest.fixture(autouse=True)
def set_test_password(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", os.urandom(32))

@pytest.mark.parametrize("apikeys,api_key,expected_result", [
    ({}, API_KEY, None),
    ({"test": sha256_str(API_KEY)}, API_KEY, ApiAuthResult(auth_name="test", auth_type=API_AUTH_TYPE_CONFIG)),
    ({"test": sha256_str(API_KEY)}, "invalid", None),
])
@pytest.mark.unit
def test_get_config_api_key_match(monkeypatch, apikeys, api_key, expected_result):
    monkeypatch.setattr(get_config(), "apikeys", apikeys)
    assert _get_config_api_key_match(sha256_str(api_key)) == expected_result

@pytest.mark.integration
def test_set_user_api_key():
    api_key = set_user_api_key(get_global_runtime_settings().automation_user_id, None)
    assert is_uuid(api_key)
    assert get_user_api_key(get_global_runtime_settings().automation_user_id) == api_key
    # unknown user
    assert set_user_api_key(-1) is None
    assert get_user_api_key(-1) is None

    # testing clear
    assert clear_user_api_key(get_global_runtime_settings().automation_user_id)
    assert get_user_api_key(get_global_runtime_settings().automation_user_id) is None

    # invalid clear
    assert not clear_user_api_key(-1)
    assert not clear_user_api_key(get_global_runtime_settings().automation_user_id)

@pytest.mark.integration
def test_set_invalid_user_api_key():
    with pytest.raises(ValueError):
        set_user_api_key(get_global_runtime_settings().automation_user_id, "invalid")

@pytest.mark.integration
def test_get_user_api_key_match():
    api_key = set_user_api_key(get_global_runtime_settings().automation_user_id, None)
    assert _get_user_api_key_match(sha256_str(api_key)) == ApiAuthResult(auth_name="ace", auth_type=API_AUTH_TYPE_USER, auth_user_id=get_global_runtime_settings().automation_user_id)

@pytest.mark.integration
def test_verify_api_key(monkeypatch):
    assert verify_api_key(None) is None
    assert verify_api_key(API_KEY) is None
    monkeypatch.setattr(get_config(), "apikeys", { "test": sha256_str(API_KEY) })
    assert verify_api_key(API_KEY) == ApiAuthResult(auth_name="test", auth_type=API_AUTH_TYPE_CONFIG)
    user_api_key = set_user_api_key(get_global_runtime_settings().automation_user_id, None)
    assert verify_api_key(user_api_key) == ApiAuthResult(auth_name="ace", auth_type=API_AUTH_TYPE_USER, auth_user_id=get_global_runtime_settings().automation_user_id)
