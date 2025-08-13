import os

import pytest

import aceapi.auth
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

from saq.constants import G_AUTOMATION_USER_ID, G_ENCRYPTION_KEY
from saq.environment import g_int, g_obj
from saq.util import sha256_str, is_uuid

API_KEY = "0c89aad4-c942-4275-8282-5772aedb6bcd"

@pytest.fixture(autouse=True)
def set_test_password(monkeypatch):
    monkeypatch.setattr(g_obj(G_ENCRYPTION_KEY), "value", os.urandom(32))

@pytest.mark.parametrize("apikeys,api_key,expected_result", [
    ({}, API_KEY, None),
    ({"test": sha256_str(API_KEY)}, API_KEY, ApiAuthResult(auth_name="test", auth_type=API_AUTH_TYPE_CONFIG)),
    ({"test": sha256_str(API_KEY)}, "invalid", None),
])
@pytest.mark.unit
def test_get_config_api_key_match(monkeypatch, apikeys, api_key, expected_result):
    monkeypatch.setattr(aceapi.auth, "get_config", lambda: { "apikeys": apikeys })
    assert _get_config_api_key_match(sha256_str(api_key)) == expected_result

@pytest.mark.integration
def test_set_user_api_key():
    api_key = set_user_api_key(g_int(G_AUTOMATION_USER_ID), None)
    assert is_uuid(api_key)
    assert get_user_api_key(g_int(G_AUTOMATION_USER_ID)) == api_key
    # unknown user
    assert set_user_api_key(-1) is None
    assert get_user_api_key(-1) is None

    # testing clear
    assert clear_user_api_key(g_int(G_AUTOMATION_USER_ID))
    assert get_user_api_key(g_int(G_AUTOMATION_USER_ID)) is None

    # invalid clear
    assert not clear_user_api_key(-1)
    assert not clear_user_api_key(g_int(G_AUTOMATION_USER_ID))

@pytest.mark.integration
def test_set_invalid_user_api_key():
    with pytest.raises(ValueError):
        set_user_api_key(g_int(G_AUTOMATION_USER_ID), "invalid")

@pytest.mark.integration
def test_get_user_api_key_match():
    api_key = set_user_api_key(g_int(G_AUTOMATION_USER_ID), None)
    assert _get_user_api_key_match(sha256_str(api_key)) == ApiAuthResult(auth_name="ace", auth_type=API_AUTH_TYPE_USER, auth_user_id=g_int(G_AUTOMATION_USER_ID))

@pytest.mark.integration
def test_verify_api_key(monkeypatch):
    assert verify_api_key(None) is None
    assert verify_api_key(API_KEY) is None
    monkeypatch.setattr(aceapi.auth, "get_config", lambda: { "apikeys": { "test": sha256_str(API_KEY) } })
    assert verify_api_key(API_KEY) == ApiAuthResult(auth_name="test", auth_type=API_AUTH_TYPE_CONFIG)
    user_api_key = set_user_api_key(g_int(G_AUTOMATION_USER_ID), None)
    assert verify_api_key(user_api_key) == ApiAuthResult(auth_name="ace", auth_type=API_AUTH_TYPE_USER, auth_user_id=g_int(G_AUTOMATION_USER_ID))
