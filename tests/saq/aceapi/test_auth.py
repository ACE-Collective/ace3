import os

import pytest

from aceapi.auth import (
    ApiAuthResult,
    _get_config_api_key_match,
    _get_user_api_key_match,
    create_api_key,
    list_api_keys,
    revoke_api_key,
    verify_api_key,
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
    # bare-string config entries carry no scope (key_scope stays None); the default matches.
    monkeypatch.setattr(get_config(), "apikeys", apikeys)
    assert _get_config_api_key_match(sha256_str(api_key)) == expected_result

@pytest.mark.integration
def test_create_list_revoke_user_api_key():
    user_id = get_global_runtime_settings().automation_user_id
    api_key = create_api_key(user_id, "test", inherit=True)
    assert is_uuid(api_key)

    keys = list_api_keys(user_id)
    assert any(k.key_hash == sha256_str(api_key) for k in keys)

    match = _get_user_api_key_match(sha256_str(api_key))
    assert match.auth_user_id == user_id
    assert match.auth_type == API_AUTH_TYPE_USER
    assert match.key_scope is None  # inherit key

    key_id = next(k.id for k in list_api_keys(user_id) if k.key_hash == sha256_str(api_key))
    assert revoke_api_key(key_id)
    assert _get_user_api_key_match(sha256_str(api_key)) is None
    assert not revoke_api_key(-1)

@pytest.mark.integration
def test_scoped_key_carries_scope():
    user_id = get_global_runtime_settings().automation_user_id
    api_key = create_api_key(user_id, "ai", scope=[("ai", "read")])
    match = _get_user_api_key_match(sha256_str(api_key))
    assert match.key_scope == [("ai", "read")]

@pytest.mark.integration
def test_create_requires_exactly_one_of_inherit_or_scope():
    user_id = get_global_runtime_settings().automation_user_id
    with pytest.raises(ValueError):
        create_api_key(user_id, "bad")  # neither inherit nor scope
    with pytest.raises(ValueError):
        create_api_key(user_id, "bad", inherit=True, scope=[("ai", "read")])  # both

@pytest.mark.integration
def test_create_invalid_uuid():
    with pytest.raises(ValueError):
        create_api_key(
            get_global_runtime_settings().automation_user_id, "test", inherit=True, api_key="invalid"
        )

@pytest.mark.integration
def test_disabled_user_api_key_does_not_authenticate():
    """Disabling a user must revoke API access, not just browser access."""
    from saq.database.model import User
    from saq.database.pool import get_db

    user_id = get_global_runtime_settings().automation_user_id
    api_key = create_api_key(user_id, "test", inherit=True)
    assert _get_user_api_key_match(sha256_str(api_key)).auth_user_id == user_id

    db = get_db()
    user = db.query(User).filter(User.id == user_id).one()
    original_enabled = user.enabled
    try:
        user.enabled = False
        db.commit()
        assert _get_user_api_key_match(sha256_str(api_key)) is None
        assert verify_api_key(api_key) is None
    finally:
        user.enabled = original_enabled
        db.commit()

    # re-enabling restores API access with the same key
    assert _get_user_api_key_match(sha256_str(api_key)).auth_user_id == user_id


@pytest.mark.integration
def test_verify_api_key(monkeypatch):
    assert verify_api_key(None) is None
    assert verify_api_key(API_KEY) is None
    monkeypatch.setattr(get_config(), "apikeys", {"test": sha256_str(API_KEY)})
    assert verify_api_key(API_KEY) == ApiAuthResult(auth_name="test", auth_type=API_AUTH_TYPE_CONFIG)

    user_api_key = create_api_key(get_global_runtime_settings().automation_user_id, "test", inherit=True)
    match = verify_api_key(user_api_key)
    assert match.auth_user_id == get_global_runtime_settings().automation_user_id
    assert match.auth_type == API_AUTH_TYPE_USER
