"""Tests for API-key authentication in aceapi_v2."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth import (
    API_AUTH_TYPE_CONFIG,
    API_AUTH_TYPE_USER,
    API_CREDENTIAL_CONFIG_KEY,
    API_CREDENTIAL_USER_KEY,
    verify_api_key,
)
from saq.database.model import AuthApiKey, User
from saq.util import sha256_str

pytestmark = pytest.mark.integration


async def _make_user_with_key(session: AsyncSession, username: str, api_key: str, enabled: bool = True) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        password="pw",
        enabled=enabled,
    )
    session.add(user)
    await session.flush()
    # an inherit-scoped key with a known hash so the test can present the plaintext value
    session.add(AuthApiKey(
        user_id=user.id, name="test", key_hash=sha256_str(api_key), inherit_user_scope=True
    ))
    await session.flush()
    return user


class TestApiKeyAuth:
    @pytest.mark.asyncio
    async def test_enabled_user_key_authenticates(self, session: AsyncSession):
        await _make_user_with_key(session, "apikey_enabled_user", "11111111-1111-1111-1111-111111111111")
        await session.flush()

        result = await verify_api_key("11111111-1111-1111-1111-111111111111", session)
        assert result.auth_type == API_AUTH_TYPE_USER
        assert result.auth_name == "apikey_enabled_user"
        assert result.credential == API_CREDENTIAL_USER_KEY

    @pytest.mark.asyncio
    async def test_config_key_is_a_config_key_credential(self, session: AsyncSession):
        # api.api_key in etc/saq.unittest.default.yaml, listed under apikeys
        result = await verify_api_key("dcef0db0-556f-44b3-9e1b-3d97b435d264", session)
        assert result.auth_type == API_AUTH_TYPE_CONFIG
        assert result.key_id is None
        assert result.credential == API_CREDENTIAL_CONFIG_KEY

    @pytest.mark.asyncio
    async def test_unknown_key_has_no_credential(self, session: AsyncSession):
        result = await verify_api_key("44444444-4444-4444-4444-444444444444", session)
        assert not result
        assert result.credential is None

    @pytest.mark.asyncio
    async def test_disabled_user_key_is_rejected(self, session: AsyncSession):
        """Regression: disabling a user must revoke API access, not just browser access."""
        await _make_user_with_key(
            session, "apikey_disabled_user", "22222222-2222-2222-2222-222222222222", enabled=False
        )
        await session.flush()

        result = await verify_api_key("22222222-2222-2222-2222-222222222222", session)
        assert result.auth_type != API_AUTH_TYPE_USER
        assert not result

    @pytest.mark.asyncio
    async def test_re_enabling_restores_access_with_same_key(self, session: AsyncSession):
        user = await _make_user_with_key(
            session, "apikey_toggle_user", "33333333-3333-3333-3333-333333333333", enabled=False
        )
        await session.flush()
        assert not await verify_api_key("33333333-3333-3333-3333-333333333333", session)

        user.enabled = True
        await session.flush()
        result = await verify_api_key("33333333-3333-3333-3333-333333333333", session)
        assert result.auth_name == "apikey_toggle_user"
