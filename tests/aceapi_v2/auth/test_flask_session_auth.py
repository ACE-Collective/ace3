"""
Tests for Flask session cookie authentication in FastAPI.

TODO: Remove this entire file when we no longer use Flask.
"""

import hashlib

import pytest
from httpx import AsyncClient
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth import API_AUTH_TYPE_USER, API_CREDENTIAL_SESSION, verify_flask_session
from saq.configuration import get_config
from saq.database.model import User

pytestmark = pytest.mark.integration


def _make_flask_session_cookie(user_id) -> str:
    """Create a Flask session cookie encoding the given user_id."""
    s = URLSafeTimedSerializer(
        get_config().gui.secret_key,
        salt="cookie-session",
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
    )
    return s.dumps({"_user_id": str(user_id)})


class TestFlaskSessionAuth:
    """Test Flask session cookie as a third auth fallback."""

    @pytest.mark.asyncio
    async def test_valid_flask_session_cookie(
        self, unauth_client: AsyncClient, test_user: User
    ):
        """Valid Flask session cookie should authenticate successfully."""
        cookie = _make_flask_session_cookie(test_user.id)
        unauth_client.cookies.set("session", cookie)
        response = await unauth_client.get("/observable-types/")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_flask_session_is_a_session_credential(self, session: AsyncSession, test_user: User):
        # a session shares auth_type "user" with a user API key and, like a config key, has no key_id,
        # so only credential tells a GUI session apart from a key
        result = await verify_flask_session(_make_flask_session_cookie(test_user.id), session)
        assert result.auth_type == API_AUTH_TYPE_USER
        assert result.key_id is None
        assert result.credential == API_CREDENTIAL_SESSION

    @pytest.mark.asyncio
    async def test_invalid_flask_session_cookie(self, unauth_client: AsyncClient):
        """Tampered/invalid cookie should return 401."""
        unauth_client.cookies.set("session", "not-a-valid-cookie")
        response = await unauth_client.get("/observable-types/")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_flask_session_cookie_nonexistent_user(
        self, unauth_client: AsyncClient
    ):
        """Cookie for a user ID that doesn't exist should return 401."""
        cookie = _make_flask_session_cookie(999999)
        unauth_client.cookies.set("session", cookie)
        response = await unauth_client.get("/observable-types/")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_flask_session_cookie_disabled_user(
        self, session: AsyncSession, unauth_client: AsyncClient, test_user: User
    ):
        """Cookie for a disabled user should return 401."""
        test_user.enabled = False
        session.add(test_user)
        await session.commit()

        cookie = _make_flask_session_cookie(test_user.id)
        unauth_client.cookies.set("session", cookie)
        response = await unauth_client.get("/observable-types/")
        assert response.status_code == 401
