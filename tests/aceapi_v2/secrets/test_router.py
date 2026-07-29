"""Tests for the aceapi_v2 encrypted-secrets router."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.application import app
from aceapi_v2.auth import create_access_token
from aceapi_v2.secrets import service
from saq.configuration.encryption import delete_password, list_encrypted_password_keys
from saq.database.model import AuthUserPermission, User

pytestmark = pytest.mark.integration


async def _make_user(session: AsyncSession, username: str, perms: list[tuple[str, str]]) -> User:
    user = User(username=username, email=f"{username}@e.com", display_name=username, password="pw")
    session.add(user)
    await session.flush()
    for major, minor in perms:
        session.add(AuthUserPermission(user_id=user.id, major=major, minor=minor, effect="ALLOW"))
    await session.flush()
    return user


def _client_for(user: User) -> AsyncClient:
    token = create_access_token(user.username, user.id)
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.fixture(autouse=True)
def _cleanup_leaked_keys():
    """Router writes commit to the real encrypted_passwords table; remove any test.* leftovers."""
    yield
    for key in list_encrypted_password_keys():
        if key.startswith("test."):
            delete_password(key)


class TestAuth:
    @pytest.mark.asyncio
    async def test_list_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get("/secrets/")).status_code == 401

    @pytest.mark.asyncio
    async def test_put_requires_auth(self, unauth_client: AsyncClient):
        r = await unauth_client.put("/secrets/test.k", json={"value": "v"})
        assert r.status_code == 401


class TestPermissionGates:
    @pytest.mark.asyncio
    async def test_read_gate(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "sec_noperm", perms=[])
        async with _client_for(user) as c:
            assert (await c.get("/secrets/")).status_code == 403

    @pytest.mark.asyncio
    async def test_read_cannot_write(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "sec_readonly", perms=[("secret", "read")])
        async with _client_for(user) as c:
            assert (await c.get("/secrets/")).status_code == 200
            r = await c.put("/secrets/test.k", json={"value": "v"})
            assert r.status_code == 403


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_set_lists_and_delete(self, client: AsyncClient):
        key = "test.router_secret"

        put = await client.put(f"/secrets/{key}", json={"value": "s3cr3t"})
        assert put.status_code == 200
        body = put.json()
        assert body["key"] == key and body["is_set"] is True
        # write-only: the value must never come back
        assert "value" not in body

        listing = await client.get("/secrets/")
        assert listing.status_code == 200
        page = listing.json()
        assert page["encryption_unlocked"] is True
        entry = next(s for s in page["secrets"] if s["key"] == key)
        assert entry["is_set"] is True
        # no secret in the listing may carry a value
        assert all("value" not in s for s in page["secrets"])

        delete = await client.delete(f"/secrets/{key}")
        assert delete.status_code == 200
        assert key not in list_encrypted_password_keys()

    @pytest.mark.asyncio
    async def test_delete_unknown_404(self, client: AsyncClient):
        r = await client.delete("/secrets/test.unknown_xyz")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_key_rejected(self, client: AsyncClient):
        r = await client.put("/secrets/has%20space", json={"value": "v"})
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_empty_value_rejected(self, client: AsyncClient):
        r = await client.put("/secrets/test.k", json={"value": ""})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_locked_returns_409(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "encryption_unlocked", lambda: False)
        r = await client.put("/secrets/test.k", json={"value": "v"})
        assert r.status_code == 409
