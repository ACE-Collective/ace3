"""Tests for the aceapi_v2 observable-detection settings router."""

import hashlib

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.application import app
from aceapi_v2.auth import create_access_token
from saq.database.model import AuthUserPermission, Observable, User

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


async def _make_observable(session: AsyncSession, value: str, **kwargs) -> Observable:
    obs = Observable(type="ipv4", sha256=_sha256(value), value=value.encode("utf8"), **kwargs)
    session.add(obs)
    await session.flush()
    return obs


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


class TestAuth:
    @pytest.mark.asyncio
    async def test_list_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get("/detection/")).status_code == 401

    @pytest.mark.asyncio
    async def test_patch_requires_auth(self, unauth_client: AsyncClient):
        r = await unauth_client.patch("/detection/1/detection", json={"enabled": True})
        assert r.status_code == 401


class TestPermissionGates:
    @pytest.mark.asyncio
    async def test_read_gate(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "det_noperm", perms=[])
        async with _client_for(user) as c:
            assert (await c.get("/detection/")).status_code == 403

    @pytest.mark.asyncio
    async def test_read_cannot_write(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "det_readonly", perms=[("detection", "read")])
        obs = await _make_observable(session, "5.5.5.5", for_detection=False)
        oid = obs.id
        async with _client_for(user) as c:
            assert (await c.get("/detection/")).status_code == 200
            r = await c.patch(f"/detection/{oid}/detection", json={"enabled": True})
            assert r.status_code == 403


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_list_and_toggle(self, client: AsyncClient, session: AsyncSession):
        obs = await _make_observable(session, "6.6.6.6", for_detection=False)
        oid = obs.id

        listing = await client.get("/detection/", params={"search": "6.6.6.6", "for_detection": "false"})
        assert listing.status_code == 200
        body = listing.json()
        assert set(body) >= {"items", "total", "page", "page_size", "total_pages"}
        assert any(o["id"] == oid for o in body["items"])

        r = await client.patch(f"/detection/{oid}/detection", json={"enabled": True, "detection_context": "ctx"})
        assert r.status_code == 200
        assert r.json()["for_detection"] is True
        assert r.json()["detection_context"] == "ctx"

    @pytest.mark.asyncio
    async def test_expiration(self, client: AsyncClient, session: AsyncSession):
        obs = await _make_observable(session, "7.7.7.7", for_detection=True)
        oid = obs.id
        r = await client.patch(f"/detection/{oid}/expiration", json={"expires_on": "2030-06-01T00:00:00"})
        assert r.status_code == 200
        assert r.json()["expires_on"].startswith("2030-06-01")

    @pytest.mark.asyncio
    async def test_types_endpoint(self, client: AsyncClient, session: AsyncSession):
        await _make_observable(session, "8.8.8.8")
        await session.flush()
        r = await client.get("/detection/types")
        assert r.status_code == 200
        assert "ipv4" in r.json()

    @pytest.mark.asyncio
    async def test_types_requires_read_permission(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "det_types_noperm", perms=[])
        async with _client_for(user) as c:
            assert (await c.get("/detection/types")).status_code == 403

    @pytest.mark.asyncio
    async def test_page_size_cannot_be_abused(self, client: AsyncClient):
        """An arbitrary page_size must clamp, not dump the whole table."""
        r = await client.get("/detection/", params={"page_size": 100000})
        assert r.status_code == 200
        assert r.json()["page_size"] == 50  # DEFAULT_PAGE_SIZE

    @pytest.mark.asyncio
    async def test_toggle_unknown_404(self, client: AsyncClient):
        r = await client.patch("/detection/999999/detection", json={"enabled": True})
        assert r.status_code == 404
