"""Tests for the aceapi_v2 observable-detection router."""

import hashlib

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.application import app
from aceapi_v2.auth import create_access_token
from saq.database.model import AuthUserPermission, ObservableDetection, User

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


async def _make_detection(session: AsyncSession, value: str, otype: str = "ipv4", **kwargs) -> ObservableDetection:
    detection = ObservableDetection(
        type=otype, value=value, value_sha256=_sha256(value), **kwargs)
    session.add(detection)
    await session.flush()
    return detection


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
    async def test_create_requires_auth(self, unauth_client: AsyncClient):
        r = await unauth_client.post("/detection/", json={"type": "ipv4", "value": "1.1.1.1"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_delete_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.delete("/detection/1")).status_code == 401

    @pytest.mark.asyncio
    async def test_patch_requires_auth(self, unauth_client: AsyncClient):
        r = await unauth_client.patch("/detection/1/expiration", json={"expires_on": None})
        assert r.status_code == 401


class TestPermissionGates:
    @pytest.mark.asyncio
    async def test_read_gate(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "det_noperm", perms=[])
        async with _client_for(user) as c:
            assert (await c.get("/detection/")).status_code == 403

    @pytest.mark.asyncio
    async def test_read_cannot_create(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "det_readonly", perms=[("detection", "read")])
        async with _client_for(user) as c:
            assert (await c.get("/detection/")).status_code == 200
            r = await c.post("/detection/", json={"type": "ipv4", "value": "5.5.5.5"})
            assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_read_cannot_delete(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "det_readonly_del", perms=[("detection", "read")])
        detection = await _make_detection(session, "5.5.5.6")
        async with _client_for(user) as c:
            assert (await c.delete(f"/detection/{detection.id}")).status_code == 403

    @pytest.mark.asyncio
    async def test_types_requires_read_permission(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "det_types_noperm", perms=[])
        async with _client_for(user) as c:
            assert (await c.get("/detection/types")).status_code == 403


class TestCreate:
    @pytest.mark.asyncio
    async def test_create_for_a_never_seen_observable(self, client: AsyncClient):
        """The capability the old design could not express at all."""
        r = await client.post("/detection/", json={
            "type": "fqdn", "value": "brand-new.example.com",
            "detection_context": "from threat intel"})
        assert r.status_code == 201
        body = r.json()
        assert body["value"] == "brand-new.example.com"
        assert body["detection_context"] == "from threat intel"
        assert body["observable_id"] is None

    @pytest.mark.asyncio
    async def test_context_defaults_to_who(self, client: AsyncClient):
        r = await client.post("/detection/", json={"type": "ipv4", "value": "6.6.6.6"})
        assert r.status_code == 201
        assert r.json()["detection_context"] == "manually added by unittest"

    @pytest.mark.asyncio
    async def test_create_with_expiration(self, client: AsyncClient):
        r = await client.post("/detection/", json={
            "type": "ipv4", "value": "6.6.6.7", "expires_on": "2030-06-01T00:00:00"})
        assert r.status_code == 201
        assert r.json()["expires_on"].startswith("2030-06-01")

    @pytest.mark.asyncio
    async def test_invalid_value_for_type_is_400(self, client: AsyncClient):
        r = await client.post("/detection/", json={"type": "ipv4", "value": "notanip"})
        assert r.status_code == 400
        assert "ipv4" in r.json()["detail"]

    @pytest.mark.asyncio
    async def test_duplicate_is_409(self, client: AsyncClient):
        assert (await client.post("/detection/", json={"type": "fqdn", "value": "dupe.example.com"})).status_code == 201
        r = await client.post("/detection/", json={"type": "fqdn", "value": "dupe.example.com"})
        assert r.status_code == 409


class TestListAndDelete:
    @pytest.mark.asyncio
    async def test_list(self, client: AsyncClient, session: AsyncSession):
        detection = await _make_detection(session, "7.7.7.7")

        listing = await client.get("/detection/", params={"search": "7.7.7.7"})
        assert listing.status_code == 200
        body = listing.json()
        assert set(body) >= {"items", "total", "page", "page_size", "total_pages"}
        assert any(d["id"] == detection.id for d in body["items"])

    @pytest.mark.asyncio
    async def test_delete(self, client: AsyncClient, session: AsyncSession):
        detection = await _make_detection(session, "7.7.7.8")
        assert (await client.delete(f"/detection/{detection.id}")).status_code == 204

        listing = await client.get("/detection/", params={"search": "7.7.7.8"})
        assert listing.json()["total"] == 0

    @pytest.mark.asyncio
    async def test_delete_unknown_404(self, client: AsyncClient):
        assert (await client.delete("/detection/999999")).status_code == 404

    @pytest.mark.asyncio
    async def test_page_size_cannot_be_abused(self, client: AsyncClient):
        """An arbitrary page_size must clamp, not dump the whole table."""
        r = await client.get("/detection/", params={"page_size": 100000})
        assert r.status_code == 200
        assert r.json()["page_size"] == 50  # DEFAULT_PAGE_SIZE


class TestExpiration:
    @pytest.mark.asyncio
    async def test_set_and_clear(self, client: AsyncClient, session: AsyncSession):
        detection = await _make_detection(session, "8.8.8.8")

        r = await client.patch(f"/detection/{detection.id}/expiration",
                               json={"expires_on": "2030-06-01T00:00:00"})
        assert r.status_code == 200
        assert r.json()["expires_on"].startswith("2030-06-01")

        cleared = await client.patch(f"/detection/{detection.id}/expiration", json={"expires_on": None})
        assert cleared.json()["expires_on"] is None

    @pytest.mark.asyncio
    async def test_unknown_404(self, client: AsyncClient):
        r = await client.patch("/detection/999999/expiration", json={"expires_on": None})
        assert r.status_code == 404


class TestTypes:
    @pytest.mark.asyncio
    async def test_types_endpoint(self, client: AsyncClient, session: AsyncSession):
        await _make_detection(session, "9.9.9.9", otype="ipv4")
        await session.flush()

        r = await client.get("/detection/types")
        assert r.status_code == 200
        body = r.json()
        # `present` filters the table; `all` populates the create form and comes from the registry,
        # so it offers types that have no detection yet
        assert "ipv4" in body["present"]
        assert "ipv4" in body["all"]
        assert set(body["all"]) > set(body["present"])
