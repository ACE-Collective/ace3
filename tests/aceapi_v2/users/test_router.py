"""Tests for the aceapi_v2 users/roles management router."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.application import app
from aceapi_v2.auth import create_access_token
from saq.database.model import AuthGroup, AuthUserPermission, User

pytestmark = pytest.mark.integration


async def _make_user(session: AsyncSession, username: str, perms: list[tuple[str, str]]) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        queue="default",
        timezone="UTC",
        password="pw",
    )
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
    async def test_management_view_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get("/users/management-view")).status_code == 401

    @pytest.mark.asyncio
    async def test_create_requires_auth(self, unauth_client: AsyncClient):
        r = await unauth_client.post("/users/", json={"username": "x", "email": "x@e.com"})
        assert r.status_code == 401


class TestPermissionGates:
    @pytest.mark.asyncio
    async def test_no_permission_forbidden(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "rtr_noperm", perms=[])
        async with _client_for(user) as c:
            assert (await c.get("/users/management-view")).status_code == 403
            r = await c.post("/users/", json={"username": "y", "email": "y@e.com"})
            assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_read_cannot_write(self, _override_db_session, session: AsyncSession):
        user = await _make_user(session, "rtr_readonly", perms=[("user", "read")])
        async with _client_for(user) as c:
            assert (await c.get("/users/management-view")).status_code == 200
            r = await c.post("/users/", json={"username": "z", "email": "z@e.com"})
            assert r.status_code == 403


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_management_view(self, client: AsyncClient):
        r = await client.get("/users/management-view")
        assert r.status_code == 200
        body = r.json()
        assert set(body) >= {"users", "permissions", "groups", "group_permissions", "catalog"}

    @pytest.mark.asyncio
    async def test_catalog(self, client: AsyncClient):
        r = await client.get("/users/catalog")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.asyncio
    async def test_create_and_details(self, client: AsyncClient, session: AsyncSession):
        r = await client.post("/users/", json={
            "username": "rtr_created",
            "email": "rtr_created@example.com",
            "display_name": "Created",
            "password": "Secret123!",
            "permissions": [{"major": "alert", "minor": "read", "effect": "ALLOW"}],
            "groups": [],
        })
        assert r.status_code == 201
        new_id = r.json()["id"]

        session.expire_all()
        created = (await session.execute(select(User).where(User.id == new_id))).scalar_one()
        assert created.username == "rtr_created"
        assert created.verify_password("Secret123!")

        details = await client.get("/users/details", params={"user_ids": new_id})
        assert details.status_code == 200
        assert str(new_id) in details.json()

    @pytest.mark.asyncio
    async def test_update_users(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_update", perms=[])
        r = await client.patch("/users/", json={str(user.id): {"queue": "high", "enabled": False}})
        assert r.status_code == 200
        session.expire_all()
        await session.refresh(user)
        assert user.queue == "high" and user.enabled is False

    @pytest.mark.asyncio
    async def test_update_users_not_found(self, client: AsyncClient):
        r = await client.patch("/users/", json={"999999": {"queue": "x"}})
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_group_lifecycle(self, client: AsyncClient, session: AsyncSession):
        created = await client.post("/users/groups", json={"name": "rtr_group"})
        assert created.status_code == 201
        gid = created.json()["id"]

        deleted = await client.post("/users/groups/delete", json={"groups": [gid]})
        assert deleted.status_code == 200
        session.expire_all()
        assert (await session.execute(select(AuthGroup).where(AuthGroup.id == gid))).scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_grant_and_revoke_permission(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_grant", perms=[])
        uid = user.id
        grant = await client.post("/users/permissions", json={
            "major": "event", "minor": "read", "effect": "ALLOW", "users": [uid], "groups": [],
        })
        assert grant.status_code == 200
        session.expire_all()
        perm = (await session.execute(
            select(AuthUserPermission).where(
                AuthUserPermission.user_id == uid, AuthUserPermission.major == "event"
            )
        )).scalar_one()
        perm_id = perm.id

        revoke = await client.post("/users/permissions/delete", json={"users": [perm_id], "groups": []})
        assert revoke.status_code == 200
        session.expire_all()
        assert (await session.execute(
            select(AuthUserPermission).where(AuthUserPermission.id == perm_id)
        )).scalar_one_or_none() is None
