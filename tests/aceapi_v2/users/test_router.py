"""Tests for the aceapi_v2 users/roles management router."""

import logging

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.application import app
from aceapi_v2.auth import (
    API_AUTH_TYPE_CONFIG,
    API_AUTH_TYPE_USER,
    API_CREDENTIAL_CONFIG_KEY,
    API_CREDENTIAL_SESSION,
    API_CREDENTIAL_USER_KEY,
    ApiAuthResult,
)
from aceapi_v2.dependencies import check_permission, require_self_service
from aceapi_v2.users.service import create_user_api_key, list_user_api_keys
from saq.configuration import get_config
from saq.configuration.schema import ConfigApiKey
from saq.database.model import AuthApiKey, AuthGroup, AuthGroupUser, AuthUserPermission, User
from saq.util import sha256_str
from tests.aceapi_v2.conftest import (
    add_analyst_group,
    api_key_client,
    key_scope,
    make_api_key,
    make_flask_session_cookie,
)

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
    _, user.test_api_key = await create_user_api_key(session, user.id, name="test", inherit=True, scope=[])
    await session.flush()
    return user


def _client_for(user: User) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"x-ace-auth": user.test_api_key},
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
    async def test_cannot_disable_own_account(
        self, client: AsyncClient, session: AsyncSession, test_user: User
    ):
        """A disabled user fails authentication outright, so this call would lock the caller out
        of every endpoint including the PATCH that would undo it."""
        r = await client.patch("/users/", json={str(test_user.id): {"enabled": False}})
        assert r.status_code == 400
        assert "your own account" in r.json()["detail"]

        session.expire_all()
        await session.refresh(test_user)
        assert test_user.enabled is True

    @pytest.mark.asyncio
    async def test_self_disable_guard_does_not_apply_partial_changes(
        self, client: AsyncClient, session: AsyncSession, test_user: User
    ):
        """The guard is a pre-scan, so the other user in the same request is untouched too."""
        other = await _make_user(session, "rtr_self_disable_other", perms=[])
        r = await client.patch("/users/", json={
            str(other.id): {"queue": "high"},
            str(test_user.id): {"enabled": False},
        })
        assert r.status_code == 400

        session.expire_all()
        await session.refresh(other)
        assert other.queue != "high"

    @pytest.mark.asyncio
    async def test_can_still_disable_another_account(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_disable_other", perms=[])
        r = await client.patch("/users/", json={str(user.id): {"enabled": False}})
        assert r.status_code == 200
        session.expire_all()
        await session.refresh(user)
        assert user.enabled is False

    @pytest.mark.asyncio
    async def test_can_still_enable_own_account(
        self, client: AsyncClient, session: AsyncSession, test_user: User
    ):
        """Only `enabled: false` on the caller's own id is refused; nothing else about the
        caller's own row is."""
        r = await client.patch("/users/", json={str(test_user.id): {"enabled": True, "queue": "high"}})
        assert r.status_code == 200
        session.expire_all()
        await session.refresh(test_user)
        assert test_user.enabled is True and test_user.queue == "high"

    @pytest.mark.asyncio
    async def test_create_rejects_blank_username(self, client: AsyncClient):
        r = await client.post("/users/", json={"username": "  ", "email": "x@e.com"})
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_create_rejects_blank_email(self, client: AsyncClient):
        r = await client.post("/users/", json={"username": "rtr_blank_email", "email": ""})
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_update_users_not_found(self, client: AsyncClient):
        r = await client.patch("/users/", json={"999999": {"queue": "x"}})
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_create_group_rejects_blank_name(self, client: AsyncClient):
        assert (await client.post("/users/groups", json={"name": "   "})).status_code == 400

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
    async def test_grant_rejects_blank_components(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_blank_perm", perms=[])
        r = await client.post("/users/permissions", json={
            "major": "", "minor": "read", "effect": "ALLOW", "users": [user.id], "groups": [],
        })
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_api_key_create_and_revoke(self, client: AsyncClient, session: AsyncSession):
        from saq.util import is_uuid

        user = await _make_user(session, "rtr_apikey", perms=[])
        uid = user.id

        created = await client.post(f"/users/{uid}/apikeys", json={"name": "k", "inherit": True, "scope": []})
        assert created.status_code == 201
        body = created.json()
        assert is_uuid(body["api_key"])
        key_id = body["key_id"]
        # a credential must not be cached by the browser or any intermediary
        assert created.headers.get("cache-control") == "no-store"

        listed = (await client.get(f"/users/{uid}/apikeys")).json()
        assert any(k["id"] == key_id for k in listed)

        revoked = await client.delete(f"/users/apikeys/{key_id}")
        assert revoked.status_code == 200 and revoked.json()["revoked"] is True

        listed = (await client.get(f"/users/{uid}/apikeys")).json()
        assert not any(k["id"] == key_id for k in listed)

    @pytest.mark.asyncio
    async def test_key_changes_are_audited_as_the_admin(
        self, client: AsyncClient, session: AsyncSession, test_user: User, valid_api_key: str, caplog
    ):
        """An admin changing another user's key: each record names the key's owner, and the admin's
        account and the API key the admin used."""
        caplog.set_level(logging.INFO)
        admin_key_id = (await session.execute(
            select(AuthApiKey.id).where(AuthApiKey.key_hash == sha256_str(valid_api_key)))).scalar_one()
        owner = await _make_user(session, "rtr_apikey_audit", perms=[])

        created = await client.post(
            f"/users/{owner.id}/apikeys", json={"name": "k", "inherit": False, "scope": [{"major": "alert", "minor": "read"}]})
        key_id = created.json()["key_id"]
        assert (await client.put(f"/users/apikeys/{key_id}", json={"name": "k", "inherit": True, "scope": []})).status_code == 200
        assert (await client.delete(f"/users/apikeys/{key_id}")).json()["revoked"] is True

        audits = [r for r in caplog.records if r.getMessage().startswith("AUDIT:") and getattr(r, "api_key_id", None) == key_id]
        assert [r.getMessage().split()[3] for r in audits] == ["created", "updated", "revoked"]
        assert [(r.user_id, r.actor, r.actor_user_id, r.actor_key_id) for r in audits] == [
            (owner.id, "unittest", test_user.id, admin_key_id)] * 3

    @pytest.mark.asyncio
    async def test_create_scoped_key_via_api(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_apikey_scoped", perms=[])
        r = await client.post(
            f"/users/{user.id}/apikeys",
            json={"name": "ai", "inherit": False, "scope": [{"major": "ai", "minor": "read"}]},
        )
        assert r.status_code == 201
        key_id = r.json()["key_id"]
        listed = (await client.get(f"/users/{user.id}/apikeys")).json()
        entry = next(k for k in listed if k["id"] == key_id)
        assert entry["inherit_user_scope"] is False
        assert entry["scope"] == [{"major": "ai", "minor": "read"}]

    @pytest.mark.asyncio
    async def test_create_rejects_neither_inherit_nor_scope(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_apikey_bad", perms=[])
        r = await client.post(f"/users/{user.id}/apikeys", json={"name": "x", "inherit": False, "scope": []})
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_create_rejects_a_pattern_too_long_to_store(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_apikey_long", perms=[])
        r = await client.post(
            f"/users/{user.id}/apikeys",
            json={"name": "x", "inherit": False, "scope": [{"major": "alert", "minor": "*" * 513}]},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_update_key_scope_and_name(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_apikey_update", perms=[])
        r = await client.post(
            f"/users/{user.id}/apikeys",
            json={"name": "ai", "inherit": False, "scope": [{"major": "ai", "minor": "*"}]},
        )
        key_id = r.json()["key_id"]

        r = await client.put(
            f"/users/apikeys/{key_id}",
            json={"name": "ai+obs", "inherit": False,
                  "scope": [{"major": "ai", "minor": "*"}, {"major": "observable", "minor": "read"}]},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == key_id and body["name"] == "ai+obs"
        assert body["inherit_user_scope"] is False
        assert body["scope"] == [{"major": "ai", "minor": "*"}, {"major": "observable", "minor": "read"}]
        assert "api_key" not in body

        listed = (await client.get(f"/users/{user.id}/apikeys")).json()
        entry = next(k for k in listed if k["id"] == key_id)
        assert entry["scope"] == [{"major": "ai", "minor": "*"}, {"major": "observable", "minor": "read"}]

        # switching to inherit drops the scope rows; switching back replaces them wholesale
        r = await client.put(f"/users/apikeys/{key_id}", json={"name": "ai+obs", "inherit": True, "scope": []})
        assert r.status_code == 200 and r.json()["inherit_user_scope"] is True and r.json()["scope"] == []
        r = await client.put(
            f"/users/apikeys/{key_id}",
            json={"name": "ai+obs", "inherit": False, "scope": [{"major": "observable", "minor": "read"}]},
        )
        assert r.status_code == 200 and r.json()["scope"] == [{"major": "observable", "minor": "read"}]

    @pytest.mark.asyncio
    async def test_update_rejects_bad_input(self, client: AsyncClient, session: AsyncSession):
        user = await _make_user(session, "rtr_apikey_update_bad", perms=[])
        r = await client.post(f"/users/{user.id}/apikeys", json={"name": "k", "inherit": True, "scope": []})
        key_id = r.json()["key_id"]

        # neither inherit nor scope
        r = await client.put(f"/users/apikeys/{key_id}", json={"name": "k", "inherit": False, "scope": []})
        assert r.status_code == 400
        # empty name
        r = await client.put(f"/users/apikeys/{key_id}", json={"name": " ", "inherit": True, "scope": []})
        assert r.status_code == 400
        # unknown key
        r = await client.put("/users/apikeys/999999", json={"name": "k", "inherit": True, "scope": []})
        assert r.status_code == 404
        # nothing above touched the key
        listed = (await client.get(f"/users/{user.id}/apikeys")).json()
        assert next(k for k in listed if k["id"] == key_id)["inherit_user_scope"] is True

    @pytest.mark.asyncio
    async def test_update_requires_user_write(self, _override_db_session, session: AsyncSession):
        reader = await _make_user(session, "rtr_apikey_update_reader", perms=[("user", "read")])
        async with _client_for(reader) as c:
            r = await c.put("/users/apikeys/1", json={"name": "k", "inherit": True, "scope": []})
            assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_updated_scope_applies_to_the_existing_key(
        self, client: AsyncClient, _override_db_session, session: AsyncSession
    ):
        """The point of editing: a key already handed out gains the new permission on its next
        request, without being reissued. Scope is read per request, so no restart is needed."""
        from saq.database.model import AuthApiKey
        from saq.util import sha256_str
        user = await _make_user(session, "rtr_apikey_live", perms=[("user", "read")])
        plaintext = await make_api_key(session, user.id, inherit=False, scope=[("ai", "*")])
        # _make_user also minted an inherit key, so find the scoped one by its hash
        key_id = (await session.execute(
            select(AuthApiKey.id).where(AuthApiKey.key_hash == sha256_str(plaintext))
        )).scalar_one()

        async with api_key_client(plaintext) as c:
            assert (await c.get("/users/management-view")).status_code == 403

        r = await client.put(
            f"/users/apikeys/{key_id}",
            json={"name": "test", "inherit": False,
                  "scope": [{"major": "ai", "minor": "*"}, {"major": "user", "minor": "read"}]},
        )
        assert r.status_code == 200

        async with api_key_client(plaintext) as c:
            assert (await c.get("/users/management-view")).status_code == 200

    @pytest.mark.asyncio
    async def test_me_apikeys_lists_only_the_callers_own_keys(self, _override_db_session, session: AsyncSession):
        """GET /users/me/apikeys takes its id from the auth result, so no other user's keys appear."""
        from saq.database.model import AuthApiKey

        caller = await _make_user(session, "rtr_me_caller", perms=[])
        other = await _make_user(session, "rtr_me_other", perms=[])
        await session.flush()

        caller_ids = {
            k.id for k in (await session.execute(select(AuthApiKey).where(AuthApiKey.user_id == caller.id))).scalars()
        }
        other_ids = {
            k.id for k in (await session.execute(select(AuthApiKey).where(AuthApiKey.user_id == other.id))).scalars()
        }

        async with _client_for(caller) as c:
            r = await c.get("/users/me/apikeys")
            assert r.status_code == 200
            data = r.json()
            returned = {k["id"] for k in data}
            assert returned == caller_ids
            assert returned.isdisjoint(other_ids)
            # metadata only -- the secret is never returned
            assert all("api_key" not in k for k in data)

    @pytest.mark.asyncio
    async def test_me_apikeys_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get("/users/me/apikeys")).status_code == 401

    @pytest.mark.asyncio
    async def test_api_key_unknown_user_404(self, client: AsyncClient):
        r = await client.post("/users/999999/apikeys", json={"name": "k", "inherit": True, "scope": []})
        assert r.status_code == 404
        # revoking a nonexistent key id is a no-op, not an error
        assert (await client.delete("/users/apikeys/999999")).json()["revoked"] is False

    @pytest.mark.asyncio
    async def test_api_key_requires_user_write(self, _override_db_session, session: AsyncSession):
        reader = await _make_user(session, "rtr_apikey_reader", perms=[("user", "read")])
        target = await _make_user(session, "rtr_apikey_target", perms=[])
        async with _client_for(reader) as c:
            created = await c.post(f"/users/{target.id}/apikeys", json={"name": "k", "inherit": True, "scope": []})
            assert created.status_code == 403
            assert (await c.delete("/users/apikeys/1")).status_code == 403

    @pytest.mark.asyncio
    async def test_grant_and_revoke_permission(
        self, client: AsyncClient, session: AsyncSession, test_user: User, caplog
    ):
        caplog.set_level(logging.INFO)
        admin_id = test_user.id  # read before the expire_all() calls below
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

        revoke = await client.post("/users/permissions/delete", json={
            "user_permission_ids": [perm_id], "group_permission_ids": [],
        })
        assert revoke.status_code == 200
        session.expire_all()
        assert (await session.execute(
            select(AuthUserPermission).where(AuthUserPermission.id == perm_id)
        )).scalar_one_or_none() is None

        audit = next(r for r in caplog.records if r.getMessage().startswith(f"AUDIT: user unittest revoked user permission rows [{perm_id}]"))
        assert audit.actor_user_id == admin_id and audit.actor_key_id is not None

    @pytest.mark.asyncio
    async def test_revoke_rejects_unknown_fields(self, client: AsyncClient, session: AsyncSession):
        """Unknown fields such as `users` (user ids on PermissionGrant) are rejected."""
        uid = (await _make_user(session, "rtr_unknown_field", perms=[("event", "read")])).id
        session.expire_all()
        perm = (await session.execute(
            select(AuthUserPermission).where(AuthUserPermission.user_id == uid)
        )).scalar_one()
        perm_id = perm.id

        response = await client.post("/users/permissions/delete", json={"users": [perm_id]})
        assert response.status_code == 422

        session.expire_all()
        assert (await session.execute(
            select(AuthUserPermission).where(AuthUserPermission.id == perm_id)
        )).scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_revoke_unknown_id_is_404_and_deletes_nothing(
        self, client: AsyncClient, session: AsyncSession
    ):
        """An id that matches no row must not come back as success, and must not take the ids
        alongside it down with it."""
        uid = (await _make_user(session, "rtr_revoke_404", perms=[("event", "read")])).id
        session.expire_all()
        perm = (await session.execute(
            select(AuthUserPermission).where(AuthUserPermission.user_id == uid)
        )).scalar_one()
        perm_id = perm.id

        response = await client.post("/users/permissions/delete", json={
            "user_permission_ids": [perm_id, 999999], "group_permission_ids": [],
        })
        assert response.status_code == 404
        assert "999999" in response.json()["detail"]

        session.expire_all()
        assert (await session.execute(
            select(AuthUserPermission).where(AuthUserPermission.id == perm_id)
        )).scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_revoke_empty_request_is_a_noop(self, client: AsyncClient):
        response = await client.post("/users/permissions/delete", json={})
        assert response.status_code == 200


class TestSelfService:
    """GET/PATCH /users/me: a user's own account, no permission grant required."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client):
        assert (await unauth_client.get("/users/me")).status_code == 401
        assert (await unauth_client.patch("/users/me", json={"timezone": "UTC"})).status_code == 401

    @pytest.mark.asyncio
    async def test_get_me(self, noperm_client, session: AsyncSession):
        response = await noperm_client.get("/users/me")
        assert response.status_code == 200
        assert response.json()["username"] == "noperm_test"

    @pytest.mark.asyncio
    async def test_patch_me_changes_only_the_allowed_fields(self, noperm_client, session: AsyncSession):
        response = await noperm_client.patch("/users/me", json={
            "display_name": "  New Name ", "timezone": "America/New_York", "queue": "phishing",
        })
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["display_name"] == "New Name"
        assert body["timezone"] == "America/New_York"
        assert body["queue"] == "phishing"

        user = (await session.execute(select(User).where(User.username == "noperm_test"))).scalar_one()
        await session.refresh(user)
        assert user.display_name == "New Name"
        assert user.timezone == "America/New_York"
        assert user.queue == "phishing"

    @pytest.mark.asyncio
    async def test_patch_me_leaves_absent_fields_alone(self, noperm_client, session: AsyncSession):
        assert (await noperm_client.patch("/users/me", json={"timezone": "UTC"})).status_code == 200
        response = await noperm_client.patch("/users/me", json={"display_name": "Only Name"})
        assert response.status_code == 200
        assert response.json()["timezone"] == "UTC"

    @pytest.mark.asyncio
    async def test_patch_me_rejects_admin_only_fields(self, noperm_client):
        for body in ({"username": "root"}, {"email": "x@e.com"}, {"password": "pw"}, {"enabled": False}, {"permissions": []}):
            assert (await noperm_client.patch("/users/me", json=body)).status_code == 422, body

    @pytest.mark.asyncio
    async def test_scoped_key_cannot_reach_the_self_service_routes(
        self, _override_db_session, session: AsyncSession
    ):
        """A scoped key names the permissions it may use; "manage my owner's account" is not one
        of them. Regression guard: these routes shipped with no gate at all, which made them
        reachable by every authenticated key whatever its scope."""
        user = await _make_user(session, "rtr_scoped_self", perms=[("user", "write")])
        plaintext = await make_api_key(
            session, user.id, inherit=False, scope=[("user", "*"), ("alert", "*")]
        )

        async with api_key_client(plaintext) as c:
            assert (await c.get("/users/me")).status_code == 403
            assert (await c.patch("/users/me", json={"timezone": "UTC"})).status_code == 403
            assert (await c.get("/users/me/apikeys")).status_code == 403

        # the same user's inherit key -- no scope -- still gets through
        async with _client_for(user) as c:
            assert (await c.get("/users/me")).status_code == 200

    @pytest.mark.asyncio
    async def test_patch_me_validates(self, noperm_client):
        assert (await noperm_client.patch("/users/me", json={"timezone": "Mars/Olympus"})).status_code == 422
        assert (await noperm_client.patch("/users/me", json={"display_name": "   "})).status_code == 422
        assert (await noperm_client.patch("/users/me", json={"queue": ""})).status_code == 422


# a signature:read route that needs no data behind it: 404 once past the gate, 403 at it
SIGNATURE_READ_PATH = "/signatures/yara-qa/matches/999999"

CONFIG_KEY = "7d0c6a52-3f7e-4f5e-9a51-6c1f0f3b2e11"


def _warned(caplog, text: str) -> bool:
    return any(r.levelno == logging.WARNING and text in r.getMessage() for r in caplog.records)


async def _make_analyst(session: AsyncSession, username: str) -> tuple[User, AuthGroup]:
    """A user whose only grants come from an analyst group (and so who holds user:self)."""
    user = await _make_user(session, username, perms=[])
    return user, await add_analyst_group(session, user)


def _browser_for(user: User, fetch_site: str = "same-origin") -> AsyncClient:
    """The GUI's credential: the Flask session cookie, sent by the browser's same-origin fetch."""
    client = AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers={"sec-fetch-site": fetch_site})
    client.cookies.set("session", make_flask_session_cookie(user.id))
    return client


def _key_body(name: str, *patterns: str) -> dict:
    return {"name": name, "scope": [{"major": p.split(":")[0], "minor": p.split(":")[1]} for p in patterns]}


async def _mint(c: AsyncClient, *patterns: str) -> dict:
    r = await c.post("/users/me/apikeys", json=_key_body("mine", *patterns))
    assert r.status_code == 201, r.text
    return r.json()


class TestSelfServiceApiKeyRoutes:
    """POST/PUT/DELETE /users/me/apikeys: a user with user:self manages their own keys from the GUI."""

    @pytest.mark.asyncio
    async def test_mint_returns_the_key_once_and_it_works(self, _override_db_session, session: AsyncSession):
        user, _ = await _make_analyst(session, "rtr_self_mint")
        async with _browser_for(user) as c:
            r = await c.post("/users/me/apikeys", json=_key_body("splunk app", "signature:read"))
            assert r.status_code == 201, r.text
            assert r.headers["cache-control"] == "no-store"
            created = r.json()
            assert created["user_id"] == user.id

            listed = (await c.get("/users/me/apikeys")).json()
            mine = next(k for k in listed if k["id"] == created["key_id"])
            assert mine["name"] == "splunk app" and mine["created_by"] == user.id
            assert mine["scope"] == [{"major": "signature", "minor": "read"}]
            assert "api_key" not in mine

        async with api_key_client(created["api_key"]) as key:
            assert (await key.get(SIGNATURE_READ_PATH)).status_code == 404
            # a scoped key reaches nothing outside its scope, the self-service routes included
            assert (await key.get("/users/me")).status_code == 403

    @pytest.mark.asyncio
    async def test_without_user_self_nothing_changes(self, _override_db_session, session: AsyncSession, caplog):
        caplog.set_level(logging.WARNING)
        user, _ = await _make_analyst(session, "rtr_self_denied")
        session.add(AuthUserPermission(user_id=user.id, major="user", minor="self", effect="DENY"))
        await session.flush()
        key, _ = await create_user_api_key(session, user.id, name="admin made", inherit=False, scope=key_scope("alert:read"))
        await session.flush()

        async with _browser_for(user) as c:
            assert (await c.post("/users/me/apikeys", json=_key_body("k", "alert:read"))).status_code == 403
            assert (await c.put(f"/users/me/apikeys/{key.id}", json=_key_body("k", "alert:read"))).status_code == 403
            assert (await c.delete(f"/users/me/apikeys/{key.id}")).status_code == 403
            # listing needs no permission, and the key is untouched
            listed = {k["id"]: k for k in (await c.get("/users/me/apikeys")).json()}
            assert listed[key.id]["name"] == "admin made"
            assert listed[key.id]["scope"] == [{"major": "alert", "minor": "read"}]

        assert _warned(caplog, f"user {user.id} does not have permission user.self")

    @pytest.mark.asyncio
    async def test_no_api_key_can_manage_keys(self, _override_db_session, session: AsyncSession, caplog):
        """Not a scoped key (even one whose scope covers user:self), and not an inheriting key
        either: a leaked key must not be able to leave new credentials behind."""
        caplog.set_level(logging.WARNING)
        user, _ = await _make_analyst(session, "rtr_self_keys")
        scoped = await make_api_key(session, user.id, inherit=False, scope=[("user", "*"), ("alert", "read")])
        own, _ = await create_user_api_key(session, user.id, name="target", inherit=False, scope=key_scope("alert:read"))
        await session.flush()

        refusals = {
            scoped: "this route acts on your own account, which no API key with a scope can do",
            user.test_api_key: "this route is only available in the GUI, never to an API key",
        }
        for credential, refusal in refusals.items():
            async with api_key_client(credential) as c:
                r = await c.post("/users/me/apikeys", json=_key_body("k", "alert:read"))
                assert r.status_code == 403 and r.json()["detail"] == refusal
                assert (await c.put(f"/users/me/apikeys/{own.id}", json=_key_body("k", "signature:read"))).status_code == 403
                assert (await c.delete(f"/users/me/apikeys/{own.id}")).status_code == 403

        assert _warned(caplog, "this route needs a GUI session")
        assert [k.id for k in await list_user_api_keys(session, user.id) if k.name == "target"] == [own.id]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("credential", ["inheriting key", "*:* key", "user:* key", "config key", "not a session"])
    async def test_no_api_key_ever_holds_user_self(self, session: AsyncSession, caplog, credential):
        """Whatever the key's scope says, so it holds even on a route that asks for user:self but
        forgets to ask for a GUI session too. Nothing else the key may do changes. "not a session"
        is a user credential with no key id that is not a GUI session either, which a gate that
        inferred a session from key_id would let through."""
        caplog.set_level(logging.WARNING)
        user, _ = await _make_analyst(session, "rtr_self_never")
        as_user = {"auth_type": API_AUTH_TYPE_USER, "auth_name": user.username, "auth_user_id": user.id}
        as_user_key = {**as_user, "key_id": 1, "key_name": "k", "credential": API_CREDENTIAL_USER_KEY}
        key = {
            "inheriting key": ApiAuthResult(**as_user_key),
            "*:* key": ApiAuthResult(**as_user_key, key_scope=[("*", "*")]),
            "user:* key": ApiAuthResult(**as_user_key, key_scope=[("user", "*"), ("alert", "read")]),
            "config key": ApiAuthResult(
                auth_type=API_AUTH_TYPE_CONFIG, auth_name="ops", key_name="ops", key_scope=[("*", "*")],
                credential=API_CREDENTIAL_CONFIG_KEY),
            "not a session": ApiAuthResult(**as_user),
        }[credential]

        with pytest.raises(HTTPException) as denied:
            await check_permission(session, key, "user", "self")
        assert denied.value.status_code == 403
        assert denied.value.detail == "user:self is only available in the GUI, never to an API key"
        assert _warned(caplog, "can never hold user.self")

        await check_permission(session, key, "alert", "read")
        # the same user's GUI session does hold it
        await check_permission(session, ApiAuthResult(**as_user, credential=API_CREDENTIAL_SESSION), "user", "self")

    @pytest.mark.asyncio
    async def test_a_session_only_route_refuses_a_credential_that_is_not_a_session(self, caplog):
        """A user credential with no key id is not thereby a GUI session; only the session passes."""
        caplog.set_level(logging.WARNING)
        gate = require_self_service(session_only=True)
        as_user = {"auth_type": API_AUTH_TYPE_USER, "auth_name": "rtr_not_session", "auth_user_id": 1}

        with pytest.raises(HTTPException) as denied:
            await gate(auth=ApiAuthResult(**as_user))
        assert denied.value.status_code == 403
        assert denied.value.detail == "this route is only available in the GUI, never to an API key"
        assert _warned(caplog, "this route needs a GUI session")

        session_auth = ApiAuthResult(**as_user, credential=API_CREDENTIAL_SESSION)
        assert await gate(auth=session_auth) is session_auth

    @pytest.mark.asyncio
    async def test_a_config_key_is_refused(self, _override_db_session, monkeypatch):
        monkeypatch.setattr(get_config(), "apikeys", {
            "ops": ConfigApiKey(key=sha256_str(CONFIG_KEY), scope=["*:*"]),
        })
        async with api_key_client(CONFIG_KEY) as c:
            r = await c.post("/users/me/apikeys", json=_key_body("k", "alert:read"))
        assert r.status_code == 403
        assert r.json()["detail"] == "this route acts on your own account, and this API key belongs to no user"

    @pytest.mark.asyncio
    async def test_a_cross_site_request_cannot_mint(self, _override_db_session, session: AsyncSession):
        user, _ = await _make_analyst(session, "rtr_self_csrf")
        async with _browser_for(user, fetch_site="cross-site") as c:
            assert (await c.post("/users/me/apikeys", json=_key_body("k", "alert:read"))).status_code == 403
        # nothing was minted: the only key is the inherit key _make_user gave the user
        assert [k.inherit_user_scope for k in await list_user_api_keys(session, user.id)] == [True]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("body", [
        {"name": "k", "inherit": True, "scope": []},
        {"name": "k", "inherit": False, "scope": [{"major": "alert", "minor": "read"}]},
        {"name": "  ", "scope": [{"major": "alert", "minor": "read"}]},
        {"name": "k", "scope": []},
        {"name": "x" * 256, "scope": [{"major": "alert", "minor": "read"}]},
        # both match every signature permission, and neither fits the String(512) ascii column
        {"name": "k", "scope": [{"major": "signature", "minor": "*" * 600}]},
        {"name": "k", "scope": [{"major": "signature", "minor": "[r\u00e9]ead"}]},
    ])
    async def test_the_request_body_is_validated(self, _override_db_session, session: AsyncSession, body):
        """There is no inherit field to set; a name and at least one permission are required, and
        each pattern must fit the column it is stored in."""
        user, _ = await _make_analyst(session, "rtr_self_body")
        async with _browser_for(user) as c:
            assert (await c.post("/users/me/apikeys", json=body)).status_code == 422

    @pytest.mark.asyncio
    async def test_a_scope_beyond_the_users_grants_is_refused(self, _override_db_session, session: AsyncSession):
        user, _ = await _make_analyst(session, "rtr_self_wide")
        async with _browser_for(user) as c:
            r = await c.post("/users/me/apikeys", json=_key_body("k", "*:*"))
            assert r.status_code == 400
            assert "user:write" in r.json()["detail"]

            r = await c.post("/users/me/apikeys", json=_key_body("k", "signature:wrte"))
            assert r.status_code == 400
            assert "matches no permission" in r.json()["detail"]

            # an edit is held to the same rule, and a refused edit leaves the key as it was
            created = await _mint(c, "alert:read")
            r = await c.put(f"/users/me/apikeys/{created['key_id']}", json=_key_body("k", "user:*"))
            assert r.status_code == 400
            assert "user:write" in r.json()["detail"]
            listed = {k["id"]: k for k in (await c.get("/users/me/apikeys")).json()}
            assert listed[created["key_id"]]["scope"] == [{"major": "alert", "minor": "read"}]

    @pytest.mark.asyncio
    async def test_edit_own_key_keeps_the_secret(self, _override_db_session, session: AsyncSession):
        user, _ = await _make_analyst(session, "rtr_self_edit")
        async with _browser_for(user) as c:
            created = await _mint(c, "alert:read")
            hash_before = (await session.execute(
                select(AuthApiKey.key_hash).where(AuthApiKey.id == created["key_id"]))).scalar_one()

            r = await c.put(f"/users/me/apikeys/{created['key_id']}", json=_key_body("renamed", "signature:*"))
            assert r.status_code == 200, r.text
            assert r.json()["name"] == "renamed"
            assert r.json()["scope"] == [{"major": "signature", "minor": "*"}]

        hash_after = (await session.execute(
            select(AuthApiKey.key_hash).where(AuthApiKey.id == created["key_id"]))).scalar_one()
        assert hash_after == hash_before
        async with api_key_client(created["api_key"]) as key:
            assert (await key.get(SIGNATURE_READ_PATH)).status_code == 404

    @pytest.mark.asyncio
    async def test_own_key_changes_are_audited_as_the_owner(self, _override_db_session, session: AsyncSession, caplog):
        caplog.set_level(logging.INFO)
        user, _ = await _make_analyst(session, "rtr_self_audit")
        async with _browser_for(user) as c:
            key_id = (await _mint(c, "alert:read"))["key_id"]
            assert (await c.put(f"/users/me/apikeys/{key_id}", json=_key_body("mine", "signature:read"))).status_code == 200
            assert (await c.delete(f"/users/me/apikeys/{key_id}")).json()["revoked"] is True

        audits = [r for r in caplog.records if r.getMessage().startswith("AUDIT:") and getattr(r, "api_key_id", None) == key_id]
        assert [r.getMessage().split()[3] for r in audits] == ["created", "updated", "revoked"]
        # a GUI session, so no API key acted
        assert [(r.user_id, r.actor, r.actor_user_id, r.actor_key_id) for r in audits] == [
            (user.id, "rtr_self_audit", user.id, None)] * 3

    @pytest.mark.asyncio
    async def test_another_users_key_cannot_be_edited_or_revoked(self, _override_db_session, session: AsyncSession):
        user, _ = await _make_analyst(session, "rtr_self_me")
        other, _ = await _make_analyst(session, "rtr_self_other")
        async with _browser_for(other) as c:
            theirs = await _mint(c, "alert:read")

        async with _browser_for(user) as c:
            r = await c.put(f"/users/me/apikeys/{theirs['key_id']}", json=_key_body("mine", "signature:read"))
            assert r.status_code == 404
            r = await c.delete(f"/users/me/apikeys/{theirs['key_id']}")
            assert r.status_code == 200 and r.json() == {"revoked": False}

        # 403, not 401: the key still authenticates, and its scope is still only alert:read
        async with api_key_client(theirs["api_key"]) as key:
            assert (await key.get(SIGNATURE_READ_PATH)).status_code == 403

    @pytest.mark.asyncio
    async def test_revoke_own_key(self, _override_db_session, session: AsyncSession):
        user, _ = await _make_analyst(session, "rtr_self_revoke")
        async with _browser_for(user) as c:
            created = await _mint(c, "signature:read")
            r = await c.delete(f"/users/me/apikeys/{created['key_id']}")
            assert r.status_code == 200 and r.json() == {"revoked": True}

        async with api_key_client(created["api_key"]) as key:
            assert (await key.get(SIGNATURE_READ_PATH)).status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize("removal", ["revoke_grant", "leave_group", "deny"])
    async def test_a_key_loses_what_its_owner_loses(
        self, _override_db_session, session: AsyncSession, caplog, removal
    ):
        """A self-minted key never outlives its owner's grants: the scope is intersected with the
        owner's live grants on every request, so taking the permission away from the user -- by
        any route -- takes it away from the key at once, and granting it back restores it."""
        caplog.set_level(logging.WARNING)
        if removal == "revoke_grant":
            # signature:read comes from one direct grant and nothing else, so deleting it is what
            # takes it away
            user = await _make_user(session, "rtr_self_lose", perms=[("user", "self"), ("signature", "read")])
            grant = (await session.execute(select(AuthUserPermission).where(
                AuthUserPermission.user_id == user.id, AuthUserPermission.major == "signature"))).scalar_one()
        else:
            user, group = await _make_analyst(session, "rtr_self_lose")

        async with _browser_for(user) as c:
            created = await _mint(c, "signature:read")

        async with api_key_client(created["api_key"]) as key:
            assert (await key.get(SIGNATURE_READ_PATH)).status_code == 404

            if removal == "revoke_grant":
                await session.delete(grant)
            elif removal == "leave_group":
                await session.execute(delete(AuthGroupUser).where(AuthGroupUser.user_id == user.id))
            else:
                deny = AuthUserPermission(user_id=user.id, major="signature", minor="read", effect="DENY")
                session.add(deny)
            await session.flush()

            assert (await key.get(SIGNATURE_READ_PATH)).status_code == 403
            assert _warned(caplog, f"user {user.id} does not have permission signature.read")

            if removal == "revoke_grant":
                session.add(AuthUserPermission(user_id=user.id, major="signature", minor="read", effect="ALLOW"))
            elif removal == "leave_group":
                session.add(AuthGroupUser(group_id=group.id, user_id=user.id))
            else:
                await session.delete(deny)
            await session.flush()

            assert (await key.get(SIGNATURE_READ_PATH)).status_code == 404


class TestRefusalMessages:
    """A 403 says whether the account's grants or the key's scope refused, and so whether the
    user can fix it on Preferences or needs an administrator."""

    @staticmethod
    async def _refusal(c: AsyncClient) -> str:
        r = await c.get(SIGNATURE_READ_PATH)
        assert r.status_code == 403, r.text
        return r.json()["detail"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("can_edit_keys", [True, False])
    async def test_only_the_keys_scope_is_missing_it(self, _override_db_session, session: AsyncSession, can_edit_keys):
        user, _ = await _make_analyst(session, f"rtr_refuse_scope_{can_edit_keys}")
        if not can_edit_keys:
            session.add(AuthUserPermission(user_id=user.id, major="user", minor="self", effect="DENY"))
        key = await make_api_key(session, user.id, inherit=False, scope=[("alert", "read")])

        async with api_key_client(key) as c:
            detail = await self._refusal(c)
        assert detail.startswith("this API key's scope does not include signature:read, which your account has; ")
        assert detail.endswith(
            "you can add it to the key on the Preferences page" if can_edit_keys
            else "an administrator has to add it to the key")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("credential", ["gui session", "inheriting key", "key scoped to it"])
    async def test_only_the_account_is_missing_it(self, _override_db_session, session: AsyncSession, credential):
        user, _ = await _make_analyst(session, "rtr_refuse_account")
        session.add(AuthUserPermission(user_id=user.id, major="signature", minor="read", effect="DENY"))
        scoped = await make_api_key(session, user.id, inherit=False, scope=[("signature", "read")])
        client = {
            "gui session": lambda: _browser_for(user),
            "inheriting key": lambda: api_key_client(user.test_api_key),
            "key scoped to it": lambda: api_key_client(scoped),
        }[credential]()

        async with client as c:
            assert await self._refusal(c) == "your account does not have signature:read; an administrator has to grant it"

    @pytest.mark.asyncio
    async def test_both_are_missing_it(self, _override_db_session, session: AsyncSession, caplog):
        caplog.set_level(logging.WARNING)
        user, _ = await _make_analyst(session, "rtr_refuse_both")
        session.add(AuthUserPermission(user_id=user.id, major="signature", minor="read", effect="DENY"))
        key = await make_api_key(session, user.id, inherit=False, scope=[("alert", "read")])

        async with api_key_client(key) as c:
            assert await self._refusal(c) == (
                "your account does not have signature:read, and this API key's scope does not include it; "
                "an administrator has to grant it, and then it has to be added to the key")
        # one record names both
        assert _warned(caplog, f"user {user.id} does not have permission signature.read; api key")

    @pytest.mark.asyncio
    async def test_a_config_keys_scope_is_missing_it(self, _override_db_session, monkeypatch):
        monkeypatch.setattr(get_config(), "apikeys", {
            "ops": ConfigApiKey(key=sha256_str(CONFIG_KEY), scope=["alert:read"]),
        })
        async with api_key_client(CONFIG_KEY) as c:
            assert await self._refusal(c) == (
                "this API key's scope does not include signature:read; the key is defined in ACE's "
                "configuration, so an administrator has to change it")
