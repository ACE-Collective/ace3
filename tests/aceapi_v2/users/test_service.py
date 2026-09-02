"""Tests for the aceapi_v2 users/roles management service."""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import AuthGroupUser, AuthUserPermission, User
from aceapi_v2.users import service
from aceapi_v2.users.schemas import PermissionInput, UserUpdate

pytestmark = pytest.mark.integration


async def _make_user(session: AsyncSession, username: str, enabled: bool = True) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        queue="default",
        timezone="UTC",
        password="pw",
        enabled=enabled,
    )
    session.add(user)
    await session.flush()
    return user


class TestListUsers:
    @pytest.mark.asyncio
    async def test_include_and_exclude_disabled(self, session: AsyncSession):
        await _make_user(session, "svc_enabled_u")
        await _make_user(session, "svc_disabled_u", enabled=False)
        await session.flush()

        all_users = await service.list_users(session, include_disabled=True)
        names = {u.username for u in all_users}
        assert {"svc_enabled_u", "svc_disabled_u"} <= names

        enabled_only = await service.list_users(session, include_disabled=False)
        enabled_names = {u.username for u in enabled_only}
        assert "svc_enabled_u" in enabled_names
        assert "svc_disabled_u" not in enabled_names


class TestCreateUser:
    @pytest.mark.asyncio
    async def test_creates_with_permissions_and_groups(self, session: AsyncSession):
        group = await service.create_auth_group(session, "svc_group_a")
        user = await service.create_user(
            session,
            username="svc_new_user",
            email="svc_new_user@example.com",
            display_name="New",
            password="Secret123!",
            queue="default",
            timezone="UTC",
            permissions=[PermissionInput(major="alert", minor="read", effect="ALLOW")],
            groups=[group.id],
        )
        assert user.id is not None
        assert user.verify_password("Secret123!")

        perms = await service.get_user_permissions_async(session, user.id, include_groups=False)
        assert any(p.major == "alert" and p.minor == "read" for p in perms)

        groups = await service.get_user_groups_async(session, user.id)
        assert group.id in {g.id for g in groups}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("username,email", [
        ("", "a@e.com"),         # blank username (the empty-row bug)
        ("   ", "a@e.com"),      # whitespace-only username
        ("someone", ""),         # blank email
        ("someone", "   "),      # whitespace-only email
    ])
    async def test_blank_required_fields_rejected(self, session: AsyncSession, username, email):
        with pytest.raises(service.InvalidUserError):
            await service.create_user(
                session, username=username, email=email, display_name=None, password=None,
                queue="default", timezone="UTC", permissions=[], groups=[],
            )

    @pytest.mark.asyncio
    async def test_duplicate_username_rejected(self, session: AsyncSession):
        await _make_user(session, "svc_dupe")
        await session.flush()
        with pytest.raises(service.InvalidUserError):
            await service.create_user(
                session, username="svc_dupe", email="other@e.com", display_name=None,
                password=None, queue="default", timezone="UTC", permissions=[], groups=[],
            )

    @pytest.mark.asyncio
    async def test_username_and_email_are_stripped(self, session: AsyncSession):
        user = await service.create_user(
            session, username="  svc_stripped  ", email="  svc_stripped@e.com  ",
            display_name=None, password=None, queue="default", timezone="UTC",
            permissions=[], groups=[],
        )
        assert user.username == "svc_stripped"
        assert user.email == "svc_stripped@e.com"

    @pytest.mark.asyncio
    async def test_random_password_when_omitted(self, session: AsyncSession):
        user = await service.create_user(
            session,
            username="svc_nopass_user",
            email="svc_nopass_user@example.com",
            display_name="NoPass",
            password=None,
            queue="default",
            timezone="UTC",
            permissions=[],
            groups=[],
        )
        assert user.password_hash
        assert len(user.password_hash) > 0


class TestUpdateUsers:
    @pytest.mark.asyncio
    async def test_single_user_all_fields(self, session: AsyncSession):
        user = await _make_user(session, "svc_edit_one")
        await service.update_users(
            session,
            {user.id: UserUpdate(
                username="svc_edited_one",
                display_name="Edited",
                email="svc_edited_one@example.com",
                queue="high",
                timezone="America/Los_Angeles",
                enabled=False,
                permissions=[PermissionInput(major="event", minor="write", effect="ALLOW")],
            )},
            actor_id=None,
        )
        await session.refresh(user)
        assert user.username == "svc_edited_one"
        assert user.queue == "high"
        assert user.enabled is False
        perms = await service.get_user_permissions_async(session, user.id, include_groups=False)
        assert {(p.major, p.minor) for p in perms} == {("event", "write")}

    @pytest.mark.asyncio
    async def test_multi_user_locks_identity_fields(self, session: AsyncSession):
        u1 = await _make_user(session, "svc_multi_1")
        u2 = await _make_user(session, "svc_multi_2")
        await service.update_users(
            session,
            {
                u1.id: UserUpdate(username="should_be_ignored", queue="bulk", enabled=False),
                u2.id: UserUpdate(queue="bulk", enabled=False),
            },
            actor_id=None,
        )
        await session.refresh(u1)
        await session.refresh(u2)
        # username change ignored during multi-edit
        assert u1.username == "svc_multi_1"
        assert u1.queue == "bulk" and u1.enabled is False
        assert u2.queue == "bulk" and u2.enabled is False

    @pytest.mark.asyncio
    async def test_permission_replace(self, session: AsyncSession):
        user = await _make_user(session, "svc_replace_perms")
        session.add(AuthUserPermission(user_id=user.id, major="old", minor="perm", effect="ALLOW"))
        await session.flush()

        await service.update_users(
            session,
            {user.id: UserUpdate(permissions=[PermissionInput(major="new", minor="perm", effect="ALLOW")])},
            actor_id=None,
        )
        perms = await service.get_user_permissions_async(session, user.id, include_groups=False)
        assert {(p.major, p.minor) for p in perms} == {("new", "perm")}

    @pytest.mark.asyncio
    async def test_group_replace(self, session: AsyncSession):
        user = await _make_user(session, "svc_replace_groups")
        g1 = await service.create_auth_group(session, "svc_grp_1")
        g2 = await service.create_auth_group(session, "svc_grp_2")
        session.add(AuthGroupUser(user_id=user.id, group_id=g1.id))
        await session.flush()

        await service.update_users(
            session, {user.id: UserUpdate(groups=[g2.id])}, actor_id=None
        )
        groups = await service.get_user_groups_async(session, user.id)
        assert {g.id for g in groups} == {g2.id}

    @pytest.mark.asyncio
    async def test_not_found_raises(self, session: AsyncSession):
        with pytest.raises(service.UserNotFoundError):
            await service.update_users(session, {999999: UserUpdate(queue="x")}, actor_id=None)


class TestGroupsAndPermissions:
    @pytest.mark.asyncio
    async def test_create_group_idempotent_and_delete(self, session: AsyncSession):
        g1 = await service.create_auth_group(session, "svc_idem_grp")
        g2 = await service.create_auth_group(session, "svc_idem_grp")
        assert g1.id == g2.id

        await service.delete_auth_groups(session, [g1.id])
        groups = await service.list_auth_groups(session)
        assert g1.id not in {g.id for g in groups}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", ["", "   "])
    async def test_blank_group_name_rejected(self, session: AsyncSession, name):
        with pytest.raises(service.InvalidGroupError):
            await service.create_auth_group(session, name)

    @pytest.mark.asyncio
    async def test_group_name_is_stripped(self, session: AsyncSession):
        group = await service.create_auth_group(session, "  svc_stripped_grp  ")
        assert group.name == "svc_stripped_grp"

    @pytest.mark.asyncio
    async def test_grant_and_revoke(self, session: AsyncSession):
        user = await _make_user(session, "svc_grant_user")
        group = await service.create_auth_group(session, "svc_grant_grp")

        await service.grant_permission(
            session,
            perm=PermissionInput(major="test", minor="perm", effect="ALLOW"),
            user_ids=[user.id],
            group_ids=[group.id],
        )
        user_perms = await service.get_user_permissions_async(session, user.id, include_groups=False)
        up = next(p for p in user_perms if p.major == "test")
        group_perms = await service.get_group_permissions_async(session, group.id)
        gp = next(p for p in group_perms if p.major == "test")

        await service.revoke_permissions(
            session, user_permission_ids=[up.id], group_permission_ids=[gp.id]
        )
        assert not [p for p in await service.get_user_permissions_async(session, user.id, include_groups=False) if p.major == "test"]
        assert not [p for p in await service.get_group_permissions_async(session, group.id) if p.major == "test"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("major,minor", [("", "read"), ("alert", ""), ("  ", "read"), ("alert", "  ")])
    async def test_blank_permission_components_rejected(self, session: AsyncSession, major, minor):
        user = await _make_user(session, f"svc_blank_{major.strip()}_{minor.strip()}_perm")
        with pytest.raises(service.InvalidPermissionError):
            await service.grant_permission(
                session,
                perm=PermissionInput(major=major, minor=minor, effect="ALLOW"),
                user_ids=[user.id],
                group_ids=[],
            )

    @pytest.mark.asyncio
    async def test_permission_components_are_stripped(self, session: AsyncSession):
        user = await _make_user(session, "svc_strip_perm")
        await service.grant_permission(
            session,
            perm=PermissionInput(major="  alert  ", minor="  read  ", effect="ALLOW"),
            user_ids=[user.id],
            group_ids=[],
        )
        perms = await service.get_user_permissions_async(session, user.id, include_groups=False)
        assert ("alert", "read") in {(p.major, p.minor) for p in perms}

    @pytest.mark.asyncio
    async def test_effect_uppercased(self, session: AsyncSession):
        user = await _make_user(session, "svc_effect_user")
        await service.grant_permission(
            session,
            perm=PermissionInput(major="test", minor="lc", effect="deny"),
            user_ids=[user.id],
            group_ids=[],
        )
        perms = await service.get_user_permissions_async(session, user.id, include_groups=False)
        assert next(p for p in perms if p.minor == "lc").effect == "DENY"


class TestApiKeys:
    @pytest.mark.asyncio
    async def test_create_inherit_key(self, session: AsyncSession):
        from saq.util import is_uuid

        user = await _make_user(session, "svc_apikey_gen")
        assert await service.list_user_api_keys(session, user.id) == []

        key, plaintext = await service.create_user_api_key(
            session, user.id, name="k", inherit=True, scope=[]
        )
        assert is_uuid(plaintext)
        assert key.inherit_user_scope is True
        keys = await service.list_user_api_keys(session, user.id)
        assert len(keys) == 1 and keys[0].name == "k"

    @pytest.mark.asyncio
    async def test_create_scoped_key(self, session: AsyncSession):
        from aceapi_v2.users.schemas import ApiKeyScope

        user = await _make_user(session, "svc_apikey_scope")
        key, _ = await service.create_user_api_key(
            session, user.id, name="ai", inherit=False, scope=[ApiKeyScope(major="ai", minor="read")]
        )
        assert key.inherit_user_scope is False
        assert [(s.major, s.minor) for s in key.scope] == [("ai", "read")]

    @pytest.mark.asyncio
    async def test_multiple_keys_per_user(self, session: AsyncSession):
        user = await _make_user(session, "svc_apikey_multi")
        await service.create_user_api_key(session, user.id, name="a", inherit=True, scope=[])
        await service.create_user_api_key(session, user.id, name="b", inherit=True, scope=[])
        assert len(await service.list_user_api_keys(session, user.id)) == 2

    @pytest.mark.asyncio
    async def test_create_requires_exactly_one_of_inherit_or_scope(self, session: AsyncSession):
        from aceapi_v2.users.schemas import ApiKeyScope

        user = await _make_user(session, "svc_apikey_bad")
        with pytest.raises(service.InvalidPermissionError):
            await service.create_user_api_key(session, user.id, name="x", inherit=False, scope=[])
        with pytest.raises(service.InvalidPermissionError):
            await service.create_user_api_key(
                session, user.id, name="x", inherit=True, scope=[ApiKeyScope(major="ai", minor="read")]
            )

    @pytest.mark.asyncio
    async def test_revoke_by_id(self, session: AsyncSession):
        user = await _make_user(session, "svc_apikey_revoke")
        key, _ = await service.create_user_api_key(session, user.id, name="k", inherit=True, scope=[])

        assert await service.revoke_user_api_key(session, key.id) is True
        assert await service.list_user_api_keys(session, user.id) == []

    @pytest.mark.asyncio
    async def test_revoke_is_false_when_no_key(self, session: AsyncSession):
        assert await service.revoke_user_api_key(session, -1) is False

    @pytest.mark.asyncio
    async def test_create_unknown_user_raises(self, session: AsyncSession):
        with pytest.raises(service.UserNotFoundForApiKeyError):
            await service.create_user_api_key(session, 999999, name="k", inherit=True, scope=[])

    @pytest.mark.asyncio
    async def test_update_replaces_scope_in_place(self, session: AsyncSession):
        from aceapi_v2.users.schemas import ApiKeyScope
        from saq.database.model import AuthApiKeyPermission

        user = await _make_user(session, "svc_apikey_update")
        key, _ = await service.create_user_api_key(
            session, user.id, name="ai", inherit=False, scope=[ApiKeyScope(major="ai", minor="*")]
        )
        key_hash = key.key_hash

        updated = await service.update_user_api_key(
            session, key.id, name="ai+obs", inherit=False,
            scope=[ApiKeyScope(major="ai", minor="*"), ApiKeyScope(major="observable", minor="read")],
        )
        assert updated is not None and updated.id == key.id
        assert updated.name == "ai+obs"
        assert updated.key_hash == key_hash  # the credential itself never changes
        assert sorted((s.major, s.minor) for s in updated.scope) == [("ai", "*"), ("observable", "read")]

        # the old rows are gone from the table, not just detached from the relationship
        rows = (await session.execute(
            select(AuthApiKeyPermission).where(AuthApiKeyPermission.api_key_id == key.id)
        )).scalars().all()
        assert sorted((r.major, r.minor) for r in rows) == [("ai", "*"), ("observable", "read")]

        updated = await service.update_user_api_key(session, key.id, name="ai+obs", inherit=True, scope=[])
        assert updated.inherit_user_scope is True and updated.scope == []
        rows = (await session.execute(
            select(AuthApiKeyPermission).where(AuthApiKeyPermission.api_key_id == key.id)
        )).scalars().all()
        assert rows == []

    @pytest.mark.asyncio
    async def test_update_validation_and_missing_key(self, session: AsyncSession):
        from aceapi_v2.users.schemas import ApiKeyScope

        user = await _make_user(session, "svc_apikey_update_bad")
        key, _ = await service.create_user_api_key(session, user.id, name="k", inherit=True, scope=[])

        with pytest.raises(service.InvalidPermissionError):
            await service.update_user_api_key(session, key.id, name="k", inherit=False, scope=[])
        with pytest.raises(service.InvalidPermissionError):
            await service.update_user_api_key(
                session, key.id, name="k", inherit=True, scope=[ApiKeyScope(major="ai", minor="*")]
            )
        with pytest.raises(service.InvalidPermissionError):
            await service.update_user_api_key(
                session, key.id, name="k", inherit=False, scope=[ApiKeyScope(major="ai", minor="")]
            )
        with pytest.raises(service.InvalidPermissionError):
            await service.update_user_api_key(session, key.id, name="", inherit=True, scope=[])

        assert await service.update_user_api_key(session, -1, name="k", inherit=True, scope=[]) is None

    @pytest.mark.asyncio
    async def test_api_key_count_reflected_in_management_view(self, session: AsyncSession):
        user = await _make_user(session, "svc_apikey_view")
        await session.flush()

        view = await service.get_management_view(session)
        assert next(u for u in view.users if u.id == user.id).api_key_count == 0

        await service.create_user_api_key(session, user.id, name="k", inherit=True, scope=[])
        view = await service.get_management_view(session)
        assert next(u for u in view.users if u.id == user.id).api_key_count == 1


class TestManagementViewAndCatalog:
    @pytest.mark.asyncio
    async def test_management_view_shape(self, session: AsyncSession):
        user = await _make_user(session, "svc_mv_user")
        group = await service.create_auth_group(session, "svc_mv_grp")
        session.add(AuthUserPermission(user_id=user.id, major="alert", minor="read", effect="ALLOW"))
        await session.flush()

        view = await service.get_management_view(session, include_disabled=True)
        assert any(u.id == user.id for u in view.users)
        assert user.id in view.permissions
        assert group.id in view.group_permissions
        # catalog is populated from auth_permission_catalog; may be empty in a clean txn
        assert isinstance(view.catalog, list)

    @pytest.mark.asyncio
    async def test_get_users_details(self, session: AsyncSession):
        user = await _make_user(session, "svc_detail_user")
        group = await service.create_auth_group(session, "svc_detail_grp")
        session.add(AuthGroupUser(user_id=user.id, group_id=group.id))
        session.add(AuthUserPermission(user_id=user.id, major="alert", minor="read", effect="ALLOW"))
        await session.flush()

        details = await service.get_users_details(session, [user.id])
        assert user.id in details
        d = details[user.id]
        assert d.username == "svc_detail_user"
        assert {(p.major, p.minor) for p in d.permissions} == {("alert", "read")}
        assert group.id in {g.id for g in d.groups}
