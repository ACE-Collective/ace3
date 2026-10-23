"""Tests for the aceapi_v2 users/roles management service."""

import logging

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import (
    AuthApiKeyPermission,
    AuthGroupUser,
    AuthUserPermission,
    User,
)
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.auth.utils import (
    API_AUTH_TYPE_CONFIG,
    API_AUTH_TYPE_USER,
    API_CREDENTIAL_CONFIG_KEY,
    API_CREDENTIAL_SESSION,
    API_CREDENTIAL_USER_KEY,
)
from aceapi_v2.database import create_engine_for
from aceapi_v2.users import service
from aceapi_v2.users.schemas import ApiKeyScope, PermissionInput, UserUpdate
from saq.permissions.logic import user_has_permission_async
from tests.aceapi_v2.conftest import add_analyst_group, key_scope

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
    async def test_a_case_variant_is_the_same_grant(self, session: AsyncSession):
        user = await _make_user(session, "svc_case_user")
        group = await service.create_auth_group(session, "svc_case_grp")
        for major, minor in (("Alert", "READ"), ("alert", "read")):
            await service.grant_permission(
                session,
                perm=PermissionInput(major=major, minor=minor, effect="ALLOW"),
                user_ids=[user.id],
                group_ids=[group.id],
            )

        user_perms = await service.get_user_permissions_async(session, user.id, include_groups=False)
        assert [(p.major, p.minor) for p in user_perms] == [("alert", "read")]
        group_perms = await service.get_group_permissions_async(session, group.id)
        assert [(p.major, p.minor) for p in group_perms] == [("alert", "read")]
        assert await user_has_permission_async(session, user.id, "alert", "read") is True

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


async def _make_analyst(session: AsyncSession, username: str) -> User:
    """A user whose only grants come from an analyst group."""
    user = await _make_user(session, username)
    await add_analyst_group(session, user)
    return user


def _session_of(user: User) -> ApiAuthResult:
    """The credential a user's GUI session authenticates as."""
    return ApiAuthResult(
        auth_type=API_AUTH_TYPE_USER, auth_name=user.username, auth_user_id=user.id, credential=API_CREDENTIAL_SESSION)


def _assert_foreign_key_warned(caplog, action: str, key_id: int, key_owner_id: int, actor_id: int) -> None:
    warned = [r for r in caplog.records if r.levelno == logging.WARNING and f"tried to {action} api key" in r.getMessage()]
    assert len(warned) == 1
    assert (warned[0].api_key_id, warned[0].user_id, warned[0].actor_id) == (key_id, key_owner_id, actor_id)


async def _stored_scope(session: AsyncSession, key_id: int) -> list[tuple[str, str]]:
    rows = (await session.execute(
        select(AuthApiKeyPermission).where(AuthApiKeyPermission.api_key_id == key_id)
    )).scalars().all()
    return sorted((row.major, row.minor) for row in rows)


class TestSelfServiceApiKeys:
    """A user with user:self managing their own keys: scoped only, and only to what they hold."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern", ["signature:*", "signature:read", "ai:fake"])
    async def test_create_within_grants(self, session: AsyncSession, pattern):
        # ai:fake is derived from the unittest config's ai_query_backend_fake, not the static catalog
        user = await _make_analyst(session, "svc_self_ok")
        key, plaintext = await service.create_user_api_key(
            session, user.id, name="mine", inherit=False, scope=key_scope(pattern),
            actor=_session_of(user), self_service=True,
        )
        assert plaintext
        assert key.created_by == user.id and key.inherit_user_scope is False
        assert await _stored_scope(session, key.id) == [tuple(pattern.split(":"))]

    @pytest.mark.asyncio
    async def test_create_refuses_inherit(self, session: AsyncSession):
        user = await _make_analyst(session, "svc_self_inherit")
        with pytest.raises(service.InvalidPermissionError, match="administrator"):
            await service.create_user_api_key(
                session, user.id, name="mine", inherit=True, scope=[], self_service=True)
        assert await service.list_user_api_keys(session, user.id) == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern, unheld", [
        ("*:*", "user:write"),
        ("user:*", "user:write"),
        ("*:read", "secret:read"),
        ("cli:execute", "cli:execute"),
    ])
    async def test_create_refuses_a_pattern_covering_what_the_user_lacks(
        self, session: AsyncSession, caplog, pattern, unheld
    ):
        caplog.set_level(logging.WARNING)
        user = await _make_analyst(session, "svc_self_unheld")
        with pytest.raises(service.InvalidPermissionError) as error:
            await service.create_user_api_key(
                session, user.id, name="too wide", inherit=False, scope=key_scope("signature:read", pattern),
                self_service=True,
            )
        assert f"{pattern} covers" in str(error.value) and unheld in str(error.value)
        assert "signature:read" not in str(error.value)  # only the offending pattern is reported
        assert await service.list_user_api_keys(session, user.id) == []

        refusals = [r for r in caplog.records if r.levelno == logging.WARNING and "cannot give api key" in r.getMessage()]
        assert len(refusals) == 1
        assert refusals[0].user_id == user.id and refusals[0].api_key_name == "too wide"
        assert refusals[0].api_key_id is None  # not minted

    @pytest.mark.asyncio
    async def test_a_refused_edit_names_the_key(self, session: AsyncSession, caplog):
        caplog.set_level(logging.WARNING)
        user = await _make_analyst(session, "svc_self_unheld_edit")
        key, _ = await service.create_user_api_key(
            session, user.id, name="narrow", inherit=False, scope=key_scope("alert:read"), self_service=True)

        with pytest.raises(service.InvalidPermissionError):
            await service.update_user_api_key(
                session, key.id, name="wide", inherit=False, scope=key_scope("*:*"), owner_id=user.id)

        refusals = [r for r in caplog.records if r.levelno == logging.WARNING and "cannot give api key" in r.getMessage()]
        assert len(refusals) == 1
        assert refusals[0].api_key_id == key.id and refusals[0].api_key_name == "wide"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern", ["signature:wrte", "nosuch:*"])
    async def test_create_refuses_a_pattern_matching_no_permission(self, session: AsyncSession, pattern):
        user = await _make_analyst(session, "svc_self_nothing")
        with pytest.raises(service.InvalidPermissionError, match="matches no permission ACE enforces"):
            await service.create_user_api_key(
                session, user.id, name="typo", inherit=False, scope=key_scope(pattern), self_service=True)

    @pytest.mark.asyncio
    async def test_a_user_with_no_grants_can_mint_nothing(self, session: AsyncSession):
        user = await _make_user(session, "svc_self_nogrants")
        with pytest.raises(service.InvalidPermissionError, match="which you do not hold"):
            await service.create_user_api_key(
                session, user.id, name="k", inherit=False, scope=key_scope("alert:read"), self_service=True)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("self_service", [True, False])
    async def test_a_repeated_pattern_is_stored_once(self, session: AsyncSession, self_service):
        user = await _make_analyst(session, "svc_self_dupe")
        key, _ = await service.create_user_api_key(
            session, user.id, name="k", inherit=False, scope=key_scope("signature:read", "signature:read"),
            self_service=self_service,
        )
        assert await _stored_scope(session, key.id) == [("signature", "read")]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("self_service", [True, False])
    @pytest.mark.parametrize("pattern", ["user:self", "User:Self"])
    async def test_user_self_is_never_put_on_a_key(self, session: AsyncSession, self_service, pattern):
        """No API key can use it (check_permission refuses), so an entry naming it would only mislead."""
        user = await _make_analyst(session, "svc_self_on_key")
        with pytest.raises(service.InvalidPermissionError, match="never given to an API key"):
            await service.create_user_api_key(
                session, user.id, name="k", inherit=False, scope=key_scope("alert:read", pattern),
                self_service=self_service,
            )

        key, _ = await service.create_user_api_key(session, user.id, name="k", inherit=False, scope=key_scope("alert:read"))
        with pytest.raises(service.InvalidPermissionError, match="never given to an API key"):
            await service.update_user_api_key(
                session, key.id, name="k", inherit=False, scope=key_scope(pattern),
                owner_id=user.id if self_service else None,
            )
        assert await _stored_scope(session, key.id) == [("alert", "read")]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("self_service", [True, False])
    async def test_patterns_differing_only_in_case_are_stored_once(self, session: AsyncSession, self_service):
        """The unique index is case-insensitive, so storing both would fail the INSERT (a 500)."""
        user = await _make_analyst(session, "svc_self_case")
        key, _ = await service.create_user_api_key(
            session, user.id, name="k", inherit=False, scope=key_scope("signature:read", "Signature:Read"),
            self_service=self_service,
        )
        assert await _stored_scope(session, key.id) == [("signature", "read")]

        await service.update_user_api_key(
            session, key.id, name="k", inherit=False, scope=key_scope("ALERT:*", "alert:*"),
            owner_id=user.id if self_service else None,
        )
        assert await _stored_scope(session, key.id) == [("alert", "*")]

    @pytest.mark.asyncio
    async def test_self_update_holds_the_whole_scope_to_the_rules(self, session: AsyncSession):
        """An admin may have put a pattern on the key that the user could not; the user's own edit
        must leave a scope they could have minted, and a refused edit changes nothing."""
        user = await _make_analyst(session, "svc_self_update")
        key, _ = await service.create_user_api_key(
            session, user.id, name="from admin", inherit=False, scope=key_scope("*:*"))

        with pytest.raises(service.InvalidPermissionError, match=r"\*:\* covers"):
            await service.update_user_api_key(
                session, key.id, name="renamed", inherit=False, scope=key_scope("*:*", "alert:read"),
                owner_id=user.id, actor=_session_of(user),
            )
        await session.refresh(key)
        assert key.name == "from admin"
        assert await _stored_scope(session, key.id) == [("*", "*")]

        updated = await service.update_user_api_key(
            session, key.id, name="renamed", inherit=False, scope=key_scope("signature:*"),
            owner_id=user.id, actor=_session_of(user),
        )
        assert updated is not None and updated.name == "renamed"
        assert await _stored_scope(session, key.id) == [("signature", "*")]

    @pytest.mark.asyncio
    async def test_self_update_turns_an_inherit_key_into_a_scoped_one(self, session: AsyncSession):
        user = await _make_analyst(session, "svc_self_convert")
        key, _ = await service.create_user_api_key(session, user.id, name="full", inherit=True, scope=[])

        with pytest.raises(service.InvalidPermissionError, match="administrator"):
            await service.update_user_api_key(
                session, key.id, name="full", inherit=True, scope=[], owner_id=user.id)

        updated = await service.update_user_api_key(
            session, key.id, name="narrow", inherit=False, scope=key_scope("alert:read"), owner_id=user.id)
        assert updated.inherit_user_scope is False
        assert await _stored_scope(session, key.id) == [("alert", "read")]

    @pytest.mark.asyncio
    async def test_self_update_of_another_users_key_is_not_found(self, session: AsyncSession, caplog):
        caplog.set_level(logging.WARNING)
        user = await _make_analyst(session, "svc_self_update_me")
        other = await _make_analyst(session, "svc_self_update_other")
        key, _ = await service.create_user_api_key(
            session, other.id, name="theirs", inherit=False, scope=key_scope("alert:read"))

        assert await service.update_user_api_key(
            session, key.id, name="mine now", inherit=False, scope=key_scope("signature:read"), owner_id=user.id,
        ) is None
        await session.refresh(key)
        assert key.name == "theirs"
        assert await _stored_scope(session, key.id) == [("alert", "read")]
        _assert_foreign_key_warned(caplog, "edit", key.id, other.id, user.id)

        # a key id that doesn't exist is only missing: nobody else's key was tried
        caplog.clear()
        assert await service.update_user_api_key(
            session, 999999, name="k", inherit=False, scope=key_scope("alert:read"), owner_id=user.id) is None
        assert not [r for r in caplog.records if "tried to" in r.getMessage()]

    @pytest.mark.asyncio
    async def test_self_revoke_only_reaches_the_users_own_keys(self, session: AsyncSession, caplog):
        caplog.set_level(logging.WARNING)
        user = await _make_analyst(session, "svc_self_revoke_me")
        other = await _make_analyst(session, "svc_self_revoke_other")
        mine, _ = await service.create_user_api_key(session, user.id, name="mine", inherit=False, scope=key_scope("alert:read"))
        theirs, _ = await service.create_user_api_key(session, other.id, name="theirs", inherit=False, scope=key_scope("alert:read"))

        assert await service.revoke_user_api_key(session, theirs.id, owner_id=user.id) is False
        assert [k.id for k in await service.list_user_api_keys(session, other.id)] == [theirs.id]
        _assert_foreign_key_warned(caplog, "revoke", theirs.id, other.id, user.id)

        caplog.clear()
        assert await service.revoke_user_api_key(session, 999999, owner_id=user.id) is False
        assert not [r for r in caplog.records if "tried to" in r.getMessage()]

        assert await service.revoke_user_api_key(session, mine.id, owner_id=user.id) is True
        assert await service.list_user_api_keys(session, user.id) == []

    @pytest.mark.asyncio
    async def test_key_changes_are_audited_without_the_secret(self, session: AsyncSession, caplog):
        """Each record names the key's owner and, separately, who changed it: the account and the
        API key it used, or a config key, which has no account."""
        caplog.set_level(logging.INFO)
        owner = await _make_analyst(session, "svc_audit_owner")
        admin = await _make_user(session, "svc_audit_admin")
        by_admin_key = ApiAuthResult(
            auth_type=API_AUTH_TYPE_USER, auth_name=admin.username, auth_user_id=admin.id, key_id=99, key_name="ops",
            credential=API_CREDENTIAL_USER_KEY)
        by_config_key = ApiAuthResult(
            auth_type=API_AUTH_TYPE_CONFIG, auth_name="automation", key_name="automation",
            credential=API_CREDENTIAL_CONFIG_KEY)

        key, plaintext = await service.create_user_api_key(
            session, owner.id, name="audited", inherit=False, scope=key_scope("alert:read"), actor=by_admin_key)
        assert key.created_by == admin.id
        await service.update_user_api_key(
            session, key.id, name="audited", inherit=False, scope=key_scope("signature:read"), actor=by_config_key)
        await service.revoke_user_api_key(session, key.id, actor=by_admin_key)

        audits = [r for r in caplog.records if r.getMessage().startswith("AUDIT:") and getattr(r, "api_key_id", None) == key.id]
        assert [r.getMessage().split()[3] for r in audits] == ["created", "updated", "revoked"]
        assert all(r.levelno == logging.INFO and r.user_id == owner.id for r in audits)
        assert [(r.actor, r.actor_id, r.actor_key_id) for r in audits] == [
            ("svc_audit_admin", admin.id, 99), ("automation", None, None), ("svc_audit_admin", admin.id, 99)]
        assert audits[1].getMessage().startswith("AUDIT: user automation updated")
        assert "alert:read" in audits[0].getMessage() and "signature:read" in audits[1].getMessage()
        assert plaintext not in caplog.text

    @pytest.mark.asyncio
    async def test_an_edit_waits_for_a_concurrent_edit_of_the_same_key(self, monkeypatch):
        """The owner's edit has read the key when an admin's edit of it arrives. The admin's must
        wait for the owner's to commit: if both replace the scope the owner read, the key ends up
        with both scopes, or the second insert fails u_api_key_perm (a 500).

        Real transactions on their own connections, so neither sees the other's uncommitted rows;
        the integration reset clears what they commit.
        """
        engine = create_engine_for()
        try:
            async with AsyncSession(engine, expire_on_commit=False) as setup:
                owner = await _make_analyst(setup, "svc_concurrent_owner")
                key, _ = await service.create_user_api_key(
                    setup, owner.id, name="k", inherit=False, scope=key_scope("alert:read"))
                await setup.commit()

            admin_waited: list[OperationalError] = []
            check_scope_within_grants = service._check_scope_within_grants

            async def admin_edits_meanwhile(*args, **kwargs):
                # only the owner's edit gets here, after it has read the key and before it writes
                async with AsyncSession(engine) as admin:
                    # 1 second, the minimum: the owner's edit is paused here, so it cannot commit
                    await admin.execute(text("SET SESSION innodb_lock_wait_timeout = 1"))
                    try:
                        await service.update_user_api_key(
                            admin, key.id, name="k", inherit=False, scope=key_scope("signature:read"))
                        await admin.commit()
                    except OperationalError as e:
                        admin_waited.append(e)
                await check_scope_within_grants(*args, **kwargs)

            monkeypatch.setattr(service, "_check_scope_within_grants", admin_edits_meanwhile)
            async with AsyncSession(engine) as owner_session:
                await service.update_user_api_key(
                    owner_session, key.id, name="k", inherit=False, scope=key_scope("observable:read"),
                    owner_id=owner.id)
                await owner_session.commit()

            assert len(admin_waited) == 1 and admin_waited[0].orig.args[0] == 1205  # lock wait timeout
            async with AsyncSession(engine) as check:
                assert await _stored_scope(check, key.id) == [("observable", "read")]

            # and once the owner's edit has committed, the admin's goes through on top of it
            async with AsyncSession(engine) as admin:
                await service.update_user_api_key(
                    admin, key.id, name="k", inherit=False, scope=key_scope("signature:read"))
                await admin.commit()
            async with AsyncSession(engine) as check:
                assert await _stored_scope(check, key.id) == [("signature", "read")]
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_held_catalog_lists_only_what_the_user_holds(self, session: AsyncSession):
        user = await _make_analyst(session, "svc_self_catalog")
        held = await service.list_held_catalog(session, user.id)
        pairs = [(e.major, e.minor) for e in held]

        assert pairs == sorted(pairs)
        assert {("signature", "read"), ("user", "self"), ("ai", "fake")} <= set(pairs)
        assert not {("user", "write"), ("cli", "execute"), ("secret", "read")} & set(pairs)
        assert all(e.description for e in held)
