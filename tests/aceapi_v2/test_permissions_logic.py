"""Tests for the async permission check used by apiv2.

user_has_permission_async() mirrors the synchronous user_has_permission()
(tests/saq/test_permissions.py) but runs on an AsyncSession so the FastAPI
permission dependency never touches the synchronous thread-local get_db()
session. These tests exercise the same allow/deny/wildcard logic against the
async session.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import (
    AuthGroup,
    AuthGroupPermission,
    AuthGroupUser,
    AuthUserPermission,
    User,
)
from saq.permissions.logic import get_permission_rows_async, user_has_permission_async

pytestmark = pytest.mark.integration


async def _make_user(session: AsyncSession, username: str) -> User:
    user = User()
    user.username = username
    user.email = f"{username}@example.com"
    user.password = "testpass"
    session.add(user)
    await session.flush()
    return user


async def _add_user_perm(session, user_id, major, minor, effect):
    session.add(
        AuthUserPermission(user_id=user_id, major=major, minor=minor, effect=effect)
    )
    await session.flush()


async def _add_group_with_user(session, name, user_id) -> AuthGroup:
    group = AuthGroup(name=name)
    session.add(group)
    await session.flush()
    session.add(AuthGroupUser(group_id=group.id, user_id=user_id))
    await session.flush()
    return group


async def _add_group_perm(session, group_id, major, minor, effect):
    session.add(
        AuthGroupPermission(group_id=group_id, major=major, minor=minor, effect=effect)
    )
    await session.flush()


@pytest.mark.asyncio
async def test_direct_allow(session: AsyncSession):
    user = await _make_user(session, "async_perm_allow")
    await _add_user_perm(session, user.id, "test_has", "permission", "ALLOW")
    assert await user_has_permission_async(session, user.id, "test_has", "permission") is True


@pytest.mark.asyncio
async def test_direct_deny(session: AsyncSession):
    user = await _make_user(session, "async_perm_deny")
    await _add_user_perm(session, user.id, "test_deny", "permission", "DENY")
    assert await user_has_permission_async(session, user.id, "test_deny", "permission") is False


@pytest.mark.asyncio
async def test_no_permission(session: AsyncSession):
    user = await _make_user(session, "async_perm_none")
    assert await user_has_permission_async(session, user.id, "nonexistent", "permission") is False


@pytest.mark.asyncio
async def test_group_allow(session: AsyncSession):
    user = await _make_user(session, "async_perm_group_allow")
    group = await _add_group_with_user(session, "async_allow_group", user.id)
    await _add_group_perm(session, group.id, "group_allow", "permission", "ALLOW")
    assert await user_has_permission_async(session, user.id, "group_allow", "permission") is True


@pytest.mark.asyncio
async def test_group_deny(session: AsyncSession):
    user = await _make_user(session, "async_perm_group_deny")
    group = await _add_group_with_user(session, "async_deny_group", user.id)
    await _add_group_perm(session, group.id, "group_deny", "permission", "DENY")
    assert await user_has_permission_async(session, user.id, "group_deny", "permission") is False


@pytest.mark.asyncio
async def test_deny_overrides_allow(session: AsyncSession):
    user = await _make_user(session, "async_perm_override")
    await _add_user_perm(session, user.id, "override", "permission", "ALLOW")
    await _add_user_perm(session, user.id, "override", "permission", "DENY")
    assert await user_has_permission_async(session, user.id, "override", "permission") is False


@pytest.mark.asyncio
async def test_user_deny_overrides_group_allow(session: AsyncSession):
    user = await _make_user(session, "async_perm_mixed")
    group = await _add_group_with_user(session, "async_mixed_group", user.id)
    await _add_group_perm(session, group.id, "mixed", "permission", "ALLOW")
    await _add_user_perm(session, user.id, "mixed", "permission", "DENY")
    assert await user_has_permission_async(session, user.id, "mixed", "permission") is False


@pytest.mark.asyncio
async def test_wildcard_minor(session: AsyncSession):
    user = await _make_user(session, "async_perm_wildcard")
    await _add_user_perm(session, user.id, "test", "*", "ALLOW")
    assert await user_has_permission_async(session, user.id, "test", "blah") is True
    assert await user_has_permission_async(session, user.id, "test", "anything") is True
    assert await user_has_permission_async(session, user.id, "other", "blah") is False


@pytest.mark.asyncio
async def test_permission_rows_are_the_users_own_and_their_groups(session: AsyncSession):
    user = await _make_user(session, "async_perm_rows")
    await _add_user_perm(session, user.id, "alert", "read", "ALLOW")
    group = await _add_group_with_user(session, "async_perm_rows_grp", user.id)
    await _add_group_perm(session, group.id, "signature", "*", "DENY")

    user_rows, group_rows = await get_permission_rows_async(session, user.id)
    assert [tuple(row) for row in user_rows] == [("alert", "read", "ALLOW")]
    assert [tuple(row) for row in group_rows] == [("signature", "*", "DENY")]


@pytest.mark.asyncio
async def test_permission_rows_of_a_user_in_no_group(session: AsyncSession):
    user = await _make_user(session, "async_perm_rows_nogroup")
    await _add_user_perm(session, user.id, "alert", "read", "ALLOW")

    user_rows, group_rows = await get_permission_rows_async(session, user.id)
    assert [tuple(row) for row in user_rows] == [("alert", "read", "ALLOW")]
    assert group_rows == []
