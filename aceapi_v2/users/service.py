"""Users / roles / permissions management service (ACE API v2).

Native-async ports of the logic that previously lived in the Flask ``app/auth/manage.py`` and
``app/auth/edit.py`` views plus the synchronous ``saq.permissions`` helpers. The synchronous helpers
remain in place for the CLI and the ``@require_permission`` enforcement path; these async copies are
the source of truth for the admin GUI + v2 API.
"""

import uuid

import pytz
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.crypto import encrypt_chunk
from saq.database.model import (
    AuthGroup,
    AuthGroupPermission,
    AuthGroupUser,
    AuthPermissionCatalog,
    AuthUserPermission,
    User,
)
from saq.util import sha256_str
from aceapi_v2.users.schemas import (
    CatalogEntryRead,
    GroupPermissionRead,
    GroupRead,
    ManagementView,
    PermissionInput,
    PermissionRead,
    UserDetail,
    UserRead,
    UserUpdate,
)


def _user_read(user: User) -> UserRead:
    return UserRead(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        queue=user.queue,
        enabled=user.enabled,
        timezone=user.timezone,
        has_api_key=user.apikey_hash is not None,
    )


async def list_users(session: AsyncSession, include_disabled: bool = True) -> list[User]:
    stmt = select(User)
    if not include_disabled:
        stmt = stmt.where(User.enabled == True)  # noqa: E712
    stmt = stmt.order_by(User.username)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_user_permissions_async(
    session: AsyncSession, user_id: int, include_groups: bool = True
) -> list[PermissionRead]:
    """Async port of saq.permissions.user.get_user_permissions."""
    results: list[PermissionRead] = []

    rows = (await session.execute(
        select(AuthUserPermission).where(AuthUserPermission.user_id == user_id)
    )).scalars().all()
    for p in rows:
        results.append(PermissionRead(
            id=p.id, major=p.major, minor=p.minor, effect=p.effect, source="user", group_id=None,
        ))

    if include_groups:
        group_ids = [
            r for (r,) in (await session.execute(
                select(AuthGroupUser.group_id).where(AuthGroupUser.user_id == user_id)
            )).all()
        ]
        if group_ids:
            gp_rows = (await session.execute(
                select(AuthGroupPermission, AuthGroup.name)
                .join(AuthGroup, AuthGroupPermission.group_id == AuthGroup.id)
                .where(AuthGroupPermission.group_id.in_(group_ids))
            )).all()
            for gp, group_name in gp_rows:
                results.append(PermissionRead(
                    id=gp.id, major=gp.major, minor=gp.minor, effect=gp.effect,
                    source=f"group:{group_name}", group_id=gp.group_id,
                ))

    return results


async def get_group_permissions_async(session: AsyncSession, group_id: int) -> list[GroupPermissionRead]:
    rows = (await session.execute(
        select(AuthGroupPermission).where(AuthGroupPermission.group_id == group_id)
    )).scalars().all()
    return [GroupPermissionRead(id=p.id, major=p.major, minor=p.minor, effect=p.effect) for p in rows]


async def list_auth_groups(session: AsyncSession) -> list[AuthGroup]:
    result = await session.execute(select(AuthGroup).order_by(AuthGroup.name))
    return list(result.scalars().all())


async def get_user_groups_async(session: AsyncSession, user_id: int) -> list[AuthGroup]:
    result = await session.execute(
        select(AuthGroup).join(AuthGroupUser).where(AuthGroupUser.user_id == user_id)
    )
    return list(result.scalars().all())


async def list_permission_catalog(session: AsyncSession) -> list[CatalogEntryRead]:
    rows = (await session.execute(
        select(AuthPermissionCatalog).order_by(AuthPermissionCatalog.major, AuthPermissionCatalog.minor)
    )).scalars().all()
    return [CatalogEntryRead(major=r.major, minor=r.minor, description=r.description) for r in rows]


async def get_management_view(session: AsyncSession, include_disabled: bool = True) -> ManagementView:
    """Assemble the full users/roles management page payload in one call."""
    users = await list_users(session, include_disabled=include_disabled)
    permissions = {u.id: await get_user_permissions_async(session, u.id) for u in users}
    groups = await list_auth_groups(session)
    group_permissions = {g.id: await get_group_permissions_async(session, g.id) for g in groups}
    catalog = await list_permission_catalog(session)

    return ManagementView(
        users=[_user_read(u) for u in users],
        permissions=permissions,
        groups=[GroupRead(id=g.id, name=g.name) for g in groups],
        group_permissions=group_permissions,
        catalog=catalog,
    )


async def get_users_details(session: AsyncSession, user_ids: list[int]) -> dict[int, UserDetail]:
    """Per-user detail (direct permissions only + group memberships) for the edit modal."""
    result = await session.execute(select(User).where(User.id.in_(user_ids)))
    users = list(result.scalars().all())

    details: dict[int, UserDetail] = {}
    for user in users:
        perms = await get_user_permissions_async(session, user.id, include_groups=False)
        groups = await get_user_groups_async(session, user.id)
        details[user.id] = UserDetail(
            id=user.id,
            username=user.username,
            display_name=user.display_name,
            email=user.email,
            queue=user.queue,
            timezone=user.timezone,
            permissions=perms,
            groups=[GroupRead(id=g.id, name=g.name) for g in groups],
        )
    return details


async def _add_user_permission(session: AsyncSession, user_id: int, perm: PermissionInput, created_by: int | None) -> None:
    effect = perm.effect.upper()
    existing = (await session.execute(
        select(AuthUserPermission).where(
            AuthUserPermission.user_id == user_id,
            AuthUserPermission.major == perm.major,
            AuthUserPermission.minor == perm.minor,
            AuthUserPermission.effect == effect,
        )
    )).scalar_one_or_none()
    if existing:
        return
    session.add(AuthUserPermission(
        user_id=user_id, major=perm.major, minor=perm.minor, effect=effect, created_by=created_by,
    ))


async def _add_group_permission(session: AsyncSession, group_id: int, perm: PermissionInput, created_by: int | None) -> None:
    effect = perm.effect.upper()
    existing = (await session.execute(
        select(AuthGroupPermission).where(
            AuthGroupPermission.group_id == group_id,
            AuthGroupPermission.major == perm.major,
            AuthGroupPermission.minor == perm.minor,
            AuthGroupPermission.effect == effect,
        )
    )).scalar_one_or_none()
    if existing:
        return
    session.add(AuthGroupPermission(
        group_id=group_id, major=perm.major, minor=perm.minor, effect=effect, created_by=created_by,
    ))


async def _add_user_to_group(session: AsyncSession, user_id: int, group_id: int) -> None:
    existing = (await session.execute(
        select(AuthGroupUser).where(
            AuthGroupUser.user_id == user_id, AuthGroupUser.group_id == group_id
        )
    )).scalar_one_or_none()
    if existing is None:
        session.add(AuthGroupUser(user_id=user_id, group_id=group_id))


class InvalidUserError(ValueError):
    """Raised when required user fields are missing or blank."""


async def create_user(
    session: AsyncSession,
    *,
    username: str,
    email: str,
    display_name: str | None,
    password: str | None,
    queue: str,
    timezone: str,
    permissions: list[PermissionInput],
    groups: list[int],
    created_by: int | None = None,
) -> User:
    # the users table columns are NOT NULL but an empty string satisfies that, so guard here --
    # this is the single choke point for both the admin GUI and the v2 API.
    username = (username or "").strip()
    email = (email or "").strip()
    if not username:
        raise InvalidUserError("username is required")
    if not email:
        raise InvalidUserError("email is required")

    existing = (await session.execute(
        select(User).where(User.username == username)
    )).scalar_one_or_none()
    if existing is not None:
        raise InvalidUserError(f"a user named {username!r} already exists")

    if not password:
        password = str(uuid.uuid4())

    user = User(
        username=username,
        email=email,
        display_name=display_name,
        queue=queue,
        timezone=timezone,
        password=password,  # property setter hashes with bcrypt
    )
    session.add(user)
    await session.flush()  # assign user.id

    for perm in permissions:
        await _add_user_permission(session, user.id, perm, created_by)
    for group_id in groups:
        await _add_user_to_group(session, user.id, group_id)

    await session.flush()
    return user


class UserNotFoundError(Exception):
    def __init__(self, user_id: int):
        self.user_id = user_id
        super().__init__(f"User {user_id} not found")


async def update_users(session: AsyncSession, changes: dict[int, UserUpdate], actor_id: int | None = None) -> None:
    """Port of app/auth/edit.py::edit_users. Raises UserNotFoundError if a user id is missing."""
    edit_multiple = len(changes) > 1

    for user_id, upd in changes.items():
        user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if user is None:
            raise UserNotFoundError(user_id)

        # Username/password/display_name/email are only editable for a single-user edit.
        if not edit_multiple:
            if upd.username and upd.username.strip():
                user.username = upd.username.strip()
            if upd.password:
                user.password = upd.password  # setter hashes
            if upd.display_name:
                user.display_name = upd.display_name
            if upd.email and upd.email.strip():
                user.email = upd.email.strip()

        if upd.queue:
            user.queue = upd.queue
        if upd.timezone:
            user.timezone = upd.timezone
        if upd.enabled is not None:
            user.enabled = upd.enabled

        if upd.permissions is not None:
            await session.execute(
                delete(AuthUserPermission).where(AuthUserPermission.user_id == user_id)
            )
            for perm in upd.permissions:
                await _add_user_permission(session, user_id, perm, actor_id)

        if upd.groups is not None:
            await session.execute(
                delete(AuthGroupUser).where(AuthGroupUser.user_id == user_id)
            )
            for group_id in upd.groups:
                await _add_user_to_group(session, user_id, group_id)

    await session.flush()


class InvalidGroupError(ValueError):
    """Raised when an auth group is created without a name."""


async def create_auth_group(session: AsyncSession, name: str) -> AuthGroup:
    name = (name or "").strip()
    if not name:
        raise InvalidGroupError("group name is required")

    existing = (await session.execute(
        select(AuthGroup).where(AuthGroup.name == name)
    )).scalar_one_or_none()
    if existing:
        return existing
    group = AuthGroup(name=name)
    session.add(group)
    await session.flush()
    return group


async def delete_auth_groups(session: AsyncSession, group_ids: list[int]) -> None:
    if not group_ids:
        return
    await session.execute(delete(AuthGroup).where(AuthGroup.id.in_(group_ids)))
    await session.flush()


class InvalidPermissionError(ValueError):
    """Raised when a permission grant is missing its major or minor component."""


async def grant_permission(
    session: AsyncSession,
    *,
    perm: PermissionInput,
    user_ids: list[int],
    group_ids: list[int],
    actor_id: int | None = None,
) -> None:
    # blank components would insert a meaningless (and un-revocable-looking) grant row
    perm = PermissionInput(
        major=(perm.major or "").strip(),
        minor=(perm.minor or "").strip(),
        effect=perm.effect,
    )
    if not perm.major or not perm.minor:
        raise InvalidPermissionError("both a major and a minor are required")

    for user_id in user_ids:
        await _add_user_permission(session, user_id, perm, actor_id)
    for group_id in group_ids:
        await _add_group_permission(session, group_id, perm, actor_id)
    await session.flush()


async def revoke_permissions(
    session: AsyncSession,
    *,
    user_permission_ids: list[int],
    group_permission_ids: list[int],
) -> None:
    if user_permission_ids:
        await session.execute(
            delete(AuthUserPermission).where(AuthUserPermission.id.in_(user_permission_ids))
        )
    if group_permission_ids:
        await session.execute(
            delete(AuthGroupPermission).where(AuthGroupPermission.id.in_(group_permission_ids))
        )
    await session.flush()


def all_timezones() -> list[str]:
    return list(pytz.all_timezones)


class UserNotFoundForApiKeyError(Exception):
    def __init__(self, user_id: int):
        self.user_id = user_id
        super().__init__(f"User {user_id} not found")


async def generate_user_api_key(session: AsyncSession, user_id: int) -> str:
    """Issue a new API key for the user, replacing any existing one. Returns the plaintext key.

    Mirrors aceapi.auth.set_user_api_key: the sha256 is what authentication matches on, and an
    encrypted copy is kept so the key can be shown to its owner again later.
    """
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise UserNotFoundForApiKeyError(user_id)

    api_key = str(uuid.uuid4())
    user.apikey_hash = sha256_str(api_key)
    user.apikey_encrypted = encrypt_chunk(api_key.encode(errors="ignore"))
    await session.flush()
    return api_key


async def get_own_api_key(session: AsyncSession, user_id: int) -> str | None:
    """Decrypt and return a user's own API key, or None if they have none.

    Callers MUST pass the authenticated user's own id -- this returns a credential in plaintext and
    performs no permission check of its own.
    """
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise UserNotFoundForApiKeyError(user_id)
    return user.apikey_decrypted


async def revoke_user_api_key(session: AsyncSession, user_id: int) -> bool:
    """Destroy the user's API key. Returns False if the user had no key. This is not reversible."""
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise UserNotFoundForApiKeyError(user_id)

    if user.apikey_hash is None and user.apikey_encrypted is None:
        return False

    user.apikey_hash = None
    user.apikey_encrypted = None
    await session.flush()
    return True
