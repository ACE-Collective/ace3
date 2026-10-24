from typing import Optional

from saq.database.model import AuthGroupPermission, AuthUserPermission, AuthGroupUser
from saq.database.pool import get_db
from saq.permissions.constants import ALLOW, DENY
from fnmatch import fnmatchcase

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def _pattern_matches(pattern_major: str, pattern_minor: str, major: str, minor: str) -> bool:
    """fnmatch a stored (major, minor) pattern against a requested permission, ignoring case. Case
    means nothing in a permission: the grant tables' unique indexes treat case variants as one row
    and new rows are stored lowercase, but older rows and config key scopes can be in any case."""
    return (fnmatchcase(major.lower(), pattern_major.lower())
            and fnmatchcase(minor.lower(), pattern_minor.lower()))


def _evaluate_permission(user_perms, group_perms, major: str, minor: str) -> bool:
    """Apply fnmatch over the fetched (major, minor, effect) rows. DENY overrides ALLOW."""
    matched_effects = [
        effect for (p_major, p_minor, effect) in user_perms if _pattern_matches(p_major, p_minor, major, minor)
    ] + [
        effect for (p_major, p_minor, effect) in group_perms if _pattern_matches(p_major, p_minor, major, minor)
    ]

    if not matched_effects:
        return False

    if DENY in matched_effects:
        return False

    return ALLOW in matched_effects


def parse_permission_pattern(spec: str) -> tuple[str, str]:
    """Parse a ``"major:minor"`` scope spec into a ``(major, minor)`` tuple. A bare ``"major"``
    defaults the minor to ``"*"`` (the same convention as the ``ace perm`` CLI)."""
    major, _, minor = spec.partition(":")
    return (major.strip(), (minor.strip() or "*"))


def match_config_api_key(auth_sha256: str) -> Optional[tuple[str, Optional[list[tuple[str, str]]]]]:
    """Match a presented key hash against the config ``[apikeys]`` block.

    Returns ``(name, scope)`` on a match, else ``None``. ``scope`` is a list of ``(major, minor)``
    ALLOW patterns for a structured entry, or ``None`` for a legacy bare-string entry.

    A bare-string entry is the pre-refactor form that carried no scope and bypassed permission
    checks entirely. It is still honoured (so deployment overlays keep working) but is deprecated;
    the loud warning is emitted once at config validation, not here.
    """
    # imported lazily: saq.configuration must not import the permissions layer at module load
    from saq.configuration import get_config

    apikeys = get_config().apikeys or {}
    presented = auth_sha256.lower()
    for name, entry in apikeys.items():
        if isinstance(entry, str):
            value, scope = entry, None
        else:
            value = entry.key
            scope = [parse_permission_pattern(s) for s in (entry.scope or [])]
        if value is not None and presented == value.strip().lower():
            return (name, scope)

    return None


def key_scope_allows(scope: list[tuple[str, str]], major: str, minor: str) -> bool:
    """True if an API key's scope permits the requested permission.

    ``scope`` is a positive, ALLOW-only allowlist of ``(major, minor)`` fnmatch patterns (same
    pattern direction as the grant tables: the stored row is the pattern, the request is the value).
    An empty scope allows nothing.

    This is a pure narrowing filter applied on TOP of ``user_has_permission``: the effective
    decision is ``user_has_permission(...) AND key_scope_allows(...)``, so a key can never reach
    anything the owner's own permissions (including group DENY) do not already allow. A key whose
    scope is ``None`` inherits the owner's full permissions; callers skip this check when scope is
    ``None``.
    """
    return any(_pattern_matches(p_major, p_minor, major, minor) for (p_major, p_minor) in scope)


def user_has_permission(
    user_id: int,
    major: str,
    minor: str,
) -> bool:
    """Check if a user has a specific permission. DENY overrides ALLOW."""
    session = get_db()

    # Fetch all user permissions and filter via fnmatch (pattern in DB, value is requested)
    user_perms = (
        session.query(
            AuthUserPermission.major,
            AuthUserPermission.minor,
            AuthUserPermission.effect,
        )
        .filter(AuthUserPermission.user_id == user_id)
        .all()
    )

    # Group permissions
    group_ids = [
        r.group_id
        for r in session.query(AuthGroupUser.group_id).filter(AuthGroupUser.user_id == user_id).all()
    ]

    group_perms = []
    if group_ids:
        group_perms = (
            session.query(
                AuthGroupPermission.major,
                AuthGroupPermission.minor,
                AuthGroupPermission.effect,
            )
            .filter(AuthGroupPermission.group_id.in_(group_ids))
            .all()
        )

    return _evaluate_permission(user_perms, group_perms, major, minor)


def held_catalog_pairs(user_perms, group_perms, catalog_pairs) -> frozenset[tuple[str, str]]:
    """The catalog pairs the fetched rows allow: what the user actually holds, as concrete pairs
    rather than the wildcard patterns they were granted as."""
    return frozenset(
        pair for pair in catalog_pairs if _evaluate_permission(user_perms, group_perms, *pair)
    )


async def user_has_permission_async(
    session: AsyncSession,
    user_id: int,
    major: str,
    minor: str,
) -> bool:
    """Async equivalent of user_has_permission() using an AsyncSession."""
    user_perms, group_perms = await get_permission_rows_async(session, user_id)
    return _evaluate_permission(user_perms, group_perms, major, minor)


async def get_permission_rows_async(session: AsyncSession, user_id: int) -> tuple[list, list]:
    """A user's own and group (major, minor, effect) grant rows, fetched once so that many
    permissions can be evaluated against them without another query each."""
    # Fetch all user permissions and filter via fnmatch (pattern in DB, value is requested)
    user_perms = (
        await session.execute(
            select(
                AuthUserPermission.major,
                AuthUserPermission.minor,
                AuthUserPermission.effect,
            ).where(AuthUserPermission.user_id == user_id)
        )
    ).all()

    # Group permissions
    group_ids = [
        r.group_id
        for r in (
            await session.execute(
                select(AuthGroupUser.group_id).where(AuthGroupUser.user_id == user_id)
            )
        ).all()
    ]

    group_perms = []
    if group_ids:
        group_perms = (
            await session.execute(
                select(
                    AuthGroupPermission.major,
                    AuthGroupPermission.minor,
                    AuthGroupPermission.effect,
                ).where(AuthGroupPermission.group_id.in_(group_ids))
            )
        ).all()

    return list(user_perms), list(group_perms)
