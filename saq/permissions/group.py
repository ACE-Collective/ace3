from dataclasses import dataclass
from typing import Optional
from saq.database.model import AuthGroup, AuthGroupPermission, AuthGroupUser
from saq.database.pool import get_db


def create_auth_group(name: str) -> AuthGroup:
    """Create a new auth group (idempotent). Returns the group."""
    session = get_db()
    existing = session.query(AuthGroup).filter(AuthGroup.name == name).one_or_none()
    if existing:
        return existing
    group = AuthGroup(name=name)
    session.add(group)
    session.commit()
    session.refresh(group)
    return group


def delete_auth_group(group_id: int) -> bool:
    """Delete an existing auth group by id. Returns True if deleted."""
    session = get_db()
    deleted = session.execute(
        AuthGroup.__table__.delete().where(AuthGroup.id == group_id)
    ).rowcount
    session.commit()
    return bool(deleted)


def add_user_to_auth_group(user_id: int, group_id: int) -> bool:
    """Add a user to an auth group (idempotent). Returns True if added or already present."""
    session = get_db()
    existing = (
        session.query(AuthGroupUser)
        .filter(
            AuthGroupUser.user_id == user_id,
            AuthGroupUser.group_id == group_id,
        )
        .one_or_none()
    )
    if existing:
        return True

    mapping = AuthGroupUser(user_id=user_id, group_id=group_id)
    session.add(mapping)
    session.commit()
    return True


def delete_user_from_auth_group(user_id: int, group_id: int) -> bool:
    """Remove a user from an auth group. Returns True if a row was deleted."""
    session = get_db()
    deleted = (
        session.query(AuthGroupUser)
        .filter(
            AuthGroupUser.user_id == user_id,
            AuthGroupUser.group_id == group_id,
        )
        .delete(synchronize_session=False)
    )
    session.commit()
    return bool(deleted)

def add_group_permission(
    group_id: int,
    major: str,
    minor: str,
    effect: str = 'ALLOW',
    created_by: Optional[int] = None,
) -> AuthGroupPermission:
    """Grant a permission to an auth group (idempotent on (group, major, minor, effect))."""
    session = get_db()
    effect = effect.upper()
    existing = (
        session.query(AuthGroupPermission)
        .filter(
            AuthGroupPermission.group_id == group_id,
            AuthGroupPermission.major == major,
            AuthGroupPermission.minor == minor,
            AuthGroupPermission.effect == effect,
        )
        .one_or_none()
    )
    
    if existing:
        return existing

    perm = AuthGroupPermission(
        group_id=group_id,
        major=major,
        minor=minor,
        effect=effect,
        created_by=created_by,
    )

    session.add(perm)
    session.commit()
    session.refresh(perm)
    return perm


def delete_group_permission(
    permission_id: Optional[int] = None,
    *,
    group_id: Optional[int] = None,
    major: Optional[str] = None,
    minor: Optional[str] = None,
    effect: Optional[str] = None,
) -> int:
    """Revoke group permission(s). Returns number of rows deleted.

    Provide either permission_id or a filter on (group_id, major, minor[, company_id, effect]).
    """
    session = get_db()
    query = session.query(AuthGroupPermission)
    if permission_id is not None:
        query = query.filter(AuthGroupPermission.id == permission_id)
    else:
        if group_id is None or major is None or minor is None:
            raise ValueError('group_id, major and minor are required when permission_id is not provided')

        query = query.filter(
            AuthGroupPermission.group_id == group_id,
            AuthGroupPermission.major == major,
            AuthGroupPermission.minor == minor,
        )

        if effect is not None:
            query = query.filter(AuthGroupPermission.effect == effect.upper())

    deleted = query.delete(synchronize_session=False)
    session.commit()
    return deleted


@dataclass
class GroupPermission:
    id: int
    major: str
    minor: str
    effect: str


def get_group_permissions(group_id: int) -> list[GroupPermission]:
    """Return all permissions for an auth group as list of dicts."""
    session = get_db()
    results: list[GroupPermission] = []
    for permission in session.query(AuthGroupPermission).filter(AuthGroupPermission.group_id == group_id).all():
        results.append(
            GroupPermission(
                id=permission.id,
                major=permission.major,
                minor=permission.minor,
                effect=permission.effect,
            )
        )

    return results
