
# User permission management

from dataclasses import dataclass
from typing import Optional

from saq.database.model import AuthGroup, AuthGroupPermission, AuthGroupUser, AuthUserPermission
from saq.database.pool import get_db


def add_user_permission(
    user_id: int,
    major: str,
    minor: str,
    effect: str = 'ALLOW',
    created_by: Optional[int] = None,
) -> AuthUserPermission:
    """Grant a permission to a user (idempotent on (user, major, minor, effect))."""
    session = get_db()
    effect = effect.upper()
    existing = (
        session.query(AuthUserPermission)
        .filter(
            AuthUserPermission.user_id == user_id,
            AuthUserPermission.major == major,
            AuthUserPermission.minor == minor,
            AuthUserPermission.effect == effect,
        )
        .one_or_none()
    )
    if existing:
        return existing

    perm = AuthUserPermission(
        user_id=user_id,
        major=major,
        minor=minor,
        effect=effect,
        created_by=created_by,
    )

    session.add(perm)
    session.commit()
    session.refresh(perm)
    return perm


def delete_user_permission(
    user_id: int,
    permission_id: int
) -> bool:
    """Revoke user permission(s). Returns number of rows deleted.

    Args:
        user_id: The ID of the user to delete the permission for.
        permission_id: The ID of the permission to delete.

    Returns:
        True if the permission was deleted, False if it was not found.
    """
    session = get_db()
    query = session.query(AuthUserPermission)
    query = query.filter(AuthUserPermission.id == permission_id)
    query = query.filter(AuthUserPermission.user_id == user_id)
    deleted = query.delete(synchronize_session=False)
    session.commit()
    return deleted == 1

@dataclass
class UserPermission:
    id: int
    major: str
    minor: str
    effect: str
    source: str  # 'user' or 'group'
    group_id: Optional[int] = None


def get_user_permissions(user_id: int, include_groups: bool = True) -> list[UserPermission]:
    """Return all permissions for a user.

    When include_groups is True, includes permissions inherited via auth groups.
    Returns list of dicts: {'major', 'minor', 'effect', 'source', 'company_id', 'group_id'}
    """
    session = get_db()
    results: list[UserPermission] = []

    for permission in session.query(AuthUserPermission).filter(AuthUserPermission.user_id == user_id).all():
        results.append(
            UserPermission(
                id=permission.id,
                major=permission.major,
                minor=permission.minor,
                effect=permission.effect,
                source='user',
                group_id=None,
            )
        )

    if include_groups:
        group_ids = [
            r.group_id
            for r in session.query(AuthGroupUser.group_id).filter(AuthGroupUser.user_id == user_id).all()
        ]
        if group_ids:
            # Join AuthGroupPermission to AuthGroup to get the group name in one query
            for gp, group_name in (
                session.query(AuthGroupPermission, AuthGroup.name)
                .join(AuthGroup, AuthGroupPermission.group_id == AuthGroup.id)
                .filter(AuthGroupPermission.group_id.in_(group_ids))
                .all()
            ):
                results.append(
                    UserPermission(
                        id=gp.id,
                        major=gp.major,
                        minor=gp.minor,
                        effect=gp.effect,
                        source=f'group:{group_name}',
                        group_id=gp.group_id,
                    )
                )

    return results