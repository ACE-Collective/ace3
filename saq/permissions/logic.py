from saq.database.model import AuthGroupPermission, AuthUserPermission, AuthGroupUser
from saq.database.pool import get_db
from saq.permissions.constants import ALLOW, DENY
from fnmatch import fnmatchcase


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

    # Apply fnmatch: stored patterns (major/minor) against requested values
    def matches(pattern_major: str, pattern_minor: str) -> bool:
        return fnmatchcase(major, pattern_major) and fnmatchcase(minor, pattern_minor)

    matched_effects = [
        effect for (p_major, p_minor, effect) in user_perms if matches(p_major, p_minor)
    ] + [
        effect for (p_major, p_minor, effect) in group_perms if matches(p_major, p_minor)
    ]

    # Evaluate effects where DENY overrides ALLOW among matched entries
    effects = matched_effects

    if not effects:
        return False

    if DENY in effects:
        return False

    return ALLOW in effects