"""seed permission catalog and normalize user:edit -> user:write

Data-only migration (the auth_permission_catalog table already exists):

1. Seeds/updates auth_permission_catalog from the authoritative catalog snapshot below so the
   management UI has a canonical list of permissions to render. Uses ON DUPLICATE KEY UPDATE, so it
   is idempotent and refreshes descriptions without creating duplicates.

2. Normalizes the historical `user:edit` permission to the canonical `user:write` in both grant
   tables (auth_user_permission, auth_group_permission), for both ALLOW and DENY effects. Because
   the model is default-deny, simply renaming the decorators would silently strip access from any
   deployment holding `user:edit` grants, so those rows must be rewritten. Duplicate `edit` rows
   (where a same-effect `write` row already exists) are deleted first to avoid violating the
   (subject, major, minor, effect) unique constraint, then the survivors are renamed.

The catalog values here are a point-in-time snapshot; new permissions added to
saq/permissions/catalog.py later get their own migration (or `ace perm catalog sync` in dev).

Revision ID: f1a2b3c4d5e6
Revises: 418783a10fa4
Create Date: 2026-07-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, None] = '418783a10fa4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("admin", "read", "Access the administration area (individual actions require their own permissions)."),
    ("system", "read", "Read system metadata and supported types via API."),
    ("email", "read", "Read archived email content via API/GUI."),
    ("alert", "create", "Create new alerts or upload alert data via API/GUI."),
    ("alert", "read", "Read alert data, submissions, status, and files via API/GUI."),
    ("alert", "write", "Modify alerts (disposition, tags, ownership, comments)."),
    ("lock", "delete", "Clear processing locks on alerts or resources."),
    ("file_collection", "read", "Read file collection requests and history."),
    ("remediation", "read", "View remediation actions and history."),
    ("event", "read", "View events, details, and export event data."),
    ("event", "write", "Create and modify events."),
    ("observable", "read", "Query observables via the API."),
    ("observable", "write", "Modify observables and run observable actions."),
    ("whitelist", "write", "Whitelist observables."),
    ("user", "read", "View users, groups, and their permissions."),
    ("user", "write", "Create/modify users, groups, memberships, and permission grants."),
    ("node", "read", "Read node status and outstanding work counts via API."),
    ("node", "manage", "Drain and resume nodes via API."),
    ("detection", "read", "View observable-detection settings."),
    ("detection", "write", "Modify observable-detection settings."),
]


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Seed/refresh the permission catalog (idempotent upsert on the u_perm unique key).
    upsert = sa.text(
        "INSERT INTO auth_permission_catalog (major, minor, description) "
        "VALUES (:major, :minor, :description) "
        "ON DUPLICATE KEY UPDATE description = VALUES(description)"
    )
    for major, minor, description in _CATALOG:
        bind.execute(upsert, {"major": major, "minor": minor, "description": description})

    # 2. Normalize user:edit -> user:write in both grant tables, both effects.
    for table, subject_col in (("auth_user_permission", "user_id"), ("auth_group_permission", "group_id")):
        # Delete `edit` rows that would collide with an existing same-effect `write` row.
        bind.execute(sa.text(
            f"DELETE e FROM {table} e "
            f"JOIN {table} w "
            f"  ON w.{subject_col} = e.{subject_col} "
            f" AND w.major = 'user' AND w.minor = 'write' "
            f" AND w.effect = e.effect "
            f"WHERE e.major = 'user' AND e.minor = 'edit'"
        ))
        # Rename the survivors.
        bind.execute(sa.text(
            f"UPDATE {table} SET minor = 'write' "
            f"WHERE major = 'user' AND minor = 'edit'"
        ))


def downgrade() -> None:
    # Normalization is one-way (the merge loses which grants were originally `edit`), and the
    # catalog is reference data, so downgrade is a no-op.
    pass
