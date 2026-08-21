"""add engine permissions, migrate lock:delete grants

Data-only migration (no schema change).

Background: the /api/engine/ endpoints are ACE's machine-to-machine node-to-node surface, but each
was gated on a permission borrowed from an unrelated major -- download on alert:read, upload on
alert:create, clear on lock:delete. When the automation config API key gained an enforced scope, the
scope was written from a hand-maintained comment that listed only alert:create, so every cross-node
work transfer 403'd. Giving the surface its own `engine` major makes the required scope a single
`engine:*` entry that a test can derive from the routes instead of restating.

This migration:

1. Seeds the three new engine:* rows into auth_permission_catalog and removes the now-unused
   lock:delete row. The catalog table is a derived read-model of
   saq/permissions/catalog.py::PERMISSION_CATALOG (see sync_permission_catalog); these statements
   keep it in step for deployments that do not run `ace perm catalog sync`.

2. Rewrites lock:delete grants to engine:clear in both grant tables, for both effects. Following
   f1a2b3c4d5e6: because the model is default-deny, renaming the decorator without rewriting the
   rows would silently strip access from any deployment holding lock:delete grants. This is an
   exact 1:1 mapping -- lock:delete had precisely one enforcement site,
   GET /api/engine/clear/<uuid>/<lock_uuid>.

3. Deliberately does NOT rewrite alert:read grants to engine:download. That pair is a *narrowing*,
   not a rename: alert:read covers the whole /api/analysis/ read surface, while
   GET /api/engine/download/<uuid> returns a tar of an entire storage directory and is machine-only.
   Human users who held alert:read losing the ability to call it is the intended tightening, not an
   oversight. The automation key keeps working because its scope grants engine:*.

Revision ID: 69a4820ec468
Revises: 3c0e5d7a54f1
Create Date: 2026-08-20 16:50:47.126932

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '69a4820ec468'
down_revision: Union[str, None] = '3c0e5d7a54f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Snapshot of the entries added to saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_NEW_CATALOG = [
    ("engine", "clear", "Clear a transferred work item's stale copy on a remote node (node-to-node)."),
    ("engine", "download", "Download a work item's storage directory from a node (node-to-node)."),
    ("engine", "upload", "Upload a work item's storage directory to a node (node-to-node)."),
]

_GRANT_TABLES = (
    ("auth_user_permission", "user_id"),
    ("auth_group_permission", "group_id"),
)


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Seed the new engine:* catalog rows (idempotent upsert on the u_perm unique key).
    upsert = sa.text(
        "INSERT INTO auth_permission_catalog (major, minor, description) "
        "VALUES (:major, :minor, :description) "
        "ON DUPLICATE KEY UPDATE description = VALUES(description)"
    )
    for major, minor, description in _NEW_CATALOG:
        bind.execute(upsert, {"major": major, "minor": minor, "description": description})

    # 2. Rewrite lock:delete grants to engine:clear, both effects.
    for table, subject_col in _GRANT_TABLES:
        # Drop lock:delete rows that would collide with an existing same-effect engine:clear row.
        bind.execute(sa.text(
            f"DELETE l FROM {table} l "
            f"JOIN {table} e "
            f"  ON e.{subject_col} = l.{subject_col} "
            f" AND e.major = 'engine' AND e.minor = 'clear' "
            f" AND e.effect = l.effect "
            f"WHERE l.major = 'lock' AND l.minor = 'delete'"
        ))
        # Rename the survivors.
        bind.execute(sa.text(
            f"UPDATE {table} SET major = 'engine', minor = 'clear' "
            f"WHERE major = 'lock' AND minor = 'delete'"
        ))

    # 3. lock:delete now has no enforcement site; drop it from the catalog read-model.
    bind.execute(sa.text(
        "DELETE FROM auth_permission_catalog WHERE major = 'lock' AND minor = 'delete'"
    ))


def downgrade() -> None:
    bind = op.get_bind()

    # Restore the lock:delete catalog row.
    bind.execute(sa.text(
        "INSERT INTO auth_permission_catalog (major, minor, description) "
        "VALUES ('lock', 'delete', 'Clear processing locks on alerts or resources.') "
        "ON DUPLICATE KEY UPDATE description = VALUES(description)"
    ))

    # Rename engine:clear grants back to lock:delete. engine:download and engine:upload grants are
    # left alone: upgrade() never created any (it only renamed lock:delete), so anything holding
    # them was granted deliberately after the upgrade and is not ours to revoke.
    for table, subject_col in _GRANT_TABLES:
        bind.execute(sa.text(
            f"DELETE e FROM {table} e "
            f"JOIN {table} l "
            f"  ON l.{subject_col} = e.{subject_col} "
            f" AND l.major = 'lock' AND l.minor = 'delete' "
            f" AND l.effect = e.effect "
            f"WHERE e.major = 'engine' AND e.minor = 'clear'"
        ))
        bind.execute(sa.text(
            f"UPDATE {table} SET major = 'lock', minor = 'delete' "
            f"WHERE major = 'engine' AND minor = 'clear'"
        ))

    # Drop every engine:* catalog row this revision introduced, so downgrade leaves the read-model
    # exactly as it found it.
    bind.execute(sa.text(
        "DELETE FROM auth_permission_catalog WHERE major = 'engine'"
    ))
