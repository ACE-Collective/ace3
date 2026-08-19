"""ai permission catalog per backend

Data-only migration (no schema change): the AI investigation API gates each query backend on its
own ai:<backend> permission plus ai:alert for alert download, replacing the single placeholder
ai:read entry that shipped with the authz refactor before any AI endpoint existed.

Only ai:alert is seeded here: the per-backend ai:<name> entries are derived from each deployment's
ai_query_backend_<name> config sections and reach the table through sync_permission_catalog (the
startup seed and `ace perm catalog sync`), so backend names -- including integration-provided
ones -- never appear in this open-source migration.

Only the catalog read-model is touched -- never the grant tables -- so no one's access changes.
No key was ever scoped to ai:read (the permission gated nothing), so no scope rewrite is needed.

Revision ID: ba6dccb596ce
Revises: 3c0e5d7a54f1
Create Date: 2026-08-07 12:29:32.860422

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'ba6dccb596ce'
down_revision: str | None = '3c0e5d7a54f1'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Snapshot of the static ai: entries in saq/permissions/catalog.py::PERMISSION_CATALOG at this
# revision (the per-backend entries are config-derived and not seeded by migration).
_AI_CATALOG = [
    ("ai", "alert", "Download alert packages via the AI investigation API."),
]


def upgrade() -> None:
    bind = op.get_bind()

    upsert = sa.text(
        "INSERT INTO auth_permission_catalog (major, minor, description) "
        "VALUES (:major, :minor, :description) "
        "ON DUPLICATE KEY UPDATE description = VALUES(description)"
    )
    for major, minor, description in _AI_CATALOG:
        bind.execute(upsert, {"major": major, "minor": minor, "description": description})

    bind.execute(sa.text(
        "DELETE FROM auth_permission_catalog WHERE major = 'ai' AND minor = 'read'"))


def downgrade() -> None:
    bind = op.get_bind()

    bind.execute(sa.text(
        "INSERT INTO auth_permission_catalog (major, minor, description) "
        "VALUES ('ai', 'read', 'Run read-only AI investigation queries against data sources via the AI API.') "
        "ON DUPLICATE KEY UPDATE description = VALUES(description)"))

    for major, minor, _ in _AI_CATALOG:
        bind.execute(sa.text(
            "DELETE FROM auth_permission_catalog WHERE major = :major AND minor = :minor"),
            {"major": major, "minor": minor})
