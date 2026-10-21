"""cli permission catalog

Data-only migration (no schema change): running ACE CLI commands from the GUI (docs/GUI_CLI.md)
needs cli:execute (the user) and engine:cli (the node-to-node call that starts the run on the
target node, covered by the automation key's engine:* scope). This seeds the catalog read-model
entries; the grant tables are untouched, so no one's access changes.

Revision ID: d57fc644f8d5
Revises: 1f6fb570aaf0
Create Date: 2026-10-20 18:43:10.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd57fc644f8d5'
down_revision: Union[str, None] = '1f6fb570aaf0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new entries in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("cli", "execute", "Run ACE CLI commands on any node from the GUI (Admin -> CLI) and read every recorded run and its output."),
    ("engine", "cli", "Run a CLI command that a user with cli:execute recorded for this node (node-to-node)."),
]

_UPSERT = sa.text(
    "INSERT INTO auth_permission_catalog (major, minor, description) "
    "VALUES (:major, :minor, :description) "
    "ON DUPLICATE KEY UPDATE description = VALUES(description)"
)


def upgrade() -> None:
    bind = op.get_bind()
    for major, minor, description in _CATALOG:
        bind.execute(_UPSERT, {"major": major, "minor": minor, "description": description})


def downgrade() -> None:
    bind = op.get_bind()
    for major, minor, _ in _CATALOG:
        bind.execute(sa.text(
            "DELETE FROM auth_permission_catalog WHERE major = :major AND minor = :minor"),
            {"major": major, "minor": minor})
