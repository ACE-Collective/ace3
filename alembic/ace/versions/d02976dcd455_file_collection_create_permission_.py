"""file collection create permission catalog

Data-only migration (no schema change): requesting a file collection through the API needs
file_collection:create. This seeds the catalog read-model entry; no grants are copied, so only *:*
and file_collection:* holders have it until someone grants it.

Revision ID: d02976dcd455
Revises: bf31365b177f
Create Date: 2026-10-26 23:05:18.592251

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd02976dcd455'
down_revision: Union[str, None] = 'bf31365b177f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new file_collection: entry in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("file_collection", "create", "Request file collections from hosts through the API; a collector may run a script on the host to produce the file."),
]


def upgrade() -> None:
    bind = op.get_bind()

    upsert = sa.text(
        "INSERT INTO auth_permission_catalog (major, minor, description) "
        "VALUES (:major, :minor, :description) "
        "ON DUPLICATE KEY UPDATE description = VALUES(description)"
    )
    for major, minor, description in _CATALOG:
        bind.execute(upsert, {"major": major, "minor": minor, "description": description})


def downgrade() -> None:
    bind = op.get_bind()

    for major, minor, _ in _CATALOG:
        bind.execute(sa.text(
            "DELETE FROM auth_permission_catalog WHERE major = :major AND minor = :minor"),
            {"major": major, "minor": minor})
