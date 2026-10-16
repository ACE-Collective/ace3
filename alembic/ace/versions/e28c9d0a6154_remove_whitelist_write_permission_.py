"""remove whitelist write permission catalog

Data-only migration (no schema change): the alert page's Whitelist and Un-Whitelist observable
actions were deleted, and with them the only check of whitelist:write. This removes its catalog
read-model entry (saq/permissions/catalog.py no longer lists it). Grants of whitelist:write are left
alone: nothing checks the pair any more, so they grant nothing, and deleting them could not be
undone.

Revision ID: e28c9d0a6154
Revises: 434f3139d204
Create Date: 2026-10-15 17:58:51.190173

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e28c9d0a6154'
down_revision: Union[str, None] = '434f3139d204'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the removed entry, for downgrade.
_CATALOG = [
    ("whitelist", "write", "Whitelist observables."),
]


def upgrade() -> None:
    bind = op.get_bind()

    for major, minor, _ in _CATALOG:
        bind.execute(sa.text(
            "DELETE FROM auth_permission_catalog WHERE major = :major AND minor = :minor"),
            {"major": major, "minor": minor})


def downgrade() -> None:
    bind = op.get_bind()

    upsert = sa.text(
        "INSERT INTO auth_permission_catalog (major, minor, description) "
        "VALUES (:major, :minor, :description) "
        "ON DUPLICATE KEY UPDATE description = VALUES(description)"
    )
    for major, minor, description in _CATALOG:
        bind.execute(upsert, {"major": major, "minor": minor, "description": description})
