"""user self permission catalog

Data-only migration (no schema change): user:self lets a user create, edit and revoke their own
scoped API keys from the Preferences page, limited to permissions they already hold
(docs/USER_PREFERENCES.md). This seeds the catalog read-model entry; the grant tables are
untouched, so no one's access changes beyond what an existing wildcard grant already matches.

Revision ID: 782f52ae593a
Revises: d57fc644f8d5
Create Date: 2026-10-21 20:54:52.071356

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '782f52ae593a'
down_revision: Union[str, None] = 'd57fc644f8d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new entry in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("user", "self", "Create, edit and revoke your own scoped API keys, limited to permissions you already hold."),
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
