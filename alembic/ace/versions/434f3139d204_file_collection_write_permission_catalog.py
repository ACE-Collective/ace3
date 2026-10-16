"""file collection write permission catalog

Data-only migration (no schema change): stopping, retrying and deleting file collection requests
(the File Collections page, through /api/v2/file-collections) require file_collection:write,
where file_collection:read used to cover them. This seeds the catalog read-model entry. The grant
tables are deliberately untouched, as for remediation:write in f26a884b17f3: a principal holding
only file_collection:read becomes read-only, while *:* and file_collection:* grants already cover
the new pair.

Revision ID: 434f3139d204
Revises: f26a884b17f3
Create Date: 2026-10-15 17:12:00.206221

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '434f3139d204'
down_revision: Union[str, None] = 'f26a884b17f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new file_collection: entry in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("file_collection", "write", "Stop, retry and delete file collection requests on the File Collections page."),
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
