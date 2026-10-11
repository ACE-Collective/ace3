"""svs admin permission catalog

Data-only migration (no schema change): the analyst actions on SVS samples (docs/SVS_SAMPLES.md,
*Actions*) add svs:admin, which retiring a sample for its rule and deleting a sample file require.
This seeds the catalog read-model entry; the grant tables are untouched, so no one's access changes.

Revision ID: b222aad71f7e
Revises: 703a55037596
Create Date: 2026-10-10 14:40:46.064454

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b222aad71f7e'
down_revision: Union[str, None] = '703a55037596'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new static svs: entries in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("svs", "admin", "Administer SVS: retire SVS YARA samples for a rule and delete sample files (their bytes are purged, audited)."),
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
