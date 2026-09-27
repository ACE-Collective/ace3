"""cas permission catalog

Data-only migration (no schema change): the content-addressed storage subsystem (docs/CAS.md) adds
two permissions, cas:hold (legal holds) and cas:purge (forced deletion across holds, audited in
cas_purges). This seeds the catalog read-model entries; the grant tables are untouched, so no one's
access changes. Nothing enforces them in-repo yet (`ace cas hold|purge` record --actor without
checking); the entries exist so an API surface can enforce them without a catalog migration.

Revision ID: 61b26390b94e
Revises: 56cafaed6b55
Create Date: 2026-09-27 17:00:06.842515

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '61b26390b94e'
down_revision: Union[str, None] = '56cafaed6b55'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new static cas: entries in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("cas", "hold", "Place and release legal holds on content-addressed storage objects (docs/CAS.md); an object under legal hold cannot be purged."),
    ("cas", "purge", "Force-delete a content-addressed storage object across its holds; audited in cas_purges."),
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
