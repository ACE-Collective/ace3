"""svs validate permission catalog

Data-only migration (no schema change): requesting a YARA validation (docs/SVS_VALIDATION.md) needs
svs:validate, the permission of the signature repository's CI key. This seeds the catalog
read-model entry; the grant tables are untouched, so no one's access changes.

Revision ID: d5a0a9150ff2
Revises: d27ca425ddcd
Create Date: 2026-10-11 13:23:53.723167

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5a0a9150ff2'
down_revision: Union[str, None] = 'd27ca425ddcd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new static svs: entries in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("svs", "validate", "Request SVS YARA validations of a rule repository's commits and read their status (counts, rule names and uuids only; the CI key's permission)."),
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
