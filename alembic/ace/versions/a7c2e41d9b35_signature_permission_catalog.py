"""signature permission catalog

Data-only migration (no schema change): the Signatures GUI area and the YARA QA results API
(docs/YARA_QA.md) add two permissions, signature:read (the area, rules in QA mode, match counts and
match records) and signature:download (the matched files themselves). This seeds the catalog
read-model entries; the grant tables are untouched, so no one's access changes.

Revision ID: a7c2e41d9b35
Revises: d3f648d96551
Create Date: 2026-09-30 15:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7c2e41d9b35'
down_revision: Union[str, None] = 'd3f648d96551'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new static signature: entries in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("signature", "download", "Download the files matched by YARA rules in QA mode (live malware, in zips protected with the password infected)."),
    ("signature", "read", "Access the Signatures area and read YARA QA results: rules in QA mode, match counts and match records."),
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
