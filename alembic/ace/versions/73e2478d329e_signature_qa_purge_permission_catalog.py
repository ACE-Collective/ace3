"""signature qa_purge permission catalog

Data-only migration (no schema change): purging the files stored for YARA rules in QA mode
(docs/YARA_QA.md) needs signature:qa_purge. This seeds the catalog read-model entry; the grant
tables are untouched, so no one's access changes.

Revision ID: 73e2478d329e
Revises: 86290b564888
Create Date: 2026-11-03 20:26:01.885604

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '73e2478d329e'
down_revision: Union[str, None] = '86290b564888'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new static signature: entry in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("signature", "qa_purge", "Purge the files stored for YARA rules in QA mode: a rule's versions, or chosen files (audited). Touches only the YARA QA store."),
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
