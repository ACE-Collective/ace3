"""ai export permission catalog

Data-only migration (no schema change): the AI investigation API gained a bulk export of alerts and
observables (GET /ai/v1/export/alerts and POST /export/observables), gated on its own ai:export
permission because it reads every observable value ACE has seen. This seeds the catalog
read-model entry; the grant tables are untouched, so no one's access changes.

Revision ID: efcd01617ee8
Revises: 4ba5a47774b4
Create Date: 2026-10-10 22:41:09.184944

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'efcd01617ee8'
down_revision: Union[str, None] = '4ba5a47774b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new static ai: entry in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("ai", "export", "Bulk-export every alert's database state, observable ids, detections and events, and the observable values themselves, via the AI investigation API."),
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
