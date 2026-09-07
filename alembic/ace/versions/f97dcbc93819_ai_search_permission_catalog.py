"""ai search permission catalog

Data-only migration (no schema change): the AI investigation API gained alert search
(POST /ai/v1/search/alerts and /search/similar), gated on its own ai:search permission so an AI
key never needs alert:read on the main app. This seeds the catalog read-model entry; the grant
tables are untouched, so no one's access changes.

Revision ID: f97dcbc93819
Revises: decc3390927c
Create Date: 2026-09-04 14:28:21.444853

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f97dcbc93819'
down_revision: Union[str, None] = 'decc3390927c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new static ai: entry in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("ai", "search", "Search alerts (exact indicator/tag matches plus semantic matches) and find similar alerts via the AI investigation API."),
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
