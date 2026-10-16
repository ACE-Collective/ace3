"""remediation write permission catalog

Data-only migration (no schema change): queueing, stopping and clearing remediations (the alert
pages' remediation dialog through /api/v2/remediation, and the Remediations page's writes) require
remediation:write, which separates them from remediation:read. This seeds the catalog read-model
entry. The grant tables are deliberately untouched: like engine:download in 69a4820ec468 this is a
narrowing, not a rename, so a principal holding only remediation:read becomes read-only, while
*:* and remediation:* grants already cover the new pair.

Revision ID: f26a884b17f3
Revises: d5a0a9150ff2
Create Date: 2026-10-15 16:21:32.757750

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f26a884b17f3'
down_revision: Union[str, None] = 'd5a0a9150ff2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new remediation: entry in saq/permissions/catalog.py::PERMISSION_CATALOG at this revision.
_CATALOG = [
    ("remediation", "write", "Queue, stop and clear remediations: the alert pages' remediation dialog and the Remediations page."),
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
