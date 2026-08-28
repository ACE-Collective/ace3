"""add alerts.version

Revision ID: b2e9c137a93c
Revises: 3fc96f75fb59
Create Date: 2026-08-28 11:19:28.435779

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b2e9c137a93c'
down_revision: str | None = '3fc96f75fb59'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('alerts', sa.Column('version', sa.String(length=36), nullable=False))
    # existing rows get an initial version; new rows get one from the ORM default.
    # (a DEFAULT (UUID()) on the column is not an option: MySQL rejects it as
    # replication-unsafe DDL under binlog + GTID. this UPDATE is row-logged and fine.)
    op.execute("UPDATE alerts SET version = UUID()")


def downgrade() -> None:
    op.drop_column('alerts', 'version')
