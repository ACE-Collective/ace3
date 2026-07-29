"""add work_distribution attempt_count and delivery indexes

Revision ID: ebd578f0f7a0
Revises: c9e3f70a15d2
Create Date: 2026-07-29 11:49:40.997134

Bounds delivery retries so a work item that keeps failing cannot stall a collection group
forever, and adds the two indexes the delivery loop queries on every pass.

NOTE autogenerate also emits a drop/create for idx_erc_collector_loop and
idx_file_collection_collector_loop. Those are declared with desc('insert_date'), which alembic
cannot round-trip against the reflected MySQL schema, so they show up as spurious drift on every
autogenerate run. They are unrelated to this change and have been removed from this migration.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ebd578f0f7a0'
down_revision: Union[str, None] = 'c9e3f70a15d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'work_distribution',
        sa.Column('attempt_count', sa.Integer(), server_default=sa.text('0'), nullable=False))
    op.create_index(
        'idx_wd_group_status', 'work_distribution', ['group_id', 'status'], unique=False)
    op.create_index(
        'idx_wd_lock_uuid_status', 'work_distribution', ['lock_uuid', 'status'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_wd_lock_uuid_status', table_name='work_distribution')
    op.drop_index('idx_wd_group_status', table_name='work_distribution')
    op.drop_column('work_distribution', 'attempt_count')
