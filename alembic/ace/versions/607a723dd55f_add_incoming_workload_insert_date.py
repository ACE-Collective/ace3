"""add incoming_workload.insert_date

Records when a work item was handed to the collector so RemoteNodeGroup can report how
long each submission waited before it was delivered to a node.

Revision ID: 607a723dd55f
Revises: 1524a2e6bf28
Create Date: 2026-07-23 11:24:49.991235

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '607a723dd55f'
down_revision: Union[str, None] = '1524a2e6bf28'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('incoming_workload', sa.Column('insert_date', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False))
    op.create_index(op.f('ix_incoming_workload_insert_date'), 'incoming_workload', ['insert_date'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_incoming_workload_insert_date'), table_name='incoming_workload')
    op.drop_column('incoming_workload', 'insert_date')
