"""add node_id column to locks

Revision ID: 418783a10fa4
Revises: 44a496c21410
Create Date: 2026-07-07 16:10:12.799006

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '418783a10fa4'
down_revision: Union[str, None] = '44a496c21410'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('locks', sa.Column('node_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_locks_node_id'), 'locks', ['node_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_locks_node_id'), table_name='locks')
    op.drop_column('locks', 'node_id')
