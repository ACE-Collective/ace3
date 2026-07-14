"""drop external_remediation_check_history table

Revision ID: 1524a2e6bf28
Revises: 418783a10fa4
Create Date: 2026-07-14 15:01:22.852213

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '1524a2e6bf28'
down_revision: Union[str, None] = '418783a10fa4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The external_remediation_check_history table was a write-only per-attempt
    # audit log that nothing ever read; drop it. The parent
    # external_remediation_check table (which the alert Remediation Timeline reads
    # via events_json) is left intact. Dropping the table drops its indexes.
    op.drop_table('external_remediation_check_history')


def downgrade() -> None:
    op.create_table('external_remediation_check_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('check_id', sa.Integer(), nullable=False),
    sa.Column('insert_date', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('result', sa.Enum('CONFIRMED', 'NOT_FOUND', 'EXPIRED', 'ERROR', 'CANCELLED', 'PENDING'), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('NEW', 'IN_PROGRESS', 'COMPLETED'), nullable=False),
    sa.ForeignKeyConstraint(['check_id'], ['external_remediation_check.id'], onupdate='CASCADE', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_external_remediation_check_history_check_id'), 'external_remediation_check_history', ['check_id'], unique=False)
    op.create_index(op.f('ix_external_remediation_check_history_insert_date'), 'external_remediation_check_history', ['insert_date'], unique=False)
