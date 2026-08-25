"""add saved_filters table

Backs the analyst-managed alert filter feature: named saved filters, the per-user
quick-filter badges, and the scratch rows ('working' / 'temp') that hold unsaved edits and
active pivots. Moving that state into the database is what lets the Flask session carry
only UUIDs instead of the multi-KB filter payload it used to keep in a cookie.

NOTE: autogenerate also proposed rewriting the idx_erc_collector_loop and
idx_file_collection_collector_loop indexes. That is pre-existing drift -- alembic renders
the DESC component of those composite indexes differently than the reflected schema
reports it -- and is unrelated to this change, so it is deliberately not included here.

Revision ID: 3fc96f75fb59
Revises: ba6dccb596ce
Create Date: 2026-08-25 15:45:43.737883

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3fc96f75fb59'
down_revision: str | None = 'ba6dccb596ce'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'saved_filters',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('uuid', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=16), server_default=sa.text("'named'"), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.Column('filters_json', sa.Text(), nullable=False),
        sa.Column('quick_filter_order', sa.Integer(), nullable=True),
        sa.Column('quick_filter_indicator', sa.Boolean(), server_default=sa.text('0'), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], onupdate='CASCADE', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'name', name='uq_saved_filter_user_name'),
        sa.UniqueConstraint('uuid'),
    )
    op.create_index('i_saved_filter_user_kind', 'saved_filters', ['user_id', 'kind'], unique=False)
    op.create_index('i_saved_filter_user_quick', 'saved_filters', ['user_id', 'quick_filter_order'], unique=False)


def downgrade() -> None:
    op.drop_index('i_saved_filter_user_quick', table_name='saved_filters')
    op.drop_index('i_saved_filter_user_kind', table_name='saved_filters')
    op.drop_table('saved_filters')
