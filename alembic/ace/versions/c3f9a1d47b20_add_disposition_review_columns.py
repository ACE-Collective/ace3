"""add disposition review columns

Adds columns that track senior-analyst review of alert dispositions, and seeds the
``alert:review`` permission into ``auth_permission_catalog``.

Revision ID: c3f9a1d47b20
Revises: ebd578f0f7a0
Create Date: 2026-07-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3f9a1d47b20'
down_revision: Union[str, None] = 'ebd578f0f7a0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alerts', sa.Column('disposition_review', sa.String(length=64), nullable=False, server_default='UNREVIEWED'))
    op.add_column('alerts', sa.Column('review_user_id', sa.Integer(), nullable=True))
    op.add_column('alerts', sa.Column('review_time', sa.TIMESTAMP(), nullable=True))
    op.add_column('alerts', sa.Column('incorrect_disposition', sa.String(length=64), nullable=True))
    op.add_column('alerts', sa.Column('incorrect_disposition_user_id', sa.Integer(), nullable=True))
    op.add_column('alerts', sa.Column('incorrect_disposition_time', sa.TIMESTAMP(), nullable=True))
    op.create_index('ix_alerts_disposition_review', 'alerts', ['disposition_review'])
    op.create_index('ix_alerts_review_user_id', 'alerts', ['review_user_id'])
    op.create_index('ix_alerts_incorrect_disposition_user_id', 'alerts', ['incorrect_disposition_user_id'])

    # Seed the permission that gates disposition review (idempotent upsert).
    op.get_bind().execute(
        sa.text(
            "INSERT INTO auth_permission_catalog (major, minor, description) "
            "VALUES (:major, :minor, :description) "
            "ON DUPLICATE KEY UPDATE description = VALUES(description)"
        ),
        {
            "major": "alert",
            "minor": "review",
            "description": "Review and correct alert dispositions.",
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text(
            "DELETE FROM auth_permission_catalog "
            "WHERE major = :major AND minor = :minor"
        ),
        {"major": "alert", "minor": "review"},
    )
    op.drop_index('ix_alerts_incorrect_disposition_user_id', table_name='alerts')
    op.drop_index('ix_alerts_review_user_id', table_name='alerts')
    op.drop_index('ix_alerts_disposition_review', table_name='alerts')
    op.drop_column('alerts', 'incorrect_disposition_time')
    op.drop_column('alerts', 'incorrect_disposition_user_id')
    op.drop_column('alerts', 'incorrect_disposition')
    op.drop_column('alerts', 'review_time')
    op.drop_column('alerts', 'review_user_id')
    op.drop_column('alerts', 'disposition_review')
