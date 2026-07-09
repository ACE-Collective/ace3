"""add observables for_detection id index

Revision ID: a048d96a939a
Revises: f1a2b3c4d5e6
Create Date: 2026-07-09 15:45:39.302925

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a048d96a939a'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Covers "observables enabled for detection, newest first": the admin detection page and the
    # every-minute update-for-detection-observable-cache cron, both of which currently full-scan the
    # table because no index includes for_detection.
    #
    # NOTE: autogenerate also proposed dropping/recreating idx_erc_collector_loop and
    # idx_file_collection_collector_loop. That is a known Alembic quirk with DESC index columns
    # (it cannot round-trip them) and is unrelated to this change, so it was removed.
    op.create_index('i_obs_for_detection_id', 'observables', ['for_detection', 'id'], unique=False)


def downgrade() -> None:
    op.drop_index('i_obs_for_detection_id', table_name='observables')
