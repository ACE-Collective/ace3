"""add nodes.expected_state

Records operator intent for a node, as opposed to the observed state already in
nodes.status. Draining a node sets expected_state to offline; resuming it, or restarting
the engine on it, sets it back to online.

Both are needed because status alone cannot distinguish a node that was drained and then
deliberately shut down from one that crashed: the graceful shutdown path and
reconcile_stale_node_statuses() both land on 'stopped'. Monitoring reads the pair --
stopped + online is a failure, stopped + offline is a planned outage.

NOTE: autogenerate also proposed rewriting the idx_erc_collector_loop and
idx_file_collection_collector_loop indexes. That is pre-existing drift -- alembic renders
the DESC component of those composite indexes differently than the reflected schema
reports it -- and is unrelated to this change, so it is deliberately not included here.
See 3fc96f75fb59, which made the same call.

Revision ID: decc3390927c
Revises: b2e9c137a93c
Create Date: 2026-09-05 12:17:37.273202

"""
from collections.abc import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'decc3390927c'
down_revision: Union[str, None] = 'b2e9c137a93c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'nodes',
        sa.Column('expected_state', sa.Enum('online', 'offline'),
                  server_default=sa.text("'online'"), nullable=False))


def downgrade() -> None:
    op.drop_column('nodes', 'expected_state')
