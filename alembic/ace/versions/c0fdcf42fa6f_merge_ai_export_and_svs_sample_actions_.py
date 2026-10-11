"""merge ai export and svs sample actions heads

Merge revision (no schema change): #670 (efcd01617ee8, the ai:export catalog row) and #671
(703a55037596 and b222aad71f7e, the SVS sample action tables and svs:admin) both branched off
4ba5a47774b4, which left the chain with two heads. They change unrelated rows and tables, so a
database at either head upgrades through this one.

Revision ID: c0fdcf42fa6f
Revises: b222aad71f7e, efcd01617ee8
Create Date: 2026-10-11 13:06:45.019291

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c0fdcf42fa6f'
down_revision: Union[str, None] = ('b222aad71f7e', 'efcd01617ee8')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
