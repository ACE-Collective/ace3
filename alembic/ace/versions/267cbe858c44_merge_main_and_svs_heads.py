"""merge main and svs heads

Merge revision (no schema change): the merge of main (#706-#731) into jd/svs joins main's
permission catalog migrations (f26a884b17f3, 434f3139d204, e28c9d0a6154: remediation:write,
file_collection:write, the whitelist permission removed) with the SVS run migrations ending at
85a3df1c2dc1. They change unrelated rows and tables, so a database at either head upgrades
through this one.

Revision ID: 267cbe858c44
Revises: 85a3df1c2dc1, e28c9d0a6154
Create Date: 2026-10-16 18:26:03.638618

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '267cbe858c44'
down_revision: Union[str, None] = ('85a3df1c2dc1', 'e28c9d0a6154')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
