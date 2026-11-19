"""observable value_rev for suffix patterns

Adds observables.value_rev, the value's bytes reversed, and an index on it, so an Observable
Pattern filter anchored at the end of the value (`*.evil.com`) is a range scan instead of a scan
of the whole table (saq/gui/observable_pattern.py).

Safe on a populated table: the column is VIRTUAL, so adding it is ALGORITHM=INSTANT and no row
is rewritten, and the index is built with ALGORITHM=INPLACE, LOCK=NONE, so inserts into
observables carry on while it builds (about 4 seconds for 1.25M rows). Both clauses are
explicit so MySQL refuses the statement rather than fall back to a table copy or a lock.

Revision ID: 87cae96b23b0
Revises: 645197ef7df8
Create Date: 2026-11-19 19:51:32.193248

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '87cae96b23b0'
down_revision: Union[str, None] = '645197ef7df8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE observables ADD COLUMN value_rev VARBINARY(255) "
        "GENERATED ALWAYS AS (LEFT(REVERSE(`value`), 255)) VIRTUAL, ALGORITHM=INSTANT")
    op.execute("ALTER TABLE observables ADD INDEX i_obs_value_rev (value_rev), ALGORITHM=INPLACE, LOCK=NONE")


def downgrade() -> None:
    op.execute("ALTER TABLE observables DROP INDEX i_obs_value_rev, ALGORITHM=INPLACE, LOCK=NONE")
    op.execute("ALTER TABLE observables DROP COLUMN value_rev, ALGORITHM=INSTANT")
