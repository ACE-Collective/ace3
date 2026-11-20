"""observable value_rev for suffix patterns

Adds observables.value_rev, the value's bytes reversed, and an index on it, so an Observable
Pattern filter anchored at the end of the value (`*.evil.com`) is a range scan instead of a scan
of the whole table (saq/gui/observable_pattern.py).

Safe on a populated table: the column is VIRTUAL, so adding it is ALGORITHM=INSTANT and no row
is rewritten, and the index is built with ALGORITHM=INPLACE, LOCK=NONE, so inserts into
observables carry on while it builds (about 4 seconds for 1.25M rows). Both clauses are
explicit so MySQL refuses the statement rather than fall back to a table copy or a lock.

Each ALTER still needs a moment's exclusive metadata lock on the table, and while it waits for one
every later read and write of observables waits behind it. So it waits at most a few seconds and,
if a transaction kept the table that long, lets the queue through and tries again.

Revision ID: 87cae96b23b0
Revises: 645197ef7df8
Create Date: 2026-11-19 19:51:32.193248

"""
import logging
import time
from typing import Sequence, Union

from alembic import op
from sqlalchemy.exc import OperationalError


# revision identifiers, used by Alembic.
revision: str = '87cae96b23b0'
down_revision: Union[str, None] = '645197ef7df8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# how long one ALTER waits for its metadata lock, holding up the table's other queries meanwhile
LOCK_WAIT_TIMEOUT_SECONDS = 5
# how many times it waits before the migration fails, and the pause between, which lets the
# queries that queued behind it run
ATTEMPTS = 12
RETRY_DELAY_SECONDS = 1

ER_LOCK_WAIT_TIMEOUT = 1205


def _alter(statement: str) -> None:
    connection = op.get_bind()
    previous = connection.exec_driver_sql("SELECT @@SESSION.lock_wait_timeout").scalar()
    connection.exec_driver_sql(f"SET SESSION lock_wait_timeout = {LOCK_WAIT_TIMEOUT_SECONDS}")
    try:
        for attempt in range(1, ATTEMPTS + 1):
            try:
                connection.exec_driver_sql(statement)
                return
            except OperationalError as e:
                if e.orig is None or e.orig.args[0] != ER_LOCK_WAIT_TIMEOUT or attempt == ATTEMPTS:
                    raise

                logging.warning("gave up waiting %ds for the lock on observables (attempt %d of %d), trying again: %s",
                                LOCK_WAIT_TIMEOUT_SECONDS, attempt, ATTEMPTS, statement)
                time.sleep(RETRY_DELAY_SECONDS)
    finally:
        connection.exec_driver_sql(f"SET SESSION lock_wait_timeout = {int(previous)}")


def upgrade() -> None:
    _alter("ALTER TABLE observables ADD COLUMN value_rev VARBINARY(255) "
           "GENERATED ALWAYS AS (LEFT(REVERSE(`value`), 255)) VIRTUAL, ALGORITHM=INSTANT")
    _alter("ALTER TABLE observables ADD INDEX i_obs_value_rev (value_rev), ALGORITHM=INPLACE, LOCK=NONE")


def downgrade() -> None:
    _alter("ALTER TABLE observables DROP INDEX i_obs_value_rev, ALGORITHM=INPLACE, LOCK=NONE")
    _alter("ALTER TABLE observables DROP COLUMN value_rev, ALGORITHM=INSTANT")
