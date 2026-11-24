"""normalize comment line breaks

Rewrites the comments and observable_comments rows stored before every write normalized its text
(saq/database/model.py::normalize_comment): a form post's CRLF line breaks become LF and the edge
whitespace goes, so a stored comment compares equal to the same text sent back by the edit box.

Safe on a populated table: no DDL, and each table is walked by primary key, BATCH_SIZE rows at a
time, updating only the rows whose text changes, each by primary key. An update applies only while
the row still holds the text that was read, compared byte for byte (the column's collation ignores
case), so a comment edited while this runs keeps the edit. The rows it rewrites stay locked until
the migration commits.

The text is normalized here rather than by normalize_comment(), so that this revision keeps doing
what it did when it was written. downgrade() does nothing: the original line breaks are not kept.

Revision ID: 21ef0452ff5a
Revises: 65f3715cc525
Create Date: 2026-11-24 01:15:51.682154

"""
import logging
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '21ef0452ff5a'
down_revision: Union[str, None] = '65f3715cc525'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


BATCH_SIZE = 1000


def _normalized(comment: str) -> str:
    return comment.replace("\r\n", "\n").strip()


def _normalize_table(table: str, key: str) -> None:
    connection = op.get_bind()
    select = sa.text(f"SELECT {key}, comment FROM {table} WHERE {key} > :last ORDER BY {key} LIMIT :limit")
    update = sa.text(f"UPDATE {table} SET comment = :new "
                     f"WHERE {key} = :key AND CAST(comment AS BINARY) = CAST(:old AS BINARY)")
    last, scanned, rewritten = 0, 0, 0
    while rows := connection.execute(select, {"last": last, "limit": BATCH_SIZE}).fetchall():
        changes = []
        for row_key, comment in rows:
            new = _normalized(comment)
            if new != comment:
                changes.append({"key": row_key, "old": comment, "new": new})

        if changes:
            rewritten += connection.execute(update, changes).rowcount

        scanned += len(rows)
        last = rows[-1][0]

    logging.info("normalized the line breaks of %d of %d rows in %s", rewritten, scanned, table)


def upgrade() -> None:
    _normalize_table("comments", "comment_id")
    _normalize_table("observable_comments", "id")


def downgrade() -> None:
    pass
