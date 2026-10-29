"""file_collection alert_uuid nullable on pre-Alembic databases

A database that got its file collection tables from the hand-written
sql/migrations/add_file_collection_tables.sql, before ACE moved to Alembic, has
file_collection.alert_uuid NOT NULL. The baseline 88d97a42fbef was taken from sql/01-ace.sql,
where it is nullable, as the model is, so autogenerate sees nothing to change and every database
the chain builds already has it nullable. A file collection no alert asked for stores NULL there,
and on such a database its INSERT fails.

The column changes only where it is NOT NULL. MySQL makes a column nullable in place, with
concurrent reads and writes allowed. The MODIFY also drops the column's comment, which the model
does not declare.

Revision ID: 04a424e8da0b
Revises: 92d11ba16267
Create Date: 2026-10-29 13:03:32.555706

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '04a424e8da0b'
down_revision: Union[str, None] = '92d11ba16267'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    columns = {column["name"]: column for column in sa.inspect(op.get_bind()).get_columns("file_collection")}
    if not columns["alert_uuid"]["nullable"]:
        op.alter_column("file_collection", "alert_uuid", existing_type=sa.String(length=36), nullable=True)


def downgrade() -> None:
    # nothing to undo: the previous revision has the column nullable on every database the chain
    # builds, and making it NOT NULL again would fail on the rows no alert asked for
    pass
