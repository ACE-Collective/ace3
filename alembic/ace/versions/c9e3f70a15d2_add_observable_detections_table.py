"""add observable_detections table

Detection management moves off the ``observables`` table and into a table of its own.

``observables`` is an index of everything ever seen in an alert -- hundreds of thousands of rows,
grown by ingest. Managing detections through it made the admin UI's substring search a full table
scan, forced a generated sort column onto a BLOB just to paginate, and made it impossible to add a
detection for an observable that had not been seen yet. ``observable_detections`` is a curated list
a human maintains, so it is small enough that ordering and searching need no special treatment.

This revision makes **no schema change to ``observables``**. The detection columns
(``for_detection``, ``expires_on``, ``fa_hits``, ``enabled_by``, ``detection_context``,
``batch_id``) are left exactly as they are, so ``downgrade()`` is lossless for everything that was
migrated. A follow-up revision, one release later, drops the dead ones.

Note for developers: this revision replaces an earlier one on the same branch,
``d4b8e6c2a719_observables_detection_and_sort``, which added ``value_sort`` and three indexes to
``observables``. It was never merged to main and never applied to production. If you already ran
``alembic upgrade head`` off that branch you must run ``alembic downgrade f1a2b3c4d5e6`` *before*
pulling this change, or rebuild your development database -- otherwise alembic cannot resolve the
revision recorded in ``alembic_version``.

Revision ID: c9e3f70a15d2
Revises: f1a2b3c4d5e6
Create Date: 2026-07-27
"""

import logging
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c9e3f70a15d2'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Keep in sync with saq.constants.MAX_DETECTION_VALUE_LENGTH.
VALUE_LENGTH = 4096

COLLATION = 'utf8mb4_unicode_520_ci'

# Module-level so tests can execute exactly this statement rather than a paraphrase of it.
# See tests/alembic/test_observable_detections_migration.py.
BACKFILL_SQL = """
    INSERT INTO observable_detections
        (type, value, value_sha256, expires_on, detection_context, batch_id, created_by, modified_by)
    SELECT o.type,
           CONVERT(o.value USING utf8mb4),
           o.sha256,
           CASE WHEN o.expires_on IS NOT NULL AND o.expires_on <= NOW() THEN NULL ELSE o.expires_on END,
           o.detection_context,
           o.batch_id,
           o.enabled_by,
           o.enabled_by
    FROM observables o
    WHERE o.for_detection = 1
      AND CHAR_LENGTH(CONVERT(o.value USING utf8mb4)) <= :max_length
"""


def upgrade() -> None:
    op.create_table(
        'observable_detections',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('type', sa.String(length=64), nullable=False),
        sa.Column('value', sa.String(length=VALUE_LENGTH, collation=COLLATION), nullable=False),
        sa.Column('value_sha256', sa.VARBINARY(32), nullable=False),
        sa.Column('expires_on', sa.DateTime(), nullable=True),
        sa.Column('detection_context', sa.Text(), nullable=True),
        sa.Column('batch_id', sa.String(length=36), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('modified_by', sa.Integer(), nullable=True),
        sa.Column('modified_at', sa.TIMESTAMP(),
                  server_default=sa.text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['modified_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('type', 'value_sha256', name='uq_obs_det_type_sha256'),
    )
    # No explicit index is created for created_by / modified_by. MySQL creates one implicitly for
    # each foreign key, named after the column, and alembic's MySQL dialect suppresses a reflected
    # index only when its name matches a column it covers -- which is how bin/check_model_drift.py
    # stays quiet about the other 57 foreign keys in the schema. Naming them anything else would be
    # reported as drift.
    op.create_index('i_obs_det_batch_id', 'observable_detections', ['batch_id'], unique=False)

    _backfill_from_observables()


def _backfill_from_observables() -> None:
    """Copies the currently-enabled detections out of the observables table.

    Two deliberate choices:

    * Only ``for_detection = 1`` rows are copied. Rows that merely carry disable history are left
      behind; a row in the new table *is* an active detection.
    * An ``expires_on`` that is already in the past becomes NULL. On an observables row that column
      was written by *ingest* (now + observable_expiration_mappings[type]) for every observable ever
      indexed, not by an analyst, so copying it verbatim would silently switch off live detections
      at cutover for anything last seen a while ago. Mapping expired to "never expires" fails safe:
      a detection stays on until a human turns it off.
    """
    bind = op.get_bind()

    skipped = bind.execute(sa.text("""
        SELECT id, type, LENGTH(value) AS byte_length FROM observables
        WHERE for_detection = 1 AND CHAR_LENGTH(CONVERT(value USING utf8mb4)) > :max_length
    """), {"max_length": VALUE_LENGTH}).fetchall()

    if skipped:
        logging.warning(
            "%d enabled observable(s) exceed the %d character detection value limit and were NOT "
            "migrated; observable ids: %s",
            len(skipped), VALUE_LENGTH, ", ".join(str(row.id) for row in skipped))

    expired = bind.execute(sa.text("""
        SELECT id FROM observables
        WHERE for_detection = 1 AND expires_on IS NOT NULL AND expires_on <= NOW()
    """)).fetchall()

    if expired:
        logging.warning(
            "%d enabled observable(s) had an already-expired expires_on, which was written by the "
            "ingest path rather than by an analyst; their detections were migrated as "
            "never-expiring. observable ids: %s",
            len(expired), ", ".join(str(row.id) for row in expired))

    result = bind.execute(sa.text(BACKFILL_SQL), {"max_length": VALUE_LENGTH})

    logging.info("migrated %d observable detection(s) into observable_detections", result.rowcount)


def downgrade() -> None:
    # observables was never altered and still holds every migrated value, so dropping the table is
    # enough. Detections created after the upgrade for observables that were never seen have no
    # observables row to fall back to and are lost -- count them so that is not silent.
    bind = op.get_bind()
    orphaned = bind.execute(sa.text("""
        SELECT COUNT(*) FROM observable_detections d
        LEFT JOIN observables o ON o.type = d.type AND o.sha256 = d.value_sha256
        WHERE o.id IS NULL
    """)).scalar()

    if orphaned:
        logging.warning(
            "%d detection(s) have no corresponding observables row and will be lost on downgrade",
            orphaned)

    op.drop_index('i_obs_det_batch_id', table_name='observable_detections')
    op.drop_table('observable_detections')
