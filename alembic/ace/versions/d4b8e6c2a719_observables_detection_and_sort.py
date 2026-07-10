"""observables: detection_modified_by rename, value_sort column, detection/sort indexes

Three related changes to `observables`, all in service of the admin observable-detection page.

1. `enabled_by` -> `detection_modified_by`.

   `enabled_by` only ever recorded who *enabled* an observable for detection. Disabling left it (and
   detection_context) untouched, so the UI would report a disabled observable as still "enabled by
   X", and the context still described the enable action. The column now records the user who last
   changed the detection status either way, paired with a detection_context describing that change.
   Disabling additionally clears expires_on -- an expiration only governs an enabled detection, and a
   stale one would be silently inherited on re-enable, excluding the observable from the detection
   cache while the UI claimed it was enabled.

   MySQL's CHANGE COLUMN preserves the foreign key and its index, but does not rename the index. The
   index must therefore be renamed by hand, and it must be renamed *to the new column name*: MySQL
   names implicit foreign-key indexes after their column, and Alembic's autogenerate relies on that
   convention to recognize (and ignore) them -- see `correct_for_autogen_constraints` in
   `alembic/ddl/mysql.py`. An index on an FK column named anything else is reported as model drift,
   because no table in saq/database/model.py declares its FK indexes explicitly.

2. `value_sort`, a stored generated column.

   `observables.value` is a BLOB: binary, no collation, so it cannot be sorted in any efficient way.
   A prefix index cannot satisfy ORDER BY, and MySQL truncates blob sort keys at max_sort_length
   (default 1024 bytes), producing unstable ties that break offset pagination. Sorting the admin
   detection page by primary key instead is meaningless to analysts.

   `value_sort` holds a case-insensitive, character-typed prefix of `value` that CAN be indexed and
   ordered. `value` itself is left alone: it stays binary and byte-exact, so sha256/uniqueness/LIKE
   semantics are unchanged. value_sort is derived, so it cannot drift.

   The generated expression converts `value` to utf8mb4, and MySQL raises an error in strict mode if
   any row holds bytes that are not valid UTF-8, failing the ALTER with an opaque message. Most
   writers encode from a Python str (always valid), but the v1 intel API can store arbitrary bytes,
   so we validate up-front and fail with an actionable message instead.

3. Three indexes.

   `i_obs_for_detection_id` serves the every-minute update-for-detection-observable-cache cron, which
   would otherwise full-scan the table to find the enabled rows. It is NOT redundant with
   `i_obs_fd_type_value_sort_id`: (for_detection, id) is not a prefix of
   (for_detection, type, value_sort, id).

   The other two give the admin page index-ordered "group by type, alphabetical by value" with no
   filesort, one for each of its two views. `id` is always appended as a tiebreaker so rows sharing a
   value_sort prefix paginate deterministically.

NOTE: running autogenerate against this table also proposes dropping and recreating
idx_erc_collector_loop and idx_file_collection_collector_loop. That is a known Alembic quirk with
DESC index columns (it cannot round-trip them), unrelated to this change, and must be stripped from
any generated output.

Revision ID: d4b8e6c2a719
Revises: f1a2b3c4d5e6
Create Date: 2026-07-10 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'd4b8e6c2a719'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# InnoDB DYNAMIC caps an index key at 3072 bytes. The widest index using this column is
# (for_detection, type, value_sort, id) = 1 + 256 + 4*N + 4, so N <= 702. 512 leaves headroom for the
# index to gain a column later while covering ~98% of observed values in full.
VALUE_SORT_LENGTH = 512
_GENERATED_EXPR = f"LEFT(CONVERT(`value` USING utf8mb4), {VALUE_SORT_LENGTH})"


def _assert_all_values_are_valid_utf8(bind) -> None:
    """Fail with an actionable error rather than letting the ALTER die on a bad row."""
    bad: list[int] = []
    # stream: the production table is ~371k rows and the driver would otherwise buffer every BLOB.
    result = bind.execution_options(stream_results=True).execute(
        sa.text("SELECT id, `value` FROM observables"))
    for observable_id, value in result:
        try:
            value.decode("utf8")
        except UnicodeDecodeError:
            bad.append(observable_id)
            if len(bad) >= 10:
                break

    result.close()

    if bad:
        raise RuntimeError(
            f"cannot add observables.value_sort: {len(bad)}+ rows contain bytes that are not valid "
            f"UTF-8 (observable ids: {bad}). The generated column converts `value` to utf8mb4 and "
            f"would fail on these rows. Clean or delete them first."
        )


def upgrade() -> None:
    bind = op.get_bind()
    _assert_all_values_are_valid_utf8(bind)

    op.alter_column(
        'observables',
        'enabled_by',
        new_column_name='detection_modified_by',
        existing_type=sa.Integer(),
        existing_nullable=True,
    )
    op.execute("ALTER TABLE observables RENAME INDEX `enabled_by` TO `detection_modified_by`")

    op.add_column(
        'observables',
        sa.Column(
            'value_sort',
            sa.String(length=VALUE_SORT_LENGTH, collation='utf8mb4_unicode_520_ci'),
            sa.Computed(_GENERATED_EXPR, persisted=True),
            nullable=False,
        ),
    )

    op.create_index('i_obs_for_detection_id', 'observables', ['for_detection', 'id'], unique=False)
    op.create_index('i_obs_type_value_sort_id', 'observables', ['type', 'value_sort', 'id'], unique=False)
    op.create_index('i_obs_fd_type_value_sort_id', 'observables', ['for_detection', 'type', 'value_sort', 'id'], unique=False)


def downgrade() -> None:
    op.drop_index('i_obs_fd_type_value_sort_id', table_name='observables')
    op.drop_index('i_obs_type_value_sort_id', table_name='observables')
    op.drop_index('i_obs_for_detection_id', table_name='observables')

    op.drop_column('observables', 'value_sort')

    op.execute("ALTER TABLE observables RENAME INDEX `detection_modified_by` TO `enabled_by`")
    op.alter_column(
        'observables',
        'detection_modified_by',
        new_column_name='enabled_by',
        existing_type=sa.Integer(),
        existing_nullable=True,
    )
