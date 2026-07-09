"""add observables.value_sort generated column and sort indexes

`observables.value` is a BLOB (binary, no collation), which makes it unsortable in any efficient
way: a prefix index cannot satisfy ORDER BY, and MySQL truncates blob sort keys at max_sort_length
(default 1024 bytes), producing unstable ties that break offset pagination. Sorting the admin
detection page by the primary key instead is meaningless to analysts.

This adds a STORED GENERATED column holding a case-insensitive, character-typed 191-char prefix of
`value`, plus two composite indexes so "group by type, alphabetical by value" is served directly
from an index with no filesort. `id` is always appended as a tiebreaker so rows sharing a
value_sort prefix paginate deterministically.

`value` itself is left alone: it stays binary and byte-exact, so sha256/uniqueness/LIKE semantics
are unchanged. value_sort is derived, so it cannot drift.

NOTE: the generated expression converts `value` to utf8mb4. MySQL raises an error in strict mode if
any row holds bytes that are not valid UTF-8, which would make the ALTER fail with an opaque
message. Most writers encode from a Python str (always valid), but the v1 intel API can store
arbitrary bytes, so we validate up-front and fail with an actionable message instead.

Revision ID: b7c31e0f5a24
Revises: a048d96a939a
Create Date: 2026-07-09 16:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b7c31e0f5a24'
down_revision: Union[str, None] = 'a048d96a939a'
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
    result = bind.execute(sa.text("SELECT id, `value` FROM observables"))
    for observable_id, value in result:
        try:
            value.decode("utf8")
        except UnicodeDecodeError:
            bad.append(observable_id)
            if len(bad) >= 10:
                break

    if bad:
        raise RuntimeError(
            f"cannot add observables.value_sort: {len(bad)}+ rows contain bytes that are not valid "
            f"UTF-8 (observable ids: {bad}). The generated column converts `value` to utf8mb4 and "
            f"would fail on these rows. Clean or delete them first."
        )


def upgrade() -> None:
    bind = op.get_bind()
    _assert_all_values_are_valid_utf8(bind)

    op.add_column(
        'observables',
        sa.Column(
            'value_sort',
            sa.String(length=VALUE_SORT_LENGTH, collation='utf8mb4_unicode_520_ci'),
            sa.Computed(_GENERATED_EXPR, persisted=True),
            nullable=False,
        ),
    )
    op.create_index('i_obs_type_value_sort_id', 'observables', ['type', 'value_sort', 'id'], unique=False)
    op.create_index('i_obs_fd_type_value_sort_id', 'observables', ['for_detection', 'type', 'value_sort', 'id'], unique=False)


def downgrade() -> None:
    op.drop_index('i_obs_fd_type_value_sort_id', table_name='observables')
    op.drop_index('i_obs_type_value_sort_id', table_name='observables')
    op.drop_column('observables', 'value_sort')
