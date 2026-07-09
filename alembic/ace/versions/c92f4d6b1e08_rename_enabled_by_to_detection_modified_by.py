"""rename observables.enabled_by to detection_modified_by

`enabled_by` only ever recorded who *enabled* an observable for detection. Disabling left it (and
detection_context) untouched, so the UI would report a disabled observable as still "enabled by X",
and the context still described the enable action.

The column now records the user who last changed the detection status either way, paired with a
detection_context describing that change. Disabling additionally clears expires_on -- an expiration
only governs an enabled detection, and a stale one would be silently inherited on re-enable,
excluding the observable from the detection cache while the UI claimed it was enabled.

MySQL RENAME COLUMN preserves the foreign key and the index on the column, so only the name changes.

Revision ID: c92f4d6b1e08
Revises: b7c31e0f5a24
Create Date: 2026-07-09 17:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c92f4d6b1e08'
down_revision: Union[str, None] = 'b7c31e0f5a24'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        'observables',
        'enabled_by',
        new_column_name='detection_modified_by',
        existing_type=sa.Integer(),
        existing_nullable=True,
    )
    # the index was implicitly created for the foreign key and kept its old name
    op.execute("ALTER TABLE observables RENAME INDEX `enabled_by` TO `i_obs_detection_modified_by`")


def downgrade() -> None:
    op.execute("ALTER TABLE observables RENAME INDEX `i_obs_detection_modified_by` TO `enabled_by`")
    op.alter_column(
        'observables',
        'detection_modified_by',
        new_column_name='enabled_by',
        existing_type=sa.Integer(),
        existing_nullable=True,
    )
