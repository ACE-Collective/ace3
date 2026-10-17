"""svs worklist permission catalog

Data-only migration (no schema change): SVS coverage gains the declared-vs-measured worklist
(docs/SVS_COVERAGE.md, *The worklist*). svs:run_read now also reads it and svs:run_manage resolves
its rows. This updates the catalog read-model descriptions only; the grant tables are untouched, so
no one's access changes.

Revision ID: a59acde4547c
Revises: d2cdf5246919
Create Date: 2026-10-17 01:02:11.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a59acde4547c'
down_revision: Union[str, None] = 'd2cdf5246919'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the changed static svs: entries in saq/permissions/catalog.py::PERMISSION_CATALOG
# at this revision.
_CATALOG = [
    ("svs", "run_manage", "Manage SVS test runs: take ownership, cancel, close and review runs, decide a test's expectations, ignores and settings, resolve the coverage worklist, associate alerts with runs."),
    ("svs", "run_read", "Read SVS test runs, the Atomic Red Team test catalog, the test hosts, coverage and the coverage worklist, on their screens and through the API."),
]

# the descriptions before this revision, restored on downgrade
_PREVIOUS = [
    ("svs", "run_manage", "Manage SVS test runs: take ownership, cancel, close and review runs, decide a test's expectations, ignores and settings, associate alerts with runs."),
    ("svs", "run_read", "Read SVS test runs, the Atomic Red Team test catalog, the test hosts and coverage, on their screens and through the API."),
]

_UPSERT = sa.text(
    "INSERT INTO auth_permission_catalog (major, minor, description) "
    "VALUES (:major, :minor, :description) "
    "ON DUPLICATE KEY UPDATE description = VALUES(description)"
)


def upgrade() -> None:
    bind = op.get_bind()
    for major, minor, description in _CATALOG:
        bind.execute(_UPSERT, {"major": major, "minor": minor, "description": description})


def downgrade() -> None:
    bind = op.get_bind()
    for major, minor, description in _PREVIOUS:
        bind.execute(_UPSERT, {"major": major, "minor": minor, "description": description})
