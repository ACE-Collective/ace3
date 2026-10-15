"""svs ignores permission catalog

Data-only migration (no schema change): SVS run results (docs/SVS_RUNS.md, *Expectations and
ignores*) split ignores by scope. svs:admin now also covers global ignores, which change every
test's results; svs:run_manage covers a test's expectations, ignores and settings. This updates
the catalog read-model descriptions only; the grant tables are untouched, so no one's access
changes.

Revision ID: ab562f1903d0
Revises: 33a6f5b5842f
Create Date: 2026-10-15 11:50:30.428670

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ab562f1903d0'
down_revision: Union[str, None] = '33a6f5b5842f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the changed static svs: entries in saq/permissions/catalog.py::PERMISSION_CATALOG
# at this revision.
_CATALOG = [
    ("svs", "admin", "Administer SVS: retire SVS YARA samples for a rule and delete sample files (their bytes are purged, audited), manage the test hosts, and ignore signatures for every test (global ignores)."),
    ("svs", "run_manage", "Manage SVS test runs: take ownership, cancel, close and review runs, decide a test's expectations, ignores and settings, associate alerts with runs."),
]

# the descriptions before this revision (19cd3b98d43f), restored on downgrade
_PREVIOUS = [
    ("svs", "admin", "Administer SVS: retire SVS YARA samples for a rule and delete sample files (their bytes are purged, audited), and manage the test hosts."),
    ("svs", "run_manage", "Manage SVS test runs: take ownership, cancel, close and review runs, decide expectations and ignores, associate alerts with runs."),
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
