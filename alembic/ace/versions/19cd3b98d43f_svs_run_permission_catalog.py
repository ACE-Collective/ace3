"""svs run permission catalog

Data-only migration (no schema change): SVS test runs (docs/SVS_RUNS.md) need svs:run_register
(the launcher), svs:run_read (the Runs and Tests screens, the catalog, the test hosts and their
APIs) and svs:run_manage (ownership, review, close, expectations). svs:admin now also covers the
test hosts. This seeds the catalog read-model entries; the grant tables are untouched, so no one's
access changes.

Revision ID: 19cd3b98d43f
Revises: f7d406cb7e9c
Create Date: 2026-10-14 11:51:45.340735

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '19cd3b98d43f'
down_revision: Union[str, None] = 'f7d406cb7e9c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the new and changed static svs: entries in saq/permissions/catalog.py::PERMISSION_CATALOG
# at this revision.
_CATALOG = [
    ("svs", "admin", "Administer SVS: retire SVS YARA samples for a rule and delete sample files (their bytes are purged, audited), and manage the test hosts."),
    ("svs", "run_manage", "Manage SVS test runs: take ownership, cancel, close and review runs, decide expectations and ignores, associate alerts with runs."),
    ("svs", "run_read", "Read SVS test runs, the Atomic Red Team test catalog, the test hosts and coverage, on their screens and through the API."),
    ("svs", "run_register", "Register SVS test runs and drive their lifecycle (the test launcher's permission)."),
]

_NEW = [entry for entry in _CATALOG if entry[1] != "admin"]

# svs:admin's description before this revision (b222aad71f7e), restored on downgrade
_PREVIOUS_ADMIN = "Administer SVS: retire SVS YARA samples for a rule and delete sample files (their bytes are purged, audited)."

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

    for major, minor, _ in _NEW:
        bind.execute(sa.text(
            "DELETE FROM auth_permission_catalog WHERE major = :major AND minor = :minor"),
            {"major": major, "minor": minor})
    bind.execute(_UPSERT, {"major": "svs", "minor": "admin", "description": _PREVIOUS_ADMIN})
