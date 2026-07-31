#!/usr/bin/env python3
"""Check for drift between SQLAlchemy models and Alembic migrations.

Runs alembic autogenerate diff against a migrated database and reports
any pending operations that would require a new migration.  Exits 0 if
models and migrations are in sync, 1 otherwise.

Expression-based indexes (e.g. ``desc('col')``) produce false positives
because Alembic cannot round-trip compare them.  These are filtered out
automatically.

Usage (inside dev container):
    /venv/bin/python bin/check_model_drift.py                       # main ace DB (default)
    /venv/bin/python bin/check_model_drift.py --database cache          # analysis cache DB
    /venv/bin/python bin/check_model_drift.py --database brocess        # brocess DB
    /venv/bin/python bin/check_model_drift.py --database email-archive  # email-archive DB

Or via Make:
    make db-check
    make cache-db-check
    make brocess-db-check
    make email-archive-db-check
"""

import argparse
import logging
import os
import sys

# Suppress noisy warnings from Alembic about expression indexes
logging.getLogger("alembic.ddl.impl").setLevel(logging.ERROR)

# The project root contains an ``alembic/`` directory (our migrations
# folder) which shadows the installed ``alembic`` package.  Remove the
# project root from sys.path before importing alembic so Python finds
# the real package from the venv.
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [p for p in sys.path if os.path.realpath(p) != os.path.realpath(project_root)]

from urllib.parse import quote_plus

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Column, create_engine

# Re-add project root so saq is importable
sys.path.insert(0, project_root)

from saq.database.meta import Base, BrocessBase, CacheBase, EmailArchiveBase
import saq.database.model  # noqa: F401 — populates the Base, CacheBase, BrocessBase and EmailArchiveBase metadata


DATABASES = {
    "ace": {
        "metadata": Base.metadata,
        "env_var": "DATABASE_NAME",
        "default_name": "ace",
        "revision_cmd": "make db-revision",
    },
    "cache": {
        "metadata": CacheBase.metadata,
        "env_var": "CACHE_DATABASE_NAME",
        "default_name": "analysis-result-cache-unittest",
        "revision_cmd": "make cache-db-revision",
    },
    "brocess": {
        "metadata": BrocessBase.metadata,
        "env_var": "BROCESS_DATABASE_NAME",
        "default_name": "brocess-unittest",
        "revision_cmd": "make brocess-db-revision",
    },
    "email-archive": {
        "metadata": EmailArchiveBase.metadata,
        "env_var": "EMAIL_ARCHIVE_DATABASE_NAME",
        "default_name": "email-archive-unittest",
        "revision_cmd": "make email-archive-db-revision",
    },
}


def get_url(db_name: str) -> str:
    password = os.environ.get("ACE_SUPERUSER_DB_USER_PASSWORD") or ""
    if not password:
        with open("/auth/passwords/ace-superuser") as fp:
            password = fp.read().strip()
    password = quote_plus(password)
    host = os.environ.get("ACE_DB_HOST", "ace-db")
    return f"mysql+pymysql://ace-superuser:{password}@{host}:3306/{db_name}"


def _expression_index_names(diffs) -> set[str]:
    """Return names of indexes that appear as false-positive add/remove pairs.

    Alembic cannot round-trip compare expression-based indexes (e.g. those
    using ``desc()``).  It emits a ``remove_index`` + ``add_index`` pair for
    the *same* index name even though nothing changed.  We detect these by
    finding index names that have *both* an add and a remove, where at least
    one side contains a non-column expression.
    """
    by_name: dict[str, set[str]] = {}  # index_name -> set of ops
    has_expr: set[str] = set()  # index names with expression elements

    for diff in diffs:
        if not isinstance(diff, tuple) or len(diff) < 2:
            continue
        op = diff[0]
        if op not in ("remove_index", "add_index"):
            continue
        index = diff[1]
        name = index.name
        by_name.setdefault(name, set()).add(op)
        for expr in index.expressions:
            if not isinstance(expr, Column):
                has_expr.add(name)
                break

    # Only filter indexes that appear as a matched pair with expressions
    return {
        name
        for name, ops in by_name.items()
        if ops == {"remove_index", "add_index"} and name in has_expr
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument(
        "--database",
        choices=list(DATABASES),
        default="ace",
        help="which database to drift-check (default: ace)",
    )
    args = parser.parse_args()

    cfg = DATABASES[args.database]
    metadata = cfg["metadata"]
    db_name = os.environ.get(cfg["env_var"], cfg["default_name"])
    revision_cmd = cfg["revision_cmd"]

    engine = create_engine(get_url(db_name))
    with engine.connect() as conn:
        migration_ctx = MigrationContext.configure(conn)
        diffs = compare_metadata(migration_ctx, metadata)

    # Filter out expression-index false positives (paired add/remove)
    false_positive_indexes = _expression_index_names(diffs)
    real_diffs = []
    for diff in diffs:
        if (
            isinstance(diff, tuple)
            and len(diff) >= 2
            and diff[0] in ("remove_index", "add_index")
            and diff[1].name in false_positive_indexes
        ):
            continue
        real_diffs.append(diff)

    if not real_diffs:
        print("OK: Models and migrations are in sync.")
        return 0

    print("DRIFT DETECTED: The following changes need a migration:\n")
    for diff in real_diffs:
        print(f"  {diff}")
    print(
        f"\nRun '{revision_cmd} MESSAGE=\"describe your change\"' to generate a migration."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
