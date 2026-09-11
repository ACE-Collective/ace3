#!/usr/bin/env python3
"""Check for drift between SQLAlchemy models and Alembic migrations.

Runs alembic autogenerate diff against a migrated database and reports
any pending operations that would require a new migration.  Exits 0 if
models and migrations are in sync, 1 otherwise.

By default the check builds its own throwaway database (``<name>-drift-<token>``),
migrates it to the head of the chain, compares, and drops it again, so it never
depends on the state of any other database.  Setting the chain's environment
variable (``DATABASE_NAME``, ``CACHE_DATABASE_NAME``, ``BROCESS_DATABASE_NAME`` or
``EMAIL_ARCHIVE_DATABASE_NAME``) checks that existing, already-migrated database
instead and never drops anything -- this is what CI does.

Expression-based indexes (e.g. ``desc('col')``) produce false positives
because Alembic cannot round-trip compare them.  These are filtered out
automatically.

Usage (inside dev container):
    /venv/bin/python bin/check_model_drift.py                       # main ace models (default)
    /venv/bin/python bin/check_model_drift.py --database cache          # analysis cache models
    /venv/bin/python bin/check_model_drift.py --database brocess        # brocess models
    /venv/bin/python bin/check_model_drift.py --database email-archive  # email-archive models
    DATABASE_NAME=ace /venv/bin/python bin/check_model_drift.py         # check the live ace database

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
import uuid

# Suppress noisy warnings from Alembic about expression indexes
logging.getLogger("alembic.ddl.impl").setLevel(logging.ERROR)

# The project root contains an ``alembic/`` directory (our migrations
# folder) which shadows the installed ``alembic`` package.  Remove the
# project root from sys.path before importing alembic so Python finds
# the real package from the venv.
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [p for p in sys.path if os.path.realpath(p) != os.path.realpath(project_root)]

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Column, create_engine

# bin/ is sys.path[0] when this runs as a script. upgrade_databases strips the project
# root from sys.path again when imported, so it has to come before the root is re-added.
from upgrade_databases import upgrade

# Re-add project root so saq is importable
sys.path.insert(0, project_root)

from saq.database.admin import get_superuser_url, superuser_connection
from saq.database.meta import Base, BrocessBase, CacheBase, EmailArchiveBase
import saq.database.model  # noqa: F401 — populates the Base, CacheBase, BrocessBase and EmailArchiveBase metadata


DATABASES = {
    "ace": {
        "metadata": Base.metadata,
        "env_var": "DATABASE_NAME",
        "base_name": "ace",
        "chain": "ace",
        "revision_cmd": "make db-revision",
    },
    "cache": {
        "metadata": CacheBase.metadata,
        "env_var": "CACHE_DATABASE_NAME",
        "base_name": "analysis-result-cache",
        "chain": "cache",
        "revision_cmd": "make cache-db-revision",
    },
    "brocess": {
        "metadata": BrocessBase.metadata,
        "env_var": "BROCESS_DATABASE_NAME",
        "base_name": "brocess",
        "chain": "brocess",
        "revision_cmd": "make brocess-db-revision",
    },
    "email-archive": {
        "metadata": EmailArchiveBase.metadata,
        "env_var": "EMAIL_ARCHIVE_DATABASE_NAME",
        "base_name": "email-archive",
        "chain": "email_archive",
        "revision_cmd": "make email-archive-db-revision",
    },
}

# the same charset and collation the real databases are created with (sql/0*.sql); the
# comparison is only silent about column collations when the database default matches
DATABASE_CHARSET = "utf8mb4"
DATABASE_COLLATION = "utf8mb4_unicode_520_ci"
LOCK_WAIT_TIMEOUT = 15


def create_throwaway_database(db_name: str) -> None:
    with superuser_connection() as db:
        db.cursor().execute(f"CREATE DATABASE `{db_name}` CHARACTER SET {DATABASE_CHARSET} COLLATE {DATABASE_COLLATION}")


def drop_throwaway_database(db_name: str) -> None:
    with superuser_connection() as db:
        cursor = db.cursor()
        cursor.execute(f"SET SESSION lock_wait_timeout = {LOCK_WAIT_TIMEOUT}")
        cursor.execute(f"DROP DATABASE IF EXISTS `{db_name}`")


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


def compare(db_name: str, metadata) -> list:
    """Returns the autogenerate diff between the models and the given database."""
    engine = create_engine(get_superuser_url(db_name))
    try:
        with engine.connect() as conn:
            migration_ctx = MigrationContext.configure(conn)
            return compare_metadata(migration_ctx, metadata)
    finally:
        # a pooled connection left open would hold a metadata lock against the DROP
        engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument(
        "--database",
        choices=list(DATABASES),
        default="ace",
        help="which models to drift-check (default: ace)",
    )
    args = parser.parse_args()

    cfg = DATABASES[args.database]
    metadata = cfg["metadata"]
    revision_cmd = cfg["revision_cmd"]

    # read once, up front: upgrade() sets this same variable for the migration
    existing = os.environ.get(cfg["env_var"])
    if existing:
        db_name, throwaway = existing, False
        print(f"checking existing database {db_name}")
    else:
        db_name, throwaway = f"{cfg['base_name']}-drift-{uuid.uuid4().hex[:8]}", True
        print(f"checking throwaway database {db_name}")

    try:
        if throwaway:
            create_throwaway_database(db_name)
            upgrade(cfg["chain"], db_name)

        diffs = compare(db_name, metadata)
    finally:
        if throwaway:
            try:
                drop_throwaway_database(db_name)
            except Exception as e:
                print(f"WARNING: unable to drop {db_name} ({e}); run bin/cleanup-unittest-databases.py --orphans")

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
