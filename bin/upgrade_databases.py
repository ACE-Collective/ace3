#!/usr/bin/env python3
"""Run ``alembic upgrade head`` for one or more ACE databases in a single process.

Each of the four Alembic chains reads the name of the database it should migrate from an
environment variable (see alembic/*/env.py). docker/startup/setup.sh runs the ``alembic``
command once per chain; this script does the same thing from one interpreter, which
matters when it runs at the start of every test session (importing the model is most of
the cost of each invocation).

Usage (inside the dev container):
    /venv/bin/python bin/upgrade_databases.py --ace ace-unittest-1f2e3d4c \\
        --brocess brocess-unittest-1f2e3d4c \\
        --email-archive email-archive-unittest-1f2e3d4c \\
        --cache analysis-result-cache-unittest-1f2e3d4c

Any subset of the four options may be given. The databases must already exist. Connects
as ace-superuser (see saq/database/admin.py for where the credentials come from).
"""

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# The project root contains an ``alembic/`` directory (our migrations folder) which shadows
# the installed ``alembic`` package. Remove the project root from sys.path before importing
# alembic so Python finds the real package from the venv. (env.py puts the root back on
# sys.path so it can import saq, but by then the package is already in sys.modules.)
sys.path = [p for p in sys.path if os.path.realpath(p or ".") != os.path.realpath(PROJECT_ROOT)]

from alembic import command
from alembic.config import Config

# option name -> (alembic chain directory, environment variable read by that chain's env.py)
CHAINS: dict[str, tuple[str, str]] = {
    "ace": ("ace", "DATABASE_NAME"),
    "brocess": ("brocess", "BROCESS_DATABASE_NAME"),
    "email_archive": ("email_archive", "EMAIL_ARCHIVE_DATABASE_NAME"),
    "cache": ("analysis_cache", "CACHE_DATABASE_NAME"),
}


def upgrade(chain: str, database: str) -> None:
    """Upgrades the given database to the head of the given chain."""
    chain_dir, env_var = CHAINS[chain]

    # the ini files use a script_location relative to the project root, and alembic
    # resolves that against the current working directory, so make both absolute
    config = Config(str(PROJECT_ROOT / "alembic" / f"{chain_dir}.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "alembic" / chain_dir))

    os.environ[env_var] = database
    print(f"upgrading {database} ({chain_dir}) to head")
    command.upgrade(config, "head")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ace", metavar="NAME", help="main ACE database to upgrade")
    parser.add_argument("--brocess", metavar="NAME", help="brocess database to upgrade")
    parser.add_argument("--email-archive", dest="email_archive", metavar="NAME", help="email archive database to upgrade")
    parser.add_argument("--cache", metavar="NAME", help="analysis result cache database to upgrade")
    args = parser.parse_args()

    requested = [(chain, getattr(args, chain)) for chain in CHAINS if getattr(args, chain)]
    if not requested:
        parser.error("nothing to do: specify at least one database")

    for chain, database in requested:
        upgrade(chain, database)

    return 0


if __name__ == "__main__":
    sys.exit(main())
