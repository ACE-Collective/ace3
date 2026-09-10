"""Seed the database with initial reference data.

The seeding itself lives in saq.database.seed; this is the command line front end used by
docker/startup/setup.sh and bin/build-unittest-database.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from saq.database.seed import seed, seed_unittest

# the static unittest databases provisioned by docker/startup/setup.sh. the test suite no
# longer uses these (it provisions its own per session, see tests/unittest_database.py) but
# make *-db-check still does.
STATIC_UNITTEST_DATABASES = ["ace-unittest", "ace-unittest-2"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the database with initial reference data.")
    parser.add_argument(
        "--seed-unittests",
        action="store_true",
        default=False,
        help="Also seed the static unittest databases (ace-unittest, ace-unittest-2).",
    )
    parser.add_argument(
        "--unittest-only",
        action="store_true",
        default=False,
        help="Only seed the static unittest databases, leaving the primary ace database alone. "
             "Used by bin/build-unittest-database.",
    )
    parser.add_argument(
        "--database",
        action="append",
        default=[],
        metavar="NAME",
        help="Seed this database as a unittest database (repeatable) instead of the static ones.",
    )
    args = parser.parse_args()
    if not args.unittest_only and not args.database:
        seed()

    if args.database:
        for db_name in args.database:
            seed_unittest(db_name)
    elif args.seed_unittests or args.unittest_only:
        for db_name in STATIC_UNITTEST_DATABASES:
            seed_unittest(db_name)
