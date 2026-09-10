#!/usr/bin/env python3
"""Drop per-session unittest databases that a pytest session left behind.

The test suite creates a fresh set of databases for every session (see
tests/unittest_database.py) and normally drops them itself, and the next session drops
anything a killed session left behind. This is for cleaning up without starting a session.

Usage (inside the dev container):
    bin/cleanup-unittest-databases.py            # drop every registered set (unless a session is running)
    bin/cleanup-unittest-databases.py --list     # just show what is registered and what looks orphaned
    bin/cleanup-unittest-databases.py --force    # drop even if the session marker file exists
    bin/cleanup-unittest-databases.py --orphans  # also drop databases that look like ours but have no record
"""

import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import session_lock, unittest_database


def session_may_be_running() -> bool:
    """Returns True unless it can be shown that no pytest session is running."""
    marker_path = session_lock.get_marker_path()
    if not os.path.exists(marker_path):
        return False

    marker = session_lock._read_marker(marker_path)
    if marker is None:
        return True

    # None means "cannot tell" (started on another host), which is not proof either way
    return session_lock._is_pytest_still_running(marker) is not False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", default=False, help="show registered and orphaned databases and exit")
    parser.add_argument("--force", action="store_true", default=False, help="drop even if a pytest session appears to be running")
    parser.add_argument("--orphans", action="store_true", default=False,
                        help="also drop databases matching the naming pattern that have no registry record "
                             "(skipping any with open connections)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    registered = unittest_database.list_registered()
    orphans = unittest_database.find_orphans()

    if args.list or (not registered and not orphans):
        if not registered:
            print("no registered unittest databases")
        for record in registered:
            print(f"registered (pid {record.get('pid')} on {record.get('hostname')}, started {record.get('started')}):")
            for name in record["databases"].values():
                print(f"    {name}")

        if orphans:
            print("databases matching the unittest naming pattern with no registry record:")
            for name, connections in orphans:
                print(f"    {name} ({connections} open connection(s))")

        return 0

    if not args.force and session_may_be_running():
        sys.stderr.write(f"a pytest session appears to be running ({session_lock.get_marker_path()} exists); "
                         "wait for it to finish, remove the marker, or use --force\n")
        return 1

    failed = False
    for record in registered:
        try:
            unittest_database.drop_registered(record)
        except Exception as e:
            logging.error("unable to drop databases recorded in %s: %s", record["path"], e)
            failed = True

    if args.orphans:
        for name, connections in orphans:
            if connections and not args.force:
                logging.warning("skipping %s: %s open connection(s) (use --force to drop anyway)", name, connections)
                continue

            try:
                unittest_database._drop_databases([name], None)
            except Exception as e:
                logging.error("unable to drop %s: %s", name, e)
                failed = True
    elif orphans:
        logging.warning("%s database(s) match the unittest naming pattern but have no registry record; "
                        "use --list to see them and --orphans to drop them", len(orphans))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
