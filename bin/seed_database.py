"""Seed the primary database with initial reference data.

The seeding itself lives in saq.database.seed; this is the command line front end used by
docker/startup/setup.sh and make db-seed.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from saq.database.seed import seed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the primary database with initial reference data.")
    parser.parse_args()
    seed()
