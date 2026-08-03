"""Persistence of what each export target published last, so a run with no changes is a no-op.

The state is a small JSON file per target under the data directory. It is deliberately node-local:
the artifacts an export produces (yara rules on disk, for one) are node-local too, so a shared
record would let one node's successful run suppress another node's needed one.
"""

import json
import logging
import os
from typing import Optional

from saq.environment import get_data_dir
from saq.util.filesystem import create_directory
from saq.util.time import local_time

STATE_DIR = "var/observable_export"


def get_state_dir() -> str:
    """The directory holding the per-target state files."""
    return os.path.join(get_data_dir(), STATE_DIR)


def get_state_path(name: str) -> str:
    """The path of the state file for the export target with the given name."""
    return os.path.join(get_state_dir(), f"{name}.json")


def read_fingerprint(name: str) -> Optional[str]:
    """The fingerprint this target last successfully published, or None if it never has.

    An unreadable or malformed state file is treated as "never published" -- the cost of that is one
    redundant export, which is strictly better than refusing to export at all.
    """
    path = get_state_path(name)
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r") as fp:
            return json.load(fp).get("fingerprint")
    except Exception as e:
        logging.warning(f"unable to read observable export state {path}: {e}")
        return None


def write_fingerprint(name: str, fingerprint: str) -> None:
    """Records that this target successfully published the given fingerprint."""
    create_directory(get_state_dir())
    path = get_state_path(name)
    with open(path, "w") as fp:
        json.dump({"fingerprint": fingerprint, "updated_at": local_time().isoformat()}, fp)
