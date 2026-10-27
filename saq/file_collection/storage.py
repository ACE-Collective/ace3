"""Where the files of collections no alert asked for are kept, and for how long.

An alert's collected files live in the alert's storage directory and go when the alert does. A
collection queued without an alert (an API caller's) has no such directory, so its files go under
data/file_collection/<node>/<collection id>/ on the node that collected them, and each node prunes
its own directory once a day (``ace file-collection prune``).
"""

import logging
import os
import shutil
import time

from saq.environment import get_base_dir, get_data_dir, get_global_runtime_settings

UNATTACHED_DIR_NAME = "file_collection"


def _node_root(node: str) -> str:
    return os.path.join(get_data_dir(), UNATTACHED_DIR_NAME, node)


def unattached_storage_dir(collection_id: int) -> str:
    """The directory (relative to SAQ_HOME, like an alert's storage_dir) that holds the files of the
    collection with the given id on this node."""
    return os.path.relpath(
        os.path.join(_node_root(get_global_runtime_settings().saq_node), str(collection_id)),
        start=get_base_dir())


def prune_unattached_files(retention_days: int, dry_run: bool = False) -> int:
    """Removes this node's collection directories whose last change is more than retention_days
    old. Returns how many were removed (or would be, with dry_run). The file_collection rows stay:
    they are the record of who collected what from which host, and a download of a pruned file
    finds it gone."""
    node_root = _node_root(get_global_runtime_settings().saq_node)
    if not os.path.isdir(node_root):
        return 0

    cutoff = time.time() - retention_days * 86400
    removed = 0
    for entry in os.scandir(node_root):
        try:
            if entry.stat(follow_symlinks=False).st_mtime >= cutoff:
                continue

            if dry_run:
                logging.info("would remove collected files %s", entry.path, extra={"file_collection_id": entry.name})
            else:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path)
                else:
                    os.remove(entry.path)
                logging.info("removed collected files %s older than %d days", entry.path, retention_days,
                             extra={"file_collection_id": entry.name})
            removed += 1
        except Exception as e:
            logging.exception("unable to remove collected files %s: %s", entry.path, e,
                              extra={"file_collection_id": entry.name})

    return removed
