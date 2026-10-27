"""Where the files of collections no alert asked for are kept, and for how long.

An alert's collected files live in the alert's storage directory and go when the alert does. A
collection queued without an alert (an API caller's) has no such directory, so its files go under
data/file_collection/<node>/<collection id>/ on the node that collected them, and each node prunes
its own directory once a day (``ace file-collection prune``).
"""

import logging
import os
import shutil

from sqlalchemy import func, or_, select, text

from saq.database.model import FileCollection
from saq.database.pool import get_db
from saq.environment import get_base_dir, get_data_dir, get_global_runtime_settings
from saq.file_collection.types import FileCollectionStatus

UNATTACHED_DIR_NAME = "file_collection"

# collection ids looked up per query when pruning
PRUNE_BATCH_SIZE = 1000


def _node_root(node: str) -> str:
    return os.path.join(get_data_dir(), UNATTACHED_DIR_NAME, node)


def unattached_storage_dir(collection_id: int) -> str:
    """The directory (relative to SAQ_HOME, like an alert's storage_dir) that holds the files of the
    collection with the given id on this node."""
    return os.path.relpath(
        os.path.join(_node_root(get_global_runtime_settings().saq_node), str(collection_id)),
        start=get_base_dir())


def _retained_collection_ids(collection_ids: list[int], retention_days: int) -> set[int]:
    """The ids, of those given, whose collection is still pending or was last attempted less than
    retention_days ago. update_time is set with every attempt and reset by a retry, so a collection
    retried into the same directory is kept for retention_days after the retry."""
    cutoff = func.date_sub(func.now(), text(f"INTERVAL {int(retention_days)} DAY"))
    retained = set()
    for start in range(0, len(collection_ids), PRUNE_BATCH_SIZE):
        batch = collection_ids[start:start + PRUNE_BATCH_SIZE]
        retained.update(get_db().execute(
            select(FileCollection.id).where(
                FileCollection.id.in_(batch),
                or_(
                    FileCollection.status != FileCollectionStatus.COMPLETED.value,
                    FileCollection.update_time.is_(None),
                    FileCollection.update_time >= cutoff,
                ))).scalars())

    return retained


def prune_unattached_files(retention_days: int, dry_run: bool = False) -> int:
    """Removes this node's collection directories whose collection completed more than retention_days
    ago, or whose file_collection row is gone, and anything else in the node's directory that is not
    a collection's. Returns how many were removed (or would be, with dry_run). The file_collection
    rows stay: they are the record of who collected what from which host, and a download of a pruned
    file finds it gone."""
    node_root = _node_root(get_global_runtime_settings().saq_node)
    if not os.path.isdir(node_root):
        return 0

    entries = list(os.scandir(node_root))
    retained = _retained_collection_ids([int(entry.name) for entry in entries if entry.name.isdigit()], retention_days)
    removed = 0
    for entry in entries:
        if entry.name.isdigit() and int(entry.name) in retained:
            continue

        try:
            if dry_run:
                logging.info("would remove collected files %s", entry.path, extra={"file_collection_id": entry.name})
            else:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path)
                else:
                    os.remove(entry.path)
                logging.info("removed collected files %s (retention %d days)", entry.path, retention_days,
                             extra={"file_collection_id": entry.name})
            removed += 1
        except Exception as e:
            logging.exception("unable to remove collected files %s: %s", entry.path, e,
                              extra={"file_collection_id": entry.name})

    return removed
