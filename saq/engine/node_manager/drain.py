"""Support for draining a node.

A draining node receives no new work but completes the work it already has.
Delayed analysis is the exception: those requests are pinned to the node and
can be scheduled far into the future, so a draining node pushes them to
another node that can accept them. If no compatible node exists the work
stays put (it does not block the drain) and resumes when the node starts back
up.
"""

import logging
import os
import shutil
import uuid as uuidlib

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_engine_config
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.database.util.locking import acquire_lock, release_lock
from saq.environment import get_base_dir, get_global_runtime_settings


def get_compatible_transfer_target(analysis_mode: str) -> tuple[int, str, str] | None:
    """Returns the (id, name, location) of the least loaded running node that
    can accept work in the given analysis mode, or None if no such node
    exists. Uses the same mode compatibility rules as collector node
    selection."""

    freshness = get_engine_config().node_status_update_frequency * 2

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT
    nodes.id,
    nodes.name,
    nodes.location,
    ( SELECT COUNT(*) FROM workload WHERE workload.node_id = nodes.id ) AS workload_count
FROM
    nodes
    LEFT JOIN node_modes ON nodes.id = node_modes.node_id
        AND node_modes.analysis_mode = %s
    LEFT JOIN node_modes_excluded ON nodes.id = node_modes_excluded.node_id
        AND node_modes_excluded.analysis_mode = %s
WHERE
    nodes.id != %s
    AND nodes.company_id = %s
    AND nodes.status = 'running'
    AND TIMESTAMPDIFF(SECOND, nodes.last_update, NOW()) <= %s
    AND ( ( nodes.any_mode AND node_modes_excluded.analysis_mode IS NULL )
        OR node_modes.analysis_mode IS NOT NULL )
ORDER BY
    workload_count ASC
LIMIT 1""", (
            analysis_mode,
            analysis_mode,
            get_global_runtime_settings().saq_node_id,
            get_global_runtime_settings().company_id,
            freshness))

        row = cursor.fetchone()
        if row is None:
            return None

        return row[0], row[1], row[2]


def transfer_delayed_analysis(transfer_limit: int = 16) -> tuple[int, int, int]:
    """Pushes outstanding delayed analysis on this (draining) node to other
    compatible nodes. At most transfer_limit transfers are attempted per call
    to keep the controller loop responsive.

    Returns a tuple of (transferred, untransferable, skipped) where
    transferred is the number of roots moved to another node, untransferable
    is the number of delayed_analysis ROWS that remain because no compatible
    node exists for them (these do not block the drain), and skipped is the
    number of roots that were not processed this pass (locked, raced, errored
    or over the transfer limit) and will be retried next cycle."""

    # imported here to avoid a circular import with distributed_node_manager
    from saq.engine.node_manager.distributed_node_manager import translate_node

    node_id = get_global_runtime_settings().saq_node_id
    saq_node = get_global_runtime_settings().saq_node

    transferred = 0
    skipped = 0
    untransferable_uuids = []

    # find the roots that only have delayed analysis outstanding
    # roots with a workload entry are skipped -- those move through the normal work transfer path
    # roots with a lock are skipped -- something else is working on them right now
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT DISTINCT
    delayed_analysis.uuid,
    delayed_analysis.storage_dir
FROM
    delayed_analysis
    LEFT JOIN workload ON delayed_analysis.uuid = workload.uuid
    LEFT JOIN locks ON delayed_analysis.uuid = locks.uuid
WHERE
    delayed_analysis.node_id = %s
    AND workload.uuid IS NULL
    AND locks.uuid IS NULL""", (node_id,))
        candidates = cursor.fetchall()

    for index, (uuid, storage_dir) in enumerate(candidates):
        if transferred + skipped >= transfer_limit:
            skipped += len(candidates) - index
            break

        local_dir = storage_dir
        if not os.path.isabs(local_dir):
            local_dir = os.path.join(get_base_dir(), local_dir)

        try:
            root = RootAnalysis(storage_dir=local_dir)
            root.load()
            analysis_mode = root.analysis_mode
        except Exception as e:
            logging.exception("unable to load root %s for delayed analysis transfer: %s", uuid, e)
            skipped += 1
            continue

        target = get_compatible_transfer_target(analysis_mode)
        if target is None:
            logging.warning("no compatible node available to transfer delayed analysis %s (mode %s) -- "
                            "work will resume when this node restarts", uuid, analysis_mode)
            untransferable_uuids.append(uuid)
            continue

        target_id, target_name, target_location = target
        target_location = translate_node(target_location)

        lock_uuid = str(uuidlib.uuid4())
        if not acquire_lock(uuid, lock_uuid, lock_owner="{}-drain-{}".format(saq_node, os.getpid())):
            logging.info("unable to acquire lock on %s for delayed analysis transfer", uuid)
            skipped += 1
            continue

        try:
            import ace_api

            # push the storage directory to the target node
            # sync stays False so the target does not schedule it (that would create a workload entry)
            # overwrite makes a retry after a partial failure idempotent
            result = ace_api.upload(
                uuid,
                local_dir,
                overwrite=True,
                sync=False,
                move=True,
                is_alert=True,
                remote_host=target_location)

            remote_storage_dir = result.get("storage_dir") if isinstance(result, dict) else None
            if not remote_storage_dir:
                # the target node computes the storage directory (it includes the node name)
                # without it we cannot repoint the database rows
                logging.error("upload of %s to node %s did not return a storage_dir "
                              "(target may be running an older version)", uuid, target_name)
                skipped += 1
                continue

            # repoint the delayed analysis at the target node
            # the local storage is only removed after this commits
            with get_db_connection() as db:
                cursor = db.cursor()
                rowcount = execute_with_retry(
                    db,
                    cursor,
                    "UPDATE delayed_analysis SET node_id = %s, storage_dir = %s WHERE uuid = %s AND node_id = %s",
                    (target_id, remote_storage_dir, uuid, node_id),
                    commit=True)

            if not rowcount:
                logging.warning("delayed analysis %s moved during transfer -- leaving as-is", uuid)
                skipped += 1
                continue

            try:
                shutil.rmtree(local_dir)
            except Exception as e:
                logging.error("unable to remove transferred storage directory %s: %s", local_dir, e)

            logging.info("transferred delayed analysis %s (mode %s) to node %s", uuid, analysis_mode, target_name)
            transferred += 1

        except Exception as e:
            logging.exception("unable to transfer delayed analysis %s to node %s: %s", uuid, target_name, e)
            skipped += 1

        finally:
            release_lock(uuid, lock_uuid)

    # the drained check compares against the count of delayed_analysis rows
    # a single root can have more than one row so we count rows for the untransferable roots
    untransferable = 0
    if untransferable_uuids:
        with get_db_connection() as db:
            cursor = db.cursor()
            sql = "SELECT COUNT(*) FROM delayed_analysis WHERE node_id = %s AND uuid IN ( {} )".format(
                ",".join(["%s" for _ in untransferable_uuids]))
            params = [node_id]
            params.extend(untransferable_uuids)
            cursor.execute(sql, tuple(params))
            untransferable = cursor.fetchone()[0]

    if transferred or untransferable or skipped:
        logging.info("delayed analysis transfer pass: %s transferred, %s untransferable rows, %s skipped",
                     transferred, untransferable, skipped)

    return transferred, untransferable, skipped
