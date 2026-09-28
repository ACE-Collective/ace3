"""What the CAS looks like right now, for monitoring (docs/CAS.md, "Observability").

pool_health() reads the index, which is shared, so it describes the whole cluster: the cas.pool
monitor runs it from the monitoring service on one node. node_stats() describes this node only
(the read cache, and the disks under local-backend pools): `ace cas node-stats` runs it hourly on
every node.
"""

import os
import shutil
from typing import Optional

from saq.cas import index
from saq.cas.backend import LocalBackend
from saq.cas.registry import CAS, get_cas
from saq.environment import get_global_runtime_settings

VERIFIED_WITHIN_SECONDS = 7 * 24 * 3600
PURGES_WITHIN_SECONDS = 24 * 3600

_OBJECT_FIELDS = ("objects_present", "objects_deleting", "size_bytes", "stored_bytes", "never_verified", "verified_last_7d")
_HOLD_FIELDS = ("holds_live", "holds_expired", "legal_holds", "objects_held")


def pool_health(cas: Optional[CAS] = None) -> list[dict]:
    """One record per configured pool, plus one per pool that still has rows in the index but is no
    longer configured (a renamed pool leaves its rows and bytes behind)."""
    cas = cas or get_cas()
    with index.transaction() as session:
        objects = index.object_summaries(session, VERIFIED_WITHIN_SECONDS)
        holds = index.hold_summaries(session)
        purges = index.purge_counts_since(session, PURGES_WITHIN_SECONDS)

        # present, unheld, and further past their pool's grace than an hourly GC should ever let them get
        overdue = {}
        for pool in cas.pools():
            if pool.retention == "held":
                overdue[pool.name] = index.count_gc_candidates(
                    session, pool.name, pool.grace_seconds + cas.config.gc_overdue_seconds)

    records: dict[str, dict] = {}

    def record(name: str) -> dict:
        if name not in records:
            records[name] = {"pool": name, **{field: 0 for field in _OBJECT_FIELDS + _HOLD_FIELDS}}

        return records[name]

    for name in cas.pool_names():
        record(name)

    for name, state, count, size, stored, never_verified, verified_recently in objects:
        entry = record(name)
        entry["objects_present" if state == index.STATE_PRESENT else "objects_deleting"] += int(count)
        entry["size_bytes"] += int(size)
        entry["stored_bytes"] += int(stored)
        entry["never_verified"] += int(never_verified)
        entry["verified_last_7d"] += int(verified_recently)

    for name, live, expired, legal, held in holds:
        entry = record(name)
        entry.update(holds_live=int(live), holds_expired=int(expired), legal_holds=int(legal), objects_held=int(held))

    # no node field: the index is shared, so this describes the cluster, not the node reporting it
    for name, entry in records.items():
        configured = name in cas.config.pools
        config = cas.config.pools.get(name)
        entry.update(
            configured=configured,
            backend=config.backend if configured else None,
            encryption=config.encryption if configured else None,
            retention=config.retention if configured else None,
            purges_last_24h=purges.get(name, 0),
            gc_overdue=overdue.get(name))

    return [records[name] for name in sorted(records)]


def _disk(path: str) -> tuple[Optional[int], Optional[int]]:
    """(free, total) bytes of the filesystem path is on, measured at its nearest existing ancestor
    (a pool's root does not exist until its first put)."""
    path = os.path.abspath(path)
    while not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent == path:
            return None, None

        path = parent

    usage = shutil.disk_usage(path)
    return usage.free, usage.total


def node_stats(cas: Optional[CAS] = None) -> list[dict]:
    """This node's read cache, and the filesystem under each local-backend pool."""
    cas = cas or get_cas()
    node = get_global_runtime_settings().saq_node

    entries, cached_bytes = cas.cache.usage()
    free, total = _disk(cas.cache.root)
    records = [{
        "node": node, "kind": "read_cache", "path": cas.cache.root, "entries": entries, "bytes": cached_bytes,
        "max_bytes": cas.cache.max_bytes, "fs_free_bytes": free, "fs_total_bytes": total,
    }]

    for pool in cas.pools():
        if not isinstance(pool.backend, LocalBackend):
            continue

        free, total = _disk(pool.backend.root)
        records.append({
            "node": node, "kind": "pool", "pool": pool.name, "path": pool.backend.root,
            "fs_free_bytes": free, "fs_total_bytes": total,
        })

    return records
