"""``ace cas`` -- operate the content-addressed storage subsystem from the command line (docs/CAS.md).

``gc``, ``verify`` and ``orphans`` are the maintenance verbs the cron tasks under etc/cron run.
They change shared state (the index, a pool's backend), so they exit 0 without doing anything on a
node that is not the primary unless --force is given; they exit 2 when anything failed.
``node-stats`` is the one cron verb that runs on every node, since it describes the node.
``purge`` and ``hold`` record who acted (--actor) in cas_purges / cas_holds but do not check
permissions: the cas:purge and cas:hold catalog entries exist for an API surface to enforce.
"""

import logging
import os

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.cas / saq.database imports below are inside their command functions on purpose,
# matching the convention in this package (see crash.py): this module is imported on every `ace`
# invocation just to register its parsers, and saq.cas pulls in the config, the database models and
# the crypto module.

cas_parser = get_cli_subparsers().add_parser("cas", help="Content-addressed storage operations (docs/CAS.md).")
cas_sp = cas_parser.add_subparsers(dest="cas_cmd")


def _primary_or_forced(args, what: str) -> bool:
    from saq.database.util.node import is_primary_node

    if is_primary_node() or getattr(args, "force", False):
        return True

    print(f"skipping cas {what}: not the primary node (--force overrides)")
    return False


def _selected_pools(args):
    from saq.cas import get_cas

    cas = get_cas()
    if getattr(args, "pool", None):
        return [cas.pool(args.pool)]

    pools = cas.pools()
    if not pools:
        print("no cas pools are configured (cas.pools)")

    return pools


def _run_per_pool(verb: str, pools, run) -> bool:
    """Run run(pool) for each pool. A pool that raises is logged and reported, and the rest still
    run: one pool's failure must not hide the others' results. Returns False if any pool raised."""
    ok = True
    for pool in pools:
        try:
            run(pool)
        except Exception as e:
            logging.error(f"cas {verb} failed", extra={"cas_pool": pool.name, "error": str(e)}, exc_info=True)
            print(f"{pool.name}: error: {e}")
            ok = False

    return ok


def _add_maintenance_arguments(parser):
    parser.add_argument("--pool", help="Only this pool (default: every configured pool).")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Report what would be done without changing anything.")
    parser.add_argument("--force", action="store_true", default=False, help="Run even on a node that is not the primary.")


#
# pools
#

def cli_pools(args):
    """List the configured pools and what the index holds for each."""
    from saq.cas import get_cas, index

    cas = get_cas()
    with index.transaction() as session:
        summaries = {pool: (count, size, stored) for pool, count, size, stored in index.pool_summaries(session)}

    print(f"{'POOL':24} {'BACKEND':8} {'ENCRYPTION':10} {'RETENTION':9} {'GRACE':>8} {'SHARED':6} {'OBJECTS':>8} {'SIZE':>14} {'STORED':>14}  LOCATION")
    for name in cas.pool_names():
        pool = cas.pool(name)
        count, size, stored = summaries.pop(name, (0, 0, 0))
        location = pool.backend.root if hasattr(pool.backend, "root") else type(pool.backend).__name__
        print("{:24} {:8} {:10} {:9} {:>8} {:6} {:>8} {:>14} {:>14}  {}".format(
            name, pool.config.backend, pool.config.encryption, pool.retention,
            pool.grace_seconds if pool.retention == "held" else "-",
            "yes" if pool.config.shared else "no", count, size, stored, location))

    # rows whose pool is no longer configured (a renamed pool leaves its rows and bytes behind)
    for name, (count, size, stored) in sorted(summaries.items()):
        print("{:24} {:8} {:10} {:9} {:>8} {:6} {:>8} {:>14} {:>14}  {}".format(
            name, "?", "?", "?", "-", "?", count, size, stored, "NOT CONFIGURED"))

    return 0


pools_parser = cas_sp.add_parser("pools", help="List the configured pools and their index totals.")
pools_parser.set_defaults(func=cli_pools)


#
# stat
#

def cli_stat(args):
    """Show one object's index row and its holds."""
    from saq.cas import CASError, ObjectNotFound, get_cas

    try:
        pool = get_cas().pool(args.pool)
        stat = pool.stat(args.digest)
        holds = pool.holds(args.digest)
    except ObjectNotFound as e:
        print(e)
        return 1
    except CASError as e:
        print(f"error: {e}")
        return 1

    for label, value in [
        ("pool", stat.pool), ("digest", stat.digest), ("state", stat.state), ("size", stat.size),
        ("stored_size", stat.stored_size), ("key_id", stat.key_id or "-"), ("created_at", stat.created_at),
        ("last_held_at", stat.last_held_at), ("verified_at", stat.verified_at or "-"), ("holds", stat.hold_count),
    ]:
        print(f"{label:14} {value}")

    for hold in holds:
        print(f"  hold {hold.holder_kind}:{hold.holder_id} expires {hold.expires_at or 'never'}")

    return 0


stat_parser = cas_sp.add_parser("stat", help="Show an object's index row and holds.")
stat_parser.add_argument("pool")
stat_parser.add_argument("digest", help="sha256 of the plaintext")
stat_parser.set_defaults(func=cli_stat)


#
# get
#

def cli_get(args):
    """Materialize an object's plaintext at a path."""
    from saq.cas import CASError, get_cas

    if os.path.exists(args.dest):
        if not args.force:
            print(f"{args.dest} exists (--force overwrites)")
            return 1

        os.unlink(args.dest)

    try:
        get_cas().pool(args.pool).materialize(args.digest, args.dest)
    except CASError as e:
        print(f"error: {e}")
        return 1

    print(f"wrote {args.dest}")
    return 0


get_parser = cas_sp.add_parser("get", help="Write an object's verified plaintext to a file.")
get_parser.add_argument("pool")
get_parser.add_argument("digest")
get_parser.add_argument("dest", help="Destination path (must not exist unless --force).")
get_parser.add_argument("--force", action="store_true", default=False, help="Overwrite the destination.")
get_parser.set_defaults(func=cli_get)


#
# gc
#

def cli_gc(args):
    """Garbage-collect held pools: delete objects that have outlived their last hold by the grace
    period. Exits 2 if any object could not be deleted or any pool failed."""
    if not _primary_or_forced(args, "gc"):
        return 0

    errors = 0

    def run(pool):
        nonlocal errors
        stats = pool.gc(dry_run=args.dry_run)
        if stats.skipped:
            print(f"{pool.name}: retention {pool.retention}, nothing to collect")
            return

        errors += stats.errors
        print(f"{pool.name}: {'would delete' if args.dry_run else 'deleted'} {stats.candidates if args.dry_run else stats.deleted} "
              f"object(s), {stats.bytes_reclaimed} bytes, resumed {stats.resumed}, skipped {stats.skipped_held} "
              f"(held since the scan), pruned {stats.expired_holds_pruned} expired hold(s), {stats.errors} error(s)")

    ok = _run_per_pool("gc", _selected_pools(args), run)
    return 0 if ok and not errors else 2


gc_parser = cas_sp.add_parser("gc", help="Delete objects that no longer have a live hold (held pools).")
_add_maintenance_arguments(gc_parser)
gc_parser.set_defaults(func=cli_gc)


#
# verify
#

def cli_verify(args):
    """Re-hash a sample of objects per pool. Exits 2 if any object is corrupt, encrypted under the
    wrong key or missing, or any pool failed."""
    if not _primary_or_forced(args, "verify"):
        return 0

    failed = False

    def run(pool):
        nonlocal failed
        stats = pool.verify(sample_size=args.sample, dry_run=args.dry_run)
        print(f"{pool.name}: checked {stats.checked}, intact {stats.verified}, corrupt {stats.mismatched}, "
              f"wrong key {stats.key_mismatch}, missing {stats.missing}, removed since sampled {stats.removed}")
        for digest in stats.failures:
            print(f"  FAILED {pool.name}/{digest}")

        failed = failed or bool(stats.failures)

    ok = _run_per_pool("verify", _selected_pools(args), run)
    return 2 if failed or not ok else 0


verify_parser = cas_sp.add_parser("verify", help="Re-hash a sample of objects and record verified_at.")
_add_maintenance_arguments(verify_parser)
verify_parser.add_argument("--sample", type=int, default=None, help="Objects per pool (default: cas.verify_sample_size).")
verify_parser.set_defaults(func=cli_verify)


#
# orphans
#

def cli_orphans(args):
    """Remove backend bytes that have no index row and are older than the grace period. Exits 2 if
    any pool failed."""
    if not _primary_or_forced(args, "orphans"):
        return 0

    def run(pool):
        stats = pool.orphans(grace_seconds=args.grace, dry_run=args.dry_run)
        print(f"{pool.name}: scanned {stats.scanned}, orphaned {stats.orphaned}, "
              f"{'would delete' if args.dry_run else 'deleted'} {stats.deleted} ({stats.bytes_reclaimed} bytes), "
              f"{stats.skipped_within_grace} within grace, {stats.unparseable} unrecognized key(s), "
              f"{stats.temp_files_removed} temp file(s) removed")

    return 0 if _run_per_pool("orphans", _selected_pools(args), run) else 2


orphans_parser = cas_sp.add_parser("orphans", help="Remove backend bytes that have no index row (the only operation that lists a backend).")
_add_maintenance_arguments(orphans_parser)
orphans_parser.add_argument("--grace", type=int, default=None, help="Seconds an orphan must be older than (default: cas.orphan_grace_seconds).")
orphans_parser.set_defaults(func=cli_orphans)


#
# node-stats
#

def cli_node_stats(args):
    """Report this node's read cache and the free space under its local-backend pools, as cas.node
    monitor records. Runs on every node: it describes the node, not shared state."""
    from saq.cas.health import node_stats
    from saq.monitor import emit_monitor
    from saq.monitor_definitions import MONITOR_CAS_NODE

    for record in node_stats():
        emit_monitor(MONITOR_CAS_NODE, record)
        free = record["fs_free_bytes"]
        free_text = f"{free} bytes free" if free is not None else "free space unknown"
        if record["kind"] == "read_cache":
            print(f"read cache {record['path']}: {record['entries']} entries, {record['bytes']} of "
                  f"{record['max_bytes']} bytes, {free_text}")
        else:
            print(f"pool {record['pool']} {record['path']}: {free_text}")

    return 0


node_stats_parser = cas_sp.add_parser("node-stats", help="Emit this node's read cache and disk space as cas.node monitor records.")
node_stats_parser.set_defaults(func=cli_node_stats)


#
# purge
#

def cli_purge(args):
    """Force-delete an object across its holds. Audited in cas_purges. Refused under a legal hold."""
    from saq.cas import CASError, LegalHoldActive, ObjectNotFound, get_cas

    if not args.yes:
        answer = input(f"purge {args.pool}/{args.digest} for {args.actor} ({args.reason})? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted")
            return 1

    try:
        get_cas().pool(args.pool).purge(args.digest, reason=args.reason, actor=args.actor)
    except LegalHoldActive as e:
        print(f"{e}; release the legal hold first (ace cas hold release)")
        return 1
    except ObjectNotFound as e:
        print(e)
        return 1
    except CASError as e:
        print(f"error: {e}")
        return 1

    print(f"purged {args.pool}/{args.digest}")
    return 0


purge_parser = cas_sp.add_parser("purge", help="Force-delete an object regardless of holds (audited).")
purge_parser.add_argument("pool")
purge_parser.add_argument("digest")
purge_parser.add_argument("--reason", required=True, help="Why; recorded in cas_purges.")
purge_parser.add_argument("--actor", required=True, help="Who; recorded in cas_purges.")
purge_parser.add_argument("-y", "--yes", action="store_true", default=False, help="Do not prompt.")
purge_parser.set_defaults(func=cli_purge)


#
# hold add | release  (legal holds)
#

def cli_hold_add(args):
    """Place a legal hold: never expires, and blocks purge until released."""
    from saq.cas import CASError, Hold, get_cas

    try:
        get_cas().pool(args.pool).hold(args.digest, Hold.legal(args.id), created_by=args.actor)
    except CASError as e:
        print(f"error: {e}")
        return 1

    print(f"legal hold {args.id} placed on {args.pool}/{args.digest}")
    return 0


def cli_hold_release(args):
    """Release a legal hold."""
    from saq.cas import CASError, Hold, get_cas

    try:
        released = get_cas().pool(args.pool).release(args.digest, Hold.legal(args.id))
    except CASError as e:
        print(f"error: {e}")
        return 1

    if not released:
        print(f"no legal hold {args.id} on {args.pool}/{args.digest}")
        return 1

    print(f"legal hold {args.id} released from {args.pool}/{args.digest}")
    return 0


hold_parser = cas_sp.add_parser("hold", help="Place or release a legal hold on an object.")
hold_sp = hold_parser.add_subparsers(dest="cas_hold_cmd")
for verb, func, help_text in [("add", cli_hold_add, "Place a legal hold."), ("release", cli_hold_release, "Release a legal hold.")]:
    parser = hold_sp.add_parser(verb, help=help_text)
    parser.add_argument("pool")
    parser.add_argument("digest")
    parser.add_argument("--id", required=True, help="Identifies the hold (a case or ticket reference).")
    parser.add_argument("--actor", required=True, help="Who; recorded in cas_holds.created_by.")
    parser.set_defaults(func=func)
