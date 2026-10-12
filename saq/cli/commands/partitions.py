"""``ace partitions`` -- the date-partitioned tables (docs/DATABASE_PARTITIONS.md).

``status`` shows each table's partitions and whether its catchall can still be split. ``maintain``
drops expired partitions and provisions the coming ones; it is what the daily cron task runs, it
changes shared state, so it exits 0 without doing anything on a node that is not the primary unless
--force is given, and it exits 1 when a table needs attention. ``rebuild`` repairs a table whose
catchall holds data; it only reports what it would do unless --execute is given.
"""

import json

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.database imports below are inside their command functions on purpose, matching the
# convention in this package (see cas.py): this module is imported on every `ace` invocation just to
# register its parsers, and saq.database.partitions pulls in the config.

partitions_parser = get_cli_subparsers().add_parser("partitions", help="Date-partitioned tables (docs/DATABASE_PARTITIONS.md).")
partitions_sp = partitions_parser.add_subparsers(dest="partitions_cmd")


def cli_status(args):
    """Show the partitions of every managed table."""
    from saq.database.partitions import CATCHALL_SPLIT_MAX_ROWS, get_managed_tables, inspect_table, partition_connection

    tables = get_managed_tables()
    report = []
    for database in dict.fromkeys(t.database for t in tables):
        with partition_connection(database) as connection:
            for table in (t for t in tables if t.database == database):
                state = inspect_table(connection, table.table)
                bounds = [p.upper_bound for p in state.dated_partitions if p.upper_bound]
                report.append({
                    "table": table.key,
                    "exists": state.exists,
                    "partitioned": state.partitioned,
                    "dated_partitions": len(state.dated_partitions),
                    "oldest": state.dated_partitions[0].name if state.dated_partitions else None,
                    "newest": state.dated_partitions[-1].name if state.dated_partitions else None,
                    "provisioned_until": max(bounds).date().isoformat() if bounds else None,
                    "catchall_rows": f"> {CATCHALL_SPLIT_MAX_ROWS}" if state.catchall_too_full else str(state.catchall_rows),
                    "retention_days": table.retention_days,
                    "needs_rebuild": state.exists and state.needs_rebuild,
                })

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"{'TABLE':<44} {'PARTS':>5}  {'OLDEST':<10} {'NEWEST':<10} {'UNTIL':<10} {'CATCHALL':>9} {'KEEP':>4}  STATUS")
    for row in report:
        if not row["exists"]:
            status = "MISSING"
        elif row["needs_rebuild"]:
            status = f"NEEDS REBUILD: ace partitions rebuild {row['table']}"
        elif not row["partitioned"]:
            status = "not partitioned yet (maintain will partition it)"
        else:
            status = "ok"

        print(f"{row['table']:<44} {row['dated_partitions']:>5}  {row['oldest'] or '-':<10} {row['newest'] or '-':<10} "
              f"{row['provisioned_until'] or '-':<10} {row['catchall_rows']:>9} {row['retention_days']:>4}  {status}")

    return 0


status_parser = partitions_sp.add_parser("status", help="Show each table's partitions and whether it needs a rebuild.")
status_parser.add_argument("--json", action="store_true", default=False, help="Print JSON.")
status_parser.set_defaults(func=cli_status)


def cli_maintain(args):
    """Drop expired partitions and provision the coming ones (run daily from cron on the primary node)."""
    from saq.database.partitions import maintain_all
    from saq.database.util.node import is_primary_node

    if not (is_primary_node() or args.force):
        print("skipping partition maintenance: not the primary node (--force overrides)")
        return 0

    results = maintain_all(dry_run=args.dry_run)
    verb = "would drop" if args.dry_run else "dropped"
    for result in results:
        print(f"{result.key}: {verb} {len(result.dropped)}, {'would create' if args.dry_run else 'created'} {len(result.created)}"
              + ("" if result.ok else " -- NEEDS ATTENTION"))
        for name in result.dropped:
            print(f"  - {name}")
        for name in result.created:
            print(f"  + {name}")
        for problem in result.problems:
            print(f"  ! {problem}")

    return 0 if all(r.ok for r in results) else 1


maintain_parser = partitions_sp.add_parser("maintain", help="Drop expired partitions and provision the coming ones.")
maintain_parser.add_argument("--dry-run", action="store_true", default=False, help="Report what would change without changing anything.")
maintain_parser.add_argument("--force", action="store_true", default=False, help="Run even on a node that is not the primary.")
maintain_parser.set_defaults(func=cli_maintain)


def cli_rebuild(args):
    """Repair a table whose catchall holds data, without blocking writes to it."""
    from saq.database.partitions import get_managed_table, rebuild_table

    result = rebuild_table(get_managed_table(args.table), execute=args.execute, force=args.force,
                           batch_size=args.batch_size, pause_seconds=args.pause)
    for note in result.notes:
        print(note)

    if not args.execute and result.notes and not result.notes[0].startswith("nothing to do"):
        print("re-run with --execute to do it")

    return 0


rebuild_parser = partitions_sp.add_parser(
    "rebuild", help="Repair a table whose catchall holds data: swap in a freshly partitioned copy and copy the retained rows back.")
rebuild_parser.add_argument("table", help="The table to rebuild, e.g. email_archive.archive_index (see `ace partitions status`).")
rebuild_parser.add_argument("--execute", action="store_true", default=False, help="Do it. Without this, only report what would happen.")
rebuild_parser.add_argument("--force", action="store_true", default=False, help="Rebuild even a table that maintenance can handle.")
rebuild_parser.add_argument("--batch-size", type=int, default=5_000, help="Rows of the old table read per batch while copying back (default 5000).")
rebuild_parser.add_argument("--pause", type=float, default=0.1, help="Seconds to pause between batches (default 0.1).")
rebuild_parser.set_defaults(func=cli_rebuild)
