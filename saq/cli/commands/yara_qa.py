"""``ace yara-qa`` -- the files matched by YARA rules in QA mode (docs/YARA_QA.md).

``list`` shows the rules in QA mode (including ones that have never matched) and their counts, the
same listing the API serves. ``prune`` removes expired matches and is what the daily cron task
runs; it changes shared state, so it exits 0 without doing anything on a node that is not the
primary unless --force is given.
"""

import json

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.yara_qa / saq.database imports below are inside their command functions on purpose,
# matching the convention in this package (see cas.py): this module is imported on every `ace`
# invocation just to register its parsers, and saq.yara_qa pulls in the config, the database models,
# the CAS and the signature inventory.

yara_qa_parser = get_cli_subparsers().add_parser("yara-qa", help="Files matched by YARA rules in QA mode (docs/YARA_QA.md).")
yara_qa_sp = yara_qa_parser.add_subparsers(dest="yara_qa_cmd")


def cli_list(args):
    """List YARA rules in QA mode, and rules with recorded QA matches, with their counts."""
    from saq.yara_qa.db import transaction
    from saq.yara_qa.inventory import get_yara_inventory
    from saq.yara_qa.listing import QASort, QAStatus, filter_and_sort, merge, version_rows_statement

    inventory = get_yara_inventory()
    with transaction() as session:
        rows = session.execute(version_rows_statement()).scalars().all()
        signatures = filter_and_sort(
            merge(inventory, rows), q=args.q, status=QAStatus(args.status) if args.status else None,
            sort=QASort(args.sort), descending=args.sort != QASort.NAME)

    if inventory.error:
        print(f"warning: {inventory.error}")

    if args.json:
        print(json.dumps([{
            "signature_uuid": s.signature_uuid, "name": s.name, "status": s.status.value,
            "enabled": s.enabled, "current_version": s.current_version, "source_path": s.source_path,
            "match_count": s.match_count, "stored_count": s.stored_count, "version_count": s.version_count,
            "last_match_at": s.last_match_at.isoformat() if s.last_match_at else None,
        } for s in signatures], indent=2))
        return 0

    if not signatures:
        print("no rules in qa mode and no recorded qa matches")
        return 0

    print(f"{'STATUS':<8} {'MATCHES':>8} {'STORED':>7} {'VERS':>5} {'LAST MATCH':<19}  {'UUID':<36}  NAME")
    for s in signatures:
        last_match = s.last_match_at.strftime("%Y-%m-%d %H:%M:%S") if s.last_match_at else "never"
        print(f"{s.status.value:<8} {s.match_count:>8} {s.stored_count:>7} {s.version_count:>5} {last_match:<19}  "
              f"{s.signature_uuid:<36}  {s.name}")

    return 0


list_parser = yara_qa_sp.add_parser("list", help="List rules in QA mode and their match counts.")
list_parser.add_argument("--status", choices=["qa", "not_qa", "missing"], help="Only rules with this status (default: all).")
list_parser.add_argument("--sort", choices=["name", "last_match", "match_count"], default="name", help="Sort order (counts and dates sort descending).")
list_parser.add_argument("-q", help="Only rules whose name, uuid, namespace or file contains this.")
list_parser.add_argument("--json", action="store_true", default=False, help="Print JSON.")
list_parser.set_defaults(func=cli_list)


def cli_prune(args):
    """Remove expired QA matches and release their holds; CAS GC then reclaims the bytes."""
    from saq.database.util.node import is_primary_node
    from saq.yara_qa.prune import prune_expired

    if not (is_primary_node() or args.force):
        print("skipping yara-qa prune: not the primary node (--force overrides)")
        return 0

    stats = prune_expired(dry_run=args.dry_run)
    if args.dry_run:
        print(f"would remove {stats.expired} expired match(es)")
        return 0

    print(f"removed {stats.deleted} expired match(es) in {stats.batches} batch(es), "
          f"{stats.release_failures} hold release(s) failed")
    return 0


prune_parser = yara_qa_sp.add_parser("prune", help="Remove expired QA matches (run daily from cron on the primary node).")
prune_parser.add_argument("--dry-run", action="store_true", default=False, help="Report how many matches have expired without removing them.")
prune_parser.add_argument("--force", action="store_true", default=False, help="Run even on a node that is not the primary.")
prune_parser.set_defaults(func=cli_prune)
