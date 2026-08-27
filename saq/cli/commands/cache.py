import sys

from saq.cli.cli_main import get_cli_subparsers


cache_parser = get_cli_subparsers().add_parser('cache',
    help="Analysis result cache maintenance commands.")
cache_sp = cache_parser.add_subparsers(dest='cache_cmd')

def analysis_cache_stats(args):
    """Emits an analysis result cache health heartbeat for Splunk (primary node only). Meant to be called from cron."""
    from saq.util.maintenance import emit_cache_stats
    emit_cache_stats()
    sys.exit(0)

def analysis_cache_gc(args):
    """Garbage-collects the durable analysis cache blob store tier (primary node only). Meant to be called from cron."""
    from saq.util.maintenance import gc_durable_blobs
    gc_durable_blobs(dry_run=args.dry_run)
    sys.exit(0)

def analysis_cache_local_maintenance(args):
    """Evicts stale/excess blobs from this node's local blob cache tier. Meant to be called from cron on every node."""
    from saq.util.maintenance import maintain_local_cache
    maintain_local_cache(dry_run=args.dry_run)
    sys.exit(0)

analysis_cache_stats_parser = cache_sp.add_parser('stats',
    help="Emits an analysis result cache health heartbeat for Splunk (primary node only).")
analysis_cache_stats_parser.set_defaults(func=analysis_cache_stats)

analysis_cache_gc_parser = cache_sp.add_parser('gc',
    help="Garbage-collects the durable analysis cache blob store tier (primary node only).")
analysis_cache_gc_parser.add_argument('--dry-run', required=False, dest='dry_run', default=False, action='store_true',
    help="Just report what would be garbage-collected.")
analysis_cache_gc_parser.set_defaults(func=analysis_cache_gc)

analysis_cache_local_maintenance_parser = cache_sp.add_parser('local-maintenance',
    help="Evicts stale/excess blobs from this node's local blob cache tier.")
analysis_cache_local_maintenance_parser.add_argument('--dry-run', required=False, dest='dry_run', default=False, action='store_true',
    help="Just report what would be evicted.")
analysis_cache_local_maintenance_parser.set_defaults(func=analysis_cache_local_maintenance)
