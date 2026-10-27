"""``ace file-collection`` -- maintenance of the file collection service's files.

``prune`` removes this node's files of collections no alert asked for once they are older than
service_file_collection.retention_days; the daily cron task runs it on every node.
"""

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration.config import get_service_config
from saq.constants import SERVICE_FILE_COLLECTION
from saq.file_collection.storage import prune_unattached_files

file_collection_parser = get_cli_subparsers().add_parser(
    "file-collection", help="Maintain the files the file collection service collects.")
file_collection_sp = file_collection_parser.add_subparsers(dest="file_collection_cmd")


def cli_prune(args):
    try:
        retention_days = get_service_config(SERVICE_FILE_COLLECTION).retention_days
    except ValueError:
        # a site without the file collection service has nothing to prune
        print("skipping file-collection prune: the file_collection service is not configured")
        return 0

    removed = prune_unattached_files(retention_days, dry_run=args.dry_run)
    print(f"{'would remove' if args.dry_run else 'removed'} {removed} collection(s) older than {retention_days} days")
    return 0


prune_parser = file_collection_sp.add_parser(
    "prune", help="Remove this node's files of collections no alert asked for once they expire (run daily from cron).")
prune_parser.add_argument("--dry-run", action="store_true", default=False,
                          help="Report what would be removed without removing it.")
prune_parser.set_defaults(func=cli_prune)
