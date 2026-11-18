"""``ace email-archive`` -- the email archive (docs/EMAIL_ARCHIVE.md).

``migrate`` copies the Message-IDs of the archive from before the CAS into archived_messages and moves
its files into the email_archive pool. Each node kept the emails it archived itself, so it runs on
every node that archived email, and it is safe to run again (or to stop and resume).
"""

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.email_archive imports below are inside their command functions on purpose, matching the
# convention in this package (see cas.py): this module is imported on every `ace` invocation just to
# register its parsers, and the migration pulls in the CAS and the database models.

email_archive_parser = get_cli_subparsers().add_parser("email-archive", help="The email archive (docs/EMAIL_ARCHIVE.md).")
email_archive_sp = email_archive_parser.add_subparsers(dest="email_archive_cmd")


def cli_migrate(args):
    """Move the emails of the old archive directory into the email archive's CAS pool. Exits 2 when
    any file could not be migrated (it is kept, and logged)."""
    # local: see the NOTE at the top of this module
    from saq.crypto import is_encryption_initialized
    # local: the migration loads the CAS and the ORM models
    from saq.email_archive.migrate import get_legacy_archive_dir, migrate_legacy_archive

    if not is_encryption_initialized():
        print("error: the old archive is encrypted and the encryption key is not available")
        return 1

    archive_dir = args.archive_dir or get_legacy_archive_dir()
    stats = migrate_legacy_archive(archive_dir, dry_run=args.dry_run, keep_source=args.keep_source, limit=args.limit)

    verb = "would migrate" if args.dry_run else "migrated"
    copied = "message-id row(s) to copy" if args.dry_run else "message-id row(s) copied"
    print(f"{stats.rows_backfilled} {copied} into archived_messages")
    print(f"{archive_dir}: scanned {stats.scanned} file(s), {verb} {stats.migrated} ({stats.bytes_migrated} bytes), "
          f"{stats.already_present} already in the pool, {stats.unreferenced} with no archive row (left for the "
          f"archive cron task), {stats.unrecognized} unrecognized, {stats.failed} failed, "
          f"{stats.sources_removed} old file(s) removed")
    if stats.stopped_at_limit:
        print(f"stopped after {args.limit} file(s) (--limit); run again to continue")

    return 2 if stats.failed else 0


migrate_parser = email_archive_sp.add_parser(
    "migrate", help="Copy the old archive's Message-IDs and move its files into the email_archive pool.")
migrate_parser.add_argument("--archive-dir", default=None,
                            help="The old archive directory (default: email_archive.archive_dir under the data directory).")
migrate_parser.add_argument("--dry-run", action="store_true", default=False,
                            help="Report what would be migrated without changing anything.")
migrate_parser.add_argument("--keep-source", action="store_true", default=False,
                            help="Leave each old file in place after the pool has it (by default it is removed).")
migrate_parser.add_argument("--limit", type=int, default=None,
                            help="Stop after migrating this many emails.")
migrate_parser.set_defaults(func=cli_migrate)
