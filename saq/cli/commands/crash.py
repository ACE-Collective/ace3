"""``ace crash`` -- operate on analysis module crash reports from the command line.

``prune`` is what keeps the crash report directory from growing without bound. It removes the
directory *and* its index row together, so a listing never points at a directory that is gone.
"""

import logging
import os
import shutil
from datetime import datetime, timedelta

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.crash_report / saq.database imports below are inside their command functions on
# purpose, matching the convention in this package (see nrd.py): this module is imported on every
# `ace` invocation just to register its parsers, and pulling in the config and the database pool
# for that would slow down every unrelated subcommand.

crash_parser = get_cli_subparsers().add_parser("crash", help="Analysis module crash report operations.")
crash_sp = crash_parser.add_subparsers(dest="crash_cmd")


def cli_list(args):
    """List crash reports on this node, newest first."""
    from saq.crash_report import get_crash_report_root_dir, read_crash_report

    root_dir = get_crash_report_root_dir()
    if not os.path.isdir(root_dir):
        print(f"no crash reports ({root_dir} does not exist)")
        return 0

    rows = []
    for crash_dir, _ in _iter_report_dirs(root_dir):
        crash_id = os.path.basename(crash_dir)
        metadata = read_crash_report(crash_id) or {"crash_id": crash_id, "complete": False}
        rows.append(metadata)

    rows.sort(key=lambda _: _.get("timestamp") or "", reverse=True)
    rows = rows[: args.limit]

    if not rows:
        print("no crash reports")
        return 0

    print(f"{'CRASH ID':38} {'TYPE':10} {'TIMESTAMP':27} MODULE")
    for row in rows:
        print("{:38} {:10} {:27} {}".format(
            row.get("crash_id", "?"),
            row.get("crash_type", "?"),
            (row.get("timestamp") or "")[:26],
            row.get("module_path") or row.get("module_name") or "",
        ))

    return 0


def cli_prune(args):
    """Delete crash reports older than N days, along with their index rows and shared copies."""
    from saq.configuration.config import get_config
    from saq.crash_replication import delete_report, replication_enabled
    from saq.crash_report import get_crash_report_root_dir

    days = args.days if args.days is not None else get_config().crash_reporting.retention_days
    if days <= 0:
        print("retention is disabled (retention_days <= 0); nothing pruned")
        return 0

    cutoff = datetime.now() - timedelta(days=days)
    root_dir = get_crash_report_root_dir()
    if not os.path.isdir(root_dir):
        return 0

    removed = []
    for crash_dir, modified in _iter_report_dirs(root_dir):
        if modified >= cutoff:
            continue

        crash_id = os.path.basename(crash_dir)
        if args.dry_run:
            print(f"would remove {crash_dir}")
            removed.append(crash_id)
            continue

        # shared copy first, and only delete locally if that succeeded. The other order leaves a
        # report that is gone locally but still in the bucket, still servable by every node, and
        # no longer reachable by any future prune -- retention silently unenforced, on malware.
        # Keeping them in lockstep means a failed remote delete simply retries tomorrow.
        if replication_enabled() and not delete_report(crash_id):
            logging.warning(
                "keeping local crash report %s: its shared copy could not be deleted", crash_id
            )
            continue

        try:
            shutil.rmtree(crash_dir)
            removed.append(crash_id)
        except Exception as e:
            logging.error("unable to remove crash report %s: %s", crash_dir, e)

    if removed and not args.dry_run:
        _delete_rows(removed)
        _remove_empty_date_dirs(root_dir)

    print(f"{'would prune' if args.dry_run else 'pruned'} {len(removed)} crash report(s) older than {days} days")
    return 0


def cli_sync(args):
    """Replicate any local crash report that is not yet in shared storage.

    The catch-up half of replication. The inline background upload in record_module_crash() owns
    freshness; this owns eventual completeness -- it picks up reports whose upload failed, whose
    worker was killed mid-upload, or which were written by the timeout watchdog (which skips
    replication deliberately, because os._exit(1) would kill the upload thread anyway).

    Stateless: it asks the bucket what is already there rather than tracking state locally. A
    marker file in the report directory would have been cheaper per-report but would leak into the
    API's file inventory, into the archive handed to the analyst, and -- worst -- would refresh the
    directory mtime that `ace crash prune` ages reports by, silently extending retention.
    """
    from saq.crash_replication import list_replicated_ids, replicate_report, replication_enabled
    from saq.crash_report import get_crash_report_root_dir

    if not replication_enabled():
        print("crash report replication is disabled (set crash_reporting.replicate)")
        return 0

    root_dir = get_crash_report_root_dir()
    if not os.path.isdir(root_dir):
        return 0

    already = list_replicated_ids()
    uploaded = 0
    skipped = 0

    for crash_dir, _ in _iter_report_dirs(root_dir):
        crash_id = os.path.basename(crash_dir)

        # list_replicated_ids() keys off the <id>/metadata.json completeness marker, so a report
        # in this set is finished up there. Anything else -- never uploaded, or uploaded until the
        # worker died partway -- gets (re)uploaded, which is idempotent.
        if crash_id in already:
            skipped += 1
            continue

        if args.dry_run:
            print(f"would replicate {crash_id}")
            uploaded += 1
            continue

        if replicate_report(crash_dir, crash_id):
            uploaded += 1
        else:
            logging.warning("unable to replicate crash report %s", crash_id)

    print(
        f"{'would replicate' if args.dry_run else 'replicated'} {uploaded} crash report(s); "
        f"{skipped} already in shared storage"
    )
    return 0


def _iter_report_dirs(root_dir: str):
    """Yield (path, mtime) for every YYYY/MM/DD/<crash_id> directory under root_dir.

    The fixed depth is what makes this safe: it can only ever match a report directory, never a
    date level and never the root itself.
    """
    for year in sorted(os.listdir(root_dir)):
        year_dir = os.path.join(root_dir, year)
        if not os.path.isdir(year_dir):
            continue
        for month in sorted(os.listdir(year_dir)):
            month_dir = os.path.join(year_dir, month)
            if not os.path.isdir(month_dir):
                continue
            for day in sorted(os.listdir(month_dir)):
                day_dir = os.path.join(month_dir, day)
                if not os.path.isdir(day_dir):
                    continue
                for crash_id in sorted(os.listdir(day_dir)):
                    crash_dir = os.path.join(day_dir, crash_id)
                    if not os.path.isdir(crash_dir):
                        continue
                    try:
                        yield crash_dir, datetime.fromtimestamp(os.path.getmtime(crash_dir))
                    except OSError:
                        continue


def _delete_rows(crash_ids: list[str]):
    """Delete the index rows for reports whose directories are gone.

    Best effort in the same spirit as the insert: the directories are already gone, and a
    surviving row is a listing inaccuracy rather than a lost report.
    """
    try:
        from saq.database.model import AnalysisModuleCrash
        from saq.database.pool import get_db

        get_db().query(AnalysisModuleCrash).filter(
            AnalysisModuleCrash.uuid.in_(crash_ids)
        ).delete(synchronize_session=False)
        get_db().commit()
    except Exception as e:
        logging.error("unable to delete crash report index rows: %s", e)


def _remove_empty_date_dirs(root_dir: str):
    """Reap YYYY/MM/DD levels the sweep drained, deepest first."""
    for dirpath, dir_names, file_names in os.walk(root_dir, topdown=False):
        if dirpath == root_dir:
            continue
        if not dir_names and not file_names:
            try:
                os.rmdir(dirpath)
            except OSError:
                pass


crash_list_parser = crash_sp.add_parser("list", help="list crash reports stored on this node")
crash_list_parser.add_argument("--limit", type=int, default=50, help="maximum number of reports to show")
crash_list_parser.set_defaults(func=cli_list)

crash_prune_parser = crash_sp.add_parser(
    "prune",
    help="delete crash reports (and their index rows) older than the retention window",
)
crash_prune_parser.add_argument(
    "--days", type=int, default=None,
    help="override crash_reporting.retention_days",
)
crash_prune_parser.add_argument(
    "--dry-run", action="store_true", default=False,
    help="report what would be removed without removing anything",
)
crash_prune_parser.set_defaults(func=cli_prune)

crash_sync_parser = crash_sp.add_parser(
    "sync",
    help="replicate local crash reports to shared storage (catch-up for `crash_reporting.replicate`)",
)
crash_sync_parser.add_argument(
    "--dry-run", action="store_true", default=False,
    help="report what would be replicated without uploading anything",
)
crash_sync_parser.set_defaults(func=cli_sync)
