import datetime
import logging
import os
import os.path
import shutil
import sys
from uuid import uuid4

import pytz

from saq.cli.alert_sweep import (
    DEFAULT_BATCH_SIZE,
    AlertAction,
    count_node_alerts,
    iter_node_alert_id_batches,
    resolve_alert_ids_by_storage_dir,
    run_alert_sweep,
)
from saq.cli.cli_main import get_cli_subparsers
from saq.cli.cli_util import display_analysis
from saq.constants import ANALYSIS_MODE_CORRELATION, F_FILE, F_SUSPECT_FILE
from saq.configuration import get_config
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.database.util.alert import AlertFrozen, ensure_not_frozen
from saq.database.util.index import chunked
from saq.database.util.locking import acquire_lock, release_lock
from saq.gui.icon import KEY_ICON_CONFIGURATION, IconConfiguration
from saq.environment import get_base_dir, get_global_runtime_settings
from saq.search.tasks import submit_delete_task
from saq.util.relative_time import RelativeTimeError, parse_date_range
from saq.util.uuid import storage_dir_from_uuid


# ============================================================================
# alert management
#

def create_alert(args):
    from saq.analysis.root import RootAnalysis

    root = RootAnalysis(storage_dir=args.dir)
    root.tool = 'command line'
    root.tool_instance = 'n/a'
    root.alert_type = 'debug'
    root.description = 'Manual Alert'
    root.event_time = datetime.datetime.now()

    root.initialize_storage()

    root.details = { 'description': 'manually created root' }
    root.save()

alert_parser = get_cli_subparsers().add_parser('alert',
    help="Alert management commands.")
alert_sp = alert_parser.add_subparsers(dest='alert_cmd')

create_alert_parser = alert_sp.add_parser('create', aliases=['new'],
    help="Create a blank alert in the given directory.")
create_alert_parser.add_argument('dir', help="The directory to store the alert in.")
create_alert_parser.set_defaults(func=create_alert)

def _add_sweep_arguments(parser):
    parser.add_argument('--insert-date', metavar='RANGE', default=None,
        help="With --all, only the alerts inserted in this range, written the way the alert management "
             "page's date filters are: a relative token such as -90d, or '<start> - <end>' (UTC).")
    parser.add_argument('--after-id', metavar='ID', type=int, default=0,
        help="With --all, only the alerts with a database id above this one. The progress lines of an "
             "earlier run print the value that resumes it where it stopped.")
    parser.add_argument('--workers', metavar='N', type=int, default=1,
        help="Handle the alerts in this many processes (default 1). Each one holds two database connections.")
    parser.add_argument('--batch-size', metavar='N', type=int, default=DEFAULT_BATCH_SIZE,
        help=f"How many alerts are fetched and handed to a worker at a time (default {DEFAULT_BATCH_SIZE}).")

def _sweep_alerts(args, action: AlertAction, verb: str) -> int:
    """Runs action over the alerts selected by --all (narrowed by --insert-date and --after-id)
    or by the given storage directories. Returns the exit code."""
    if not args.resync_all and (args.insert_date or args.after_id):
        logging.error("--insert-date and --after-id narrow --all; pass it too")
        return 1

    if args.workers < 1 or args.batch_size < 1:
        logging.error("--workers and --batch-size must be at least 1")
        return 1

    if args.resync_all:
        insert_range = None
        if args.insert_date:
            try:
                insert_range = parse_date_range(args.insert_date, now=datetime.datetime.now(pytz.utc), tz=pytz.utc)
            except RelativeTimeError as e:
                logging.error(f"invalid --insert-date {args.insert_date!r}: {e}")
                return 1

        missing = []
        total = count_node_alerts(args.after_id, insert_range)
        batches = iter_node_alert_id_batches(args.after_id, insert_range, args.batch_size)
        after_id = args.after_id
    else:
        alert_ids, missing = resolve_alert_ids_by_storage_dir(args.dirs)
        for storage_dir in missing:
            logging.error("missing alert with storage directory %s", storage_dir)

        total = len(alert_ids)
        batches = chunked(alert_ids, args.batch_size)
        after_id = None

    result = run_alert_sweep(batches, action, total=total, workers=args.workers, verb=verb, after_id=after_id)
    return 0 if result.completed and not result.failed and not missing else 1

def _rebuild_alert_index(alert: Alert):
    logging.debug("rebuilding %s", alert.storage_dir)
    alert.rebuild_index()

def rebuild_index(args):
    """Rebuilds the indexes for the given alerts."""
    sys.exit(_sweep_alerts(args, _rebuild_alert_index, "rebuilt"))

rebuild_index_parser = alert_sp.add_parser('rebuild',
    help="Rebuilds the indexes for the given alerts.")
rebuild_index_parser.add_argument('--all', default=False, action='store_true', dest='resync_all',
    help="Resyncs all alerts that belong to this node. This can take a long time.")
_add_sweep_arguments(rebuild_index_parser)
rebuild_index_parser.add_argument('dirs', nargs='*', default=[], help="One ore more alert directories to resync.")
rebuild_index_parser.set_defaults(func=rebuild_index)

def _backfill_alert_icons(alert: Alert):
    icon_configuration_dict = (alert.root_analysis.extensions or {}).get(KEY_ICON_CONFIGURATION)
    icon_configuration = IconConfiguration.model_validate(icon_configuration_dict) if icon_configuration_dict else None
    alert.apply_icon_configuration(icon_configuration)
    get_db().commit()
    logging.debug("backfilled icon columns for %s", alert.storage_dir)

def backfill_icons(args):
    """Backfills the icon_* columns for alerts created before those columns existed."""
    sys.exit(_sweep_alerts(args, _backfill_alert_icons, "backfilled icons for"))

backfill_icons_parser = alert_sp.add_parser('backfill-icons',
    help="Backfills the alert icon columns from the root analysis for existing alerts.")
backfill_icons_parser.add_argument('--all', default=False, action='store_true', dest='resync_all',
    help="Backfills all alerts that belong to this node. This can take a long time.")
_add_sweep_arguments(backfill_icons_parser)
backfill_icons_parser.add_argument('dirs', nargs='*', default=[], help="One or more alert directories to backfill.")
backfill_icons_parser.set_defaults(func=backfill_icons)

def import_alerts(args):
    """Imports one or more alerts from the given directories."""
    from saq.analysis.root import RootAnalysis
    from saq.database.util.alert import ALERT

    for _dir in args.dirs:
        json_path = os.path.join(_dir, 'data.json')
        if not os.path.exists(json_path):
            logging.error("{} does not exist".format(json_path))
            continue

        root = RootAnalysis(storage_dir=_dir)
        if not root.load():
            logging.error("unable to load {}: try running saq upgrade {}".format(_dir, _dir))
            continue

        target_storage_dir = storage_dir_from_uuid(root.uuid)
        if os.path.exists(target_storage_dir):
            logging.error("not importing {}: {} already exists".format(_dir, target_storage_dir))
            continue

        # copy the root analysis into the system
        shutil.copytree(_dir, target_storage_dir)

        # load the alert
        root = RootAnalysis(storage_dir=target_storage_dir)
        if not root.load():
            logging.error("unable to load {}: try running saq upgrade {}".format(target_storage_dir, target_storage_dir))
            continue

        # set on the root, which the alert row and the workload entry are made from
        root.location = get_global_runtime_settings().saq_node
        root.company_id = get_config().global_settings.company_id
        root.company_name = get_config().global_settings.company_name
        root.analysis_mode = ANALYSIS_MODE_CORRELATION
        root.save()

        alert = ALERT(root)
        root.schedule()

        logging.info("imported alert {}".format(alert))

import_alert_parser = alert_sp.add_parser('import',
    help="Import one or more alert directories.")
import_alert_parser.add_argument('-r', '--reset', action='store_true', default=False, dest='reset',
    help="Reset imported alerts.")
import_alert_parser.add_argument('dirs', nargs='+', default=[], help="One ore more alert directories to import.")
import_alert_parser.set_defaults(func=import_alerts)

def delete_alerts(args):
    """Completely deletes the given alerts from both the storage system and the database."""

    for uuid in args.uuids:
        try:
            # we do them one at a time in case one of them fails
            get_db().execute(Alert.__table__.delete().where(Alert.uuid == uuid))
            get_db().commit()
            submit_delete_task(uuid)
        except Exception as e:
            get_db().rollback()
            logging.error("unable to delete alert {0}: {1}".format(uuid, str(e)))

    for uuid in args.uuids:
        storage_dir = os.path.join(get_base_dir(), storage_dir_from_uuid(uuid))
        if not os.path.exists(storage_dir):
            logging.warning("storage directory {0} does not exist".format(storage_dir))
            continue

        try:
            shutil.rmtree(storage_dir)
        except Exception as e:
            logging.error("unable to delete storage directory {0}: {1}".format(storage_dir, str(e)))

    sys.exit(0)

delete_alert_parser = alert_sp.add_parser('delete',
    help="Delete one or more alerts by UUID.")
delete_alert_parser.add_argument('uuids', nargs='+', default=[], help="One ore more alert UUIDs to delete.")
delete_alert_parser.set_defaults(func=delete_alerts)

def reset_alerts(args): 
    from saq.analysis.root import RootAnalysis

    for storage_dir in args.dirs:
        # get the storage directory of the alert
        if not os.path.exists(storage_dir):
            logging.error("storage directory {0} does not exist".format(storage_dir))
            continue

        # alerts record their storage directory relative to SAQ_HOME
        relative_dir = os.path.relpath(os.path.abspath(storage_dir), start=get_base_dir())

        # a directory that is not an alert (yet) is reset on disk only
        alert = get_db().query(Alert).filter(Alert.storage_dir.in_([storage_dir, relative_dir])).one_or_none()
        if alert:
            logging.info("loaded {} from database".format(storage_dir))
            try:
                ensure_not_frozen(alert)
            except AlertFrozen as e:
                logging.error("not resetting %s: %s", storage_dir, e)
                continue

        try:
            root = RootAnalysis(storage_dir=storage_dir)
            root.load()
            root.reset()
        except Exception as e:
            logging.error("unable to reset {}: {}".format(storage_dir, e))
            continue

        if alert:
            # saves the root and drops the index rows of the observables the reset removed
            alert.attach_root_analysis(root)
            alert.sync()
        else:
            root.save()

# reset-alerts
reset_alert_parser = alert_sp.add_parser('reset',
    help="Reset the given alerts allowing for re-analysis.")
reset_alert_parser.add_argument('dirs', nargs='+', help="One or more alert directories to reset.")
reset_alert_parser.set_defaults(func=reset_alerts)

def archive_alerts(args):
    for storage_dir in args.dirs:
        # get the storage directory of the alert
        if not os.path.exists(storage_dir):
            logging.error("storage directory {} does not exist".format(storage_dir))
            continue

        # alerts record their storage directory relative to SAQ_HOME
        relative_dir = os.path.relpath(os.path.abspath(storage_dir), start=get_base_dir())
        alert = get_db().query(Alert).filter(Alert.storage_dir.in_([storage_dir, relative_dir])).one_or_none()
        if alert is None:
            logging.warning(f"cannot find alert with storage_dir {storage_dir}")
            continue

        alert.load()
        alert.archive()
        # records the archive in the database, as the cleanup job does
        alert.sync()

# archive-alerts
archive_alert_parser = alert_sp.add_parser('archive',
    help="Archives a given alert by deleting analysis details and external files but keeping observations and tags.")
archive_alert_parser.add_argument('dirs', nargs='+', help="One or more alert directories to archive.")
archive_alert_parser.set_defaults(func=archive_alerts)

def add_observable(args):
    from saq.analysis.root import RootAnalysis
    from saq.database.model import Observable
    from saq.observables.type_hierarchy import get_all_valid_types

    db_types = {row[0] for row in get_db().query(Observable.type).distinct().all()}
    all_valid = db_types | set(get_all_valid_types())
    if args.observable_type not in all_valid:
        logging.error("invalid observable type {}".format(args.observable_type))
        sys.exit(1)

    # the uuid that is locked comes from the root on disk
    alert = RootAnalysis(storage_dir=args.dir)
    try:
        alert.load()
    except Exception:
        logging.exception("unable to load alert from %s", args.dir)
        sys.exit(1)

    lock_uuid = str(uuid4())
    if not acquire_lock(alert.uuid, lock_uuid):
        logging.error("unable to lock alert {}".format(alert))
        sys.exit(1)

    try:
        if args.observable_type == F_FILE or args.observable_type == F_SUSPECT_FILE:
            observable = alert.add_file_observable(args.observable_value, time=args.reference_time)
        else:
            observable = alert.add_observable_by_spec(args.observable_type, args.observable_value, o_time=args.reference_time)

        if observable is None:
            logging.error("unable to add {} observable {} to {}".format(args.observable_type, args.observable_value, alert))
            sys.exit(1)

        alert.save()

    finally:
        release_lock(alert.uuid, lock_uuid)

add_observable_parser = alert_sp.add_parser('add-observable',
    help="Add an observable to an existing alert and re-analyze.")
add_observable_parser.add_argument('dir', help="The path to the alert to modify.")
add_observable_parser.add_argument('observable_type', help="The type of the observable to add.")
add_observable_parser.add_argument('observable_value', help="The value of the observable.")
add_observable_parser.add_argument('-t', '--reference-time', required=False, dest='reference_time', default=None,
    help="Specify a datetime in YYYY-MM-DD HH:MM:SS format the observable should be referenced from.")
add_observable_parser.set_defaults(func=add_observable)

def reload_alerts(args):
    from saq.database.util.alert import get_alert_by_uuid

    for uuid in args.uuids:
        alert = get_alert_by_uuid(uuid)
        if alert is None:
            logging.error("unknown alert {}".format(uuid))
            continue

        try:
            ensure_not_frozen(alert)
        except AlertFrozen as e:
            logging.error("not analyzing %s: %s", uuid, e)
            continue

        # the engine analyzes in the mode of the workload entry, whatever mode the root was saved with
        alert.root_analysis.analysis_mode = ANALYSIS_MODE_CORRELATION
        alert.root_analysis.schedule()

reload_alert_parser = alert_sp.add_parser('analyze', aliases=['reload'],
    help="Force analysis (again) on one or more existing alert(s).")
reload_alert_parser.add_argument('uuids', nargs='+',
    help="One or more alert UUIDs to analyze.")
reload_alert_parser.set_defaults(func=reload_alerts)

def cleanup_alerts(args):
    """Performs system maintenance.  This is meant to be called from a cron job."""
    from saq.util.maintenance import cleanup_alerts
    cleanup_alerts(fp_days_old=args.fp_days_old, 
                   ignore_days_old=args.ignore_days_old,
                   simulated_days_old=args.simulated_days_old,
                   dry_run=args.dry_run)
    sys.exit(0)

cleanup_alerts_parsers = alert_sp.add_parser('cleanup',
    help="Deletes alerts dispositioned as ignore and archives false positive and simulated (test-run) alerts "
         "older than some amount of time.")
cleanup_alerts_parsers.add_argument('--dry-run', required=False, dest='dry_run', default=False, action='store_true',
    help="Just report how many would be deleted and archived.")
cleanup_alerts_parsers.add_argument('--fp-days-old', type=int, required=False, dest='fp_days_old', default=None, action='store',
    help='Specify how many days old an alert dispositioned as FALSE_POSITIVE should be for it to be archived.')
cleanup_alerts_parsers.add_argument('--ignore-days-old', type=int, required=False, dest='ignore_days_old', default=None, action='store',
    help='Specify how many days old an alert dispositioned as IGNORE should be for it to be deleted.')
cleanup_alerts_parsers.add_argument('--simulated-days-old', type=int, required=False, dest='simulated_days_old', default=None, action='store',
    help='Specify how many days old an alert dispositioned as SIMULATED should be for it to be archived (default svs.simulated_days). '
         'SIMULATED alerts are never deleted.')
#cleanup_alerts_parsers.add_argument('--force-delete', required=False, dest='force_delete', default=None, action='store_true',
    #help='force delete fp alerts instead of archiving them')
cleanup_alerts_parsers.set_defaults(func=cleanup_alerts)


def distribute_alerts(args):
    from saq.util.maintenance import distribute_old_alerts
    target = args.target
    if not target:
        target = get_config().global_settings.distribution_target
    days = args.days
    if not days:
        days = get_config().global_settings.distribute_days_old

    distribute_old_alerts(days, args.dry_run, target, args.max)

# distribute-alerts
distribute_alerts_parsers = alert_sp.add_parser('distribute',
    help="Moves old alerts not associated to events to another node.")
distribute_alerts_parsers.add_argument('--dry-run', required=False, default=False, action='store_true',
    help="Just report how many would be distributed.")
distribute_alerts_parsers.add_argument('--days', type=int,
    help="Specify how many days old an alert should be to be considered for distribution.")
distribute_alerts_parsers.add_argument('--max', type=int, default=0,
    help="Specify the maximum number of alerts to distribute. Defaults to all alerts that match the criteria.")
distribute_alerts_parsers.add_argument('--target',
    help="Optional target. Defaults to the value for distribution_target in the [global] configuration section.")
distribute_alerts_parsers.set_defaults(func=distribute_alerts)

def display_alert(args):
    from saq.analysis.root import RootAnalysis
    
    alert = RootAnalysis(storage_dir=args.dir)
    try:
        alert.load()
    except Exception:
        logging.exception("unable to load alert from %s", args.dir)
        sys.exit(1)

    display_analysis(alert, include_context=args.context)
    sys.exit(0)

display_alert_parser = alert_sp.add_parser('display',
    help="Displays the results of the analysis for a given alert.")
display_alert_parser.add_argument('dir', 
    help="The directory of the alert to display")
display_alert_parser.add_argument('-c', '--context', action='store_true', default=False,
    help="Include LLM context records in the output")
display_alert_parser.set_defaults(func=display_alert)
