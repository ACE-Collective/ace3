import datetime
import logging
import os
import os.path
import shutil
import sys
import traceback

from saq.cli.cli_main import get_cli_subparsers
from saq.cli.cli_util import display_analysis
from saq.constants import ANALYSIS_MODE_CORRELATION, F_FILE, F_SUSPECT_FILE
from saq.configuration import get_config
from saq.database.pool import get_db
from saq.environment import get_data_dir, get_global_runtime_settings
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

create_alert_parser = get_cli_subparsers().add_parser('create-alert',
    help="Create a blank alert in the given directory.")
create_alert_parser.add_argument('dir', help="The directory to store the alert in.")
create_alert_parser.set_defaults(func=create_alert)

create_alert_parser = alert_sp.add_parser('create', aliases=['new'],
    help="Create a blank alert in the given directory.")
create_alert_parser.add_argument('dir', help="The directory to store the alert in.")
create_alert_parser.set_defaults(func=create_alert)

def rebuild_index(args):
    """Rebuilds the indexes for the given alerts."""
    from saq.database.model import Alert
    from saq.database import get_db_connection

    storage_dirs = []
    if args.resync_all:
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""SELECT storage_dir FROM alerts WHERE location = %s""", (get_global_runtime_settings().saq_node,))
            for row in c:
                storage_dirs.append(row[0])
    else:
        storage_dirs = args.dirs

    logging.info("rebuilding indexes for {} alerts".format(len(storage_dirs)))

    for storage_dir in storage_dirs:
        logging.info("rebuilding {}".format(storage_dir))
        alert = get_db().query(Alert).filter(Alert.storage_dir==storage_dir).first()
        if alert is None:
            logging.error(f"missing alert with storage directory {storage_dir}")
            continue

        try:
            if not alert.load():
                logging.error("unable to load {}".format(alert))
                continue

            alert.rebuild_index()

        except Exception as e:
            logging.error("rebuild failure on {}: {} ({})".format(storage_dir, e, type(e)))
            continue

        finally:
            get_db().commit()

    sys.exit(0)

rebuild_index_parser = get_cli_subparsers().add_parser('rebuild-index',
    help="Rebuilds the indexes for the given alerts.")
rebuild_index_parser.add_argument('--all', default=False, action='store_true', dest='resync_all',
    help="Resyncs all alerts that belong to this node. This can take a long time.")
rebuild_index_parser.add_argument('dirs', nargs='*', default=[], help="One ore more alert directories to resync.")
rebuild_index_parser.set_defaults(func=rebuild_index)

rebuild_index_parser = alert_sp.add_parser('rebuild',
    help="Rebuilds the indexes for the given alerts.")
rebuild_index_parser.add_argument('--all', default=False, action='store_true', dest='resync_all',
    help="Resyncs all alerts that belong to this node. This can take a long time.")
rebuild_index_parser.add_argument('dirs', nargs='*', default=[], help="One ore more alert directories to resync.")
rebuild_index_parser.set_defaults(func=rebuild_index)

def backfill_icons(args):
    """Backfills the icon_* columns for alerts created before those columns existed."""
    from saq.database.model import Alert
    from saq.database import get_db_connection
    from saq.gui.icon import IconConfiguration, KEY_ICON_CONFIGURATION

    storage_dirs = []
    if args.resync_all:
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""SELECT storage_dir FROM alerts WHERE location = %s""", (get_global_runtime_settings().saq_node,))
            for row in c:
                storage_dirs.append(row[0])
    else:
        storage_dirs = args.dirs

    logging.info("backfilling icon columns for %s alerts", len(storage_dirs))

    for storage_dir in storage_dirs:
        alert = get_db().query(Alert).filter(Alert.storage_dir == storage_dir).first()
        if alert is None:
            logging.error("missing alert with storage directory %s", storage_dir)
            continue

        try:
            if not alert.load():
                logging.error("unable to load %s", storage_dir)
                continue

            icon_configuration_dict = (alert.root_analysis.extensions or {}).get(KEY_ICON_CONFIGURATION)
            icon_configuration = IconConfiguration.model_validate(icon_configuration_dict) if icon_configuration_dict else None
            alert.apply_icon_configuration(icon_configuration)
            get_db().commit()
            logging.info("backfilled icon columns for %s", storage_dir)

        except Exception as e:
            get_db().rollback()
            logging.error("icon backfill failure on %s: %s (%s)", storage_dir, e, type(e))
            continue

    sys.exit(0)

backfill_icons_parser = alert_sp.add_parser('backfill-icons',
    help="Backfills the alert icon columns from the root analysis for existing alerts.")
backfill_icons_parser.add_argument('--all', default=False, action='store_true', dest='resync_all',
    help="Backfills all alerts that belong to this node. This can take a long time.")
backfill_icons_parser.add_argument('dirs', nargs='*', default=[], help="One or more alert directories to backfill.")
backfill_icons_parser.set_defaults(func=backfill_icons)

def import_alerts(args):
    """Imports one or more alerts from the given directories."""
    from saq.analysis.root import RootAnalysis
    from saq.database.util.alert import ALERT, get_alert_by_uuid

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

        # copy the root analysis into the system
        shutil.copytree(_dir, target_storage_dir)

        # load the alert
        root = RootAnalysis(storage_dir=target_storage_dir)
        if not root.load():
            logging.error("unable to load {}: try running saq upgrade {}".format(target_storage_dir, target_storage_dir))
            continue

        ALERT(root)
        alert = get_alert_by_uuid(root.uuid)

        # are we resetting the alerts?
        #if args.reset:
            #alert.reset()

        # change a few more things
        alert.location = get_global_runtime_settings().saq_node
        alert.company_id = get_config().global_settings.company_id
        alert.company_name = get_config().global_settings.company_name
        alert.analysis_mode = ANALYSIS_MODE_CORRELATION

        # sync it to the database
        alert.sync()

        # request analysis
        alert.root_analysis.schedule()

        logging.info("imported alert {}".format(alert))

import_alert_parser = get_cli_subparsers().add_parser('import-alerts',
    help="Import one or more alert directories.")
import_alert_parser.add_argument('-r', '--reset', action='store_true', default=False, dest='reset',
    help="Reset imported alerts.")
import_alert_parser.add_argument('dirs', nargs='+', default=[], help="One ore more alert directories to import.")
import_alert_parser.set_defaults(func=import_alerts)

import_alert_parser = alert_sp.add_parser('import',
    help="Import one or more alert directories.")
import_alert_parser.add_argument('-r', '--reset', action='store_true', default=False, dest='reset',
    help="Reset imported alerts.")
import_alert_parser.add_argument('dirs', nargs='+', default=[], help="One ore more alert directories to import.")
import_alert_parser.set_defaults(func=import_alerts)

def delete_alerts(args):
    """Completely deletes the given alerts from both the storage system and the database."""
    import saq
    from saq.database import Alert, DatabaseSession

    for uuid in args.uuids:
        try:
            # we do them one at a time in case one of them fails
            session = DatabaseSession()
            session.execute(Alert.__table__.delete().where(Alert.uuid == uuid))
            session.commit()
            session.close()
        except Exception as e:
            logging.error("unable to delete alert {0}: {1}".format(uuid, str(e)))

    for uuid in args.uuids:
        storage_dir = os.path.join(saq.SAQ_HOME, get_data_dir(), get_config().global_settings.node, uuid[0:3], uuid)
        if not os.path.exists(storage_dir):
            logging.warning("storage directory {0} does not exist".format(storage_dir))
            continue

        try:
            shutil.rmtree(storage_dir)
        except Exception as e:
            logging.error("unable to delete storage directory {0}: {1}".format(storage_dir, str(e)))

    sys.exit(0)

delete_alert_parser = get_cli_subparsers().add_parser('delete-alerts',
    help="Delete one or more alerts by UUID.")
delete_alert_parser.add_argument('uuids', nargs='+', default=[], help="One ore more alert UUIDs to delete.")
delete_alert_parser.set_defaults(func=delete_alerts)

delete_alert_parser = alert_sp.add_parser('delete',
    help="Delete one or more alerts by UUID.")
delete_alert_parser.add_argument('uuids', nargs='+', default=[], help="One ore more alert UUIDs to delete.")
delete_alert_parser.set_defaults(func=delete_alerts)

def reset_alerts(args): 
    from saq.analysis.root import RootAnalysis
    from saq.database import Alert, DatabaseSession

    for storage_dir in args.dirs:
        # get the storage directory of the alert
        if not os.path.exists(storage_dir):
            logging.error("storage directory {0} does not exist".format(storage_dir))
            continue

        session = None

        # try to load it from the database first
        try:
            session = DatabaseSession()
            root = session.query(Alert).filter(Alert.storage_dir==storage_dir).one()
            logging.info("loaded {} from database".format(storage_dir))
        except:
            root = RootAnalysis()
            root.storage_dir = storage_dir
        finally:
            if session:
                session.close()

        try:
            root.load()
        except Exception as e:
            logging.error("unable to load {}: {}".format(root.storage_dir, e))
            continue

        root.reset()
        root.save()

# reset-alerts
reset_alert_parser = get_cli_subparsers().add_parser('reset-alerts',
    help="Reset the given alerts allowing for re-analysis.")
reset_alert_parser.add_argument('dirs', nargs='+', help="One or more alert directories to reset.")
reset_alert_parser.set_defaults(func=reset_alerts)

reset_alert_parser = alert_sp.add_parser('reset',
    help="Reset the given alerts allowing for re-analysis.")
reset_alert_parser.add_argument('dirs', nargs='+', help="One or more alert directories to reset.")
reset_alert_parser.set_defaults(func=reset_alerts)

def archive_alerts(args):
    from saq.database.model import load_alert_by_storage_dir

    for storage_dir in args.dirs:
        # get the storage directory of the alert
        if not os.path.exists(storage_dir):
            logging.error("storage directory {} does not exist".format(storage_dir))
            continue

        alert = load_alert_by_storage_dir(storage_dir)
        if alert is None:
            logging.warning(f"cannot find alert with storage_dir {storage_dir}")
            continue

        alert.archive()
        alert.root_analysis.save()

# archive-alerts
archive_alert_parser = get_cli_subparsers().add_parser('archive-alerts',
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

    # get the alert to modify
    alert = RootAnalysis(storage_dir=args.dir)
    if not alert.lock():
        logging.error("unable to lock alert {}".format(alert))
        sys.exit(1)

    try:
        alert.load()

        if args.observable_type == F_FILE or args.observable_type == F_SUSPECT_FILE:
            try:
                dest_path = os.path.join(alert.storage_dir, os.path.basename(args.observable_value))
                shutil.copy(args.observable_value, dest_path)
                args.observable_value = os.path.relpath(dest_path, start=alert.storage_dir)
            except Exception as e:
                logging.error("unable to copy file into storage directory: {0}".format(str(e)))

        alert.add_observable(args.observable_type, args.observable_value, o_time=args.reference_time)
        alert.save()

    except Exception as e:
        logging.error(str(e))
        traceback.print_exc()
        sys.exit(1)

    finally:
        alert.unlock()

# add-observable
add_observable_parser = get_cli_subparsers().add_parser('add-observable',
    help="Add an observable to an existing alert and re-analyze.")
add_observable_parser.add_argument('dir', help="The path to the alert to modify.")
add_observable_parser.add_argument('observable_type', help="The type of the observable to add.")
add_observable_parser.add_argument('observable_value', help="The value of the observable.")
add_observable_parser.add_argument('-t', '--reference-time', required=False, dest='reference_time', default=None,
    help="Specify a datetime in YYYY-MM-DD HH:MM:SS format the observable should be referenced from.")
add_observable_parser.set_defaults(func=add_observable)

add_observable_parser = alert_sp.add_parser('add-observable',
    help="Add an observable to an existing alert and re-analyze.")
add_observable_parser.add_argument('dir', help="The path to the alert to modify.")
add_observable_parser.add_argument('observable_type', help="The type of the observable to add.")
add_observable_parser.add_argument('observable_value', help="The value of the observable.")
add_observable_parser.add_argument('-t', '--reference-time', required=False, dest='reference_time', default=None,
    help="Specify a datetime in YYYY-MM-DD HH:MM:SS format the observable should be referenced from.")
add_observable_parser.set_defaults(func=add_observable)

def reload_alerts(args):
    from saq.database import Alert, DatabaseSession

    # generate the list of alerts to reload
    session = DatabaseSession()
    for uuid in args.uuids:
        alert = session.query(Alert).filter(Alert.uuid == uuid).one()
        #alert.request_correlation()
        alert.analysis_mode = ANALYSIS_MODE_CORRELATION
        alert.schedule()

reload_alert_parser = get_cli_subparsers().add_parser('reload-alerts',
    help="Force analysis (again) on one or more existing alert(s).")
reload_alert_parser.add_argument('uuids', nargs='+',
    help="One or more alert UUIDs to analyze.")
reload_alert_parser.set_defaults(func=reload_alerts)

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
                   dry_run=args.dry_run)
    sys.exit(0)

cleanup_alerts_parsers = get_cli_subparsers().add_parser('cleanup-alerts',
    help="Removes alerts dispositioned as ignore or false positive and older than some amount of time.")
cleanup_alerts_parsers.add_argument('--dry-run', required=False, dest='dry_run', default=False, action='store_true',
    help="Just report how many would be deleted and archived.")
cleanup_alerts_parsers.add_argument('--fp-days-old', type=int, required=False, dest='fp_days_old', default=None, action='store',
    help='Specify how many days old an alert dispositioned as FALSE_POSITIVE should be for it to be archived.')
cleanup_alerts_parsers.add_argument('--ignore-days-old', type=int, required=False, dest='ignore_days_old', default=None, action='store',
    help='Specify how many days old an alert dispositioned as IGNORE should be for it to be deleted.')
#cleanup_alerts_parsers.add_argument('--force-delete', required=False, dest='force_delete', default=None, action='store_true',
    #help='force delete fp alerts instead of archiving them')
cleanup_alerts_parsers.set_defaults(func=cleanup_alerts)

cleanup_alerts_parsers = alert_sp.add_parser('cleanup',
    help="Removes alerts dispositioned as ignore or false positive and older than some amount of time.")
cleanup_alerts_parsers.add_argument('--dry-run', required=False, dest='dry_run', default=False, action='store_true',
    help="Just report how many would be deleted and archived.")
cleanup_alerts_parsers.add_argument('--fp-days-old', type=int, required=False, dest='fp_days_old', default=None, action='store',
    help='Specify how many days old an alert dispositioned as FALSE_POSITIVE should be for it to be archived.')
cleanup_alerts_parsers.add_argument('--ignore-days-old', type=int, required=False, dest='ignore_days_old', default=None, action='store',
    help='Specify how many days old an alert dispositioned as IGNORE should be for it to be deleted.')
#cleanup_alerts_parsers.add_argument('--force-delete', required=False, dest='force_delete', default=None, action='store_true',
    #help='force delete fp alerts instead of archiving them')
cleanup_alerts_parsers.set_defaults(func=cleanup_alerts)

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

analysis_cache_stats_parser = get_cli_subparsers().add_parser('analysis-cache-stats',
    help="Emits an analysis result cache health heartbeat for Splunk (primary node only).")
analysis_cache_stats_parser.set_defaults(func=analysis_cache_stats)

analysis_cache_gc_parser = get_cli_subparsers().add_parser('analysis-cache-gc',
    help="Garbage-collects the durable analysis cache blob store tier (primary node only).")
analysis_cache_gc_parser.add_argument('--dry-run', required=False, dest='dry_run', default=False, action='store_true',
    help="Just report what would be garbage-collected.")
analysis_cache_gc_parser.set_defaults(func=analysis_cache_gc)

analysis_cache_local_maintenance_parser = get_cli_subparsers().add_parser('analysis-cache-local-maintenance',
    help="Evicts stale/excess blobs from this node's local blob cache tier.")
analysis_cache_local_maintenance_parser.add_argument('--dry-run', required=False, dest='dry_run', default=False, action='store_true',
    help="Just report what would be evicted.")
analysis_cache_local_maintenance_parser.set_defaults(func=analysis_cache_local_maintenance)

def distribute_alerts(args):
    from saq.util.maintenance import distribute_old_alerts
    target = args.target
    if not target:
        target = get_config().global_settings.distribution_target
    days = args.days
    if not days:
        days = get_config().global_settings.distribute_days_old

    distribute_old_alerts(days, args.dry_run, target, args.max)

distribute_alerts_parsers = get_cli_subparsers().add_parser('distribute-alerts',
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
    except Exception as e:
        logging.error("unable to load alert from {}: {}".format(args.dir, str(e)))
        traceback.print_exc()
        sys.exit(1)

    display_analysis(alert, include_context=args.context)
    sys.exit(0)

display_alert_parser = get_cli_subparsers().add_parser('display-alert',
    help="Displays the results of the analysis for a given alert.")
display_alert_parser.add_argument('dir', 
    help="The directory of the alert to display")
display_alert_parser.add_argument('-c', '--context', action='store_true', default=False,
    help="Include LLM context records in the output")
display_alert_parser.set_defaults(func=display_alert)

display_alert_parser = alert_sp.add_parser('display',
    help="Displays the results of the analysis for a given alert.")
display_alert_parser.add_argument('dir', 
    help="The directory of the alert to display")
display_alert_parser.set_defaults(func=display_alert)
