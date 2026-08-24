import datetime
import json
import logging
import operator
import os.path
import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.constants import ANALYSIS_MODE_CORRELATION
from saq.environment import get_global_runtime_settings
from saq.observables.file import FileObservable
from saq.util.uuid import storage_dir_from_uuid


def execute_hunt(args):
    import ace_api
    import pytz
    from saq.collectors.hunter import HunterService
    from saq.collectors.hunter.query_hunter import QueryHunt
    hunter_service = HunterService()
    hunter_service.load_hunt_managers()

    hunt_type, hunt_name = args.hunt.split(':', 1)
    if hunt_type not in hunter_service.hunt_managers:
        logging.error(f"invalid hunt type {hunt_type}")
        sys.exit(1)

    hunter_service.hunt_managers[hunt_type].load_hunts_from_config()
    hunt = hunter_service.hunt_managers[hunt_type].get_hunt(lambda hunt: hunt_name.lower() in hunt.name.lower())
    if hunt is None:
        logging.error(f"unknown hunt {hunt_name} for type {hunt_type}")
        sys.exit(1)

    # set the Hunt to manual so we don't record the execution timestamps
    hunt.manual_hunt = True
    exec_kwargs = {}

    if isinstance(hunt, QueryHunt):
        start_time = datetime.datetime.strptime(args.start_time, '%m/%d/%Y:%H:%M:%S')
        end_time = datetime.datetime.strptime(args.end_time, '%m/%d/%Y:%H:%M:%S')
        if args.timezone is not None:
            start_time = pytz.timezone(args.timezone).localize(start_time)
            end_time = pytz.timezone(args.timezone).localize(end_time)
        else:
            start_time = pytz.utc.localize(start_time)
            end_time = pytz.utc.localize(end_time)

        exec_kwargs['start_time'] = start_time
        exec_kwargs['end_time'] = end_time

        hunt.query_result_file = args.query_result_file

    if args.json_dir is not None:
        os.makedirs(args.json_dir, exist_ok=True)

    json_dir_index = 0
    for submission in hunt.execute(**exec_kwargs):
        print(submission.root.description)
        if args.details:
            for o in submission.root.observables:
                output = f"\t(*) {o.display_type} - {o.display_value}"
                if o.time:
                    output += " - {}".format(o.time)
                if o.tags:
                    output += " tags [{}]".format(','.join(o.tags))
                if o.directives:
                    output += " direc [{}]".format(','.join(o.directives))
                if o.relationships:
                    output += " rels [{}]".format(','.join([f"{r.r_type} -> {r.target.type}:{r.target.value}" for r in o.relationships]))
                #if o.pivot_links:
                    #for pv in o.pivot_links:
                        #output += f" pivot ({pv.url})[{pv.text}]"
                # TODO the other stuff
                print(output)

            for t in submission.root.tags:
                print(f"\t(+) {t}")

            if submission.root.pivot_links:
                for pv in submission.root.pivot_links:
                    print(f"\t🔗 pivot ({pv.url})[{pv.text}]")

        if args.events:
            print("BEGIN EVENTS")
            for event in submission.root.details["events"]:
                print(json.dumps(event, indent=True, sort_keys=True))
            print("END EVENTS")

        if args.json_dir is not None:
            buffer = []
            for event in submission.root.details:
                buffer.append(event)

            target_json_file = os.path.join(args.json_dir, '{}.json'.format(str(json_dir_index)))
            with open(target_json_file, 'w') as fp:
                json.dump(buffer, fp)

            with open(os.path.join(args.json_dir, 'manifest'), 'a') as fp:
                fp.write(f'{json_dir_index} = {submission.root.description}\n')

            json_dir_index += 1

        observables = []
        for observable in submission.root.observables:
            #observable_json = observable.json
            observable_json = {
                'type': observable.type,
                'value': observable.value,
                'time': observable.time,
                'tags': observable.tags,
                'directives': observable.directives,
                'limited_analysis': observable.limited_analysis,
                #'pivot_links': observable.pivot_links,
                #'file_path': observable.file_path,
            }

            if isinstance(observable, FileObservable):
                observable_json['file_path'] = observable.file_path

            observables.append(observable_json)

        if args.submit_alerts_local:
            from saq.database.util.alert import ALERT

            # we duplicate because we could be sending multiple copies to multiple remote nodes
            new_root = submission.root.duplicate()
            new_root.move(storage_dir_from_uuid(new_root.uuid))
            new_root.save()

            # if we received a submission for correlation mode then we go ahead and add it to the database
            if new_root.analysis_mode == ANALYSIS_MODE_CORRELATION:
                ALERT(new_root)

            new_root.schedule()
        elif args.submit_alerts is not None:
            result = ace_api.submit(
                submission.root.description,
                remote_host=args.submit_alerts,
                ssl_verification=get_global_runtime_settings().ca_chain_path,
                analysis_mode=submission.root.analysis_mode,
                tool=submission.root.tool,
                tool_instance=submission.root.tool_instance,
                type=submission.root.alert_type,
                event_time=submission.root.event_time,
                details=submission.root.details,
                observables=observables,
                tags=submission.root.tags,
                queue=submission.root.queue,
                instructions=submission.root.instructions,
                extensions=submission.root.extensions,
                # LOL this awful "api" -- these params are backwards to how they are actually sent :(
                files=[(_.file_path, open(_.full_path, "rb")) for _ in submission.root.observables if isinstance(_, FileObservable)]
            )

hunt_parser = get_cli_subparsers().add_parser('hunt')
hunt_sp = hunt_parser.add_subparsers(dest='hunt_cmd')

execute_hunt_parser = hunt_sp.add_parser('execute',
    help="Execute a hunt with the given parameters.")
execute_hunt_parser.add_argument('hunt',
    help="The name of the hunt to execute in the format type:name where type is the hunt type.")
execute_hunt_parser.add_argument('-s', '--start-time', required=False, default=None,
    help="Optional start time. Time spec absolute format is MM/DD/YYYY:HH:MM:SS")
execute_hunt_parser.add_argument('-e', '--end-time', required=False, default=None,
    help="Optional end time. Time spec absolute format is MM/DD/YYYY:HH:MM:SS")
execute_hunt_parser.add_argument('-z', '--timezone', required=False, default=None,
    help="Optional time zone for start time and end time. Defaults to local time zone.")
execute_hunt_parser.add_argument('-v', '--events', required=False, default=False, action='store_true',
    help="Output the events instead of the submissions.")
execute_hunt_parser.add_argument('--json-dir', required=False, default=None,
    help="Store the events as JSON files in the given directory, one per submission created.")
execute_hunt_parser.add_argument('-d', '--details', required=False, default=False, action='store_true',
    help="Include the details of the submissions in the output.")
execute_hunt_parser.add_argument('--submit-alerts', required=False, default=None, 
    help="Submit as alerts to the given host[:port]")
execute_hunt_parser.add_argument('--submit-alerts-local', required=False, default=False, action='store_true', 
    help="Submit as alerts to the local ACE instance")
execute_hunt_parser.add_argument('--query-result-file', required=False, default=None,
    help="Valid only for query hunts. Save the raw query results to the given file.")
execute_hunt_parser.set_defaults(func=execute_hunt)

def verify_hunt(args):
    from saq.collectors.hunter import HunterCollector
    collector = HunterCollector()
    collector.load_hunt_managers()
    failed = False
    for hunt_type, manager in collector.hunt_managers.items():
        manager.load_hunts_from_config()
        if manager.failed_ini_files:
            sys.stderr.write(f"ERROR: unable to load {len(manager.failed_ini_files)} {hunt_type} hunts\n")
            failed = True

    if failed:
        sys.exit(1)

    print("hunt syntax verified")
    sys.exit(0)

verify_hunt_parser = hunt_sp.add_parser('verify',
    help="Verifies that all configured hunts are able to load.")
verify_hunt_parser.set_defaults(func=verify_hunt)

# XXX broken
def list_hunts(args):
    from saq.collectors.hunter import HunterCollector
    collector = HunterCollector()
    collector.load_hunt_managers()
    for hunt_type, manager in sorted(collector.hunt_managers.items()):
        manager.load_hunts_from_config()
        for hunt in sorted(sorted(manager.hunts, key=operator.attrgetter('name')), 
                key=operator.attrgetter('enabled'), reverse=True):
            ini_file = os.path.splitext(os.path.basename(hunt.ini_path))[0]
            status = "E" if hunt.enabled else "D"
            print(f"{status} {hunt_type}:{ini_file} - {hunt.name}")

    sys.exit(0)

list_hunts_parser = hunt_sp.add_parser('list',
    help="""List the available hunts.
    The format of the output is
    E|D type:name - description
    E: enabled
    D: disabled""")
list_hunts_parser.set_defaults(func=list_hunts)

def list_hunt_types(args):
    from saq.collectors.hunter import HunterCollector
    collector = HunterCollector()
    collector.load_hunt_managers()
    for hunt_type in collector.hunt_managers.keys():
        print(hunt_type)

    sys.exit(0)

list_hunt_types_parser = hunt_sp.add_parser('list-types',
    help="List the available hunting types.")
list_hunt_types_parser.set_defaults(func=list_hunt_types)

# XXX broken
def list_saved_searches(args):
    from saq.splunk_ss import load_saved_searches
    for saved_search in load_saved_searches(args.section, args.user, args.app):
        print(saved_search.name)

    sys.exit(0)

list_saved_searches_parser = hunt_sp.add_parser('list-saved-searches',
    help="List all managed saved searches.")
list_saved_searches_parser.add_argument("-s", "--section", default="splunk_cloud",
    help="The splunk configuration section in the INI files to use.")
list_saved_searches_parser.add_argument("-u", "--user", default="nobody",
    help="The splunk services namespace user.")
list_saved_searches_parser.add_argument("-a", "--app", default="ftb_search_infosec",
    help="The splunk services namespace app.")
list_saved_searches_parser.set_defaults(func=list_saved_searches)

# XXX broken
def publish_saved_searches(args):
    from saq.splunk_ss import load_ini_files, publish_saved_search
    for saved_search in load_ini_files(args.dir):
        publish_saved_search(saved_search)

    sys.exit(0)

publish_saved_searches_parser = hunt_sp.add_parser('publish-saved-searches',
    help="Publish all saved searches specified in the given directory.")
publish_saved_searches_parser.add_argument("-d", "--dir",
    help="The directory to load the saved searches from.")
publish_saved_searches_parser.set_defaults(func=publish_saved_searches)

# XXX broken
def delete_saved_search(args):
    from saq.splunk_ss import delete_saved_search, load_from_ini, SavedSearch
    search = None
    if args.file_path:
        search = load_from_ini(args.file_path)
    else:
        search = SavedSearch(
            name=args.name,
            type=args.section,
            ns_user=args.user,
            ns_app=args.app,
        )

    delete_saved_search(search)
    sys.exit(0)

delete_saved_search_parser = hunt_sp.add_parser('delete-saved-search',
    help="""Deletes a saved search. An existing ini file can be specified, or individual options.
    NOTE if you specify --file you do NOT need to specify the other arguments.
    """)
delete_saved_search_parser.add_argument("-f", "--file-path",
    help="The .savedsearch INI file specifying the saved search to delete.")
delete_saved_search_parser.add_argument("-s", "--section", default="splunk_cloud",
    help="The splunk configuration section in the INI files to use.")
delete_saved_search_parser.add_argument("-u", "--user", default="nobody",
    help="The splunk services namespace user.")
delete_saved_search_parser.add_argument("-a", "--app", default="ftb_search_infosec",
    help="The splunk services namespace app.")
delete_saved_search_parser.add_argument("-n", "--name", default="ftb_search_infosec",
    help="The name of the saved search to delete.")
delete_saved_search_parser.set_defaults(func=delete_saved_search)

# XXX broken
def sync_saved_searches(args):
    from saq.splunk_ss import sync_saved_searches
    sync_saved_searches(args.dir, config=args.section, ns_user=args.user, ns_app=args.app)
    sys.exit(0)

sync_saved_searches_parser = hunt_sp.add_parser('sync-saved-searches',
    help="Sync all saved searches specified in the given directory.")
sync_saved_searches_parser.add_argument("-d", "--dir",
    help="The directory to load the saved searches from.")
sync_saved_searches_parser.add_argument("-s", "--section", default="splunk_cloud",
    help="The splunk configuration section in the INI files to use.")
sync_saved_searches_parser.add_argument("-u", "--user", default="nobody",
    help="The splunk services namespace user.")
sync_saved_searches_parser.add_argument("-a", "--app", default="ftb_search_infosec",
    help="The splunk services namespace app.")
sync_saved_searches_parser.set_defaults(func=sync_saved_searches)
