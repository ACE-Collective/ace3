import argparse
import json
import logging
import os
import os.path
import re
import shutil
import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration import get_config
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_SNORT_SIGNATURE_ANALYSIS_V1, ANALYSIS_MODULE_USER_TAGGER
from saq.environment import get_base_dir
from saq.error.reporting import report_exception


def build_suricata_db(args):
    from saq.modules.snort import build_signature_db
    signature_path = get_analysis_module_config(ANALYSIS_MODULE_SNORT_SIGNATURE_ANALYSIS_V1).signature_path
    if args.signature_path:
        signature_path = args.signature_path

    try:
        build_signature_db(signature_path)
    except Exception as e:
        logging.error(f"unable to rebuild suricata db: {e}")
        sys.exit(1)

    sys.exit(0)

build_suricata_db_parser = get_cli_subparsers().add_parser('build-suricata-db',
    help="Builds the fast suricata signature lookup redis database.")
build_suricata_db_parser.add_argument('--signature-path', default=None,
    help="""Path to the suricata signature file to load. 
            Defaults to the signature_path option in the analysis_module_snort_signature_analysis_v1 configuration section.""")
build_suricata_db_parser.set_defaults(func=build_suricata_db)

#
# events
#

def close_event(args):
    from saq.database.model import Event, EventStatus
    from saq.database.pool import get_db
    from saq.event import get_auto_close_events

    # are we automatically closing events?
    if args.auto:
        event_ids = get_auto_close_events()
    else:
        # otherwise we're closing an event manually
        event_ids = args.event_id

    # Set the event status to the configured closed status
    for event_id in event_ids:
        if not event_id:
            continue

        try:
            logging.info(f"closing event {event_id}")
            event = get_db().query(Event).filter(Event.id == event_id).one()
            config_closed_status = get_config().events.closed_status
            closed_status = get_db().query(EventStatus).filter(EventStatus.value == config_closed_status).one()
            event.status = closed_status
            print("event closed")
        except Exception as e:
            print(f"unable to close event: {e}")
            report_exception()

    if args.dry_run:
        get_db().rollback()
    else:
        get_db().commit()

    sys.exit(0)

event_parser = get_cli_subparsers().add_parser('event')
event_sp = event_parser.add_subparsers(dest='event_cmd')

close_event_parser = event_sp.add_parser('close',
    help="Manually or automatically close an event.")
close_event_parser.add_argument("-a", "--auto", action="store_true", default=False,
    help="Automatically close any events that are set to auto close and have expired.")
close_event_parser.add_argument("-i", "--event-id", type=int, action="append", default=[],
    help="The ID of an event to close. This can be specified multiple times.")
close_event_parser.add_argument("--dry-run", action="store_true", default=False,
    help="Don't actually close the event.")
close_event_parser.set_defaults(func=close_event)

def debug(args):
    return 0

debug_parser = get_cli_subparsers().add_parser('debug')
debug_parser.set_defaults(func=debug)

def update_git_repos(args):
    from saq.git import get_configured_repos, update_repo
    for repo in get_configured_repos():
        if not args.name or repo.name in args.name:
            update_repo(repo)

    sys.exit(0)

git_parser = get_cli_subparsers().add_parser("git")
git_sp = git_parser.add_subparsers(dest="git_cmd")

git_update_parser = git_sp.add_parser("update")
git_update_parser.add_argument("name", nargs="*", help="One or more repo names to update. By default, all repos are updated.")
git_update_parser.set_defaults(func=update_git_repos)

def list_git_repos(args):
    from saq.git import get_configured_repos, repo_is_up_to_date
    from tabulate import tabulate
    repos = get_configured_repos()
    table = [
        [repo.name, repo.local_path, repo.git_url, repo.branch, repo_is_up_to_date(repo.git_url, repo.local_path, repo.branch), repo.update_frequency]
        for repo in repos
    ]
    headers = ["Name", "Local Path", "Git URL", "Branch", "Up to Date", "Update Frequency"]
    print(tabulate(table, headers=headers, tablefmt="github"))

    sys.exit(0)

git_list_parser = git_sp.add_parser("list")
git_list_parser.set_defaults(func=list_git_repos)

s3_parser = get_cli_subparsers().add_parser("s3")
s3_sp = s3_parser.add_subparsers(dest="s3_cmd")

def s3_upload_file(args) -> int:
    """Upload a file to S3 using boto3."""
    if not args.file:
        logging.error("--file is required")
        return 1
    
    if not args.bucket:
        logging.error("--bucket is required")
        return 1
    
    if not args.key:
        logging.error("--key is required")
        return 1
    
    if not os.path.exists(args.file):
        logging.error(f"File does not exist: {args.file}")
        return 1
    
    try:
        # Create S3 client using EC2 instance credentials
        import boto3
        s3_client = boto3.client('s3')
        
        # Upload the file
        logging.info(f"Uploading {args.file} to s3://{args.bucket}/{args.key}")
        s3_client.upload_file(args.file, args.bucket, args.key)
        
        logging.info(f"Successfully uploaded {args.file} to s3://{args.bucket}/{args.key}")
        return 0
    except Exception as e:
        logging.error(f"Failed to upload file: {e}")
        return 1

s3_upload_parser = s3_sp.add_parser("upload")
s3_upload_parser.add_argument("--file", help="The file to upload.")
s3_upload_parser.add_argument("--bucket", help="The bucket to upload the file to.")
s3_upload_parser.add_argument("--key", help="The key to upload the file to.")
s3_upload_parser.add_argument("--config", help="The configuration to use for the S3 client.")
s3_upload_parser.set_defaults(func=s3_upload_file)

def remove_bro_http_whitelist(args):
    removed_line = False
    src_path = os.path.join(get_base_dir(), 'bro', 'http.whitelist')
    tmp_path = os.path.join(get_base_dir(), 'bro', 'http.whitelist.tmp')

    with open(src_path, 'r') as fp_in:
        with open(tmp_path, 'a') as fp_out:
            for line in fp_in:
                if line.startswith(args.cidr):
                    logging.info("removed {}".format(line.strip()))
                    removed_line = True
                else:
                    fp_out.write(line)

    if removed_line:
        shutil.copy(tmp_path, src_path)
    
    os.remove(tmp_path)
    sys.exit(0)

remove_bro_http_whitelist_parser = get_cli_subparsers().add_parser('remove-bro-http-whitelist',
    help="Adds the given CIDR and description as a whitelist item to the bro HTTP whitelist.")
remove_bro_http_whitelist_parser.add_argument('cidr', help="The network CIDR to remove from the whitelist.")
remove_bro_http_whitelist_parser.set_defaults(func=remove_bro_http_whitelist)

def update_organization(args):

    # load the organization information
    config = get_analysis_module_config(ANALYSIS_MODULE_USER_TAGGER)

    dest_file = os.path.join(get_base_dir(), config.json_path)
    temp_file = os.path.join(get_base_dir(), '{0}.tmp'.format(config.json_path))

    # key = userID (lowercase), value = set(tags...)
    mapping = {}

    # horrible copy-pasta (sorry)
    # load ldap settings from configuration file
    ldap_server = get_config().ldap.ldap_server
    ldap_port = get_config().ldap.ldap_port or 389
    ldap_bind_user = get_config().ldap.ldap_bind_user
    ldap_bind_password = get_config().ldap.ldap_bind_password
    ldap_base_dn = get_config().ldap.ldap_base_dn

    def ldap_query(query):

        from ldap3 import Server, Connection, SIMPLE, SYNC, SUBTREE, ALL, ALL_ATTRIBUTES

        try:
            with Connection(
                Server(ldap_server, port = ldap_port, get_info = ALL), 
                auto_bind = True,
                client_strategy = SYNC,
                user=ldap_bind_user,
                password=ldap_bind_password,
                authentication=SIMPLE, 
                check_names=True) as c:

                logging.debug("running ldap query for ({0})".format(query))
                c.search(ldap_base_dn, '({0})'.format(query), SUBTREE, attributes = ALL_ATTRIBUTES)

                # a little hack to move the result into json
                response = json.loads(c.response_to_json())
                result = c.result

                if len(response['entries']) < 1:
                    return None

                # XXX not sure about the 0 here, I guess only if we only looking for one thing at a time
                return response['entries'][0]['attributes']

                # look for the result with the 'type' set to 'searchResEntry'
                #for r in response['entries']:
                    #if r['type'] == 'searchResEntry':
                        # and the what we're looking for should be in here
                    #return r['attributes']

                return None

        except Exception as e:
            logging.error("unable to perform ldap query: {0}".format(str(e)))
            report_exception()
            return None

    if os.path.exists(temp_file):
        try:
            os.remove(temp_file)
        except Exception:
            logging.error("unable to remove temp file {0}".format(temp_file))
            sys.exit(1)

    def recurse_org(group_name, limit, tag, current_user_id, current_level=0):
        # add this user
        if current_user_id.lower() not in mapping:
            mapping[current_user_id.lower()] = set()

        mapping[current_user_id.lower()].add(tag)

        current_level += 1
        if limit != 'all' and current_level > int(limit):
            return

        # figure out who works for this guy
        query_results = ldap_query("cn={0}*".format(current_user_id))
        if query_results is None:
            return

        if 'directReports' in query_results:
            for direct_report in query_results['directReports']:
                # extract the userID from this thing
                m = re.search(r'CN=([^,]+),', direct_report)
                if m is None:
                    logging.warning("unable to extract direct report info from {0}".format(direct_report))

                user_id = m.group(1)
                if user_id is not None:
                    # add this guy (and possibly all his direct reports too)
                    logging.debug("adding {0} as a direct report to {1} for group {2}".format(user_id, current_user_id, group_name))
                    recurse_org(group_name, limit, tag, user_id, current_level)

    # load all the hierarchy definitions
    for section in config.keys():
        if section.startswith('group_'):
            m = re.match(r'^group_([^_]+)$', section)
            if m is None:
                logging.error("unable to parse group name from {0}".format(section))
                continue

            group_name = m.group(1)
            parent_id, limit, tag = [x.strip() for x in config[section].split(',')]
            
            recurse_org(group_name, limit, tag, parent_id)

    # write out the json
    for key in mapping.keys():
        mapping[key] = list(mapping[key])

    with open(temp_file, 'w') as fp:
        json.dump(mapping, fp)

    # finally update the production file
    try:
        shutil.move(temp_file, dest_file)
    except Exception as e:
        logging.error("unable to move {0} to {1}: {2}".fomrat(temp_file, dest_file, str(e)))

update_organization_parsers = get_cli_subparsers().add_parser('update-organization',
    help="Updates the files used by the UserTaggingAnalyzer module.")
update_organization_parsers.set_defaults(func=update_organization)
