import logging
import os
import os.path
import shutil
import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration import get_config
from saq.environment import get_base_dir
from saq.error.reporting import report_exception


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

    with open(src_path, 'r') as fp_in, open(tmp_path, 'a') as fp_out:
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

bro_parser = get_cli_subparsers().add_parser('bro',
    help="Bro network monitor operations.")
bro_sp = bro_parser.add_subparsers(dest='bro_cmd')

remove_bro_http_whitelist_parser = bro_sp.add_parser('remove-http-whitelist',
    help="Removes the given CIDR from the bro HTTP whitelist.")
remove_bro_http_whitelist_parser.add_argument('cidr', help="The network CIDR to remove from the whitelist.")
remove_bro_http_whitelist_parser.set_defaults(func=remove_bro_http_whitelist)

