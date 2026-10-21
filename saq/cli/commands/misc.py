import logging
import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration import get_config


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
            logging.exception(f"unable to close event {event_id}: {e}")

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
    from saq.git import get_configured_repos
    for repo in get_configured_repos():
        if not args.name or repo.config.name in args.name:
            repo.update()

    sys.exit(0)

git_parser = get_cli_subparsers().add_parser("git")
git_sp = git_parser.add_subparsers(dest="git_cmd")

git_update_parser = git_sp.add_parser("update")
git_update_parser.add_argument("name", nargs="*", help="One or more repo names to update. By default, all repos are updated.")
git_update_parser.set_defaults(func=update_git_repos)

def list_git_repos(args):
    from saq.git import get_configured_repos
    from tabulate import tabulate
    repos = get_configured_repos()
    table = [
        [repo.config.name, repo.config.local_path, repo.config.git_url, repo.config.branch, repo.repo_is_up_to_date(), repo.config.update_frequency]
        for repo in repos
    ]
    headers = ["Name", "Local Path", "Git URL", "Branch", "Up to Date", "Update Frequency"]
    print(tabulate(table, headers=headers, tablefmt="github"))

    sys.exit(0)

git_list_parser = git_sp.add_parser("list")
git_list_parser.set_defaults(func=list_git_repos)
