import argparse
import logging
import sys

from sqlalchemy import and_, or_

from saq.cli.cli_main import get_cli_subparsers
from saq.database.model import Remediation, User
from saq.database.pool import get_db
from saq.remediation.types import RemediationStatus


remediation_parser = get_cli_subparsers().add_parser('remediation')
remediation_sp = remediation_parser.add_subparsers(dest='remediation_cmd')

def print_remediation_status(type=None, status=None, key=None, user_id=None, user=None):
    query = get_db().query(Remediation).join(User)

    if type:
        query = query.filter(Remediation.type == type)

    if status:
        query = query.filter(Remediation.status == status)

    if key:
        query = query.filter(Remediation.key.ilike(f'%{key}%'))

    if user_id:
        query = query.filter(Remediation.user_id == user_id)

    if user:
        query = query.filter(or_(User.username.ilike(f'%{user}%'), 
                                 User.display_name.ilike(f'%{user}%')))

    for r in query.order_by(Remediation.insert_date.desc()):
        print(f"insert_date: {r.insert_date} id:{r.id} name:{r.name} type:{r.type} action:{r.action} "
              f'user_id: {r.user_id} key: "{r.key}" result: "{r.result}" comment: "{r.comment}" '
              f'lock: {r.lock} lock_time: {r.lock_time} status: {r.status}')

def remediation_status(args):
    print_remediation_status(status=args.status,
                             type=args.type,
                             key=args.key,
                             user=args.user,
                             user_id=args.user_id)
    sys.exit(0)

remediation_status_parser = remediation_sp.add_parser('status',
    help="Shows the status of remediation requests.")
remediation_status_parser.add_argument('-s', '--status',
    help="Return results matching the given status.")
remediation_status_parser.add_argument('-t', '--type',
    help="Return results matching the given remediation type.")
remediation_status_parser.add_argument('-k', '--key', 
    help="Return results matching the given remediation target (key).")
remediation_status_parser.add_argument('-u', '--user', 
    help="Return results matching the given username or display name.")
remediation_status_parser.add_argument('--user-id', type=int,
    help="Return results matching the given user_id.")
remediation_status_parser.set_defaults(func=remediation_status)


def display_remediation_requests(args):
    row_format = "{:<8}{:<12}{:<8}{:<9}{:<20} {}"
    print(row_format.format('ID', 'STATUS', 'TYPE', 'ACTION', 'DATE', 'TARGET'))
    for r in get_db().query(Remediation).filter(Remediation.status.in_([RemediationStatus.NEW.value,
                                                                        RemediationStatus.IN_PROGRESS.value]))\
                                      .order_by(Remediation.id):

        print(row_format.format(r.id, r.status, r.type, r.action, str(r.insert_date), r.key))

    sys.exit(0)

display_remediation_parser = remediation_sp.add_parser('display', 
    help="Displays the remediation requests currently in the queue or in processing.")
display_remediation_parser.set_defaults(func=display_remediation_requests)


def clear_remediation_request(args):
    if not args.remediation_ids and not args.all:
        logging.error("no remediation ids were specified and the --all option was not used")
        sys.exit(1)

    clause = and_(Remediation.status == RemediationStatus.NEW.value,
                  Remediation.lock == None)
    if not args.all and args.remediation_ids:
        clause = and_(clause, Remediation.id.in_(args.remediation_ids))

    logging.info("deleted {} requests".format(
        get_db().execute(Remediation.__table__.delete().where(clause)).rowcount))

    get_db().commit()
    sys.exit(0)

clear_remediation_request_parser = remediation_sp.add_parser('clear',
    help="Clears one or more remediation requests.")
clear_remediation_request_parser.add_argument('-a', '--all', action='store_true', default=False,
    help="Clears all new remediation requests that are not locked.")
clear_remediation_request_parser.add_argument('remediation_ids', nargs=argparse.REMAINDER,
    help="Zero or more remediation IDs to clear, as `ace remediation display` lists them.")
clear_remediation_request_parser.set_defaults(func=clear_remediation_request)
