import argparse
import logging
import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration import get_config
from saq.database.model import Remediation
from saq.database.pool import get_db


remediation_parser = get_cli_subparsers().add_parser('remediation')
remediation_sp = remediation_parser.add_subparsers(dest='remediation_cmd')

def print_remediation_status(id=None, type=None, status=None, key=None, user_id=None, user=None):
    from saq.database import Remediation, User
    from sqlalchemy import or_

    query = get_db().query(Remediation).join(User)

    if id:
        query = query.filter(Remediation.id == id)

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
        print(f"insert_date: {r.insert_date} id:{r.id} type:{r.type} action:{r.action} "
              f'user_id: {r.user_id} key: "{r.key}" result: "{r.result}" comment: "{r.comment}" '
              f'successful: {r.successful} company_id: {r.company_id} lock: {r.lock} lock_time: {r.lock_time} '
              f'status: {r.status}')

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
    #print(['ID', 'STATUS', 'TYPE', 'ACTION', 'DATE', 'TARGET']))
    #print(['ID', 'STATUS', 'TYPE', 'ACTION', 'DATE', 'TARGET']))
    # NOTE: REMEDIATION_STATUS_NEW / REMEDIATION_STATUS_IN_PROGRESS are unresolved here
    # exactly as they were in the original script (moved verbatim)
    row_format = "{:<8}{:<10}{:<8}{:<9}{:<20} {}"
    print(row_format.format('ID', 'STATUS', 'TYPE', 'ACTION', 'DATE', 'TARGET'))
    for r in get_db().query(Remediation).filter(Remediation.company_id == get_config().global_settings.company_id,
                                              Remediation.status.in_([REMEDIATION_STATUS_NEW, 
                                                                      REMEDIATION_STATUS_IN_PROGRESS]))\
                                      .order_by(Remediation.id):

        print(row_format.format(r.id, r.status, r.type, r.action, str(r.insert_date), r.key))
        #print('\t'.join(map(str, [r.id, r.type, r.action, r.insert_date, r.key])))

    sys.exit(0)

display_remediation_parser = get_cli_subparsers().add_parser('display-remediation-requests', 
    help="Displays the remediation requests currently in the queue or in processing.")
display_remediation_parser.set_defaults(func=display_remediation_requests)


def clear_remediation_request(args):
    import argparse
    import saq
    from saq.database import Remediation
    from saq.remediation import REMEDIATION_STATUS_NEW
    from sqlalchemy import and_

    if not args.remediation_ids and not args.all:
        logging.error("no remediation ids were specified and the --all option was not used")
        sys.exit(1)
    
    clause = and_(Remediation.status == REMEDIATION_STATUS_NEW,
                  Remediation.lock == None,
                  Remediation.company_id == saq.COMPANY_ID)
    if not args.all and args.remediation_ids:
        clause = and_(clause, Remediation.id.in_(args.remediation_ids))

    logging.info("deleted {} requests".format(
        get_db().execute(Remediation.__table__.delete().where(clause)).rowcount))
    
    get_db().commit()
    sys.exit(0)

clear_remediation_request_parser = get_cli_subparsers().add_parser('clear-remediation-requests',
    help="Clears one or more remediation requests.")
clear_remediation_request_parser.add_argument('-a', '--all', action='store_true', default=False,
    help="Clears all remediation requests that are not locked or have expired locks.")
clear_remediation_request_parser.add_argument('remediation_ids', nargs=argparse.REMAINDER,
    help="Zero or more remediation IDs to clear which can be obtained using the display-remediation-request command.")
clear_remediation_request_parser.set_defaults(func=clear_remediation_request)
