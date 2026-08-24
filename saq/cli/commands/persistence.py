import logging
import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.database.model import Persistence, PersistenceSource
from saq.database.pool import get_db


persistence_parser = get_cli_subparsers().add_parser('persistence', aliases=['per'])
persistence_sp = persistence_parser.add_subparsers(dest='persistence_cmd')

def list_persistence(args):
    source_query = get_db().query(PersistenceSource)
    if args.source:
        source_query = source_query.filter(PersistenceSource.name.like('%{}%'.format(args.source)))

    for source in source_query.order_by(PersistenceSource.name):
        if args.keys or args.name:
            query = get_db().query(Persistence).filter(Persistence.source_id == source.id)
            if args.name:
                 query = query.filter(Persistence.uuid.like(f'%{args.name}%'))
            if not args.temporal:
                query = query.filter(Persistence.permanent == 1)

            for persistence in query.order_by(Persistence.uuid):
                print(f"{source.name} {persistence.uuid}")
        else:
            print(source.name)

    sys.exit(0)

list_persistence_parser = persistence_sp.add_parser('list',
    help="List all persistence sources.")
list_persistence_parser.add_argument('-k', '--keys', action='store_true', default=False,
    help="Also display permanent keys. Use --search to narrow down results.")
list_persistence_parser.add_argument('-s', '--source',
    help="Search for keys from the given source.")
list_persistence_parser.add_argument('-n', '--name',
    help="Search for key names matching the given pattern.")
list_persistence_parser.add_argument('-t', '--temporal', action='store_true', default=False,
    help="Also display temporal (non-permanent) keys.")
list_persistence_parser.set_defaults(func=list_persistence)

def clear_persistence(args):
    import dateparser
    from saq.database import Persistence, PersistenceSource
    from sqlalchemy import and_

    source = get_db().query(PersistenceSource).filter(PersistenceSource.name == args.source).first()
    if source is None:
        logging.error(f"unknown persistence source {args.source}")
        sys.exit(1)

    if args.all:
        result = get_db().execute(Persistence.__table__.delete().where(Persistence.source_id == source.id))
        logging.info(f"persistence group {args.source} cleared {result.rowcount} items")

        if not args.dry_run:
            get_db().commit()

        sys.exit(0)

    elif args.older_than:
        target_date = dateparser.parse(args.older_than)
        result = get_db().execute(Persistence.__table__.delete().where(and_(Persistence.source_id == source.id,
                                                                          Persistence.permanent == 0,
                                                                          Persistence.last_update < target_date)))

        logging.info(f"persistence group {args.source} cleared {result.rowcount} items")

        if not args.dry_run:
            get_db().commit()

        sys.exit(0)

    for key in args.keys:
        result = get_db().execute(Persistence.__table__.delete().where(and_(Persistence.source_id == source.id,
                                                                          Persistence.uuid == key)))

        logging.info(f"persistence group {args.source} key {key} cleared {result.rowcount} items")

    if not args.dry_run:
        get_db().commit()

    sys.exit(0)

clear_persistence_parser = persistence_sp.add_parser('clear',
    help="Clears persistence data for the given source.")
clear_persistence_parser.add_argument('source',
    help="The name of the source to clear.")
clear_persistence_parser.add_argument('keys', nargs="*",
    help="One or more keys to clear.")
clear_persistence_parser.add_argument('--all', action='store_true', default=False,
    help="Clear all persistence data for this source.")
clear_persistence_parser.add_argument('--older-than',
    help="Clear all non-permanent persistence data that is older than a given time.")
clear_persistence_parser.add_argument('--dry-run', action='store_true', default=False,
    help="Do no commit the changes, only report how many would be cleared out.")

clear_persistence_parser.set_defaults(func=clear_persistence)
