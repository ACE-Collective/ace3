import logging
import sys

from saq.cli.cli_main import get_cli_subparsers


# ============================================================================
# company management
#

def list_companies(args):
    from saq.database import get_db_connection

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT id, name FROM company ORDER BY name")
        print()
        print("ID\tNAME")
        for company_id, company_name in c:
            print("{}\t{}".format(company_id, company_name))

    print()
    print("use ./saq add-company and ./saq delete-company to manage companies")
    print()
    sys.exit(0)

list_companies_parser = get_cli_subparsers().add_parser('list-companies',
    help="Lists the available companies and their IDs.")
list_companies_parser.set_defaults(func=list_companies)

def add_company(args):
    from saq.database import get_db_connection

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("INSERT INTO company ( `id`, `name` ) VALUES ( %s, %s )", (args.company_id, args.company_name))
        db.commit()
        logging.info("company added")

    sys.exit(0)

add_companies_parser = get_cli_subparsers().add_parser('add-company',
    help="Adds a new company entry.")
add_companies_parser.add_argument('company_id', type=int, help="The ID of the new company (a number that is not already being used as an ID.)")
add_companies_parser.add_argument('company_name', help="The name of the new company.")
add_companies_parser.set_defaults(func=add_company)

def delete_company(args):
    import saq
    from saq.constants import INSTANCE_TYPE_PRODUCTION
    from saq.database import get_db_connection

    print("***************************************************************")
    print("Deleting a company will delete all associated EVENTS and ALERTS.")
    confirm = input("Are you SURE? (Y/n)")
    if confirm != 'Y':
        print("Action not taken.")
        sys.exit(0)

    confirm = input("Are you DAMN SURE? Seriously. If you're wrong it will be a disaster. (Y/n)")
    if confirm != 'Y':
        print("Action not taken. Pay attention to what you're doing please.")
        sys.exit(0)

    # see if we are on the production system
    if saq.INSTANCE_TYPE == INSTANCE_TYPE_PRODUCTION:
        confirm = input("You are in a PRODUCTION SERVER. Are you SURE you know what you are doing? Type YES if you are sure.")
        if confirm != 'YES':
            print("Action not taken. Pay attention to what you're doing please.")
            sys.exit(0)

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("DELETE FROM company WHERE `name` = %s", (args.company_name,))
        db.commit()
        logging.info("company deleted")

    sys.exit(0)

delete_companies_parser = get_cli_subparsers().add_parser('delete-company',
    help="Deletes a given company and all associated events and alerts.")
delete_companies_parser.add_argument('company_name', help="The name of the company to delete.")
delete_companies_parser.set_defaults(func=delete_company)
