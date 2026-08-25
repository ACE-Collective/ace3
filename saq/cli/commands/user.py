import argparse
import getpass
import logging
import sys

from saq.cli.cli_main import get_cli_subparsers


def _resolve_user_id(username):
    from saq.database import get_db_connection
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""SELECT id FROM users WHERE username = %s""", (username,))
        row = c.fetchone()
        if row is None:
            logging.error("username %s does not exist", username)
            sys.exit(1)
        return row[0]

# ============================================================================
# user management
#

def add_user(args):
    from app.models import User
    from saq.database.util.user_management import add_user

    u = User()
    u.username = args.username
    u.email = args.email
    u.display_name = args.display_name
    u.queue = args.queue

    try:
        import pytz
        u.timezone = 'UTC'
        if args.timezone:
            u.timezone = args.timezone

        pytz.timezone(u.timezone)

    except Exception:
        print(f"ERROR: invalid timezone {u.timezone}")
        sys.exit(1)

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter password for {}: ".format(u.username))
        confirm = getpass.getpass("Confirm password for {}: ".format(u.username))
        if password != confirm:
            logging.error("passwords do not match")
            sys.exit(1)
    

    u.password = password

    add_user(username=u.username, email=u.email, display_name=u.display_name, password=password, queue=u.queue, timezone=u.timezone)

    logging.info("added user {}".format(u.username))

user_parser = get_cli_subparsers().add_parser('user',
    help="User management commands.")
user_sp = user_parser.add_subparsers(dest='user_cmd')

add_user_parser = user_sp.add_parser('add',
    help="Add a new user to the system.")
add_user_parser.add_argument('username', help="The username of the new user.")
add_user_parser.add_argument('email', help="The email address of the new user.")
add_user_parser.add_argument('-z', '--timezone', required=False, default=None,
    help="The timezone the user is in. Defaults to UTC.")
add_user_parser.add_argument('-d', '--display-name', required=False, default=None,
    help="The (optional) display name for the user.")
add_user_parser.add_argument('--password', required=False, default=None,
    help="""Provide the password for the user on the command line. 
    Don't do this unless it's a part of automation.""")
add_user_parser.add_argument('-q', '--queue', required=False, default='default', 
    help="Set the default queue the user is assigned to.")
add_user_parser.set_defaults(func=add_user)

# XXX DEPRECATED
add_user_parser = get_cli_subparsers().add_parser('add-user',
    help="Add a new user to the system.")
add_user_parser.add_argument('username', help="The username of the new user.")
add_user_parser.add_argument('email', help="The email address of the new user.")
add_user_parser.add_argument('-z', '--timezone', required=False, default=None,
    help="The timezone the user is in. Defaults to UTC.")
add_user_parser.add_argument('-d', '--display-name', required=False, default=None,
    help="The (optional) display name for the user.")
add_user_parser.set_defaults(func=add_user)

def modify_user(args):
    from app.models import User
    from saq.database import get_db_connection

    u = User()
    u.username = args.username

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""SELECT id FROM users WHERE username = %s""", ( u.username, ))
        row = c.fetchone()
        if row is None:
            logging.error("username {0} does not exist".format(u.username))
            sys.exit(1)

        user_id = row[0]

    if args.email is not None:
        u.email = args.email

    if args.password:
        password = getpass.getpass("Enter password for {0}: ".format(u.username))
        confirm = getpass.getpass("Confirm password for {0}: ".format(u.username))
        if password != confirm:
            logging.error("passwords do not match")
            sys.exit(1)

        u.password = password
    
    try:
        import pytz
        u.timezone = 'UTC'
        if args.timezone:
            u.timezone = args.timezone

        pytz.timezone(u.timezone)

    except Exception as e:
        print(f"ERROR: invalid timezone {e}")
        sys.exit(1)

    with get_db_connection() as db:
        c = db.cursor()
        if args.email is not None:
            c.execute("""UPDATE users SET email = %s WHERE id = %s""", ( u.email, user_id ))
            
        if args.password:
            c.execute("""UPDATE users SET password_hash = %s WHERE id = %s""", ( u.password_hash, user_id ))

        if args.timezone:
            c.execute("""UPDATE users SET timezone = %s WHERE id = %s""", ( u.timezone, user_id ))

        if args.default_queue:
            c.execute("""UPDATE users SET queue = %s WHERE id = %s""", ( args.default_queue, user_id ))

        if args.display_name:
            c.execute("""UPDATE users SET display_name = %s WHERE id = %s""", ( args.display_name, user_id ))

        if args.enable:
            c.execute("""UPDATE users SET enabled = True WHERE id = %s""", ( user_id ))

        if args.disable:
            c.execute("""UPDATE users SET enabled = False WHERE id = %s""", ( user_id ))

        db.commit()

    if args.new_api_key:
        # legacy convenience: an inherit-scoped key that behaves like the pre-refactor single key
        from aceapi.auth import create_api_key
        api_key = create_api_key(user_id, name="cli", inherit=True)
        print()
        print(f"api key = {api_key}")
        print("(shown once; not recoverable)")
        print()

    if args.clear_api_key:
        from aceapi.auth import list_api_keys, revoke_api_key
        keys = list_api_keys(user_id)
        for k in keys:
            revoke_api_key(k.id)
        logging.info("cleared %d api key(s) for user", len(keys))

    logging.info("modified user {0}".format(u.username))

modify_user_parser = user_sp.add_parser('modify',
    help="Modifies an existing user on the system.")
modify_user_parser.add_argument('username', help="The username of the user to modify.")
modify_user_parser.add_argument('-e', '--email', dest='email', default=None, help="The new email address of the user.")
modify_user_parser.add_argument('-p', '--password', action='store_true', dest='password', default=False, help="Prompt for a new password.")
modify_user_parser.add_argument('-z', '--timezone', required=False, default=None, help="The timezone the user is in. Defaults to UTC.")
modify_user_parser.add_argument('-q', '--default_queue', required=False, default=None, help="Change the default queue the user is assigned to.")
modify_user_parser.add_argument('-n', '--display-name', required=False, default=None, help="Change the user's display name.")
modify_user_parser.add_argument('--enable', action='store_true', required=False, default=None, help="Enable the user.")
modify_user_parser.add_argument('--disable', action='store_true', required=False, default=None, help="Disable the user.")
modify_user_parser.add_argument('--new-api-key', action='store_true', required=False, default=False, help="Assign a new inherit-scoped API key to the given user. Key is printed once to standard out.")
modify_user_parser.add_argument('--clear-api-key', action='store_true', required=False, default=False, help="Revoke all API keys for the given user.")
modify_user_parser.set_defaults(func=modify_user)

def add_api_key(args):
    from aceapi.auth import create_api_key
    from saq.permissions.logic import parse_permission_pattern

    user_id = _resolve_user_id(args.username)
    if args.inherit:
        inherit, scope, name = True, None, (args.name or "cli")
    else:
        inherit = False
        scope = [parse_permission_pattern(s) for s in args.scope.split(",") if s.strip()]
        name = args.name or "cli"
        if not scope:
            logging.error("--scope did not yield any permission patterns")
            sys.exit(1)

    api_key = create_api_key(user_id, name=name, inherit=inherit, scope=scope)
    print()
    print(f"api key = {api_key}")
    print("(shown once; not recoverable)")
    print()

add_api_key_parser = user_sp.add_parser('add-api-key', help="Create a new API key for a user (shown once).")
add_api_key_parser.add_argument('username', help="The username to create the key for.")
add_api_key_parser.add_argument('--name', default=None, help="Human-readable name for the key.")
add_api_key_scope_group = add_api_key_parser.add_mutually_exclusive_group(required=True)
add_api_key_scope_group.add_argument('--inherit', action='store_true', help="The key inherits the user's full permissions.")
add_api_key_scope_group.add_argument('--scope', default=None, help='Comma-separated "major:minor" patterns to restrict the key to (e.g. "ai:splunk,ai:alert").')
add_api_key_parser.set_defaults(func=add_api_key)

def list_user_api_keys_cli(args):
    from aceapi.auth import list_api_keys
    user_id = _resolve_user_id(args.username)
    for k in list_api_keys(user_id):
        if k.inherit_user_scope:
            scope_desc = "inherit (full account)"
        else:
            scope_desc = ", ".join(f"{s.major}:{s.minor}" for s in k.scope) or "(no scope -- denies all)"
        print(f"[{k.id}] {k.name} -- {scope_desc}")

list_api_keys_parser = user_sp.add_parser('list-api-keys', help="List a user's API keys (metadata only).")
list_api_keys_parser.add_argument('username', help="The username whose keys to list.")
list_api_keys_parser.set_defaults(func=list_user_api_keys_cli)

def revoke_api_key_cli(args):
    from aceapi.auth import revoke_api_key
    if revoke_api_key(args.key_id):
        logging.info("revoked api key %s", args.key_id)
    else:
        logging.error("no api key with id %s", args.key_id)
        sys.exit(1)

revoke_api_key_parser = user_sp.add_parser('revoke-api-key', help="Revoke an API key by its id.")
revoke_api_key_parser.add_argument('key_id', type=int, help="The id of the key to revoke (see list-api-keys).")
revoke_api_key_parser.set_defaults(func=revoke_api_key_cli)

# XXX DEPRECATED
modify_user_parser = get_cli_subparsers().add_parser('modify-user',
    help="Modifies an existing user on the system.")
modify_user_parser.add_argument('username', help="The username of the user to modify.")
modify_user_parser.add_argument('-e', '--email', dest='email', default=None, help="The new email address of the user.")
modify_user_parser.add_argument('-p', '--password', action='store_true', dest='password', default=False, help="Prompt for a new password.")
modify_user_parser.add_argument('-z', '--timezone', required=False, default=None, help="The timezone the user is in. Defaults to UTC.")
modify_user_parser.set_defaults(func=modify_user)

def delete_user(args):
    from saq.database import get_db_connection

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""DELETE FROM users WHERE username = %s""", ( args.username, ))
        db.commit()

    logging.info("deleted user {0}".format(args.username))

delete_user_parser = get_cli_subparsers().add_parser('delete-user',
    help="Deletes an existing user from the system.")
delete_user_parser.add_argument('username', help="The username of the user to modify.")
delete_user_parser.set_defaults(func=delete_user)

delete_user_parser = user_sp.add_parser('delete',
    help="Deletes an existing user from the system.")
delete_user_parser.add_argument('username', help="The username of the user to modify.")
delete_user_parser.set_defaults(func=delete_user)

def list_users(args):
    from saq.database import User
    from saq.database.pool import get_db
    print("{:<6}{:<15}{:<25}{:<40}{:<25}{}".format('Id', 'User', 'Name', 'Queue', 'Enabled', 'TZ'))
    for user in get_db().query(User).order_by(User.username):
        print("{:<6}{:<15}{:<25}{:<40}{:<25}{}".format(
              user.id, 
              user.username, 
              '' if user.display_name is None else user.display_name, 
              user.queue,
              'True' if user.enabled else 'False',
              user.timezone))

    sys.exit(0)

list_users_parser = user_sp.add_parser('list',
    help="List existing users in the system.")
list_users_parser.set_defaults(func=list_users)

def user_exists(args):
    from saq.database import User
    from saq.database.pool import get_db
    if get_db().query(User).filter(User.username == args.username).one_or_none():
        logging.info("user %s exists", args.username)
        sys.exit(0)

    logging.info("user %s does not exist", args.username)
    sys.exit(1)

exists_user_parser = user_sp.add_parser('exists',
    help="Returns success if the given user exists.")
exists_user_parser.add_argument('username', help="The username of the user to check.")
exists_user_parser.set_defaults(func=user_exists)
