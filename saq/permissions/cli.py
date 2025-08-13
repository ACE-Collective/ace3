from saq.permissions.constants import ALLOW, DENY, WILDCARD
from saq.permissions.group import get_group_permissions
from saq.permissions.user import add_user_permission, get_user_permissions
from saq.database.pool import get_db
from saq.cli.cli_main import get_cli_subparsers


def parse_permission(permission: str) -> tuple[str, str]:
    """Parse a permission string into major and minor."""
    if ":" not in permission:
        if not permission:
            raise ValueError("permission cannot be empty")

        # defaults to WILDCARD for minor
        return permission, WILDCARD

    try:
        major, minor = permission.split(':', 1)
        if not major:
            raise ValueError(f"invalid permission format: {permission} (expected 'major:minor')")
        if not minor:
            raise ValueError(f"invalid permission format: {permission} (expected 'major:minor')")
    except ValueError:
        raise ValueError(f"invalid permission format: {permission} (expected 'major:minor')")

    return major, minor

permissions_parser = get_cli_subparsers().add_parser("perm", help="Manage user/group permissions.")
permissions_sp = permissions_parser.add_subparsers(dest="permissions_cmd")

user_permissions_parser = permissions_sp.add_parser("user", help="Manage user permissions.")
user_permissions_sp = user_permissions_parser.add_subparsers(dest="user_permissions_cmd")

def cli_list_user_permissions(args) -> int:
    from saq.permissions import get_user_permissions
    from tabulate import tabulate
    from saq.database.model import User
    session = get_db()
    users = []
    if args.name:
        user = session.query(User).filter(User.username == args.name).one_or_none()
        if not user:
            print(f"User {args.name} not found")
            return 1
        users.append(user)
    else:
        users = session.query(User).all()

    table = []
    for user in users:
        table.extend([
            [user.username, p.id, p.major, p.minor, p.effect, p.source, p.group_id]
            for p in get_user_permissions(user.id)
        ])

    if args.name and not table:
        print("No permissions found")
        return 0

    headers = ['User', 'ID', 'Major', 'Minor', 'Effect', 'Source', 'Group ID']
    print(tabulate(table, headers=headers, tablefmt="github"))
    return 0

list_user_permissions_parser = user_permissions_sp.add_parser("list", help="List permissions for a user.")
list_user_permissions_parser.add_argument("name", nargs="?", help="The name of the user to list permissions for. If not provided, list all permissions for all users.")
list_user_permissions_parser.set_defaults(func=cli_list_user_permissions)

def cli_add_user_permission(args) -> int:
    from saq.permissions import add_user_permission
    from saq.database.model import User

    session = get_db()

    user = session.query(User).filter(User.username == args.name).one_or_none()
    if not user:
        print(f"User {args.name} not found")
        return 1

    major, minor = parse_permission(args.permission)
    add_user_permission(user.id, major, minor, DENY if args.deny else ALLOW)
    return 0

add_user_permission_parser = user_permissions_sp.add_parser("add", help="Add a permission to a user.")
add_user_permission_parser.add_argument("name", help="The name of the user to add a permission to.")
add_user_permission_parser.add_argument("permission", help="The permission to add in the format 'major:minor'.")
add_user_permission_parser.add_argument("--deny", action="store_true", help="Deny the permission instead of allowing it. Default is to allow it.")
add_user_permission_parser.set_defaults(func=cli_add_user_permission)

def cli_delete_user_permission(args) -> int:
    from saq.permissions import delete_user_permission, delete_group_permission
    from saq.database.model import User

    session = get_db()

    user = session.query(User).filter(User.username == args.name).one_or_none()
    if not user:
        print(f"User {args.name} not found")
        return 1

    if args.all:
        for permission in get_user_permissions(user.id):
            if not delete_user_permission(user.id, permission.id):
                print(f"User permission {permission.id} not found")
                return 1
            else:
                print(f"User permission {permission.id} deleted")

        return 0

    if not args.id:
        print("No permission ID provided")
        return 1

    if not delete_user_permission(user.id, args.id):
        print(f"User permission {args.id} not found")
        return 1
    else:
        print(f"User permission {args.id} deleted")
        return 0

delete_user_permission_parser = user_permissions_sp.add_parser("delete", help="Delete a permission from a user.")
delete_user_permission_parser.add_argument("name", help="The name of the user to delete a permission from.")
delete_user_permission_parser.add_argument("id", type=int, nargs="?", help="The ID of the permission to delete.")
delete_user_permission_parser.add_argument("--all", action="store_true", help="Delete all permissions for a user.")
delete_user_permission_parser.set_defaults(func=cli_delete_user_permission)



# Group permissions CLI
group_permissions_parser = permissions_sp.add_parser("group", help="Manage auth groups and their permissions.")
group_permissions_sp = group_permissions_parser.add_subparsers(dest="group_permissions_cmd")


def cli_add_group(args) -> int:
    from saq.permissions import create_auth_group

    group = create_auth_group(args.name)
    print(f"Group created: {group.id} {group.name}")
    return 0


add_group_parser = group_permissions_sp.add_parser("add", help="Create a new auth group.")
add_group_parser.add_argument("name", help="The name of the group to create.")
add_group_parser.set_defaults(func=cli_add_group)


def cli_delete_group(args) -> int:
    from saq.database.model import AuthGroup
    from saq.permissions import delete_auth_group

    session = get_db()
    group = session.query(AuthGroup).filter(AuthGroup.name == args.name).one_or_none()
    if not group:
        print(f"Group {args.name} not found")
        return 1

    if delete_auth_group(group.id):
        print(f"Group {args.name} deleted")
        return 0

    else:
        print(f"Failed to delete group {args.name}")
        return 1


delete_group_parser = group_permissions_sp.add_parser("delete", help="Delete an existing auth group.")
delete_group_parser.add_argument("name", help="The name of the group to delete.")
delete_group_parser.set_defaults(func=cli_delete_group)


def cli_list_groups(args) -> int:
    from tabulate import tabulate
    from saq.database.model import AuthGroup

    session = get_db()
    groups = session.query(AuthGroup).all()
    table = [[g.id, g.name] for g in groups]
    headers = ["ID", "Name"]
    print(tabulate(table, headers=headers, tablefmt="github"))
    return 0


list_groups_parser = group_permissions_sp.add_parser("list", help="List all auth groups.")
list_groups_parser.set_defaults(func=cli_list_groups)


def cli_add_group_permission(args) -> int:
    from saq.permissions import add_group_permission
    from saq.database.model import AuthGroup

    session = get_db()
    group = session.query(AuthGroup).filter(AuthGroup.name == args.name).one_or_none()
    if not group:
        print(f"Group {args.name} not found")
        return 1

    major, minor = parse_permission(args.permission)
    add_group_permission(group.id, major, minor, DENY if args.deny else ALLOW)
    return 0


add_group_permission_parser = group_permissions_sp.add_parser("add-perm", help="Add a permission to an auth group.")
add_group_permission_parser.add_argument("name", help="The name of the auth group.")
add_group_permission_parser.add_argument("permission", help="The permission to add in the format 'major:minor'.")
add_group_permission_parser.add_argument("--deny", action="store_true", help="Deny the permission instead of allowing it. Default is to allow it.")
add_group_permission_parser.set_defaults(func=cli_add_group_permission)


def cli_delete_group_permission(args) -> int:
    from saq.permissions import delete_group_permission, get_group_permissions
    from saq.database.model import AuthGroup

    session = get_db()
    group = session.query(AuthGroup).filter(AuthGroup.name == args.name).one_or_none()
    if not group:
        print(f"Group {args.name} not found")
        return 1

    if args.all:
        any_deleted = False
        for permission in get_group_permissions(group.id):
            print(f"Deleting group permission {permission}")
            deleted = delete_group_permission(permission_id=permission.id)
            if deleted:
                any_deleted = True
                print(f"Group permission {permission.id} deleted")
        if not any_deleted:
            print("No permissions found")
            return 1
        return 0

    if not args.id:
        print("No permission ID provided")
        return 1

    deleted = delete_group_permission(permission_id=args.id)
    if not deleted:
        print(f"Group permission {args.id} not found")
        return 1
    else:
        print(f"Group permission {args.id} deleted")
        return 0


delete_group_permission_parser = group_permissions_sp.add_parser("delete-perm", help="Delete a permission from an auth group.")
delete_group_permission_parser.add_argument("name", help="The name of the auth group.")
delete_group_permission_parser.add_argument("id", type=int, nargs="?", help="The ID of the permission to delete.")
delete_group_permission_parser.add_argument("--all", action="store_true", help="Delete all permissions for the auth group.")
delete_group_permission_parser.set_defaults(func=cli_delete_group_permission)


def cli_list_group_permissions(args) -> int:
    from tabulate import tabulate
    from saq.permissions import get_group_permissions
    from saq.database.model import AuthGroup

    session = get_db()
    group = session.query(AuthGroup).filter(AuthGroup.name == args.name).one_or_none()
    if not group:
        print(f"Group {args.name} not found")
        return 1

    perms = get_group_permissions(group.id)
    if not perms:
        print("No permissions found")
        return 0

    table = [[group.name, p.id, p.major, p.minor, p.effect] for p in perms]
    headers = ["Group", "ID", "Major", "Minor", "Effect"]
    print(tabulate(table, headers=headers, tablefmt="github"))
    return 0


list_group_permissions_parser = group_permissions_sp.add_parser("list-perm", help="List all permissions for an auth group.")
list_group_permissions_parser.add_argument("name", help="The name of the auth group.")
list_group_permissions_parser.set_defaults(func=cli_list_group_permissions)


def cli_add_user_to_group(args) -> int:
    from saq.database.model import AuthGroup, User
    from saq.permissions import add_user_to_auth_group

    session = get_db()
    group = session.query(AuthGroup).filter(AuthGroup.name == args.name).one_or_none()
    if not group:
        print(f"Group {args.name} not found")
        return 1

    user = session.query(User).filter(User.username == args.user).one_or_none()
    if not user:
        print(f"User {args.user} not found")
        return 1

    add_user_to_auth_group(user.id, group.id)
    print(f"User {args.user} added to group {args.name}")
    return 0


add_user_to_group_parser = group_permissions_sp.add_parser("add-user", help="Add a user to an auth group.")
add_user_to_group_parser.add_argument("name", help="The name of the auth group.")
add_user_to_group_parser.add_argument("user", help="The username to add to the group.")
add_user_to_group_parser.set_defaults(func=cli_add_user_to_group)


def cli_remove_user_from_group(args) -> int:
    from saq.database.model import AuthGroup, User
    from saq.permissions import delete_user_from_auth_group

    session = get_db()
    group = session.query(AuthGroup).filter(AuthGroup.name == args.name).one_or_none()
    if not group:
        print(f"Group {args.name} not found")
        return 1

    user = session.query(User).filter(User.username == args.user).one_or_none()
    if not user:
        print(f"User {args.user} not found")
        return 1

    removed = delete_user_from_auth_group(user.id, group.id)
    if removed:
        print(f"User {args.user} removed from group {args.name}")
        return 0
    else:
        print(f"User {args.user} is not a member of group {args.name}")
        return 1


remove_user_from_group_parser = group_permissions_sp.add_parser("remove-user", help="Remove a user from an auth group.")
remove_user_from_group_parser.add_argument("name", help="The name of the auth group.")
remove_user_from_group_parser.add_argument("user", help="The username to remove from the group.")
remove_user_from_group_parser.set_defaults(func=cli_remove_user_from_group)


def cli_test_user_permission(args) -> int:
    from saq.database.model import User
    from saq.permissions import user_has_permission

    session = get_db()
    user = session.query(User).filter(User.username == args.name).one_or_none()
    if not user:
        print(f"User {args.name} not found")
        return 1

    major, minor = parse_permission(args.permission)
    allowed = user_has_permission(user.id, major, minor)
    print("ALLOW" if allowed else "DENY")
    return 0 if allowed else 1


test_user_permission_parser = user_permissions_sp.add_parser("test", help="Test whether a user has a specific permission (major:minor). DENY overrides ALLOW.")
test_user_permission_parser.add_argument("name", help="The name of the user.")
test_user_permission_parser.add_argument("permission", help="The permission to test in the format 'major:minor'.")
test_user_permission_parser.set_defaults(func=cli_test_user_permission)
