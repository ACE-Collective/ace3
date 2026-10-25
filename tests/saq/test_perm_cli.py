"""Tests for the `ace perm` commands."""

import pytest

import saq.cli.commands.permissions  # noqa: F401 -- registers the commands
from saq.cli.cli_main import get_cli_parser
from saq.database.model import AuthGroup, AuthPermissionCatalog
from saq.database.pool import get_db
from saq.database.util.user_management import add_user
from saq.permissions import add_group_permission, add_user_permission, add_user_to_auth_group, create_auth_group
from saq.permissions.constants import ALLOW, DENY
from saq.permissions.group import get_group_permissions
from saq.permissions.user import get_user_permissions


def ace(*argv):
    """Runs `ace <argv>` through the real argument parser; returns what the command returns."""
    args = get_cli_parser().parse_args(list(argv))
    return args.func(args)


@pytest.fixture
def alice():
    return add_user("perm_alice", "alice@example.com", "Alice", "password")


@pytest.fixture
def bob():
    return add_user("perm_bob", "bob@example.com", "Bob", "password")


def _own(user) -> list[tuple[str, str, str]]:
    get_db().expire_all()
    return sorted((p.major, p.minor, p.effect) for p in get_user_permissions(user.id, include_groups=False))


#
# user permissions
#

@pytest.mark.integration
def test_add_and_test_user_permission(alice, capsys):
    assert ace("perm", "user", "add", "perm_alice", "alert:read") == 0
    assert ace("perm", "user", "add", "perm_alice", "event") == 0
    assert ace("perm", "user", "add", "perm_alice", "alert:write", "--deny") == 0

    assert _own(alice) == [("alert", "read", ALLOW), ("alert", "write", DENY), ("event", "*", ALLOW)]

    capsys.readouterr()
    assert ace("perm", "user", "test", "perm_alice", "alert:read") == 0
    assert capsys.readouterr().out.strip() == "ALLOW"
    assert ace("perm", "user", "test", "perm_alice", "alert:write") == 1
    assert capsys.readouterr().out.strip() == "DENY"


@pytest.mark.integration
def test_add_user_permission_outside_the_catalog_warns(alice, capsys):
    assert ace("perm", "user", "add", "perm_alice", "no_such:thing") == 0

    assert "not in the permission catalog" in capsys.readouterr().err
    assert _own(alice) == [("no_such", "thing", ALLOW)]


@pytest.mark.integration
@pytest.mark.parametrize("permission", [":read", "alert:"])
def test_add_user_permission_rejects_a_malformed_permission(alice, permission):
    with pytest.raises(ValueError, match="invalid permission format"):
        ace("perm", "user", "add", "perm_alice", permission)


@pytest.mark.integration
def test_list_user_permissions(alice, bob, capsys):
    add_user_permission(alice.id, "alert", "read", ALLOW)
    group = create_auth_group("perm_analysts")
    add_group_permission(group.id, "event", "read", ALLOW)
    add_user_to_auth_group(bob.id, group.id)

    capsys.readouterr()
    assert ace("perm", "user", "list", "perm_alice") == 0
    listing = capsys.readouterr().out
    assert "perm_alice" in listing and "alert" in listing

    assert ace("perm", "user", "list") == 0
    listing = capsys.readouterr().out
    # every user, including permissions inherited from a group
    assert "perm_alice" in listing
    assert "perm_bob" in listing and "group" in listing


@pytest.mark.integration
def test_list_user_without_permissions(alice, capsys):
    assert ace("perm", "user", "list", "perm_alice") == 0
    assert capsys.readouterr().out.strip() == "No permissions found"


@pytest.mark.integration
def test_delete_user_permission(alice, capsys):
    add_user_permission(alice.id, "alert", "read", ALLOW)
    add_user_permission(alice.id, "event", "read", ALLOW)
    [first, _] = get_user_permissions(alice.id)

    assert ace("perm", "user", "delete", "perm_alice", str(first.id)) == 0

    assert f"User permission {first.id} deleted" in capsys.readouterr().out
    assert len(_own(alice)) == 1


@pytest.mark.integration
def test_delete_user_permission_belonging_to_another_user(alice, bob, capsys):
    add_user_permission(bob.id, "alert", "read", ALLOW)
    [bobs] = get_user_permissions(bob.id)

    assert ace("perm", "user", "delete", "perm_alice", str(bobs.id)) == 1

    assert f"User permission {bobs.id} not found" in capsys.readouterr().out
    assert _own(bob) == [("alert", "read", ALLOW)]


@pytest.mark.integration
def test_delete_all_user_permissions_keeps_group_permissions(alice):
    add_user_permission(alice.id, "alert", "read", ALLOW)
    add_user_permission(alice.id, "event", "read", ALLOW)
    group = create_auth_group("perm_analysts")
    add_group_permission(group.id, "search", "read", ALLOW)
    add_user_to_auth_group(alice.id, group.id)

    assert ace("perm", "user", "delete", "perm_alice", "--all") == 0

    assert _own(alice) == []
    assert [(p.major, p.minor) for p in get_group_permissions(group.id)] == [("search", "read")]


@pytest.mark.integration
def test_delete_user_permission_needs_an_id(alice, capsys):
    assert ace("perm", "user", "delete", "perm_alice") == 1
    assert "No permission ID provided" in capsys.readouterr().out


@pytest.mark.integration
@pytest.mark.parametrize("command", [
    ("user", "list", "nobody"),
    ("user", "add", "nobody", "alert:read"),
    ("user", "delete", "nobody", "1"),
    ("user", "test", "nobody", "alert:read"),
])
def test_unknown_user(command, capsys):
    assert ace("perm", *command) == 1
    assert "User nobody not found" in capsys.readouterr().out


#
# groups
#

def _group(name: str):
    get_db().expire_all()
    return get_db().query(AuthGroup).filter(AuthGroup.name == name).one_or_none()


@pytest.mark.integration
def test_group_lifecycle(alice, capsys):
    assert ace("perm", "group", "add", "perm_analysts") == 0
    group = _group("perm_analysts")
    assert f"Group created: {group.id} perm_analysts" in capsys.readouterr().out

    assert ace("perm", "group", "list") == 0
    assert "perm_analysts" in capsys.readouterr().out

    assert ace("perm", "group", "add-perm", "perm_analysts", "alert:read") == 0
    assert ace("perm", "group", "add-perm", "perm_analysts", "alert:write", "--deny") == 0
    assert sorted((p.major, p.minor, p.effect) for p in get_group_permissions(group.id)) == [("alert", "read", ALLOW), ("alert", "write", DENY)]

    capsys.readouterr()
    assert ace("perm", "group", "list-perm", "perm_analysts") == 0
    assert "alert" in capsys.readouterr().out

    assert ace("perm", "group", "add-user", "perm_analysts", "perm_alice") == 0
    assert ace("perm", "user", "test", "perm_alice", "alert:read") == 0
    assert ace("perm", "group", "remove-user", "perm_analysts", "perm_alice") == 0
    assert ace("perm", "user", "test", "perm_alice", "alert:read") == 1
    capsys.readouterr()
    assert ace("perm", "group", "remove-user", "perm_analysts", "perm_alice") == 1
    assert "is not a member of group perm_analysts" in capsys.readouterr().out

    assert ace("perm", "group", "delete", "perm_analysts") == 0
    assert _group("perm_analysts") is None


@pytest.mark.integration
def test_delete_group_permission(capsys):
    group = create_auth_group("perm_analysts")
    add_group_permission(group.id, "alert", "read", ALLOW)
    add_group_permission(group.id, "event", "read", ALLOW)
    [first, _] = get_group_permissions(group.id)

    assert ace("perm", "group", "delete-perm", "perm_analysts", str(first.id)) == 0
    assert [(p.major, p.minor) for p in get_group_permissions(group.id)] == [("event", "read")]

    assert ace("perm", "group", "delete-perm", "perm_analysts", "--all") == 0
    assert get_group_permissions(group.id) == []

    capsys.readouterr()
    assert ace("perm", "group", "delete-perm", "perm_analysts", "--all") == 1
    assert "No permissions found" in capsys.readouterr().out
    assert ace("perm", "group", "delete-perm", "perm_analysts") == 1
    assert ace("perm", "group", "delete-perm", "perm_analysts", "999999") == 1


@pytest.mark.integration
def test_delete_group_permission_belonging_to_another_group(capsys):
    analysts = create_auth_group("perm_analysts")
    admins = create_auth_group("perm_admins")
    add_group_permission(admins.id, "admin", "*", ALLOW)
    [admin_permission] = get_group_permissions(admins.id)

    assert ace("perm", "group", "delete-perm", "perm_analysts", str(admin_permission.id)) == 1

    assert f"Group permission {admin_permission.id} not found" in capsys.readouterr().out
    assert [(p.major, p.minor) for p in get_group_permissions(admins.id)] == [("admin", "*")]


@pytest.mark.integration
def test_list_group_without_permissions(capsys):
    create_auth_group("perm_analysts")
    assert ace("perm", "group", "list-perm", "perm_analysts") == 0
    assert capsys.readouterr().out.strip() == "No permissions found"


@pytest.mark.integration
@pytest.mark.parametrize("command", [
    ("delete", "nogroup"),
    ("add-perm", "nogroup", "alert:read"),
    ("delete-perm", "nogroup", "1"),
    ("list-perm", "nogroup"),
    ("add-user", "nogroup", "perm_alice"),
    ("remove-user", "nogroup", "perm_alice"),
])
def test_unknown_group(alice, command, capsys):
    assert ace("perm", "group", *command) == 1
    assert "Group nogroup not found" in capsys.readouterr().out


@pytest.mark.integration
@pytest.mark.parametrize("command", ["add-user", "remove-user"])
def test_unknown_group_member(command, capsys):
    create_auth_group("perm_analysts")
    assert ace("perm", "group", command, "perm_analysts", "nobody") == 1
    assert "User nobody not found" in capsys.readouterr().out


#
# catalog
#

@pytest.mark.integration
def test_catalog(capsys):
    get_db().query(AuthPermissionCatalog).delete()
    get_db().commit()

    assert ace("perm", "catalog", "list") == 0
    assert "Permission catalog is empty" in capsys.readouterr().out

    assert ace("perm", "catalog", "sync") == 0
    assert "permission catalog synced: " in capsys.readouterr().out
    assert get_db().query(AuthPermissionCatalog).count() > 0

    assert ace("perm", "catalog", "list") == 0
    assert "alert" in capsys.readouterr().out

    get_db().add(AuthPermissionCatalog(major="retired", minor="permission", description="no longer in code"))
    get_db().commit()
    assert ace("perm", "catalog", "sync", "--no-prune") == 0
    assert get_db().query(AuthPermissionCatalog).filter(AuthPermissionCatalog.major == "retired").count() == 1
    assert ace("perm", "catalog", "sync") == 0
    get_db().expire_all()
    assert get_db().query(AuthPermissionCatalog).filter(AuthPermissionCatalog.major == "retired").count() == 0
