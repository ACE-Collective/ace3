"""Tests for the `ace user` commands."""

import json
import logging
import os

import pytest

import saq.cli.commands  # noqa: F401 -- registers the commands
from saq.cli.cli_main import get_cli_parser
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_USER_TAGGER
from saq.database.model import User
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, list_api_keys
from saq.environment import get_base_dir


def ace(*argv):
    """Runs `ace <argv>` through the real argument parser, returning the exit code (0 when the
    command just returns)."""
    args = get_cli_parser().parse_args(list(argv))
    try:
        args.func(args)
    except SystemExit as e:
        return e.code
    return 0


def _user(username: str) -> User:
    get_db().expire_all()
    return get_db().query(User).filter(User.username == username).one_or_none()


@pytest.fixture
def analyst():
    return add_user("cli_analyst", "cli_analyst@example.com", "CLI Analyst", "old password")


@pytest.mark.integration
def test_add(caplog):
    assert ace("user", "add", "newuser", "newuser@example.com", "-d", "New User", "-z", "America/New_York", "-q", "external", "--password", "secret") == 0

    user = _user("newuser")
    assert (user.email, user.display_name, user.timezone, user.queue) == ("newuser@example.com", "New User", "America/New_York", "external")
    assert user.verify_password("secret")


@pytest.mark.integration
def test_add_prompts_for_the_password(monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt: "prompted")

    assert ace("user", "add", "newuser", "newuser@example.com") == 0

    user = _user("newuser")
    assert user.timezone == "UTC"
    assert user.verify_password("prompted")


@pytest.mark.integration
def test_add_rejects_mismatched_passwords(monkeypatch):
    answers = iter(["one", "two"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))

    assert ace("user", "add", "newuser", "newuser@example.com") == 1
    assert _user("newuser") is None


@pytest.mark.integration
def test_add_rejects_an_invalid_timezone(capsys):
    assert ace("user", "add", "newuser", "newuser@example.com", "-z", "Mars/Olympus", "--password", "x") == 1
    assert "invalid timezone Mars/Olympus" in capsys.readouterr().out
    assert _user("newuser") is None


@pytest.mark.integration
def test_modify(analyst, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt: "new password")

    assert ace("user", "modify", "cli_analyst", "-e", "changed@example.com", "-p", "-z", "Europe/London",
               "-q", "internal", "-n", "Changed Name", "--disable") == 0

    user = _user("cli_analyst")
    assert (user.email, user.timezone, user.queue, user.display_name, user.enabled) == ("changed@example.com", "Europe/London", "internal", "Changed Name", False)
    assert user.verify_password("new password")

    assert ace("user", "modify", "cli_analyst", "--enable") == 0
    assert _user("cli_analyst").enabled


@pytest.mark.integration
def test_modify_leaves_unset_fields_alone(analyst):
    assert ace("user", "modify", "cli_analyst", "-n", "Only The Name") == 0

    user = _user("cli_analyst")
    assert (user.email, user.timezone, user.display_name) == ("cli_analyst@example.com", "UTC", "Only The Name")
    assert user.verify_password("old password")


@pytest.mark.integration
def test_modify_rejects_mismatched_passwords(analyst, monkeypatch):
    answers = iter(["one", "two"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))

    assert ace("user", "modify", "cli_analyst", "-p") == 1
    assert _user("cli_analyst").verify_password("old password")


@pytest.mark.integration
def test_modify_rejects_an_invalid_timezone(analyst):
    assert ace("user", "modify", "cli_analyst", "-z", "Mars/Olympus") == 1
    assert _user("cli_analyst").timezone == "UTC"


@pytest.mark.integration
@pytest.mark.parametrize("command", [
    ("modify", "nobody", "-n", "x"),
    ("add-api-key", "nobody", "--inherit"),
    ("list-api-keys", "nobody"),
])
def test_unknown_user(command, caplog):
    assert ace("user", *command) == 1
    assert any(r.levelno == logging.ERROR and "nobody" in r.getMessage() and "does not exist" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_api_keys(analyst, capsys):
    assert ace("user", "modify", "cli_analyst", "--new-api-key") == 0
    assert "api key = " in capsys.readouterr().out
    assert ace("user", "add-api-key", "cli_analyst", "--name", "splunk app", "--scope", "ai:splunk, ai:alert") == 0
    capsys.readouterr()

    assert ace("user", "list-api-keys", "cli_analyst") == 0
    listing = capsys.readouterr().out
    assert "cli -- inherit (full account)" in listing
    assert "splunk app -- ai:alert, ai:splunk" in listing

    keys = list_api_keys(analyst.id)
    assert ace("user", "revoke-api-key", str(keys[0].id)) == 0
    assert len(list_api_keys(analyst.id)) == 1

    assert ace("user", "modify", "cli_analyst", "--clear-api-key") == 0
    assert list_api_keys(analyst.id) == []


@pytest.mark.integration
def test_add_api_key_needs_a_scope(analyst, caplog):
    assert ace("user", "add-api-key", "cli_analyst", "--scope", " , ") == 1
    assert list_api_keys(analyst.id) == []


@pytest.mark.integration
def test_revoke_unknown_api_key(caplog):
    assert ace("user", "revoke-api-key", "999999") == 1
    assert any(r.levelno == logging.ERROR and "no api key with id 999999" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_list_exists_and_delete(analyst, capsys):
    assert ace("user", "list") == 0
    assert "cli_analyst" in capsys.readouterr().out

    assert ace("user", "exists", "cli_analyst") == 0
    assert ace("user", "delete", "cli_analyst") == 0
    assert ace("user", "exists", "cli_analyst") == 1
    assert _user("cli_analyst") is None


#
# update-organization
#

class FakeLDAP:
    """Stands in for an ldap3 Connection over a fixed org chart."""

    # cn -> direct reports
    org = {}

    def __init__(self, *args, **kwargs):
        self.response = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def search(self, base_dn, query, scope, attributes=None):
        cn = query[len("(cn="):-len("*)")]
        if cn in FakeLDAP.org:
            self.response = {"entries": [{"attributes": {"directReports": FakeLDAP.org[cn]}}]}
        else:
            self.response = {"entries": []}

    def response_to_json(self):
        return json.dumps(self.response)

    result = None


@pytest.fixture
def org_chart(monkeypatch, tmp_path):
    import ldap3

    monkeypatch.setattr(ldap3, "Connection", FakeLDAP)
    monkeypatch.setattr(ldap3, "Server", lambda *args, **kwargs: None)
    config = get_analysis_module_config(ANALYSIS_MODULE_USER_TAGGER)
    config.json_path = os.path.relpath(tmp_path / "organization.json", get_base_dir())
    FakeLDAP.org = {}
    return config


def _dn(cn: str) -> str:
    return f"CN={cn},OU=People,DC=example,DC=com"


@pytest.mark.integration
def test_update_organization(org_chart, caplog):
    FakeLDAP.org = {
        "ceo": [_dn("cfo"), _dn("cto")],
        "cfo": [_dn("accountant")],
        "cto": [_dn("engineer"), "not a distinguished name"],
        "engineer": [_dn("intern")],
    }
    setattr(org_chart, "group_exec", "ceo, 1, executive")
    setattr(org_chart, "group_tech", "cto, all, engineering")

    assert ace("user", "update-organization") == 0

    with open(os.path.join(get_base_dir(), org_chart.json_path)) as fp:
        mapping = {user: sorted(tags) for user, tags in json.load(fp).items()}
    assert mapping == {
        # the ceo and one level of direct reports
        "ceo": ["executive"],
        "cfo": ["executive"],
        "cto": ["engineering", "executive"],
        # every level below the cto
        "engineer": ["engineering"],
        "intern": ["engineering"],
    }
    assert any(r.levelno == logging.WARNING and "not a distinguished name" in r.getMessage() for r in caplog.records)
