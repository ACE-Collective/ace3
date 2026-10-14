"""The SVS test hosts (saq.svs.hosts, docs/SVS_RUNS.md)."""

import json
import logging

import pytest

from saq.database.model import SVSTestHost
from saq.database.pool import get_db
from saq.svs import hosts
from saq.svs.hosts import (
    DuplicateTestHost,
    InvalidTestHost,
    UnknownTestHost,
    build_spec,
    match_target,
    normalize_username,
    split_hostname,
)


@pytest.mark.unit
@pytest.mark.parametrize("value, expected", [
    ("WIN10-01", ("win10-01", None)),
    ("win10-01.Corp.Example.", ("win10-01", "win10-01.corp.example")),
    ("  host  ", ("host", None)),
])
def test_split_hostname(value, expected):
    assert split_hostname(value) == expected


@pytest.mark.unit
@pytest.mark.parametrize("value", ["", "  ", "a b", "corp\\host", "host/x", "user@host", ".corp", "host..corp"])
def test_split_hostname_rejects(value):
    with pytest.raises(InvalidTestHost):
        split_hostname(value)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["alice", "ALICE", "CORP\\Alice", "alice@corp.example", " alice "])
def test_normalize_username(value):
    assert normalize_username(value) == "alice"


@pytest.mark.unit
def test_build_spec():
    spec = build_spec("WIN10-01.corp.example", usernames=["CORP\\Bob", "alice", "bob@corp.example"],
                      ips=["10.0.0.5", "::1", "10.0.0.5"], platform="Windows", notes="  lab 3  ")
    assert spec.hostname == "win10-01" and spec.fqdn == "win10-01.corp.example"
    assert spec.usernames == ("alice", "bob")
    assert spec.ips == ("10.0.0.5", "::1")
    assert spec.platform == "windows" and spec.notes == "lab 3"

    assert build_spec("win10-01", fqdn="WIN10-01.corp.example").fqdn == "win10-01.corp.example"
    assert build_spec("win10-01", platform="").platform is None


@pytest.mark.unit
@pytest.mark.parametrize("kwargs, message", [
    ({"fqdn": "other.corp.example"}, "is not a fully qualified name of"),
    ({"fqdn": "win10-01"}, "is not a fully qualified name of"),
    ({"hostname": "win10-01.a.example", "fqdn": "win10-01.b.example"}, "name different hosts"),
    ({"ips": ["10.0.0.300"]}, "is not an IP address"),
    ({"usernames": ["CORP\\"]}, "is not a user name"),
    ({"platform": "iaas"}, "is not one of windows, linux, macos"),
    ({"usernames": ["u"] * 101}, "at most 100 usernames"),
])
def test_build_spec_rejects(kwargs, message):
    hostname = kwargs.pop("hostname", "win10-01")
    with pytest.raises(InvalidTestHost, match=message):
        build_spec(hostname, **kwargs)


@pytest.fixture
def lab():
    """A host that lists its users, one that doesn't, and one without an fqdn."""
    return [
        hosts.create_host(build_spec("win10-01.corp.example", usernames=["CORP\\svc_art"], platform="windows"), None),
        hosts.create_host(build_spec("ubuntu-01.corp.example", platform="linux"), None),
        hosts.create_host(build_spec("mac-01"), None),
    ]


@pytest.mark.integration
@pytest.mark.parametrize("hostname, username, matched, reason", [
    ("win10-01", "svc_art", True, None),
    ("WIN10-01.CORP.EXAMPLE", "CORP\\SVC_ART", True, None),
    ("win10-01", "svc_art@corp.example", True, None),
    ("win10-01", "administrator", False, "administrator is not a user of test host win10-01"),
    ("win10-01", None, False, "lists its users and no user was given"),
    ("win10-01.prod.example", "svc_art", False, "win10-01.prod.example is not test host win10-01.corp.example"),
    ("ubuntu-01", None, True, None),
    ("ubuntu-01", "anyone", True, None),
    ("mac-01.anything.example", "anyone", True, None),
    ("dc-01", "svc_art", False, "dc-01 is not a test host"),
    ("not a host", "svc_art", False, "is not a host name"),
])
def test_match_target(lab, hostname, username, matched, reason):
    match = match_target(hostname, username)
    assert match.matched is matched
    if reason:
        assert reason in match.reason


@pytest.mark.integration
def test_create_update_delete_are_audited(caplog):
    with caplog.at_level(logging.INFO):
        host = hosts.create_host(build_spec("win10-01", usernames=["a"]), None, actor="admin")
        hosts.update_host(host.id, build_spec("win10-01", usernames=["b"], platform="windows"), actor="admin")
        hosts.delete_host(host.id, actor="admin")

    records = {r.getMessage(): r for r in caplog.records if r.getMessage().startswith("AUDIT: svs test host")}
    assert records["AUDIT: svs test host added"].usernames == ["a"]
    changed = records["AUDIT: svs test host changed"]
    assert changed.usernames == ["b"] and changed.before["usernames"] == ["a"] and changed.actor == "admin"
    assert records["AUDIT: svs test host removed"].svs_test_host == "win10-01"
    assert get_db().query(SVSTestHost).count() == 0


@pytest.mark.integration
def test_stored_fields():
    host = hosts.create_host(build_spec("win10-01.corp.example", usernames=["CORP\\Alice"], ips=["10.0.0.5"]), None)
    db = get_db()
    db.expire_all()
    row = db.get(SVSTestHost, host.id)
    assert (row.hostname, row.fqdn) == ("win10-01", "win10-01.corp.example")
    assert json.loads(row.usernames) == ["alice"] and json.loads(row.ips) == ["10.0.0.5"]
    assert row.created_at is not None and row.updated_at is not None


@pytest.mark.integration
def test_a_short_name_is_one_host():
    hosts.create_host(build_spec("win10-01.corp.example"), None)
    with pytest.raises(DuplicateTestHost):
        hosts.create_host(build_spec("WIN10-01.lab.example"), None)

    other = hosts.create_host(build_spec("win10-02"), None)
    with pytest.raises(DuplicateTestHost):
        hosts.update_host(other.id, build_spec("win10-01"))


@pytest.mark.integration
def test_unknown_host():
    with pytest.raises(UnknownTestHost):
        hosts.update_host(12345, build_spec("x"))
    with pytest.raises(UnknownTestHost):
        hosts.delete_host(12345)
