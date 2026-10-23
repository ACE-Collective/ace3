import os
import sys

import pytest
import saq.cli.commands # noqa: F401

from saq.analysis.root import load_root
from saq.cli import cli_main
from saq.cli.cli_main import get_cli_parser, get_cli_subparsers
from saq.constants import EventTimeSource


@pytest.mark.unit
def test_cli_commands_registered():
    """Importing saq.cli.commands must register every built-in CLI command.

    This guards against a command module being dropped from
    saq/cli/commands/__init__.py (or a new command module forgetting to
    register itself).
    """


    expected = {
        # core commands
        "hunt", "persistence", "per", "integration", "service", "correlate",
        "submit", "remediation",
        # gui
        "gui",
        # user management
        "user",
        # test utilities
        "test",
        # alert management
        "alert",
        # cache maintenance
        "cache",
        # analysis module crash reports
        "crash",
        # encryption
        "encryption", "enc",
        # company / misc
        "company",
        "config", "modules", "workload",
        "event", "debug", "git",
        "s3",
    }

    registered = set(get_cli_subparsers().choices.keys())

    missing = expected - registered
    assert not missing, f"missing CLI subcommands: {sorted(missing)}"

    # commands that live in other modules but must remain registered too
    for external in ("perm", "phishkit", "storage", "search", "nrd",
                     "observables", "signatures", "svs"):
        assert external in registered, f"missing external CLI subcommand: {external}"


@pytest.mark.unit
def test_cli_commands_use_noun_verb_pattern():
    """Every command must be exposed only through its noun group.

    Guards against the old flat command pattern (e.g. `ace add-user`)
    creeping back in alongside the noun-verb pattern (`ace user add`).
    """
    legacy = {
        "add-user", "modify-user", "delete-user", "generate-api-key",
        "update-organization",
        "test-database-connections", "test-network-semaphore", "test-proxies",
        "verify-modules",
        "create-alert", "rebuild-index", "import-alerts", "delete-alerts",
        "reset-alerts", "archive-alerts", "add-observable", "reload-alerts",
        "cleanup-alerts", "analysis-cache-stats", "analysis-cache-gc",
        "analysis-cache-local-maintenance", "distribute-alerts", "display-alert",
        "set-encryption-password", "list-encrypted-passwords",
        "delete-encrypted-password",
        "list-companies", "add-company", "delete-company",
        "list-available-modules", "display-workload",
        "remove-bro-http-whitelist", "build-suricata-db",
        "display-remediation-requests", "clear-remediation-requests",
        "start-gui", "start-api",
    }

    registered = set(get_cli_subparsers().choices.keys())
    leftover = legacy & registered
    assert not leftover, f"legacy flat commands still registered: {sorted(leftover)}"


@pytest.mark.unit
def test_cli_subcommands_registered():
    """The noun groups expose their expected verbs."""
    sp = get_cli_subparsers()

    def choices(name):
        return set(sp.choices[name]._subparsers._group_actions[0].choices.keys())

    assert {"start"} <= choices("gui")
    assert {"stats", "gc", "local-maintenance"} <= choices("cache")
    assert {"archive", "distribute"} <= choices("alert")
    assert {"add", "delete", "list"} <= choices("company")
    assert {"list"} <= choices("modules")
    assert {"display"} <= choices("workload")
    assert {"database-connections", "network-semaphore", "proxies", "modules"} <= choices("test")
    assert {"add", "modify", "delete", "list", "exists"} <= choices("user")
    assert {"build-db"} <= choices("signatures")
    assert {"display", "clear"} <= choices("remediation")
    assert {"yara"} <= choices("svs")
    svs_yara = sp.choices["svs"]._subparsers._group_actions[0].choices["yara"]
    assert {"validate", "layout", "prune"} <= set(svs_yara._subparsers._group_actions[0].choices.keys())


@pytest.mark.unit
def test_cli_runs_from_saq_home(tmp_path, monkeypatch):
    """ace --saq-home resolves a relative path against the caller's directory, changes to it,
    and hands that home to initialize_environment()."""
    home = tmp_path / "home"
    os.makedirs(home / "saq")
    # also restores the cwd after main() changes it
    monkeypatch.chdir(tmp_path)

    class Initialized(Exception):
        pass

    seen = {}

    def fake_initialize_environment(**kwargs):
        seen.update(kwargs, cwd=os.getcwd())
        raise Initialized()

    monkeypatch.setattr(cli_main, "initialize_environment", fake_initialize_environment)
    monkeypatch.setattr(sys, "argv", ["ace", "--saq-home", "home"])
    with pytest.raises(Initialized):
        cli_main.main()

    assert seen["cwd"] == str(home)
    assert seen["saq_home"] == str(home)


@pytest.mark.unit
def test_alert_create_says_its_event_time_is_when_it_was_created(tmp_path):
    args = get_cli_parser().parse_args(["alert", "create", str(tmp_path / "alert")])
    args.func(args)

    root = load_root(str(tmp_path / "alert"))
    assert root.event_time is not None
    assert root.event_time_source == EventTimeSource.NOW
