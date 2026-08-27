import pytest
import saq.cli.commands # noqa: F401

from saq.cli.cli_main import get_cli_subparsers


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
        # gui / api
        "gui", "api",
        # user management
        "user",
        # test utilities
        "test",
        # alert management
        "alert",
        # cache maintenance
        "cache",
        # encryption
        "encryption", "enc",
        # company / misc
        "company",
        "config", "modules", "workload",
        "bro", "event", "debug", "git",
        "s3",
    }

    registered = set(get_cli_subparsers().choices.keys())

    missing = expected - registered
    assert not missing, f"missing CLI subcommands: {sorted(missing)}"

    # commands that live in other modules but must remain registered too
    for external in ("perm", "phishkit", "storage", "llm", "nrd",
                     "observables", "signatures"):
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
    assert {"start"} <= choices("api")
    assert {"stats", "gc", "local-maintenance"} <= choices("cache")
    assert {"archive", "distribute"} <= choices("alert")
    assert {"add", "delete", "list"} <= choices("company")
    assert {"list"} <= choices("modules")
    assert {"display"} <= choices("workload")
    assert {"database-connections", "network-semaphore", "proxies", "modules"} <= choices("test")
    assert {"update-organization", "generate-api-key"} <= choices("user")
    assert {"build-db"} <= choices("signatures")
    assert {"remove-http-whitelist"} <= choices("bro")
    assert {"display", "clear"} <= choices("remediation")
