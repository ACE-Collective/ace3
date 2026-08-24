import pytest
import saq.cli.commands

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
        "submit", "remediation", "start-gui", "start-api",
        "user", "add-user", "modify-user", "delete-user",
        "test", "test-database-connections", "test-network-semaphore",
        "test-proxies", "verify-modules",
        # alert management
        "alert", "create-alert", "rebuild-index", "import-alerts",
        "delete-alerts", "reset-alerts", "archive-alerts", "add-observable",
        "reload-alerts", "cleanup-alerts", "analysis-cache-stats",
        "analysis-cache-gc", "analysis-cache-local-maintenance",
        "distribute-alerts", "display-alert",
        # encryption
        "encryption", "enc", "set-encryption-password",
        "list-encrypted-passwords", "delete-encrypted-password",
        # company / misc
        "list-companies", "add-company", "delete-company",
        "remove-bro-http-whitelist", "update-organization",
        "list-available-modules", "config", "display-workload",
        "generate-api-key", "build-suricata-db", "event", "debug", "git",
        "s3",
    }

    registered = set(get_cli_subparsers().choices.keys())

    missing = expected - registered
    assert not missing, f"missing CLI subcommands: {sorted(missing)}"

    # commands that live in other modules but must remain registered too
    for external in ("perm", "phishkit", "storage", "llm", "nrd",
                     "observables", "signatures"):
        assert external in registered, f"missing external CLI subcommand: {external}"
