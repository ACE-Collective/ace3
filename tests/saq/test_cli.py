import ast
import os
import pkgutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from saq.analysis.root import load_root
from saq.cli import cli_main
from saq.cli.cli_main import get_cli_parser, get_cli_subparsers
from saq.cli.commands import COMMAND_MODULES, COMMANDS, import_command_modules
from saq.environment import get_base_dir
from tests.saq.helpers import run_python

# every test here reads the parsers of every command
import_command_modules()
from saq.constants import EventTimeSource


@pytest.mark.unit
def test_cli_commands_registered():
    """import_command_modules() with no command must register every built-in CLI command.

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
@pytest.mark.parametrize("argv", [
    ["-p"],
    ["--provide-decryption-password"],
    ["-Psecret"],
    ["--set-decryption-password=secret"],
])
def test_the_decryption_password_options_are_gone(argv, capsys):
    """ace -p prompted for the encryption password with a getpass that was never imported, so it only
    ever crashed with a NameError (#1027), and nothing ever read what ace -P was given; both are gone
    and argparse rejects them."""
    with pytest.raises(SystemExit) as exc_info:
        get_cli_parser().parse_args([*argv, "config"])

    assert exc_info.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


@pytest.mark.unit
def test_alert_create_says_its_event_time_is_when_it_was_created(tmp_path):
    args = get_cli_parser().parse_args(["alert", "create", str(tmp_path / "alert")])
    args.func(args)

    root = load_root(str(tmp_path / "alert"))
    assert root.event_time is not None
    assert root.event_time_source == EventTimeSource.NOW


def _registered_alone(module: str) -> list[str]:
    result = run_python(f"import saq.cli.commands.{module}\n"
                        "from saq.cli.cli_main import get_cli_subparsers\n"
                        "print(sorted(get_cli_subparsers().choices))\n")
    return ast.literal_eval(result.stdout.strip().splitlines()[-1])


@pytest.mark.unit
def test_the_command_map_matches_what_each_module_registers():
    """ace imports only the module COMMANDS names for the command it runs, so the map has to name, for
    every top-level command and alias, the module that registers it on its own."""
    package_dir = os.path.join(get_base_dir(), "saq", "cli", "commands")
    assert sorted(COMMAND_MODULES) == sorted(info.name for info in pkgutil.iter_modules([package_dir]))

    with ThreadPoolExecutor(max_workers=4) as pool:
        registered = dict(zip(COMMAND_MODULES, pool.map(_registered_alone, COMMAND_MODULES)))

    assert {command: module for module, commands in registered.items() for command in commands} == COMMANDS


@pytest.mark.unit
@pytest.mark.parametrize("argv, command", [
    (["service", "start", "engine"], "service"),
    (["-L", "etc/logging.yaml", "--saq-home", "/opt/ace", "service", "start"], "service"),
    (["-c", "a.yaml", "-c", "b.yaml", "alert", "create", "x"], "alert"),
    (["-u", "alert", "service", "start"], "service"),
    (["--force-alerts", "correlate", "-c", "x"], "correlate"),
    (["--help"], None),
    (["-h"], None),
    ([], None),
    (["-c"], None),
])
def test_get_command(argv, command):
    assert cli_main.get_command(argv) == command


@pytest.mark.unit
def test_running_a_command_imports_only_its_module():
    result = run_python("import sys\n"
                        "from saq.cli.cli_main import get_command\n"
                        "from saq.cli.commands import import_command_modules\n"
                        "import_command_modules(get_command(['service', 'start', 'network_semaphore']))\n"
                        "print(sorted(name for name in sys.modules if name.startswith('saq.cli.commands.')))\n")
    assert ast.literal_eval(result.stdout.strip().splitlines()[-1]) == ["saq.cli.commands.service"]


@pytest.mark.unit
def test_help_lists_every_command():
    result = subprocess.run([sys.executable, "ace", "--help"], cwd=get_base_dir(), capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-4000:]
    for command in COMMANDS:
        assert command in result.stdout, command


@pytest.mark.unit
def test_an_unknown_command_lists_every_command():
    result = subprocess.run([sys.executable, "ace", "no-such-command"], cwd=get_base_dir(), capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 2
    assert "invalid choice" in result.stderr
    assert "yara-qa" in result.stderr and "js-deobfuscator" in result.stderr


def _run_ace(tmp_path, overlay: str, *argv) -> subprocess.CompletedProcess:
    config_path = tmp_path / "overlay.yaml"
    config_path.write_text(overlay)
    # etc/saq.yaml loads after -c, so it would win over the overlay
    env = dict(os.environ, SAQ_SKIP_LOCAL_SAQ_YAML="1")
    return subprocess.run([sys.executable, "ace", "-c", str(config_path), *argv], cwd=get_base_dir(),
                          capture_output=True, text=True, timeout=120, env=env)


@pytest.mark.unit
def test_ace_exits_with_its_own_code_when_it_cannot_reach_a_database(tmp_path):
    # every database on a port nothing listens on, so nothing here reaches a real one
    overlay = "".join(f"{section}:\n  port: 1\n" for section in (
        "database_ace", "database_brocess", "database_email_archive", "database_analysis_result_cache"))

    result = _run_ace(tmp_path, overlay, "test", "database-connections")

    assert result.returncode == cli_main.EXIT_DATABASE_UNAVAILABLE, result.stderr[-4000:]
    assert "unable to reach a database: (2003, " in result.stderr


@pytest.mark.unit
def test_a_configuration_error_does_not_exit_with_the_database_code(tmp_path):
    result = _run_ace(tmp_path, "global:\n  instance_name: env:ACE_NO_SUCH_VARIABLE_1008\n",
                      "test", "database-connections")

    assert result.returncode not in (0, cli_main.EXIT_DATABASE_UNAVAILABLE)
    assert "configuration referenced unknown environment variable ACE_NO_SUCH_VARIABLE_1008" in result.stderr
