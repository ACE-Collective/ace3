"""
ACE CLI command implementations.

Each module in this package registers its argparse parser(s) onto the global CLI subparsers (see
saq.cli.cli_main.get_cli_subparsers) when it is imported. Importing the package registers nothing: the ace
script imports only the module of the command it runs, since every service process starts through it, and
imports all of them only to print the full help.
"""

import importlib

# top-level command (and alias) -> the module that registers it; tests/saq/test_cli.py checks this against
# what each module registers when imported alone
COMMANDS = {
    "hunt": "hunt",
    "per": "persistence",
    "persistence": "persistence",
    "integration": "integration",
    "service": "service",
    "correlate": "correlate",
    "submit": "submit",
    "remediation": "remediation",
    "gui": "gui_api",
    "user": "user",
    "test": "testing",
    "alert": "alerts",
    "cache": "cache",
    "cas": "cas",
    "crash": "crash",
    "file-collection": "file_collection",
    "cron": "cron",
    "enc": "encryption",
    "encryption": "encryption",
    "company": "company",
    "config": "config_cmd",
    "modules": "config_cmd",
    "workload": "config_cmd",
    "debug": "misc",
    "event": "misc",
    "git": "misc",
    "s3": "misc",
    "node": "node",
    "perm": "permissions",
    "phishkit": "phishkit",
    "js-deobfuscator": "js_deobfuscator",
    "storage": "storage",
    "search": "search",
    "nrd": "nrd",
    "observables": "observables",
    "partitions": "partitions",
    "signatures": "signatures",
    "svs": "svs",
    "yara": "yara",
    "yara-qa": "yara_qa",
}

# every command module, in the order `ace --help` lists their commands
COMMAND_MODULES = list(dict.fromkeys(COMMANDS.values()))


def import_command_modules(command: str | None = None) -> None:
    """Registers the parsers of the given top-level command, or of every command when there is none or it
    is not one ACE knows (so that the help and argparse's "invalid choice" list them all)."""
    if command in COMMANDS:
        importlib.import_module(f"saq.cli.commands.{COMMANDS[command]}")
        return

    for module in COMMAND_MODULES:
        importlib.import_module(f"saq.cli.commands.{module}")
