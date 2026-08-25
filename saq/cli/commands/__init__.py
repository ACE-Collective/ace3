"""
ACE CLI command implementations.

Each module in this package registers its argparse parser(s) onto the global
CLI subparsers (see saq.cli.cli_main.get_cli_subparsers) at import time.
Importing this package registers every built-in command.
"""

# NOTE: these imports exist purely for their side effect of registering parsers
from saq.cli.commands import ( # noqa: F401
    hunt,
    persistence,
    integration,
    service,
    correlate,
    submit,
    remediation,
    gui_api,
    user,
    testing,
    alerts,
    encryption,
    company,
    config_cmd,
    misc,
    permissions,
    phishkit,
    storage,
    llm,
    nrd,
    observables,
    signatures,
)
