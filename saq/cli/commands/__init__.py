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
)

# pull in all the other CLI parsers from outside this package
from saq.permissions.cli import permissions_parser # noqa: F401
from saq.phishkit import phishkit_parser # noqa: F401
from saq.storage.cli import storage_parser # noqa: F401
from saq.llm.cli import llm_parser # noqa: F401
from saq.nrd.cli import nrd_parser # noqa: F401
from saq.observables.cli import observables_parser # noqa: F401
from saq.signatures.cli import signatures_parser # noqa: F401
