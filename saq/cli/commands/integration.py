import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.integration.integration_util import get_integration_name_from_path, get_valid_integration_dirs


def list_integrations(args):
    # local: the full help imports every command module
    from saq.integration.integration_manager import get_integration_dir_configs
    from tabulate import tabulate

    integration_info = []
    for dir_path in get_valid_integration_dirs():
        configs = get_integration_dir_configs(dir_path)
        if not configs:
            # still on: its configuration is merged and its cron tasks run
            integration_info.append((get_integration_name_from_path(dir_path), "UNDECLARED", dir_path))

        for config in configs:
            integration_info.append((config.name, "ENABLED" if config.enabled else "DISABLED", dir_path))

    headers = ["Integration", "Status", "Directory"]
    print(tabulate(integration_info, headers=headers, tablefmt="simple"))

    sys.exit(0)

integration_parser = get_cli_subparsers().add_parser('integration')
integration_sp = integration_parser.add_subparsers(dest='integration_cmd')

list_integration_parser = integration_sp.add_parser('list',
    help="List the available integrations and the enabled setting of each integration_*: section they declare.")
list_integration_parser.set_defaults(func=list_integrations)
