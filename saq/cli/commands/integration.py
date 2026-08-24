import logging
import sys

from saq.cli.cli_main import get_cli_subparsers


def enable_integration(args):
    from saq.integration.integration_manager import enable_integration
    enable_integration(args.name)
    sys.exit(0)

def disable_integration(args):
    from saq.integration.integration_manager import disable_integration
    disable_integration(args.name)
    sys.exit(0)

def list_integrations(args):
    from saq.integration.integration_loader import get_valid_integration_dirs
    from saq.integration.integration_util import get_integration_name_from_path
    from saq.integration.integration_manager import is_integration_enabled, is_integration_installed
    from tabulate import tabulate

    integration_info = []
    for dir_path in get_valid_integration_dirs():
        name = get_integration_name_from_path(dir_path)
        enabled = is_integration_enabled(name)
        installed = is_integration_installed(name)
        integration_info.append((name, "ENABLED" if enabled else "DISABLED", "YES" if installed else "NO", dir_path))

    headers = ["Integration", "Status", "Installed", "Directory"]
    print(tabulate(integration_info, headers=headers, tablefmt="simple"))

    sys.exit(0)

def install_integration(args):
    from saq.integration.integration_manager import install_integration
    install_integration(args.name)
    sys.exit(0)

def uninstall_integration(args):
    from saq.integration.integration_manager import uninstall_integration
    uninstall_integration(args.name)
    sys.exit(0)

integration_parser = get_cli_subparsers().add_parser('integration')
integration_sp = integration_parser.add_subparsers(dest='integration_cmd')

install_integration_parser = integration_sp.add_parser('install',
    help="Installs the given integration.")
install_integration_parser.add_argument('name',
    help="The name of the integration to install.")
install_integration_parser.set_defaults(func=install_integration)

uninstall_integration_parser = integration_sp.add_parser('uninstall',
    help="Uninstalls the given integration.")
uninstall_integration_parser.add_argument('name',
    help="The name of the integration to uninstall.")
uninstall_integration_parser.set_defaults(func=uninstall_integration)

enable_integration_parser = integration_sp.add_parser('enable',
    help="Enables the given integration.")
enable_integration_parser.add_argument('name',
    help="The integration to enable. Use ace integration list to get the list of available integrations.")
enable_integration_parser.set_defaults(func=enable_integration)

list_integration_parser = integration_sp.add_parser('list',
    help="List the available integrations and show enabled/disabled status.")
list_integration_parser.set_defaults(func=list_integrations)

disable_integration_parser = integration_sp.add_parser('disable',
    help="Disables the given integration.")
disable_integration_parser.add_argument('name',
    help="The integration to disable. Use ace integration list to get the list of available integrations.")
disable_integration_parser.set_defaults(func=disable_integration)
