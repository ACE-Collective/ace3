
import argparse
import os
import sys
from typing import Optional

from saq.cli.commands import import_command_modules
from saq.environment import get_base_dir, initialize_base_dir, initialize_environment


def _add_global_arguments(target: argparse.ArgumentParser):
    """The options that come before the command, on the CLI parser and on the parser that only finds
    the command (get_command())."""
    target.add_argument('--saq-home', required=False, dest='saq_home', default=None,
        help="Sets the base directory of ACE.")
    target.add_argument('-L', '--logging-config-path', required=False, dest='logging_config_path', default=None,
        help="Path to the logging configuration file.")
    target.add_argument('-c', '--config-path', required=False, dest='config_paths', action='append', default=[],
        help="""ACE configuration files. $SAQ_HOME/etc/saq.default.ini is always loaded, additional override default settings.
             This option can be specified multiple times and each file is loaded in order.""")
    target.add_argument('-u', '--user-name', required=False, dest='user_name', default=None,
        help="The user name of the ACE user executing the command. This information is required for some commands.")
    target.add_argument('--force-alerts', required=False, dest='force_alerts', default=False, action='store_true',
        help="Force all analysis to always generate an alert.")
    target.add_argument('-P', '--set-decryption-password', dest='set_decryption_password', default=None,
        help="Provide the decryption password on the command line. Not secure at all. Don't do it.")
    target.add_argument('--trace', required=False, action='store_true', dest='trace', default=False,
        help="Enable execution tracing (debugging option).")
    target.add_argument('-D', '--debug', required=False, action='store_true', dest='debug_on_error', default=False,
        help="Break into pdb if an unhanled exception is thrown or an assertion fails.")


parser = argparse.ArgumentParser(description="Analysis Correlation Engine")
_add_global_arguments(parser)

subparsers = parser.add_subparsers(dest='cmd')

def get_cli_parser() -> argparse.ArgumentParser:
    """Returns the global main CLI argument parser."""
    return parser

def get_cli_subparsers() -> argparse._SubParsersAction:
    """Returns the global main CLI subparser."""
    return subparsers

def get_command(argv: list[str]) -> Optional[str]:
    """The top-level command argv names, if any: the first argument left once the global options are
    parsed. Parsing only those needs no command module imported. Arguments it cannot parse return None,
    and the CLI parser then reports them itself."""
    global_options = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    _add_global_arguments(global_options)
    try:
        _, rest = global_options.parse_known_args(argv)
    except argparse.ArgumentError:
        return None

    return next((arg for arg in rest if not arg.startswith("-")), None)

def main():

    # there is no reason to run anything as root
    if os.geteuid() == 0:
        print("do not run ace as root please")
        sys.exit(1)

    # register the parsers of the command being run (all of them for the help), then parse
    argv = sys.argv[1:]
    import_command_modules(get_command(argv))
    args = parser.parse_args(argv)

    # ACE assumes the cwd is SAQ_HOME
    initialize_base_dir(args.saq_home)
    os.chdir(get_base_dir())

    # initialize saq
    initialize_environment(
        saq_home=get_base_dir(),
        config_paths=args.config_paths,
        logging_config_path=args.logging_config_path,
        force_alerts=args.force_alerts,
    )

    if args.debug_on_error:
        def info(type, value, tb):
            if hasattr(sys, 'ps1') or not sys.stderr.isatty():
              # we are in interactive mode or we don't have a tty-like
              # device, so we call the default hook
                sys.__excepthook__(type, value, tb)
            else:
                import traceback
                import pdb
                # we are NOT in interactive mode, print the exception...
                traceback.print_exception(type, value, tb)
                print()
                # ...then start the debugger in post-mortem mode.
                pdb.pm()

        sys.excepthook = info

    # call the handler for the given command. a handler that returns a non-zero int is reporting
    # failure (ace cas verify returns 2 on a corrupt object so cron notices); anything else is success
    result = args.func(args)
    if isinstance(result, int) and result != 0:
        sys.exit(result)