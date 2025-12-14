
import argparse
import os
import sys

from saq.environment import initialize_environment


parser = argparse.ArgumentParser(description="Analysis Correlation Engine")
parser.add_argument('--saq-home', required=False, dest='saq_home', default=None,
    help="Sets the base directory of ACE.")
parser.add_argument('-L', '--logging-config-path', required=False, dest='logging_config_path', default=None,
    help="Path to the logging configuration file.")
parser.add_argument('-c', '--config-path', required=False, dest='config_paths', action='append', default=[],
    help="""ACE configuration files. $SAQ_HOME/etc/saq.default.ini is always loaded, additional override default settings.
         This option can be specified multiple times and each file is loaded in order.""")
parser.add_argument('-u', '--user-name', required=False, dest='user_name', default=None,
    help="The user name of the ACE user executing the command. This information is required for some commands.")
parser.add_argument('--start', required=False, dest='start', default=False, action='store_true',
    help="Start the specified service.  Blocks keyboard unless --daemon (-d) is used.")
parser.add_argument('--stop', required=False, dest='stop', default=False, action='store_true',
    help="Stop the specified service.  Only applies to services started with --daemon (-d).")
parser.add_argument('-d', '--daemon', required=False, dest='daemon', default=False, action='store_true',
    help="Run this process as a daemon in the background.")
parser.add_argument('-k', '--kill-daemon', required=False, dest='kill_daemon', default=False, action='store_true',
    help="Kill the currently processing process.")
parser.add_argument('--force-alerts', required=False, dest='force_alerts', default=False, action='store_true',
    help="Force all analysis to always generate an alert.")
parser.add_argument('--relative-dir', required=False, dest='relative_dir', default=None,
    help="Assume all storage paths are relative to the given directory.  Defaults to current work directory.")
parser.add_argument('-p', '--provide-decryption-password', required=False, action='store_true', dest='provide_decryption_password', default=False,
    help="Prompt for the decryption password. Read README.CRYPTO for details.")
parser.add_argument('-P', '--set-decryption-password', dest='set_decryption_password', default=None,
    help="Provide the decryption password on the command line. Not secure at all. Don't do it.")
parser.add_argument('--trace', required=False, action='store_true', dest='trace', default=False,
    help="Enable execution tracing (debugging option).")
parser.add_argument('-D', '--debug', required=False, action='store_true', dest='debug_on_error', default=False,
    help="Break into pdb if an unhanled exception is thrown or an assertion fails.")
parser.add_argument('--skip-initialize-automation-user', action='store_true', dest='skip_initialize_automation_user', default=True,
    help="Skip the step of initializing the automation user.")

subparsers = parser.add_subparsers(dest='cmd')

def get_cli_parser() -> argparse.ArgumentParser:
    """Returns the global main CLI argument parser."""
    return parser

def get_cli_subparsers() -> argparse._SubParsersAction:
    """Returns the global main CLI subparser."""
    return subparsers

def main():

    # there is no reason to run anything as root
    if os.geteuid() == 0:
        print("do not run ace as root please")
        sys.exit(1)

    # parse the command line arguments
    args = parser.parse_args()

    encryption_password_plaintext = None
    if args.provide_decryption_password:
        encryption_password_plaintext = getpass.getpass(prompt="Enter the encryption password:")

    # initialize saq
    initialize_environment(
        saq_home=args.saq_home,
        config_paths=args.config_paths,
        logging_config_path=args.logging_config_path,
        relative_dir=args.relative_dir,
        encryption_password_plaintext=encryption_password_plaintext,
        skip_initialize_automation_user=args.skip_initialize_automation_user,
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

    # call the handler for the given command
    args.func(args)