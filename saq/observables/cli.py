import sys

from saq.cli.cli_main import get_cli_subparsers

observables_parser = get_cli_subparsers().add_parser("observables", help="Observable operations.")
observables_sp = observables_parser.add_subparsers(dest="observables_cmd")


def cli_export(args):
    """Export the observables enabled for detection to the configured systems."""
    # imported lazily so importing the parser at ace startup stays cheap
    from saq.observables.export.manager import run_exports
    sys.exit(run_exports(args.systems, force=args.force))


observables_export_parser = observables_sp.add_parser("export",
    help="Export observables enabled for detection to the systems configured for export.")
observables_export_parser.add_argument("systems", nargs="*",
    help="The names of the export systems to run. Exports to all enabled systems if not specified.")
observables_export_parser.add_argument("-f", "--force", action="store_true",
    help="Export even if nothing has changed since the last run.")
observables_export_parser.set_defaults(func=cli_export)
