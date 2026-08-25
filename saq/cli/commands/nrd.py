import sys

from saq.cli.cli_main import get_cli_subparsers

nrd_parser = get_cli_subparsers().add_parser("nrd", help="Newly-registered domains (NRD) operations.")
nrd_sp = nrd_parser.add_subparsers(dest="nrd_cmd")


def cli_refresh(args):
    """Run one NRD refresh cycle. Idempotent; almost always a sub-second no-op."""
    # imported lazily so importing the parser at ace startup stays cheap
    from saq.nrd.refresh import refresh
    sys.exit(refresh())


nrd_refresh_parser = nrd_sp.add_parser("refresh", help="refresh the local NRD SQLite database from configured upstream lists.")
nrd_refresh_parser.set_defaults(func=cli_refresh)
