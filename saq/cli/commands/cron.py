import sys

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.cron_tasks imports below are inside their command functions on purpose, matching the
# convention in this package: this module is imported on every `ace` invocation just to register its
# parsers, and pulling in the config and the integration loader for that would slow down every
# unrelated subcommand.

# must match saq.cron_tasks.CRON_CADENCES (not imported here, see above)
CRON_CADENCE_CHOICES = ["hourly", "daily", "weekly"]

cron_parser = get_cli_subparsers().add_parser("cron", help="Scheduled maintenance task operations (etc/cron/<cadence>).")
cron_sp = cron_parser.add_subparsers(dest="cron_cmd")


def cli_cron_run(args):
    from saq.cron_tasks import run_tasks
    sys.exit(run_tasks(args.cadence, max_parallel=args.max_parallel))


def cli_cron_list(args):
    from saq.cron_tasks import discover_tasks
    from tabulate import tabulate

    tasks = discover_tasks(args.cadence)
    print(tabulate([(t.source, t.name, t.slug, t.path) for t in tasks], headers=["Source", "Task", "Slug", "Path"], tablefmt="simple"))
    sys.exit(0)


def _positive_int(value: str) -> int:
    result = int(value)
    if result < 1:
        raise ValueError(value)
    return result


cron_run_parser = cron_sp.add_parser(
    "run",
    help="run every core and enabled integration task for a cadence in parallel. exits 1 if any task failed.")
cron_run_parser.add_argument("cadence", choices=CRON_CADENCE_CHOICES)
cron_run_parser.add_argument("--max-parallel", type=_positive_int, default=None,
    help="how many tasks may run at once. defaults to service_cron.max_parallel_tasks, else the number of cpus.")
cron_run_parser.set_defaults(func=cli_cron_run)

cron_list_parser = cron_sp.add_parser("list", help="list the tasks that would run for a cadence.")
cron_list_parser.add_argument("cadence", choices=CRON_CADENCE_CHOICES)
cron_list_parser.set_defaults(func=cli_cron_list)
