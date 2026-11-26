"""``ace alert-automation`` -- what alert automation rules did, and how a rule's dry run compares with
what analysts did afterwards (docs/ALERT_AUTOMATION.md, *Reporting*)."""

import json
from datetime import datetime

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.alert_automation imports are inside the command functions, as elsewhere in this
# package: this module is imported just to register its parsers, and they load the database models

alert_automation_parser = get_cli_subparsers().add_parser(
    "alert-automation", help="Alert automation rules and their runs (docs/ALERT_AUTOMATION.md).")
alert_automation_sp = alert_automation_parser.add_subparsers(dest="alert_automation_cmd")


def _since(value: str) -> datetime:
    """YYYY-MM-DD or an ISO 8601 date and time, in UTC like every ACE timestamp."""
    return datetime.fromisoformat(value)


def cli_list(args):
    """List the most recent runs, newest first."""
    from saq.alert_automation.runs import list_runs  # local: see the NOTE above

    runs = list_runs(rule_name=args.rule, mode=args.mode, since=args.since, limit=args.limit)
    if args.json:
        print(json.dumps([{
            "id": run.id, "rule": run.rule_name, "alert_uuid": run.alert_uuid, "mode": run.mode,
            "status": run.status, "insert_date": run.insert_date.isoformat() if run.insert_date else None,
            "evidence": run.evidence, "actions": run.actions,
        } for run in runs], indent=2))
        return 0

    if not runs:
        print("no alert automation runs")
        return 0

    print(f"{'INSERTED':<19}  {'RULE':<24} {'MODE':<8} {'STATUS':<8} {'ALERT':<36}  ACTIONS")
    for run in runs:
        inserted = run.insert_date.strftime("%Y-%m-%d %H:%M:%S") if run.insert_date else ""
        actions = ", ".join(f"{action['type']}={action['status']}" for action in run.actions)
        print(f"{inserted:<19}  {run.rule_name:<24} {run.mode:<8} {run.status:<8} {run.alert_uuid:<36}  {actions}")

    return 0


list_parser = alert_automation_sp.add_parser("list", help="List alert automation runs, newest first.")
list_parser.add_argument("--rule", help="Only runs of this rule.")
list_parser.add_argument("--mode", choices=["dry_run", "enforce"], help="Only runs in this mode.")
list_parser.add_argument("--since", type=_since, help="Only runs recorded at or after this UTC date (YYYY-MM-DD[THH:MM:SS]).")
list_parser.add_argument("--limit", type=int, default=100, help="Most runs to list (default 100).")
list_parser.add_argument("--json", action="store_true", default=False, help="Print JSON.")
list_parser.set_defaults(func=cli_list)


def cli_report(args):
    """Compare a rule's dry-run decisions with what happened to each alert afterwards."""
    from saq.alert_automation.runs import dry_run_report  # local: see the NOTE above

    report = dry_run_report(args.rule, since=args.since)
    print(f"rule {report.rule_name}: {report.runs} dry runs")
    print(f"  analysts dispositioned the same way: {report.same}")
    print(f"  analysts dispositioned differently:  {len(report.different)}")
    print(f"  still open:                          {report.still_open}")
    print(f"  dispositioned by ACE:                {report.automated}")
    print(f"  alert deleted:                       {report.missing}")
    print(f"  no disposition decided:              {report.undecided}")
    if report.different:
        print()
        print(f"{'ALERT':<36}  {'DRY RUN':<20} ANALYST")
        for alert_uuid, decided, actual in report.different:
            print(f"{alert_uuid:<36}  {decided:<20} {actual}")

    return 0


report_parser = alert_automation_sp.add_parser(
    "report", help="Compare a rule's dry-run decisions with how analysts dispositioned the alerts.")
report_parser.add_argument("--rule", required=True, help="The rule to report on.")
report_parser.add_argument("--since", type=_since, help="Only dry runs recorded at or after this UTC date (YYYY-MM-DD[THH:MM:SS]).")
report_parser.set_defaults(func=cli_report)
