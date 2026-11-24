"""`ace alert-automation list` and `report`."""

import json

import pytest

import saq.cli.commands.alert_automation  # registers the commands
from saq.cli.cli_main import get_cli_parser
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE
from saq.database.model import AlertAutomationRun
from saq.database.pool import get_db
from tests.saq.alert_automation.conftest import (
    DELIVERY_ALICE,
    RULE,
    analyst_id,
    confirm,
    make_alert,
    make_rule,
    set_alert,
    sweep,
)

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("remediable")]


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["alert-automation", *argv])
    return args.func(args)


def _confirmed_alert() -> str:
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    return alert_uuid


def test_report_compares_the_dry_run_with_what_analysts_did(capsys):
    same, different, _still_open, automated, deleted = (_confirmed_alert() for _ in range(5))
    sweep(make_rule(mode="dry_run"))
    set_alert(same, disposition=DISPOSITION_DELIVERY, disposition_user_id=analyst_id())
    set_alert(different, disposition=DISPOSITION_FALSE_POSITIVE, disposition_user_id=analyst_id())
    set_alert(automated, disposition=DISPOSITION_DELIVERY,
              disposition_user_id=get_config().global_settings.automation_user_id)
    db = get_db()
    db.execute(AlertAutomationRun.__table__.update().where(AlertAutomationRun.alert_uuid == deleted)
               .values(alert_uuid="00000000-0000-0000-0000-000000000000"))
    db.commit()

    assert _ace("report", "--rule", RULE) == 0

    out = capsys.readouterr().out
    assert f"rule {RULE}: 5 dry runs" in out
    assert "analysts dispositioned the same way: 1" in out
    assert "analysts dispositioned differently:  1" in out
    assert "still open:                          1" in out
    assert "dispositioned by ACE:                1" in out
    assert "alert deleted:                       1" in out
    assert f"{different}  {DISPOSITION_DELIVERY:<20} {DISPOSITION_FALSE_POSITIVE}" in out
    assert same not in out


def test_report_counts_a_dry_run_that_decided_no_disposition(capsys):
    _confirmed_alert()
    sweep(make_rule(mode="dry_run", actions=[{"type": "remediate", "targets": "same_message"}]))

    assert _ace("report", "--rule", RULE) == 0

    out = capsys.readouterr().out
    assert f"rule {RULE}: 1 dry runs" in out
    assert "no disposition decided:              1" in out


def test_report_counts_only_dry_runs_since_the_date(capsys):
    _confirmed_alert()
    sweep(make_rule(mode="dry_run"))

    assert _ace("report", "--rule", RULE, "--since", "2999-01-01") == 0

    assert f"rule {RULE}: 0 dry runs" in capsys.readouterr().out


def test_list_shows_the_runs(capsys):
    dry = _confirmed_alert()
    sweep(make_rule(mode="dry_run"))
    sweep(make_rule(mode="enforce"))

    assert _ace("list", "--mode", "dry_run", "--json") == 0
    listed = json.loads(capsys.readouterr().out)
    assert [(run["alert_uuid"], run["mode"], run["status"]) for run in listed] == [(dry, "dry_run", "done")]
    assert [action["type"] for action in listed[0]["actions"]] == ["disposition", "remediate"]

    assert _ace("list", "--rule", RULE) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split()[:5] == ["INSERTED", "RULE", "MODE", "STATUS", "ALERT"]
    assert [line.split()[3] for line in lines[1:]] == ["enforce", "dry_run"]
    assert lines[1].endswith("disposition=done, remediate=done")

    assert _ace("list", "--rule", "no_such_rule") == 0
    assert capsys.readouterr().out == "no alert automation runs\n"
