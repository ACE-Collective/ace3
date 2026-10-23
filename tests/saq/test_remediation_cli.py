"""Tests for the `ace remediation` commands."""

from datetime import datetime

import pytest

import saq.cli.commands.remediation  # registers the commands
from saq.cli.cli_main import get_cli_parser
from saq.configuration import get_config
from saq.constants import F_EMAIL_DELIVERY
from saq.database.model import Remediation
from saq.database.pool import get_db
from saq.remediation.types import RemediationAction, RemediationStatus


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["remediation", *argv])
    with pytest.raises(SystemExit) as e:
        args.func(args)

    return e.value.code


def _remediation(key: str, status: RemediationStatus = RemediationStatus.NEW, lock: str = None) -> int:
    remediation = Remediation(name="email", type=F_EMAIL_DELIVERY, key=key,
                              action=RemediationAction.REMOVE.value,
                              user_id=get_config().global_settings.automation_user_id,
                              status=status.value, lock=lock,
                              lock_time=datetime.now() if lock else None)
    get_db().add(remediation)
    get_db().commit()
    return remediation.id


def _remaining_keys() -> list[str]:
    get_db().expire_all()
    return sorted(key for (key,) in get_db().query(Remediation.key))


@pytest.mark.integration
def test_status(capsys):
    _remediation("<new@example.com>|user@example.com")
    _remediation("<done@example.com>|user@example.com", RemediationStatus.COMPLETED)

    assert _ace("status") == 0
    output = capsys.readouterr().out
    assert 'key: "<new@example.com>|user@example.com"' in output
    assert 'key: "<done@example.com>|user@example.com"' in output

    assert _ace("status", "-s", "COMPLETED", "-t", F_EMAIL_DELIVERY, "-k", "done", "-u", "automation",
                "--user-id", str(get_config().global_settings.automation_user_id)) == 0
    output = capsys.readouterr().out
    assert "done@example.com" in output
    assert "new@example.com" not in output


@pytest.mark.integration
def test_display_lists_the_pending_requests(capsys):
    new_id = _remediation("<new@example.com>|user@example.com")
    in_progress_id = _remediation("<busy@example.com>|user@example.com", RemediationStatus.IN_PROGRESS)
    _remediation("<done@example.com>|user@example.com", RemediationStatus.COMPLETED)

    assert _ace("display") == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["ID", "STATUS", "TYPE", "ACTION", "DATE", "TARGET"]
    assert [line.split()[:2] for line in lines[1:]] == [[str(new_id), "NEW"], [str(in_progress_id), "IN_PROGRESS"]]


@pytest.mark.integration
def test_clear_by_id():
    new_id = _remediation("<new@example.com>|user@example.com")
    _remediation("<other@example.com>|user@example.com")

    assert _ace("clear", str(new_id)) == 0

    assert _remaining_keys() == ["<other@example.com>|user@example.com"]


@pytest.mark.integration
def test_clear_all_keeps_what_is_locked_or_no_longer_new():
    _remediation("<new@example.com>|user@example.com")
    _remediation("<locked@example.com>|user@example.com", lock="00000000-0000-4000-8000-000000000000")
    _remediation("<busy@example.com>|user@example.com", RemediationStatus.IN_PROGRESS)

    assert _ace("clear", "--all") == 0

    assert _remaining_keys() == ["<busy@example.com>|user@example.com", "<locked@example.com>|user@example.com"]


@pytest.mark.integration
def test_clear_needs_ids_or_all(caplog):
    _remediation("<new@example.com>|user@example.com")

    assert _ace("clear") == 1

    assert "no remediation ids were specified" in caplog.text
    assert _remaining_keys() == ["<new@example.com>|user@example.com"]
