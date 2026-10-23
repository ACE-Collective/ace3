"""Tests for the `ace event`, `ace git`, `ace debug` and `ace s3` commands."""

from datetime import date, timedelta
from types import SimpleNamespace

import pytest

import saq.cli.commands.misc  # registers the commands
import saq.event
import saq.git
from saq.cli.cli_main import get_cli_parser
from saq.database.model import (
    Event,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventType,
    EventVector,
    Malware,
    MalwareMapping,
)
from saq.database.pool import get_db
from saq.event import AutoCloseCriteria, get_auto_close_events


def _parse(*argv):
    return get_cli_parser().parse_args(list(argv))


def _ace(*argv) -> int:
    args = _parse(*argv)
    with pytest.raises(SystemExit) as e:
        args.func(args)

    return e.value.code


def _status(value: str) -> EventStatus:
    # the per-test reset empties event_status
    status = get_db().query(EventStatus).filter(EventStatus.value == value).one_or_none()
    if status is None:
        status = EventStatus(value=value)
        get_db().add(status)
        get_db().flush()

    return status


def _event(name: str, days_old: int = 0, malware: str | None = None) -> int:
    db = get_db()
    lookups = [EventRemediation(value=f"{name}_r"), EventRiskLevel(value=f"{name}_rl"),
               EventPreventionTool(value=f"{name}_pt"), EventType(value=f"{name}_t"), EventVector(value=f"{name}_v")]
    db.add_all(lookups)
    db.flush()
    remediation, risk_level, prevention_tool, event_type, vector = lookups
    _status("CLOSED")
    event = Event(name=name, creation_date=date.today() - timedelta(days=days_old), status=_status("OPEN"),
                  remediation=remediation, risk_level=risk_level, prevention_tool=prevention_tool,
                  type=event_type, vector=vector)
    db.add(event)
    db.flush()
    if malware:
        m = Malware(name=malware)
        db.add(m)
        db.flush()
        db.add(MalwareMapping(event_id=event.id, malware_id=m.id))

    db.commit()
    return event.id


def _status_of(event_id: int) -> str:
    get_db().expire_all()
    return get_db().query(Event).filter(Event.id == event_id).one().status.value


@pytest.mark.integration
def test_close_event_by_id(capsys):
    first = _event("cli close first")
    second = _event("cli close second")
    untouched = _event("cli close untouched")

    assert _ace("event", "close", "-i", str(first), "-i", str(second)) == 0

    assert _status_of(first) == "CLOSED"
    assert _status_of(second) == "CLOSED"
    assert _status_of(untouched) == "OPEN"
    assert capsys.readouterr().out == "event closed\nevent closed\n"


@pytest.mark.integration
def test_close_event_dry_run_changes_nothing():
    event_id = _event("cli close dry run")

    assert _ace("event", "close", "-i", str(event_id), "--dry-run") == 0

    assert _status_of(event_id) == "OPEN"


@pytest.mark.integration
def test_close_unknown_event_is_an_error(caplog):
    event_id = _event("cli close known")

    assert _ace("event", "close", "-i", "999999", "-i", str(event_id)) == 1

    assert "unable to close event 999999" in caplog.text
    # the other event is still closed
    assert _status_of(event_id) == "CLOSED"


@pytest.mark.integration
def test_auto_close_events_with_matching_threat_after_two_days(monkeypatch):
    old_match = _event("cli auto old match", days_old=3, malware="AutoCloseMalware")
    new_match = _event("cli auto new match", days_old=0, malware="AutoCloseMalware")
    old_other = _event("cli auto old other", days_old=3, malware="SomethingElse")
    old_none = _event("cli auto old none", days_old=3)
    criteria = [AutoCloseCriteria(threat_name="AutoCloseMalware")]

    assert get_auto_close_events(criteria) == [old_match]

    monkeypatch.setattr(saq.event, "load_auto_close_criteria", lambda: criteria)
    assert _ace("event", "close", "--auto") == 0
    assert _status_of(old_match) == "CLOSED"
    assert [_status_of(e) for e in (new_match, old_other, old_none)] == ["OPEN"] * 3


@pytest.mark.integration
def test_auto_close_without_criteria_file_closes_nothing(monkeypatch, tmp_path, caplog):
    event_id = _event("cli auto no file", days_old=3, malware="AutoCloseMalware")
    monkeypatch.setattr(saq.event.get_global_runtime_settings(), "analyst_data_dir", str(tmp_path))

    assert get_auto_close_events() == []
    assert "unable to load auto close criteria" in caplog.text

    assert _ace("event", "close", "--auto") == 0
    assert _status_of(event_id) == "OPEN"


@pytest.mark.unit
def test_debug_does_nothing():
    args = _parse("debug")
    assert args.func(args) == 0


class _FakeRepo:
    def __init__(self, name: str, up_to_date: bool):
        self.config = SimpleNamespace(name=name, local_path=f"/repos/{name}", git_url=f"https://git.example.com/{name}.git",
                                      branch="main", update_frequency=60)
        self.up_to_date = up_to_date
        self.updated = False

    def repo_is_up_to_date(self) -> bool:
        return self.up_to_date

    def update(self) -> bool:
        self.updated = True
        return True


@pytest.fixture
def repos(monkeypatch):
    result = [_FakeRepo("signatures", True), _FakeRepo("hunts", False)]
    monkeypatch.setattr(saq.git, "get_configured_repos", lambda: result)
    return result


@pytest.mark.unit
def test_git_update_all(repos):
    assert _ace("git", "update") == 0
    assert [r.updated for r in repos] == [True, True]


@pytest.mark.unit
def test_git_update_by_name(repos):
    assert _ace("git", "update", "hunts") == 0
    assert [r.updated for r in repos] == [False, True]


@pytest.mark.unit
def test_git_list(repos, capsys):
    assert _ace("git", "list") == 0

    rows = [[cell.strip() for cell in line.split("|")[1:-1]] for line in capsys.readouterr().out.splitlines()]
    assert rows[0] == ["Name", "Local Path", "Git URL", "Branch", "Up to Date", "Update Frequency"]
    assert rows[2:] == [
        ["signatures", "/repos/signatures", "https://git.example.com/signatures.git", "main", "True", "60"],
        ["hunts", "/repos/hunts", "https://git.example.com/hunts.git", "main", "False", "60"],
    ]


@pytest.mark.unit
@pytest.mark.parametrize("argv, message", [
    (["--bucket", "b", "--key", "k"], "--file is required"),
    (["--file", "f", "--key", "k"], "--bucket is required"),
    (["--file", "f", "--bucket", "b"], "--key is required"),
    (["--file", "/nonexistent/file", "--bucket", "b", "--key", "k"], "File does not exist: /nonexistent/file"),
])
def test_s3_upload_argument_errors(argv, message, caplog):
    args = _parse("s3", "upload", *argv)
    assert args.func(args) == 1
    assert message in caplog.text


@pytest.mark.unit
def test_s3_upload_failure_is_logged_with_traceback(tmp_path, caplog):
    # boto3 is not installed in the dev container, so the upload fails at the import
    path = tmp_path / "upload.txt"
    path.write_text("data")
    args = _parse("s3", "upload", "--file", str(path), "--bucket", "bucket", "--key", "key")

    assert args.func(args) == 1
    [record] = [r for r in caplog.records if r.getMessage().startswith("failed to upload")]
    assert record.getMessage().startswith(f"failed to upload {path} to s3://bucket/key")
    assert record.exc_info is not None
