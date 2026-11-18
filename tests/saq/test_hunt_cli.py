"""Tests for `ace hunt verify`, `ace hunt list` and `ace hunt list-types`."""

import json
import shutil
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytz
import yaml

import saq.cli.commands.hunt  # noqa: F401 -- registers the commands
from saq.analysis.root import RootAnalysis, Submission
from saq.cli.cli_main import get_cli_parser
from saq.cli.commands.hunt import list_hunt_types, list_hunts, verify_hunt
from saq.collectors.hunter.query_hunter import QUERY_DETAILS_EVENTS, QueryHunt
from saq.constants import ANALYSIS_MODE_CORRELATION, DIRECTIVE_EXTRACT_URLS, F_FQDN, F_IPV4, R_REDIRECTED_FROM, EventTimeSource
from saq.database.model import Alert
from saq.database.pool import get_db
from tests.saq.collectors.hunter.test_base_hunter import TestHunt
from saq.configuration.config import get_config
from saq.configuration.schema import HuntTypeConfig


@pytest.fixture
def test_hunt_type(tmp_path):
    rules_dir = tmp_path / "rules"
    shutil.copytree("tests/data/hunts/test/generic", rules_dir)
    with open(rules_dir / "test_3.yaml", "w") as fp:
        yaml.dump({
            "rule": {
                "uuid": "0f0b6a3e-2f4c-4d3c-9a51-7e1f3c6d2b10",
                "enabled": False,
                "name": "unit_test_3",
                "description": "Unit Test Description 3",
                "type": "test",
                "alert_type": "test - alert",
                "frequency": "00:00:10",
                "instance_types": ["unittest"],
            }
        }, fp)

    _configure_hunt_type(rules_dir, "tests.saq.collectors.hunter.test_base_hunter", "TestHunt")
    yield
    get_config().load_hunt_type_configs()


def _configure_hunt_type(rules_dir, python_module, python_class):
    get_config().clear_hunt_type_configs()
    get_config().add_hunt_type_config("test", HuntTypeConfig(
        name="test",
        python_module=python_module,
        python_class=python_class,
        rule_dirs=[{"rule_dir": str(rules_dir)}],
        update_frequency=60,
    ))


@pytest.mark.integration
def test_list_hunts(test_hunt_type, capsys):
    with pytest.raises(SystemExit) as exc_info:
        list_hunts(Namespace())

    assert exc_info.value.code == 0
    # enabled hunts first, then by name
    assert capsys.readouterr().out.splitlines() == [
        "E test:test_1 - unit_test_1",
        "E test:test_2 - unit_test_2",
        "D test:test_3 - unit_test_3",
    ]


@pytest.mark.integration
def test_list_hunt_types(test_hunt_type, capsys):
    with pytest.raises(SystemExit) as exc_info:
        list_hunt_types(Namespace())

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.splitlines() == ["test"]


@pytest.mark.integration
def test_verify_hunts(test_hunt_type, capsys):
    with pytest.raises(SystemExit) as exc_info:
        verify_hunt(Namespace())

    assert exc_info.value.code == 0
    assert "hunt syntax verified" in capsys.readouterr().out


@pytest.mark.integration
def test_verify_hunts_fails_on_invalid_hunt(test_hunt_type, tmp_path, capsys):
    with open(tmp_path / "rules" / "broken.yaml", "w") as fp:
        fp.write("rule:\n  name: broken\n")

    with pytest.raises(SystemExit) as exc_info:
        verify_hunt(Namespace())

    assert exc_info.value.code == 1
    assert "unable to load 1 test hunts" in capsys.readouterr().err


class _SubmittingHunt(TestHunt):
    """Produces one submission with something of everything the command prints."""
    __test__ = False

    def execute(self):
        root_uuid = str(uuid4())
        root = RootAnalysis(
            uuid=root_uuid,
            storage_dir=self.manager.file_manager.get_staging_tmp_path(root_uuid),
            desc=f"{self.name} submission",
            analysis_mode=ANALYSIS_MODE_CORRELATION,
            tool="test_tool",
            tool_instance="test_tool_instance",
            alert_type="test_type",
            details={QUERY_DETAILS_EVENTS: [{"src": "10.0.0.1"}, {"src": "10.0.0.2"}]})
        # as a hunt that couldn't extract the event's timestamp
        root.set_event_time(datetime(2026, 1, 2, tzinfo=timezone.utc), EventTimeSource.QUERY_TIME)
        root.initialize_storage()
        ip = root.add_observable_by_spec(F_IPV4, "10.0.0.1", o_time=datetime(2026, 1, 2, tzinfo=timezone.utc))
        ip.add_tag("scanner")
        ip.add_directive(DIRECTIVE_EXTRACT_URLS)
        fqdn = root.add_observable_by_spec(F_FQDN, "evil.example.com")
        ip.add_relationship(R_REDIRECTED_FROM, fqdn)
        path = root.create_file_path("payload.txt")
        with open(path, "w") as fp:
            fp.write("payload")
        root.add_file_observable(path)
        root.add_tag("hunted")
        root.add_pivot_link("https://siem.example.com/search?q=10.0.0.1", None, "search")
        root.save()
        return [Submission(root)]


@pytest.fixture
def submitting_hunt_type(tmp_path):
    rules_dir = tmp_path / "rules"
    shutil.copytree("tests/data/hunts/test/generic", rules_dir)
    _configure_hunt_type(rules_dir, "tests.saq.test_hunt_cli", "_SubmittingHunt")
    yield
    get_config().load_hunt_type_configs()


def _execute(*argv):
    args = get_cli_parser().parse_args(["hunt", "execute", *argv])
    try:
        return args.func(args)
    except SystemExit as e:
        return e.code


@pytest.mark.integration
def test_execute_hunt_details_and_events(submitting_hunt_type, tmp_path, capsys):
    json_dir = tmp_path / "json"

    assert _execute("test:unit_test_1", "-d", "-v", "--json-dir", str(json_dir)) is None

    out = capsys.readouterr().out
    assert out.startswith("unit_test_1 submission\n")
    assert "\t(*) ipv4 - 10.0.0.1 - 2026-01-02 00:00:00+00:00 tags [scanner] direc [extract_urls] " \
           "rels [redirected_from -> fqdn:evil.example.com]" in out
    assert "\t(+) hunted" in out
    assert "\t🔗 pivot (https://siem.example.com/search?q=10.0.0.1)[search]" in out
    assert out.count('"src"') == 2
    # the events, not the names of the details' keys
    assert json.loads((json_dir / "0.json").read_text()) == [{"src": "10.0.0.1"}, {"src": "10.0.0.2"}]
    assert (json_dir / "manifest").read_text() == "0 = unit_test_1 submission\n"


@pytest.mark.integration
@pytest.mark.parametrize("hunt", ["nope:unit_test_1", "test:no_such_hunt"])
def test_execute_unknown_hunt(submitting_hunt_type, hunt):
    assert _execute(hunt) == 1


@pytest.mark.integration
def test_execute_hunt_submit_alerts_local(submitting_hunt_type):
    assert _execute("test:unit_test_1", "--submit-alerts-local") is None

    (alert,) = get_db().query(Alert).all()
    assert alert.description == "unit_test_1 submission"
    alert.load()
    assert alert.root_analysis.event_time_source == EventTimeSource.QUERY_TIME


@pytest.mark.integration
def test_execute_hunt_submit_alerts_remote(submitting_hunt_type, monkeypatch):
    submissions = []
    monkeypatch.setattr("ace_api.submit", lambda description, **kwargs: submissions.append((description, kwargs)))

    assert _execute("test:unit_test_1", "--submit-alerts", "ace.example.com:443") is None

    ((description, kwargs),) = submissions
    assert description == "unit_test_1 submission"
    assert kwargs["remote_host"] == "ace.example.com:443"
    assert kwargs["event_time_source"] == "query_time"
    assert kwargs["tags"] == ["hunted"]
    assert {o["value"] for o in kwargs["observables"]} >= {"10.0.0.1", "evil.example.com"}
    assert [name for name, _ in kwargs["files"]] == ["payload.txt"]
    for _, fp in kwargs["files"]:
        fp.close()


class _RecordingQueryHunt(QueryHunt):
    """Records the time range it was asked to query, and finds nothing."""
    __test__ = False

    executed = []

    def execute_query(self, start_time, end_time, *args, **kwargs):
        _RecordingQueryHunt.executed.append((start_time, end_time))
        return []

    def cancel(self):
        pass


@pytest.fixture
def query_hunt_type(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    with open(rules_dir / "query_hunt.yaml", "w") as fp:
        yaml.dump({
            "rule": {
                "uuid": "5d0f7c1e-3b8a-4f2e-9c6d-1a2b3c4d5e6f",
                "enabled": True,
                "name": "query_hunt",
                "description": "Query Hunt",
                "type": "test",
                "alert_type": "test - query",
                "frequency": "00:10:00",
                "instance_types": ["unittest"],
                "time_range": "00:10:00",
                "full_coverage": False,
                "use_index_time": False,
                "query": "index=test",
            }
        }, fp)

    _configure_hunt_type(rules_dir, "tests.saq.test_hunt_cli", "_RecordingQueryHunt")
    _RecordingQueryHunt.executed = []
    yield _RecordingQueryHunt.executed
    get_config().load_hunt_type_configs()


@pytest.mark.integration
def test_execute_query_hunt_over_its_own_time_range(query_hunt_type):
    before = datetime.now(timezone.utc)
    assert _execute("test:query_hunt") is None

    [(start_time, end_time)] = query_hunt_type
    # the range a scheduled run would query: the last time_range (start and end each read the clock)
    assert abs(end_time - start_time - timedelta(minutes=10)) < timedelta(seconds=1)
    assert end_time >= before


@pytest.mark.integration
def test_execute_query_hunt_over_a_given_time_range(query_hunt_type):
    assert _execute("test:query_hunt", "-s", "01/02/2026:03:04:05", "-e", "01/02/2026:04:04:05") is None

    assert query_hunt_type == [(datetime(2026, 1, 2, 3, 4, 5, tzinfo=pytz.utc), datetime(2026, 1, 2, 4, 4, 5, tzinfo=pytz.utc))]


@pytest.mark.integration
def test_execute_query_hunt_in_a_time_zone(query_hunt_type):
    assert _execute("test:query_hunt", "-s", "07/01/2026:08:00:00", "-e", "07/01/2026:09:00:00",
                    "-z", "America/New_York") is None

    [(start_time, end_time)] = query_hunt_type
    # EDT is four hours behind UTC
    assert start_time == datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert end_time == datetime(2026, 7, 1, 13, 0, 0, tzinfo=timezone.utc)


@pytest.mark.integration
def test_execute_query_hunt_with_only_a_start_time(query_hunt_type):
    assert _execute("test:query_hunt", "-s", "01/02/2026:03:04:05") is None

    [(start_time, end_time)] = query_hunt_type
    assert start_time == datetime(2026, 1, 2, 3, 4, 5, tzinfo=pytz.utc)
    # the end is the hunt's own: now
    assert end_time > datetime(2026, 1, 3, tzinfo=timezone.utc)
