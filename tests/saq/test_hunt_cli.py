"""Tests for `ace hunt verify`, `ace hunt list` and `ace hunt list-types`."""

import json
import shutil
from argparse import Namespace
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import yaml

import saq.cli.commands  # noqa: F401
from saq.analysis.root import RootAnalysis, Submission
from saq.cli.cli_main import get_cli_parser
from saq.cli.commands.hunt import list_hunt_types, list_hunts, verify_hunt
from saq.collectors.hunter.query_hunter import QUERY_DETAILS_EVENTS
from saq.constants import ANALYSIS_MODE_CORRELATION, DIRECTIVE_EXTRACT_URLS, F_FQDN, F_IPV4, R_REDIRECTED_FROM
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


@pytest.mark.integration
def test_execute_hunt_submit_alerts_remote(submitting_hunt_type, monkeypatch):
    submissions = []
    monkeypatch.setattr("ace_api.submit", lambda description, **kwargs: submissions.append((description, kwargs)))

    assert _execute("test:unit_test_1", "--submit-alerts", "ace.example.com:443") is None

    ((description, kwargs),) = submissions
    assert description == "unit_test_1 submission"
    assert kwargs["remote_host"] == "ace.example.com:443"
    assert kwargs["tags"] == ["hunted"]
    assert {o["value"] for o in kwargs["observables"]} >= {"10.0.0.1", "evil.example.com"}
    assert [name for name, _ in kwargs["files"]] == ["payload.txt"]
    for _, fp in kwargs["files"]:
        fp.close()
