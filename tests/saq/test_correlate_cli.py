import io
import json
import os

import pytest

import saq.cli.commands.correlate  # noqa: F401 -- registers the commands
from saq.analysis.root import RootAnalysis, load_root
from saq.cli.cli_main import get_cli_parser
from saq.constants import ANALYSIS_MODE_CORRELATION, F_IPV4, F_TEST, EventTimeSource
from saq.database.model import Alert
from saq.database.pool import get_db


def _correlate(*argv):
    args = get_cli_parser().parse_args(["correlate", *argv])
    with pytest.raises(SystemExit) as exit_info:
        args.func(args)
    return exit_info.value.code


def _load(storage_dir):
    root = RootAnalysis(storage_dir=str(storage_dir))
    root.load()
    return root


@pytest.fixture
def out(tmp_path):
    return tmp_path / "out"


@pytest.mark.integration
def test_correlate_observables(out):
    assert _correlate("--disable-all", "-d", str(out), "--description", "manual check", "--comment", "from a ticket",
                      "--add-tag", "suspect", "--add-directive", "sandbox", "--alert-type", "manual",
                      "--company-name", "default", "--instructions", "look at it", "-t", "2026-01-02 03:04:05 +0000",
                      F_IPV4, "10.0.0.1", F_TEST, "test_1") == 0

    root = _load(out)
    assert root.description == "manual check"
    assert root.details == {"comment": "from a ticket"}
    assert root.alert_type == "manual"
    assert root.instructions == "look at it"
    # the reference time is the event's
    assert (root.event_time.year, root.event_time_source) == (2026, EventTimeSource.EVENT)
    (ip,) = root.get_observables_by_type(F_IPV4)
    assert ip.value == "10.0.0.1"
    assert ip.has_tag("suspect")
    assert ip.has_directive("sandbox")
    assert [o.value for o in root.get_observables_by_type(F_TEST)] == ["test_1"]


@pytest.mark.unit
def test_correlate_odd_number_of_targets(out):
    assert _correlate("-d", str(out), F_IPV4) == 1


@pytest.mark.unit
def test_correlate_existing_storage_dir(out):
    out.mkdir()

    assert _correlate("-d", str(out), F_IPV4, "10.0.0.1") == 1


@pytest.mark.integration
def test_correlate_summary_details(out):
    # the targets go first: --add-summary-detail takes every value after it
    assert _correlate(F_IPV4, "10.0.0.1", "--disable-all", "-d", str(out), "--add-summary-detail", "just content",
                      "--add-summary-detail", "Header", "with header", "--add-summary-detail", "Pre", "x = 1",
                      "pre") == 0

    assert [(d.header, d.content, d.format) for d in _load(out).summary_details] == [
        (None, "just content", "txt"), ("Header", "with header", "txt"), ("Pre", "x = 1", "pre")]


@pytest.mark.unit
@pytest.mark.parametrize("summary_detail", [["H", "C", "html"], ["H", "C", "txt", "extra"]])
def test_correlate_invalid_summary_detail(out, summary_detail):
    assert _correlate(F_IPV4, "10.0.0.1", "-d", str(out), "--add-summary-detail", *summary_detail) == 1


@pytest.mark.integration
def test_correlate_load_details_and_stdin(out, tmp_path, monkeypatch):
    details = tmp_path / "details.json"
    details.write_text(json.dumps({"ticket": 123}))
    monkeypatch.setattr("sys.stdin", io.StringIO("10.0.0.2\n10.0.0.3\n"))

    assert _correlate("--disable-all", "-d", str(out), "--load-details", str(details), "--from-stdin",
                      "--stdin-type", F_IPV4, F_IPV4, "10.0.0.1") == 0

    root = _load(out)
    assert root.details == {"ticket": 123}
    assert {o.value for o in root.get_observables_by_type(F_IPV4)} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


@pytest.mark.integration
def test_correlate_load_existing_analysis(out):
    assert _correlate("--disable-all", "-d", str(out), "--uuid", "11111111-2222-3333-4444-555555555555",
                      F_IPV4, "10.0.0.1") == 0

    assert _correlate("--disable-all", "-d", str(out), "--load", "-m", "analysis", F_IPV4, "10.0.0.2") == 0

    root = _load(out)
    assert root.uuid == "11111111-2222-3333-4444-555555555555"
    assert root.analysis_mode == "analysis"
    assert {o.value for o in root.get_observables_by_type(F_IPV4)} == {"10.0.0.1", "10.0.0.2"}


@pytest.mark.integration
def test_correlate_split(out):
    # each observable gets a root of its own
    assert _correlate("--disable-all", "-d", str(out), "--split", F_IPV4, "10.0.0.1", F_IPV4, "10.0.0.2") == 0

    roots = [load_root(os.path.join(dirpath)) for dirpath, _, files in os.walk(out) if "data.json" in files
             and os.path.realpath(dirpath) != os.path.realpath(out)]
    assert sorted(r.description for r in roots) == [
        "ACE Manual Correlation - ipv4:10.0.0.1", "ACE Manual Correlation - ipv4:10.0.0.2"]
    assert len({r.uuid for r in roots}) == 2
    # without a reference time, each is given the time it was created, and says so
    assert {r.event_time_source for r in roots} == {EventTimeSource.NOW}
    assert sorted(o.value for r in roots for o in r.get_observables_by_type(F_IPV4)) == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.integration
def test_correlate_enable_module_and_submit_local_alert(out):
    # the unit test engine only runs the test_ analysis modes
    assert _correlate("--disable-all", "-E", "basic_test", "-m", "test_groups", "-d", str(out),
                      "--submit-alerts-local", F_TEST, "test_detection") == 0

    root = _load(out)
    assert root.analysis_mode == ANALYSIS_MODE_CORRELATION
    assert root.has_detections()
    alerts = get_db().query(Alert).all()
    assert len(alerts) == 1
    assert alerts[0].uuid != root.uuid
    assert alerts[0].description == root.description


@pytest.mark.integration
def test_correlate_no_alert_without_detections(out):
    assert _correlate("--disable-all", "-d", str(out), "--submit-alerts-local", F_IPV4, "10.0.0.1") == 0

    assert get_db().query(Alert).count() == 0


@pytest.mark.integration
def test_correlate_force_upload_to_remote(out, monkeypatch):
    uploads = []
    monkeypatch.setattr("ace_api.upload", lambda uuid, storage_dir, **kwargs: uploads.append((uuid, kwargs)))

    assert _correlate("--disable-all", "-d", str(out), "--alert", "--force", "--remote-host", "ace.example.com",
                      "--remote-port", "8443", "--ssl-ca-path", "/etc/ssl/ca.pem", F_IPV4, "10.0.0.1") == 0

    assert uploads == [(_load(out).uuid, {"remote_host": "ace.example.com:8443", "ssl_verification": "/etc/ssl/ca.pem"})]
