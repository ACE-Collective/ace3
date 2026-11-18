"""Tests for the `ace phishkit` commands. The phishkit service itself is faked."""

import os

import pytest

import saq.cli.commands.phishkit as phishkit_cli
from saq.cli.cli_main import get_cli_parser
from saq.configuration.config import get_config


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["phishkit", *argv])
    return args.func(args)


@pytest.fixture
def scans(monkeypatch):
    calls = []

    def _scanner(kind):
        def _scan(target, output_dir, is_async=False, **kwargs):
            calls.append((kind, target, output_dir, is_async, kwargs))
            return "request-id" if is_async else [f"{output_dir}/screenshot.png", f"{output_dir}/dom.html"]
        return _scan

    monkeypatch.setattr(phishkit_cli, "scan_url", _scanner("url"))
    monkeypatch.setattr(phishkit_cli, "scan_file", _scanner("file"))
    return calls


@pytest.mark.unit
def test_ping(monkeypatch, capsys):
    monkeypatch.setattr(phishkit_cli, "ping_phishkit", lambda: "pong")

    assert _ace("ping") == os.EX_OK
    assert capsys.readouterr().out == "pong\n"


@pytest.mark.unit
def test_scan_url_waits_for_the_given_timeout(scans, capsys):
    assert _ace("scan", "https://www.example.com/", "/out", "--timeout", "60", "--proxy", "proxy:3128") == os.EX_OK

    assert scans == [("url", "https://www.example.com/", "/out", False, {"timeout": 60.0, "proxy": "proxy:3128"})]
    assert capsys.readouterr().out == "/out/screenshot.png\n/out/dom.html\n"


@pytest.mark.unit
def test_target_without_scheme_is_a_file(scans):
    assert _ace("scan", "sample.html", "/out") == os.EX_OK

    assert scans == [("file", "sample.html", "/out", False, {"timeout": 15.0, "proxy": None})]


@pytest.mark.unit
def test_unparsable_target_is_a_file(scans):
    # urlparse raises ValueError on an unbalanced IPv6 bracket
    assert _ace("scan", "http://[::1/x", "/out") == os.EX_OK

    assert scans[0][0] == "file"


@pytest.mark.unit
def test_async_scan_returns_the_request_id(scans, capsys):
    assert _ace("scan", "https://www.example.com/", "/out", "--async") == os.EX_OK

    assert scans[0][3] is True
    assert capsys.readouterr().out == "Scan started. ID: request-id\n"


@pytest.mark.unit
def test_async_result(monkeypatch, scans, capsys):
    results = {"done": ["/out/screenshot.png"], "pending": None}
    requested = []

    def _result(result_id, output_dir, timeout):
        requested.append((result_id, output_dir, timeout))
        return results[result_id]

    monkeypatch.setattr(phishkit_cli, "get_async_scan_result", _result)

    assert _ace("scan", "https://www.example.com/", "/out", "--async", "--id", "pending") == os.EX_OK
    assert capsys.readouterr().out == "result not ready yet\n"

    assert _ace("scan", "https://www.example.com/", "/out", "--async", "--id", "done", "--timeout", "2") == os.EX_OK
    assert capsys.readouterr().out == "/out/screenshot.png\n"

    assert requested == [("pending", "/out", 15.0), ("done", "/out", 2.0)]
    # asking for a result never starts a new scan
    assert scans == []


@pytest.mark.unit
@pytest.mark.parametrize("argv, expected_days", [
    ([], None),
    (["--max-file-age-days", "3"], 3),
])
def test_maintain_files(monkeypatch, capsys, argv, expected_days):
    if expected_days is None:
        expected_days = get_config().phishkit.max_file_age_days

    monkeypatch.setattr(phishkit_cli, "maintain_files", lambda days: {"deleted": 2, "days": days})

    assert _ace("maintain-files", *argv) == os.EX_OK
    assert capsys.readouterr().out == f"{{'deleted': 2, 'days': {expected_days}}}\n"
