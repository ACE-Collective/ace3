"""Tests for the `ace yara` and `ace yara-qa` commands."""

import base64
import dataclasses
import io
import json
from datetime import datetime

import pytest

import saq.cli.commands.yara  # registers the commands
import saq.cli.commands.yara_qa
from saq.cli.cli_main import get_cli_parser
from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.database.model import YaraQASignature
from saq.database.private_session import private_transaction
from saq.signatures import yara_inventory
from saq.yara_qa import prune
from saq.yara_qa.prune import PruneStats
from saq.yara_scanning import client
from saq.yara_scanning.client import YaraServiceUnavailable


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(list(argv))
    return args.func(args)


#
# ace yara scan
#

MATCH = {"rule": "test_rule", "commit": "a" * 40, "strings": [(0, "$a", b"\x00abc")]}


@pytest.fixture
def scans(monkeypatch) -> list:
    """Records each scan; a path ending in .fail raises, .match matches, anything else does not."""
    scanned = []

    def _scan_file(path, meta_tags=None):
        scanned.append((path, meta_tags))
        if path.endswith(".fail"):
            raise YaraServiceUnavailable("no socket")

        return [MATCH, {"rule": "uncommitted_rule"}] if path.endswith(".match") else []

    monkeypatch.setattr(client, "scan_file", _scan_file)
    return scanned


@pytest.mark.unit
def test_scan(scans, capsys):
    assert _ace("yara", "scan", "/data/a.match", "/data/b.txt") == 0

    assert capsys.readouterr().out.splitlines() == [
        "/data/a.match: 2 rule matches",
        f"\ttest_rule ({'a' * 40})",
        "\tuncommitted_rule",
        "/data/b.txt: no matches",
    ]
    assert scans == [("/data/a.match", None), ("/data/b.txt", None)]


@pytest.mark.unit
def test_scan_failure_continues_and_exits_1(scans, capsys):
    assert _ace("yara", "scan", "/data/a.fail", "/data/b.txt") == 1

    captured = capsys.readouterr()
    assert captured.err == "/data/a.fail: YaraServiceUnavailable: no socket\n"
    assert captured.out == "/data/b.txt: no matches\n"


@pytest.mark.unit
def test_scan_from_stdin_with_meta_tags(scans, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("/data/b.txt\n\n  /data/c.txt  \n"))

    assert _ace("yara", "scan", "/data/a.txt", "--from-stdin", "--meta-tags", "email", "attachment") == 0

    assert scans == [(path, ["email", "attachment"]) for path in ["/data/a.txt", "/data/b.txt", "/data/c.txt"]]


@pytest.mark.unit
def test_scan_json_encodes_the_matched_data(scans, capsys):
    assert _ace("yara", "scan", "-j", "/data/a.match") == 0

    result = json.loads(capsys.readouterr().out)
    assert result["path"] == "/data/a.match"
    assert [match["rule"] for match in result["matches"]] == ["test_rule", "uncommitted_rule"]
    assert result["matches"][0]["strings"] == [[0, "$a", base64.b64encode(b"\x00abc").decode()]]


#
# ace yara-qa
#

QA_RULE_UUID = "5a0c7f1e-1c43-4a39-8d8e-2f1b3c4d5e6f"
GONE_UUID = "8d3fac4b-4f76-4d6c-90b1-5c4e6f708192"

RULES = f"""\
rule qa_rule
{{
    meta:
        uuid = "{QA_RULE_UUID}"
        modifiers = "qa"
    strings:
        $a = "qa"
    condition:
        $a
}}
"""


@pytest.fixture
def qa_rules(tmp_path, monkeypatch):
    """One rule in QA mode that never matched, and recorded matches of a rule that is gone."""
    root = tmp_path / "yara"
    (root / "unittest").mkdir(parents=True)
    (root / "unittest" / "rules.yar").write_text(RULES)
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(root))
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "git_repo_dirs", [])
    with private_transaction() as session:
        session.add(YaraQASignature(
            signature_uuid=GONE_UUID, signature_version="v1", rule_name="gone_rule", namespace="ns",
            match_count=4, stored_count=2, first_match_at=datetime(2026, 1, 1), last_match_at=datetime(2026, 9, 1, 12, 30)))


@pytest.mark.integration
def test_qa_list(qa_rules, capsys):
    assert _ace("yara-qa", "list") == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["STATUS", "MATCHES", "STORED", "VERS", "LAST", "MATCH", "UUID", "NAME"]
    assert lines[1].split() == ["missing", "4", "2", "1", "2026-09-01", "12:30:00", GONE_UUID, "gone_rule"]
    assert lines[2].split() == ["qa", "0", "0", "0", "never", QA_RULE_UUID, "qa_rule"]


@pytest.mark.integration
def test_qa_list_json_filtered(qa_rules, capsys):
    assert _ace("yara-qa", "list", "--json", "--status", "qa", "--sort", "match_count") == 0

    assert json.loads(capsys.readouterr().out) == [{
        "signature_uuid": QA_RULE_UUID, "name": "qa_rule", "status": "qa", "enabled": True,
        "current_version": "unknown", "source_path": "rules.yar", "match_count": 0, "stored_count": 0,
        "version_count": 0, "last_match_at": None,
    }]


@pytest.mark.integration
def test_qa_list_empty_with_an_inventory_error(qa_rules, monkeypatch, capsys):
    inventory = yara_inventory.get_yara_inventory(0)
    monkeypatch.setattr(yara_inventory, "get_yara_inventory", lambda max_age: dataclasses.replace(inventory, error="repo unreadable"))

    assert _ace("yara-qa", "list", "-q", "no such rule") == 0

    assert capsys.readouterr().out.splitlines() == ["warning: repo unreadable", "no rules in qa mode and no recorded qa matches"]


@pytest.mark.unit
@pytest.mark.parametrize("argv, expected", [
    ([], "removed 3 expired match(es) in 2 batch(es), 1 hold release(s) failed"),
    (["--dry-run"], "would remove 5 expired match(es)"),
])
def test_qa_prune(monkeypatch, capsys, argv, expected):
    monkeypatch.setenv("ACE_IS_PRIMARY_NODE", "1")
    monkeypatch.setattr(prune, "prune_expired", lambda dry_run: PruneStats(
        dry_run=dry_run, expired=5, deleted=3, batches=2, release_failures=1))

    assert _ace("yara-qa", "prune", *argv) == 0

    assert capsys.readouterr().out == expected + "\n"


@pytest.mark.unit
def test_qa_prune_skips_a_secondary_node_unless_forced(monkeypatch, capsys):
    monkeypatch.setenv("ACE_IS_PRIMARY_NODE", "0")
    pruned = []
    monkeypatch.setattr(prune, "prune_expired", lambda dry_run: pruned.append(dry_run) or PruneStats(dry_run=dry_run))

    assert _ace("yara-qa", "prune") == 0
    assert "skipping yara-qa prune: not the primary node" in capsys.readouterr().out
    assert pruned == []

    assert _ace("yara-qa", "prune", "--force") == 0
    assert pruned == [False]
