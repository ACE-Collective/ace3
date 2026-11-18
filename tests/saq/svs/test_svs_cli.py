"""ace svs yara validate, layout and prune, and the parts of the validation report the replay tests
(tests/saq/svs/yara/test_replay.py) do not reach."""

import json
import os
import uuid
from argparse import Namespace
from datetime import datetime, timedelta

import pytest

from saq.cli.commands.svs import cli_catalog_refresh, cli_layout, cli_prune, cli_validate, print_report
from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import GitRepoConfig
from saq.constants import ENV_ACE_IS_PRIMARY_NODE, SERVICE_YARA_SCANNER
from saq.database.model import SVSValidation
from saq.database.pool import get_db
from saq.svs.yara.corpus import Skipped
from saq.svs.yara.diff import Category, Outcome, ResultRow
from saq.svs.yara.layout import NotLoaded
from saq.svs.yara.replay import FileError, ReplayError, ReplayResult, RuleRef, SideReport

BASE = "a" * 40
HEAD = "b" * 40


def _row(category: Category, label=None, label_source=None, note=None) -> ResultRow:
    return ResultRow(
        sha256="c" * 64, rule_uuid="11111111-1111-1111-1111-111111111111", rule_name="one", namespace="acme",
        label=label, label_source=label_source, base=Outcome.MATCH, head=Outcome.MISS,
        raw_base=True, raw_head=False, category=category, note=note)


def _result(**kwargs) -> ReplayResult:
    defaults = dict(repository="rules", base_sha=BASE, head_sha=HEAD, base=SideReport(sha=BASE), head=SideReport(sha=HEAD))
    defaults.update(kwargs)
    return ReplayResult(**defaults)


@pytest.mark.unit
def test_the_report_prints_every_section(capsys):
    rule = RuleRef(uuid="22222222-2222-2222-2222-222222222222", name="two", file="yara/acme/two.yar")
    head = SideReport(
        sha=HEAD, namespaces=["acme"], absent_namespaces=["gone"], rule_count=3,
        file_errors=[FileError(file="yara/acme/broken.yar", namespace="acme", error="syntax error", dropped=(rule,))],
        include_warnings=[{"file": "yara/acme/a.yar", "include": "missing.yar", "error": "not found"}],
        not_loaded=[NotLoaded(path="yara/acme/deeper/nested.yar", reason="nested")],
        skipped_members=[("yara/acme/link.yar", "symlink")],
        warnings=["string $a slows down scanning"],
        timings={"acme": {"scan_seconds": 1.5}})
    result = _result(
        head=head, diffed=True, files=2, units=3, samples=2, bytes=100, duration_seconds=2.25,
        skipped=[Skipped(sha256="d" * 64, file_path=None, reason="missing", detail="no bytes")],
        truncated_paths=1,
        added_rules=[rule], removed_rules=[], changed_rules=[],
        counts={"regression": 1, "new_fp_other_rule": 1, "unlabeled_change": 1, "unchanged": 0},
        rows=[_row(Category.REGRESSION, label="tp", label_source="analyst", note="a note"),
              _row(Category.NEW_FP_OTHER_RULE), _row(Category.UNLABELED_CHANGE)],
        not_testable=[{"name": "anonymous", "uuid": None, "file": "yara/acme/anon.yar", "reason": "no uuid"}],
        full_path_rules=[rule])

    print_report(result)
    lines = capsys.readouterr().out.splitlines()

    assert lines[0] == f"repository rules: base {BASE[:12]}, head {HEAD[:12]}"
    assert lines[1] == "corpus: 2 files, 3 scans, 2 samples, 100 bytes (2.2s)"
    for expected in (
        "  1 not replayed:",
        f"    {'d' * 64}  missing no bytes",
        "  1 scans use a path that was cut when it was stored",
        f"base {BASE[:12]}: 0 rules in 0 namespaces (none)",
        f"head {HEAD[:12]}: 3 rules in 1 namespaces (acme)",
        "  namespace gone does not exist in this commit",
        "  yara/acme/broken.yar does not compile, its 1 rule(s) are dropped: syntax error",
        "  yara/acme/a.yar: include missing.yar: not found",
        "  not loaded: yara/acme/deeper/nested.yar (nested)",
        "  not exported: yara/acme/link.yar (symlink)",
        "rules: 1 added, 0 removed, 0 changed",
        f"  added two ({rule.uuid}) in yara/acme/two.yar",
        # a zero count is left out
        "counts: regression 1, new_fp_other_rule 1, unlabeled_change 1",
        "Regressions (1):",
        f"  {'c' * 64} one (11111111-1111-1111-1111-111111111111) tp (analyst): base match, head miss -- a note",
        "New false positives on another rule's sample (1):",
        f"  {'c' * 64} one (11111111-1111-1111-1111-111111111111) another rule's sample: base match, head miss",
        "Unlabeled changes (1):",
        f"  {'c' * 64} one (11111111-1111-1111-1111-111111111111) unlabeled: base match, head miss",
        "not testable: anonymous (None) in yara/acme/anon.yar: no uuid",
        f"filters on full_path, which a replay cannot reproduce: two ({rule.uuid}) in yara/acme/two.yar",
        "head compiler warning: string $a slows down scanning",
        "scan time per namespace (base / head):",
        "  acme: - / 1.50s",
    ):
        assert expected in lines

    # bands with no rows have no heading
    assert not any(line.startswith("Improvements") for line in lines)


#
# ace svs yara validate
#

@pytest.fixture
def replay(monkeypatch):
    calls = []
    outcome = {"result": _result()}

    def run_replay(repository, base, head, branch=None, retired=frozenset()):
        calls.append((repository, base, head, branch, retired))
        if isinstance(outcome["result"], Exception):
            raise outcome["result"]
        return outcome["result"]

    monkeypatch.setattr("saq.svs.yara.replay.run_replay", run_replay)
    monkeypatch.setattr("saq.svs.actions.retired_pairs", lambda: frozenset({("e" * 64, "rule")}))
    return calls, outcome


def _validate_args(**kwargs) -> Namespace:
    return Namespace(**{"repository": "rules", "base": BASE, "head": HEAD, "branch": None, "json": False, **kwargs})


@pytest.mark.unit
def test_validate_prints_the_report(replay, capsys):
    calls, _ = replay

    assert cli_validate(_validate_args(branch="feature")) == 0

    # retired samples are passed along, so they are only counted
    assert calls == [("rules", BASE, HEAD, "feature", frozenset({("e" * 64, "rule")}))]
    output = capsys.readouterr().out
    assert output.startswith(f"repository rules: base {BASE[:12]}, head {HEAD[:12]}\n")
    assert "nothing was compared: a ruleset would not load" in output


@pytest.mark.unit
def test_validate_as_json(replay, capsys):
    assert cli_validate(_validate_args(json=True)) == 0

    document = json.loads(capsys.readouterr().out)
    assert (document["repository"], document["base_sha"], document["head_sha"]) == ("rules", BASE, HEAD)


@pytest.mark.unit
def test_validate_failure(replay, capsys):
    _, outcome = replay
    outcome["result"] = ReplayError("unknown commit")

    assert cli_validate(_validate_args()) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "validation failed: unknown commit\n"


#
# ace svs yara layout
#

@pytest.mark.unit
def test_layout_prints_every_repository(tmp_path, monkeypatch, capsys):
    signature_dir = tmp_path / "checkouts" / "signatures"
    signature_dir.mkdir(parents=True)
    linked = tmp_path / "linked"
    (linked / "rules" / "acme").mkdir(parents=True)
    os.symlink(linked / "rules" / "acme", signature_dir / "acme")
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(signature_dir))

    repositories = {
        "contained_rules": tmp_path / "checkouts",
        "root_rules": signature_dir,
        "linked_rules": linked,
        "unrelated_rules": tmp_path / "unrelated",
    }
    for name, local_path in repositories.items():
        # setitem so each section is gone again after the test
        monkeypatch.setitem(get_config()._ACEConfig__git_repos, name, GitRepoConfig(
            name=name, description=name, local_path=str(local_path), git_url="https://example.com/rules.git",
            update_frequency=60, branch="main"))
    monkeypatch.setattr(get_config().svs.yara, "repositories", [*repositories, "no_section_rules"])

    assert cli_layout(Namespace()) == 1

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "contained_rules: every directory of signatures is a namespace"
    assert lines[1] == "root_rules: every directory of the repository root is a namespace"
    assert lines[2] == "linked_rules: namespace acme is rules/acme"
    assert lines[3].startswith("unrelated_rules: repository unrelated_rules")
    assert "holds no rules the yara service loads" in lines[3]
    assert lines[4] == "no_section_rules: no git_repo section is named no_section_rules"


@pytest.mark.unit
def test_layout_with_no_repositories(monkeypatch, capsys):
    monkeypatch.setattr(get_config().svs.yara, "repositories", [])

    assert cli_layout(Namespace()) == 0
    assert capsys.readouterr().out == ""


#
# ace svs yara prune
#

def _validation(finished_days_ago: int) -> SVSValidation:
    validation = SVSValidation(
        uuid=str(uuid.uuid4()), repository="rules", base_sha=BASE, head_sha=HEAD, branch="main",
        created_at=datetime.now() - timedelta(days=finished_days_ago), state="completed",
        finished_at=datetime.now() - timedelta(days=finished_days_ago))
    get_db().add(validation)
    get_db().commit()
    return validation


@pytest.mark.integration
def test_prune_skips_a_node_that_is_not_primary(monkeypatch, capsys):
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
    _validation(finished_days_ago=1000)

    assert cli_prune(Namespace(dry_run=False, force=False)) == 0

    assert capsys.readouterr().out == "skipping: not the primary node (use --force to prune anyway)\n"
    assert get_db().query(SVSValidation).count() == 1


@pytest.mark.integration
def test_prune_dry_run_and_force(monkeypatch, capsys):
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
    old_id = _validation(finished_days_ago=get_config().svs.yara.retention_days + 1).id
    recent_id = _validation(finished_days_ago=0).id

    assert cli_prune(Namespace(dry_run=True, force=True)) == 0
    assert capsys.readouterr().out == "would remove 1 validations\n"

    assert cli_prune(Namespace(dry_run=False, force=True)) == 0
    assert capsys.readouterr().out == "removed 1 validations\n"

    get_db().expire_all()
    assert [v.id for v in get_db().query(SVSValidation)] == [recent_id]
    assert old_id != recent_id


@pytest.mark.integration
def test_catalog_refresh_with_no_repositories(monkeypatch, capsys):
    monkeypatch.setattr(get_config().svs.catalog, "repositories", [])

    assert cli_catalog_refresh(Namespace(repository=None, force=False)) == 0
    assert capsys.readouterr().out == "svs.catalog.repositories is empty\n"
