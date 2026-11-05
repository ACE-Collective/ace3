"""Tests for the /ace-review bundle script, .claude/skills/ace-review/scripts/prepare.py, against
throwaway git repos: rounds and their deltas, the base-branch rules, and the mechanical leads."""

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / ".claude" / "skills" / "ace-review" / "scripts"

pytestmark = pytest.mark.unit


def _load_script(name):
    spec = importlib.util.spec_from_file_location(f"ace_review_{name}", SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = _load_script("prepare")
findings = _load_script("findings")

CLAUDE_MD = """# CLAUDE.md

## Layout

Facts about the code.

## Engineering values

- Every except logs or re-raises.

## Conventions

- Imports at module level.
"""


def git(repo, *args):
    command = ["git", "-C", str(repo), "-c", "user.name=test", "-c", "user.email=test@example.com", *args]
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def write(repo, path, text):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def commit(repo, message="change"):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """ACE core with one commit on main and the topic branch mw/topic checked out."""
    path = (tmp_path / "ace").resolve()
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    write(path, "CLAUDE.md", CLAUDE_MD)
    write(path, "saq/__init__.py", "")
    write(path, "saq/worker.py", "def run():\n    return 1\n")
    commit(path, "base")
    git(path, "switch", "-q", "-c", "mw/topic")
    monkeypatch.setattr(prepare, "SAQ_HOME", str(path))
    return path


@pytest.fixture
def review(repo, tmp_path, monkeypatch, capsys):
    """Run prepare.py on the checked-out branch and return its target.json."""
    def run(*args, base="main"):
        argv = ["prepare.py", "--repo", str(repo), "--state-dir", str(tmp_path / "state"), *(["--base", base] if base else []), *args]
        monkeypatch.setattr(sys, "argv", argv)
        prepare.main()
        return json.loads(capsys.readouterr().out)
    return run


def bundle_file(target, name):
    return Path(target["bundle"]) / name


def read_json(target, name):
    return json.loads(bundle_file(target, name).read_text())


def finish_round(target, ranked=()):
    """What step 4 of the skill leaves behind: ranked findings, numbered by findings.py."""
    bundle_file(target, "ranked.json").write_text(json.dumps(list(ranked)))
    findings.finish(target["bundle"])
    return read_json(target, "verified.json")


def finding(title, severity="fix-first", origin="new", bucket=None):
    return {"dimension": "logging", "severity": severity, "origin": origin, "file": "saq/worker.py", "line": 3,
            "title": title, "evidence": "saq/worker.py:3", "impact": "hidden failure", "fix": "log it",
            "bucket": bucket or ("noted" if severity == "nit" else "act on"), "judgment": "the lead's reason"}


def test_the_first_round_bundles_committed_uncommitted_and_untracked_work(repo, review):
    write(repo, "saq/worker.py", "def run():\n    try:\n        return 1\n    except:\n        return None\n")
    commit(repo)
    write(repo, "CLAUDE.md", CLAUDE_MD.replace("- Every except logs or re-raises.", "- An except may stay silent."))
    write(repo, "saq/new.py", "import time\n\ndef wait(t):\n    t.join()\n")

    target = review()

    assert target["round"] == 1 and target["previous_round"] is None
    assert target["bundle"].endswith("ace-mw-topic/round-1")
    # findings.py and the skill read these back, so the names are a stored format
    assert {k: target[k] for k in ("repo", "kind", "base", "merge_base", "head", "branch", "includes_uncommitted", "changed_files",
                                   "tests_selected", "unmarked_tests", "leads", "touches_models", "touches_migrations")} == {
        "repo": str(repo), "kind": "core", "base": "main", "merge_base": git(repo, "rev-parse", "main").strip(),
        "head": git(repo, "rev-parse", "HEAD").strip(), "branch": "mw/topic", "includes_uncommitted": True, "changed_files": 3,
        "tests_selected": 0, "unmarked_tests": 0, "leads": 3, "touches_models": False, "touches_migrations": [],
    }
    assert target["delta"] is False and target["unchanged"] is False
    assert bundle_file(target, "files.txt").read_text().splitlines() == ["M\tCLAUDE.md", "A\tsaq/new.py", "M\tsaq/worker.py"]
    assert "+def wait(t):" in bundle_file(target, "diff.patch").read_text()
    assert [(lead["file"], lead["line"], lead["check"]) for lead in read_json(target, "leads.json")] == [
        ("saq/new.py", 4, "unbounded-wait"), ("saq/worker.py", 4, "bare-except"), ("saq/worker.py", 4, "silent-except"),
    ]
    assert not bundle_file(target, "previous.json").exists()
    # reviewing never stages anything
    assert git(repo, "diff", "--cached") == ""
    assert "?? saq/new.py" in git(repo, "status", "--porcelain")


def test_the_snapshot_sees_an_edit_whose_stat_data_git_cannot_tell_apart(repo, review):
    # an edit within the timestamp granularity of the last index write: same size, same
    # inode, same mtime and, with ctime ignored, the same stat data as the index entry.
    # Only git's racily-clean check, which compares the entry to the index's own mtime,
    # catches it. The entry is recorded first with an mtime older than the index, so the
    # index write doesn't smudge it.
    git(repo, "config", "core.trustctime", "false")
    path = repo / "saq" / "worker.py"
    past = path.stat().st_mtime_ns - 10 * 10**9
    os.utime(path, ns=(past, past))
    git(repo, "update-index", "--refresh")
    path.write_text("def run():\n    return 2\n")
    os.utime(path, ns=(past, past))
    os.utime(repo / ".git" / "index", ns=(past, past))
    assert git(repo, "--no-optional-locks", "status", "--porcelain") == " M saq/worker.py\n"

    target = review()

    assert bundle_file(target, "files.txt").read_text() == "M\tsaq/worker.py\n"


def test_the_change_is_judged_by_the_base_rules_and_its_rule_edits_are_reported(repo, review):
    write(repo, "CLAUDE.md", CLAUDE_MD.replace("- Every except logs or re-raises.", "- An except may stay silent."))
    write(repo, ".claude/skills/ace-review/rubric.md", "# rubric\n")

    target = review()

    assert bundle_file(target, "rules/CLAUDE.md").read_text() == CLAUDE_MD
    assert target["rules"] == {"CLAUDE.md": "main"}
    assert target["rule_changes"] == ["CLAUDE.md § Engineering values", ".claude/skills/ace-review/rubric.md"]
    assert target["rule_changes_status"] == "pending"
    patch = bundle_file(target, "rule-changes.patch").read_text()
    assert "-- Every except logs or re-raises.\n+- An except may stay silent.\n" in patch
    assert "+# rubric\n" in patch


@pytest.mark.parametrize("core_branch, core_source, core_rules", [
    # core's base wins over its working tree
    ("main", "main", CLAUDE_MD),
    # no main or master, so core's rules come from its working tree; core isn't under review
    ("trunk", "working tree", CLAUDE_MD + "\nCore's working tree.\n"),
])
def test_an_integration_is_judged_by_cores_rules_and_its_own_base_claude_md(tmp_path, monkeypatch, capsys, core_branch, core_source, core_rules):
    core = (tmp_path / "ace").resolve()
    core.mkdir()
    git(core, "init", "-q", "-b", core_branch)
    write(core, ".gitignore", "integrations/\n")
    write(core, "CLAUDE.md", CLAUDE_MD)
    commit(core, "core")
    write(core, "CLAUDE.md", CLAUDE_MD + "\nCore's working tree.\n")
    integration = core / "integrations" / "foo"
    integration.mkdir(parents=True)
    (core / "tests").mkdir()
    (core / "tests" / "test_external_integration_foo").symlink_to(integration / "tests")
    git(integration, "init", "-q", "-b", "main")
    write(integration, "integration.md", "# foo\n")
    write(integration, "CLAUDE.md", "# foo\n\nNever call the vendor twice.\n")
    commit(integration, "foo")
    git(integration, "switch", "-q", "-c", "mw/foo")
    write(integration, "CLAUDE.md", "# foo\n\nCall the vendor as often as you like.\n")
    write(integration, "src/foo/client.py", "def call():\n    return 1\n")
    write(integration, "tests/test_client.py", "import pytest\n\n@pytest.mark.unit\ndef test_call():\n    pass\n")
    monkeypatch.setattr(prepare, "SAQ_HOME", str(core))
    monkeypatch.setattr(sys, "argv", ["prepare.py", "--repo", str(integration), "--state-dir", str(tmp_path / "state")])

    prepare.main()

    target = json.loads(capsys.readouterr().out)
    assert target["kind"] == "integration" and target["integrations"] == ["foo"]
    assert target["bundle"].endswith("foo-mw-foo/round-1")
    assert target["rules"] == {"CLAUDE.md": core_source, "repo-CLAUDE.md": "main"}
    assert bundle_file(target, "rules/CLAUDE.md").read_text() == core_rules
    assert bundle_file(target, "rules/repo-CLAUDE.md").read_text() == "# foo\n\nNever call the vendor twice.\n"
    assert target["rule_changes"] == ["CLAUDE.md"]
    assert bundle_file(target, "tests.txt").read_text() == "tests/test_external_integration_foo/test_client.py\n"
    assert bundle_file(target, "cov_sources.txt").read_text() == "--cov=integrations/foo/src\n"


def test_a_claude_md_the_change_adds_is_not_a_rule_it_is_judged_by(tmp_path, monkeypatch, capsys):
    core = (tmp_path / "ace").resolve()
    core.mkdir()
    git(core, "init", "-q", "-b", "main")
    write(core, "saq/__init__.py", "")
    commit(core, "no CLAUDE.md yet")
    git(core, "switch", "-q", "-c", "mw/rules")
    write(core, "CLAUDE.md", "## Engineering values\n\n- Anything goes.\n")
    monkeypatch.setattr(prepare, "SAQ_HOME", str(core))
    monkeypatch.setattr(sys, "argv", ["prepare.py", "--state-dir", str(tmp_path / "state")])

    prepare.main()

    target = json.loads(capsys.readouterr().out)
    assert target["rules"] == {}
    assert not bundle_file(target, "rules/CLAUDE.md").exists()
    assert target["rule_changes"] == ["CLAUDE.md § Engineering values"]


def test_a_range_of_commits_is_reviewed_without_the_working_tree(repo, review):
    write(repo, "saq/worker.py", "def run():\n    try:\n        return 1\n    except:\n        return None\n")
    commit(repo)
    write(repo, "saq/uncommitted.py", "X = 1\n")
    # the leads come from the committed file, not from this edit of it
    write(repo, "saq/worker.py", "def run():\n    return 2\n")

    target = review("--range", "main..mw/topic", base=None)

    assert target["includes_uncommitted"] is False
    assert target["bundle"].endswith("ace-range-main..mw-topic/round-1")
    assert target["tree"] == git(repo, "rev-parse", "mw/topic^{tree}").strip()
    assert target["rules"] == {"CLAUDE.md": "main"}
    assert bundle_file(target, "files.txt").read_text() == "M\tsaq/worker.py\n"
    assert [(lead["file"], lead["line"], lead["check"]) for lead in read_json(target, "leads.json")] == [
        ("saq/worker.py", 4, "bare-except"), ("saq/worker.py", 4, "silent-except"),
    ]


def test_base_and_range_do_not_go_together(review):
    with pytest.raises(SystemExit):
        review("--range", "main..mw/topic")


def test_changed_tests_are_selected_and_the_unmarked_ones_listed(repo, review):
    write(repo, "tests/saq/test_worker.py", "import pytest\n\n@pytest.mark.unit\ndef test_run():\n    pass\n")
    write(repo, "tests/saq/test_a_gone.py", "def test_gone():\n    pass\n")
    commit(repo)
    git(repo, "branch", "-f", "main")
    (repo / "tests" / "saq" / "test_a_gone.py").unlink()
    write(repo, "saq/worker.py", "def run():\n    return 2\n")
    write(repo, "tests/saq/test_new.py", "\n".join([
        "import pytest", "", "@pytest.mark.unit", "def test_marked():", "    pass", "",
        "def test_unmarked():", "    pass", "", "class TestGroup:", "    def test_in_class(self):", "        pass", "",
    ]))
    write(repo, "tests/saq/test_broken.py", "def test_(:\n")

    target = review()

    # test_worker.py is unchanged: only its mirroring saq/worker.py selects it
    assert bundle_file(target, "tests.txt").read_text().splitlines() == [
        "tests/saq/test_broken.py", "tests/saq/test_new.py", "tests/saq/test_worker.py"
    ]
    broken, unmarked, in_class = bundle_file(target, "unmarked.txt").read_text().splitlines()
    assert broken.startswith(f"{repo}/tests/saq/test_broken.py: could not parse")
    assert unmarked == f"{repo}/tests/saq/test_new.py:7 test_unmarked"
    assert in_class == f"{repo}/tests/saq/test_new.py:11 TestGroup.test_in_class"
    assert target["unmarked_tests"] == 3
    # a file that does not parse fails its own tests, and gives no lead
    assert read_json(target, "leads.json") == []


MARKS = """import pytest

not_the_module_mark = pytest.mark.unit


def helper():
    pass


@pytest.mark.unit
def test_marked():
    pass


@pytest.mark.integration()
def test_marked_with_a_call():
    pass


@pytest.mark.slow
def test_only_a_marker_that_runs_nothing():
    pass


async def test_async():
    pass


@pytest.mark.system
class TestMarked:
    def test_in_a_marked_class(self):
        pass


class TestOpen:
    @pytest.mark.unit
    def test_marked_method(self):
        pass

    def test_open(self):
        pass

    def helper(self):
        pass


class Helper:
    def test_never_collected(self):
        pass
"""


def test_unmarked_tests_are_the_ones_no_run_marker_reaches():
    assert prepare.unmarked_tests("t.py", MARKS) == [
        "t.py:21 test_only_a_marker_that_runs_nothing", "t.py:25 test_async", "t.py:40 TestOpen.test_open",
    ]


@pytest.mark.parametrize("pytestmark, unmarked", [
    ("pytest.mark.unit", []),
    ("[pytest.mark.slow, pytest.mark.integration]", []),
    ("pytest.mark.system", []),
    ("pytest.mark.slow", ["t.py:3 test_x"]),
])
def test_a_module_mark_reaches_every_test_only_if_it_is_a_run_marker(pytestmark, unmarked):
    assert prepare.unmarked_tests("t.py", f"pytestmark = {pytestmark}\n\ndef test_x():\n    pass\n") == unmarked


def test_an_edit_to_the_facts_in_claude_md_is_not_a_rule_change(repo, review):
    write(repo, "CLAUDE.md", CLAUDE_MD.replace("Facts about the code.", "Newer facts about the code."))

    target = review()

    assert target["rule_changes"] == []
    assert target["rule_changes_status"] == "none"
    assert not bundle_file(target, "rule-changes.patch").exists()


def test_the_second_round_reviews_the_delta_and_carries_the_first_rounds_findings(repo, review):
    write(repo, "saq/worker.py", "def run():\n    try:\n        return 1\n    except:\n        return None\n")
    write(repo, "CLAUDE.md", CLAUDE_MD.replace("- Every except logs or re-raises.", "- An except may stay silent."))
    first = review()
    finish_round(first, [finding("bare except"), finding("comment restates code", "nit"), finding("hangs", "blocker"),
                         finding("old silent except", "fix-first", "pre-existing"), finding("said to be fixed"),
                         finding("on purpose"), finding("cosmetic")])
    findings.answer(first["bundle"], "R1-3", "wrong", note="the join has a deadline upstream")
    # only a verifier's recheck closes a finding the user says is fixed
    findings.answer(first["bundle"], "R1-4", "fixed")
    findings.answer(first["bundle"], "R1-5", "intentional")
    findings.answer(first["bundle"], "R1-6", "didn't matter")
    findings.answer(first["bundle"], "rules", "accepted")

    write(repo, "saq/second.py", "def drain(q):\n    return q.get()\n")
    second = review()

    assert second["round"] == 2 and second["previous_round"] == 1
    assert second["delta"] is True and second["delta_reason"] is None and second["unchanged"] is False
    delta = bundle_file(second, "delta.patch").read_text()
    assert "saq/second.py" in delta and "saq/worker.py" not in delta
    assert bundle_file(second, "delta-files.txt").read_text() == "A\tsaq/second.py\n"
    # the bare except was the first round's lead; only what the delta adds can be one now
    assert [(lead["file"], lead["check"]) for lead in read_json(second, "leads.json")] == [("saq/second.py", "unbounded-wait")]
    previous = {f["id"]: f for f in read_json(second, "previous.json")}
    assert {fid: f["status"] for fid, f in previous.items()} == {"R1-1": "open", "R1-2": "seen", "R1-3": "dismissed", "P1-1": "seen",
                                                                 "R1-4": "open", "R1-5": "dismissed", "R1-6": "dismissed"}
    assert previous["R1-3"]["answer"] == "wrong" and previous["R1-3"]["answer_note"] == "the join has a deadline upstream"
    assert previous["R1-4"]["answer"] == "fixed" and "answer_note" not in previous["R1-4"]
    assert second["history"] == [{"round": 1, "blocker": 1, "fix-first": 4, "nit": 1}]
    # the same rule edit, accepted after the first round, is what the second round judges by
    assert first["rules"] == {"CLAUDE.md": "main"}
    assert second["rule_changes_digest"] == first["rule_changes_digest"]
    assert second["rule_changes_status"] == "accepted"
    assert second["rules"] == {"CLAUDE.md": "working tree (rule changes accepted)"}
    assert "- An except may stay silent." in bundle_file(second, "rules/CLAUDE.md").read_text()


def test_a_finding_rechecked_as_fixed_is_closed_in_the_next_round(repo, review):
    write(repo, "saq/worker.py", "def run():\n    try:\n        return 1\n    except:\n        return None\n")
    first = review()
    finish_round(first, [finding("bare except")])
    write(repo, "saq/worker.py", "def run():\n    return 1\n")
    second = review()
    bundle_file(second, "carried.json").write_text(json.dumps([{"id": "R1-1", "status": "fixed"}]))
    finish_round(second)

    write(repo, "saq/third.py", "X = 1\n")
    third = review()

    assert [(f["id"], f["status"]) for f in read_json(third, "previous.json")] == [("R1-1", "fixed")]


def test_only_what_the_lead_said_to_act_on_is_rechecked(repo, review):
    write(repo, "saq/worker.py", "def run():\n    try:\n        return 1\n    except:\n        return None\n")
    first = review()
    finish_round(first, [finding("holds the PR"), finding("the user's call", bucket="consider")])
    # a round finished before the lead judged findings: its fix-first held the PR, and its nit did not
    legacy = Path(first["bundle"]).parent / "round-0"
    legacy.mkdir()
    (legacy / "verified.json").write_text(json.dumps([{k: v for k, v in finding(title, severity).items() if k != "bucket"} | {"id": fid}
                                                      for fid, title, severity in [("R0-1", "old fix-first", "fix-first"), ("R0-2", "old nit", "nit")]]))
    (legacy / "summary.json").write_text("{}")

    write(repo, "saq/second.py", "X = 1\n")
    second = review()

    assert {f["id"]: f["status"] for f in read_json(second, "previous.json")} == {"R0-1": "open", "R0-2": "seen", "R1-1": "open", "R1-2": "seen"}


def test_a_changed_rule_edit_needs_a_new_decision(repo, review):
    write(repo, "CLAUDE.md", CLAUDE_MD.replace("- Every except logs or re-raises.", "- An except may stay silent."))
    first = review()
    finish_round(first)
    findings.answer(first["bundle"], "rules", "accepted")

    write(repo, "CLAUDE.md", CLAUDE_MD.replace("- Imports at module level.", "- Imports anywhere."))
    second = review()

    assert second["rule_changes"] == ["CLAUDE.md § Conventions"]
    assert second["rule_changes_status"] == "pending"
    assert bundle_file(second, "rules/CLAUDE.md").read_text() == CLAUDE_MD


def test_an_unfinished_round_is_redone_in_place(repo, review):
    write(repo, "saq/new.py", "X = 1\n")
    first = review()
    bundle_file(first, "findings-uptime.json").write_text("[]")

    again = review()

    assert again["round"] == 1 and again["bundle"] == first["bundle"]
    assert not bundle_file(again, "findings-uptime.json").exists()


def test_a_round_with_nothing_new_says_so(repo, review):
    write(repo, "saq/new.py", "X = 1\n")
    finish_round(review())

    second = review()

    assert second["round"] == 2 and second["unchanged"] is True
    assert bundle_file(second, "delta.patch").read_text() == ""


def test_a_moved_merge_base_means_a_full_review(repo, review):
    write(repo, "saq/new.py", "X = 1\n")
    commit(repo)
    finish_round(review())
    git(repo, "switch", "-q", "main")
    write(repo, "saq/upstream.py", "Y = 2\n")
    commit(repo, "upstream")
    git(repo, "switch", "-q", "mw/topic")
    git(repo, "rebase", "-q", "main")

    second = review()

    assert second["delta"] is False
    assert "merge-base moved" in second["delta_reason"]
    assert not bundle_file(second, "delta.patch").exists()


def test_a_pruned_tree_means_a_full_review(repo, review):
    write(repo, "saq/new.py", "X = 1\n")
    first = review()
    finish_round(first)
    # what git gc leaves behind once it prunes the unreferenced snapshot
    target = read_json(first, "target.json")
    bundle_file(first, "target.json").write_text(json.dumps({**target, "tree": "0" * 40}))
    write(repo, "saq/other.py", "Y = 2\n")

    second = review()

    assert second["delta"] is False
    assert "no longer in the object store" in second["delta_reason"]


def test_full_reviews_the_whole_change_again(repo, review):
    write(repo, "saq/new.py", "X = 1\n")
    finish_round(review())
    write(repo, "saq/other.py", "Y = 2\n")

    second = review("--full")

    assert second["delta"] is False and second["delta_reason"] == "--full"
    assert bundle_file(second, "previous.json").exists()


def test_stale_references_name_what_the_change_removes(repo, review):
    write(repo, "oldapi/__init__.py", "")
    write(repo, "oldapi/routes.py", "def legacy_route_handler():\n    return 'legacy'\n")
    write(repo, "oldassets/logo.txt", "logo\n")
    removed_functions = ("format_alert_title", "handler", "legacyHandler", "test_helper_thing", "abc_d", "abc_de", "__x_y__")
    write(repo, "saq/helpers.py", "".join(f"def {name}():\n    pass\n\n" for name in (*removed_functions, "moved_helper_function")))
    write(repo, "saq/gone_file.py", "X = 1\n")
    write(repo, "saq/part/__init__.py", "Y = 1\n")
    write(repo, "saq/part/keep.txt", "kept\n")
    write(repo, "saq/renamed_old.py", "def renamed_thing():\n    return 3\n")
    write(repo, "etc/saq.default.yaml", "api:\n  secret_key: x\n  port: 1\n  timeout: 3\nservice_yara:\n  qa:\n    spool_directory: /x\n"
                                        "debug: true\nretry_limit: 3\nremoved_block:\n  child_key: 1\n")
    write(repo, "etc/extra.yml", "extra_setting_key: 1\nkept_setting: 1\n")
    write(repo, "conf/other.yaml", "other_setting_key: 1\nkept_setting: 1\n")
    write(repo, "docs/API.md", "\n".join([
        "Routes live in `oldapi/routes.py`.",
        "Import them from oldapi.routes.",
        "Titles come from format_alert_title().",
        "moved_helper_function moved, but still exists.",
        "Set api.secret_key in the config.",
        "    secret_key: hunter2",
        "The port is api.port.",
        "Point qa.spool_directory at the spool.",
        "A handler handles it.",
        "legacyHandler runs it.",
        "test_helper_thing covers it.",
        "abc_d is short.",
        "abc_de is long enough.",
        "__x_y__ is private.",
        "Read saq/gone_file.py.",
        "Import saq.gone_file here.",
        "saq/gone_file.pyi stays.",
        "Import saq.part today.",
        "Read saq/renamed_old.py.",
        "Set debug for more.",
        "Set retry_limit low.",
        "See removed_block here.",
        "    child_key: 1",
        "Set api.timeout here.",
        "    timeout: 5",
        "extra_setting_key is set.",
        "other_setting_key is set.",
        "oldassets.logo is no module.",
    ]) + "\n")
    write(repo, "docs/EDITED.md", "intro\nSee saq/gone_file.py.\n")
    write(repo, "docs/notes.txt", "saq/gone_file.py\n")
    write(repo, "CHANGELOG.md", "- added oldapi/routes.py\n")
    write(repo, "tests/README.md", "see oldapi/routes.py\n")
    commit(repo, "the old world")
    git(repo, "branch", "-f", "main")

    git(repo, "rm", "-q", "-r", "oldapi", "oldassets", "saq/gone_file.py", "saq/part/__init__.py")
    git(repo, "mv", "saq/renamed_old.py", "saq/renamed_new.py")
    write(repo, "saq/helpers.py", "def other_function():\n    pass\n")
    write(repo, "saq/moved.py", "def moved_helper_function():\n    return 2\n")
    write(repo, "etc/saq.default.yaml", "api:\n  port: 1\nservice_yara:\n  qa: {}\n")
    write(repo, "etc/extra.yml", "kept_setting: 1\n")
    write(repo, "conf/other.yaml", "kept_setting: 1\n")
    write(repo, "docs/NEW.md", "oldapi/ is gone.\n")
    # the line the change writes is not a lead; the older line after it still is
    write(repo, "docs/EDITED.md", "saq/gone_file.py went away.\nintro\nSee saq/gone_file.py.\n")
    # the script asks for rename detection itself, whatever the user's git config says
    git(repo, "config", "diff.renames", "false")

    target = review()

    assert "R100\tsaq/renamed_new.py\n" in bundle_file(target, "files.txt").read_text()
    leads = [lead for lead in read_json(target, "leads.json") if lead["check"] == "stale-reference"]
    assert [(lead["file"], lead["line"], lead["ref"], lead["removed"]) for lead in leads] == [
        ("docs/API.md", 1, "oldapi/", "directory"),
        ("docs/API.md", 2, "oldapi", "package"),
        ("docs/API.md", 3, "format_alert_title", "function or class"),
        ("docs/API.md", 5, "api.secret_key", "config key"),
        ("docs/API.md", 6, "secret_key:", "config key"),
        ("docs/API.md", 8, "qa.spool_directory", "config key"),
        ("docs/API.md", 10, "legacyHandler", "function or class"),
        ("docs/API.md", 13, "abc_de", "function or class"),
        ("docs/API.md", 15, "saq/gone_file.py", "file"),
        ("docs/API.md", 16, "saq.gone_file", "module"),
        ("docs/API.md", 18, "saq.part", "module"),
        ("docs/API.md", 19, "saq/renamed_old.py", "file"),
        ("docs/API.md", 21, "retry_limit", "config key"),
        ("docs/API.md", 22, "removed_block", "config key"),
        ("docs/API.md", 24, "api.timeout", "config key"),
        ("docs/API.md", 26, "extra_setting_key", "config key"),
        ("docs/EDITED.md", 3, "saq/gone_file.py", "file"),
    ]
    assert all(lead["dimension"] == "design" for lead in leads)
    assert leads[1]["text"] == "Import them from oldapi.routes."
    assert {lead["hits"] for lead in leads if lead["ref"] != "saq/gone_file.py"} == {1}
    assert [lead["hits"] for lead in leads if lead["ref"] == "saq/gone_file.py"] == [2, 2]


def test_stale_references_are_capped_per_reference(repo, review):
    write(repo, "saq/legacy_module.py", "X = 1\n")
    write(repo, "docs/MANY.md", "saq/legacy_module.py\n" * 15)
    commit(repo)
    git(repo, "branch", "-f", "main")
    git(repo, "rm", "-q", "saq/legacy_module.py")

    leads = read_json(review(), "leads.json")

    assert len(leads) == 10
    assert {lead["hits"] for lead in leads} == {15}


HELPER = """def make_tool(path, name):
    tool = path / name
    tool.write_text("#!/bin/sh\\n")
    return tool
"""

SHORT = "def short():\n    x = 1\n    return x\n"
OLD_COPY = "def old_copy(a):\n    b = a\n    c = b\n    return c\n"


def test_a_function_that_repeats_another_is_a_lead(repo, review):
    git(repo, "switch", "-q", "main")
    write(repo, "tests/saq/test_tools.py", HELPER + "\n\n" + SHORT + "\n\n" + OLD_COPY)
    write(repo, "tests/saq/test_more.py", OLD_COPY.replace("old_copy", "older_copy"))
    commit(repo, "upstream helper")
    git(repo, "switch", "-q", "mw/topic")
    git(repo, "rebase", "-q", "main")
    # renamed and given a docstring, it is still the same function
    copy = HELPER.replace("make_tool(path, name):", 'fake_tool(path, name):\n    """A tool that does nothing."""')
    write(repo, "tests/saq/test_other.py", "\n\n".join([
        copy,
        # two statements are too short to judge
        SHORT.replace("short", "also_short"),
        "def its_own_body(a):\n    b = a + 1\n    c = b + 1\n    return c\n",
        # the same body over other arguments is another function
        HELPER.replace("make_tool(path, name):", "with_mode(path, name, mode):"),
    ]))
    # a change next to a function does not add it
    write(repo, "tests/saq/test_tools.py", HELPER + "\n\n" + SHORT + "\n\n" + OLD_COPY + "\n\nX = 1\n")

    target = review()

    assert [(lead["file"], lead["line"], lead["text"]) for lead in read_json(target, "leads.json") if lead["check"] == "copied-function"] == [
        ("tests/saq/test_other.py", 1, "fake_tool repeats tests/saq/test_tools.py:1 make_tool"),
    ]


def run_check(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prepare.py", "--repo", str(repo), "--base", "main", "--check", "--state-dir", str(tmp_path / "state")])
    with pytest.raises(SystemExit) as exit_info:
        prepare.main()
    return exit_info.value.code


def test_check_prints_each_lead_with_its_fix_and_writes_nothing(repo, tmp_path, monkeypatch, capsys):
    write(repo, "saq/worker.py", "import logging\n\ndef run():\n    try:\n        return 1\n    except ValueError as e:\n        logging.error('failed: %s', e)\n        logging.error('and again')\n")
    write(repo, "tests/saq/test_worker.py", "def test_run():\n    pass\n")

    assert run_check(repo, tmp_path, monkeypatch) == 1

    assert capsys.readouterr().out.splitlines() == [
        "saq/worker.py:7  error-without-traceback  logging.error('failed: %s', e)",
        "    fix: use logging.exception(), or exc_info=True (log_loop_exception() in a long-running loop)",
        "saq/worker.py:8  error-without-traceback  logging.error('and again')",
        "    fix: use logging.exception(), or exc_info=True (log_loop_exception() in a long-running loop)",
        "tests/saq/test_worker.py:1 test_run  unmarked-test",
        "    fix: add a unit, integration or system marker, or the test never runs",
        "3 line(s) to fix or justify",
    ]
    assert not (tmp_path / "state").exists()


def test_check_on_a_change_with_nothing_to_flag_exits_zero(repo, tmp_path, monkeypatch, capsys):
    write(repo, "saq/new.py", "X = 1\n")
    # each of these would be a lead in a Python file or a test file
    write(repo, "docs/notes.txt", "t.join()\n")
    write(repo, "tests/saq/helpers.py", "def test_like_helper():\n    pass\n")
    write(repo, "tests/saq/test_data.txt", "def test_like_data():\n    pass\n")

    assert run_check(repo, tmp_path, monkeypatch) == 0

    assert capsys.readouterr().out == "nothing found\n"


def test_every_check_has_a_fix_to_print():
    checks = set(re.findall(r'self\.lead\(node, "([a-z-]+)"', Path(prepare.__file__).read_text()))

    assert checks and checks | {"copied-function", "stale-reference", "unmarked-test"} == set(prepare.CHECK_FIXES)


def test_added_lines_follows_hunks_and_ignores_header_lookalikes():
    diff = "\n".join([
        "diff --git a/saq/a.py b/saq/a.py",
        "index 1..2 100644",
        "--- a/saq/a.py",
        "+++ b/saq/a.py",
        "@@ -1,3 +1,4 @@",
        " keep",
        "-gone",
        "+new two",
        "+++ an added line that looks like a file header",
        " keep",
        "@@ -10,2 +11,2 @@",
        " keep",
        "+new twelve",
        "\\ No newline at end of file",
        "diff --git a/saq/b.py b/saq/b.py",
        "deleted file mode 100644",
        "--- a/saq/b.py",
        "+++ /dev/null",
        "@@ -1 +0,0 @@",
        "-gone",
        "diff --git a/docs/x y.md b/docs/x y.md",
        "--- a/docs/x y.md\t",
        "+++ b/docs/x y.md\t",
        "@@ -0,0 +1 @@",
        "+first",
        'diff --git "a/docs/caf\\303\\251.md" "b/docs/caf\\303\\251.md"',
        '--- "a/docs/caf\\303\\251.md"',
        '+++ "b/docs/caf\\303\\251.md"',
        "@@ -1 +1 @@",
        "-old",
        "+new",
    ])

    assert prepare.added_lines(diff) == {"saq/a.py": {2, 3, 12}, "docs/x y.md": {1}, "docs/café.md": {1}}


FLAGGED = '''\
import subprocess
import time
import traceback
import requests
from time import sleep


def handler(t, q, lock, logging, e):
    try:
        t.join()
    except:
        traceback.print_exc()
    try:
        q.get()
    except ValueError:
        pass
    try:
        lock.acquire()
    except OSError as error:
        logging.error("failed: %s", error)
        raise RuntimeError("wrapped")
    subprocess.run(["ls"], shell=True)
    requests.get("https://example.com")
    import json
    return json


def more(event, proc, future, work_queue, logger, self, other):
    event.wait()
    proc.communicate()
    future.result()
    work_queue.get()
    str(future.result())
    subprocess.call(["ls"])
    subprocess.check_call(["ls"])
    subprocess.check_output(["ls"])
    httpx.post("https://example.com")
    for item in event:
        try:
            item.clear()
        except KeyError:
            continue
        except IndexError:
            return
        except OSError:
            return None
        except TypeError:
            ...
        except ValueError as error:
            raise other
        except LookupError:
            logger.critical("failed")
        except EOFError:
            self.logger.error("failed")
        except ImportError:
            print_exc()
    from json import dumps
    return dumps
'''

FLAGGED_CHECKS = [
    (10, "unbounded-wait"), (11, "bare-except"), (12, "print-exc"), (14, "unbounded-wait"), (15, "silent-except"),
    (18, "unbounded-wait"), (20, "error-without-traceback"), (21, "raise-without-from"), (22, "shell-true"),
    (22, "no-timeout"), (23, "no-timeout"), (24, "local-import"),
    (29, "unbounded-wait"), (30, "unbounded-wait"), (31, "unbounded-wait"), (32, "unbounded-wait"), (33, "unbounded-wait"),
    (34, "no-timeout"), (35, "no-timeout"), (36, "no-timeout"), (37, "no-timeout"), (41, "silent-except"), (43, "silent-except"),
    (45, "silent-except"), (47, "silent-except"), (50, "raise-without-from"), (52, "error-without-traceback"),
    (54, "error-without-traceback"), (56, "print-exc"), (57, "local-import"),
]

# which reviewer gets each kind of lead
LEAD_DIMENSIONS = {
    "bare-except": "logging", "silent-except": "logging", "raise-without-from": "logging", "print-exc": "logging",
    "error-without-traceback": "logging", "shell-true": "correctness", "unbounded-wait": "uptime", "no-timeout": "uptime",
    "local-import": "design", "offset-paging": "performance", "thread-hop": "design", "sleep-in-test": "tests",
}

CLEAN = '''\
import asyncio
import logging
import subprocess


async def handler(t, event, lock):
    try:
        t.join(timeout=5)
    except ValueError:
        pass  # the value is optional
    except OSError as e:
        logging.error("failed", exc_info=True)
        raise RuntimeError("wrapped") from e
    except KeyError as e:
        raise e
    lock.acquire(blocking=False)
    await asyncio.wait_for(event.wait(), 5)
    subprocess.run(["ls"], timeout=10)
    # json is imported here to keep startup fast
    import json
    return json


def fine(t, q, settings, choice, query, logging, self, error):
    t.join(5)
    q.get(block=False)
    q.qsize()
    settings.get()
    subprocess.run(["ls"], shell=False, timeout=10)
    subprocess.run(["ls"], shell=choice, timeout=10)
    logging.error("not in a handler")
    try:
        return 1
    except KeyError:
        self.report.error("not a logger")
    except IndexError:
        error("not a logger's method")
    except ValueError:
        logging.info("not an error")
    except TypeError:
        return 1
    except OSError:
        "not an ellipsis"
    except LookupError:
        def later():
            raise RuntimeError("runs outside the handler")
        return later
    raise ValueError("not in a handler any more")


class Holder:
    import json as class_level


import os
'''


def test_scan_flags_each_mechanical_check_on_added_lines():
    leads = prepare.scan_python("saq/x.py", FLAGGED, set(range(1, 60)))

    assert [(lead["line"], lead["check"]) for lead in leads] == FLAGGED_CHECKS
    assert leads[1] == {"check": "bare-except", "dimension": "logging", "file": "saq/x.py", "line": 11, "text": "except:"}
    assert all(lead["dimension"] == LEAD_DIMENSIONS[lead["check"]] for lead in leads)


def test_scan_reports_only_lines_the_change_adds():
    leads = prepare.scan_python("saq/x.py", FLAGGED, {11, 12})

    assert [(lead["line"], lead["check"]) for lead in leads] == [(11, "bare-except"), (12, "print-exc")]
    # a handler's lead counts as added when only its body is
    assert [(lead["line"], lead["check"]) for lead in prepare.scan_python("saq/x.py", FLAGGED, {16})] == [(15, "silent-except")]


def test_scan_leaves_bounded_commented_and_chained_code_alone():
    assert prepare.scan_python("saq/x.py", CLEAN, set(range(1, 60))) == []


API_SOURCE = """from fastapi.concurrency import run_in_threadpool

async def f(query, t, loop):
    query.offset(10)
    await run_in_threadpool(t)
    await asyncio.to_thread(t)
    await loop.run_in_executor(None, t)
    query.limit(10)
    offset(10)
"""
API_LEADS = ["offset-paging", "thread-hop", "thread-hop", "thread-hop"]
TEST_SOURCE = """import time
from time import sleep as nap, monotonic

def test_x(t):
    time.sleep(1)
    nap(1)
    monotonic()
    t.join()
"""


@pytest.mark.parametrize("path, source, checks", [
    ("aceapi_v2/alerts/router.py", API_SOURCE, API_LEADS),
    ("aceapi_ai/alerts/router.py", API_SOURCE, API_LEADS),
    # sync.py is where the one sanctioned thread hop lives
    ("aceapi_v2/sync.py", API_SOURCE, []),
    ("saq/alerts.py", API_SOURCE, []),
    # in a test, sleeping is the finding and an unbounded join is not
    ("tests/saq/x.py", TEST_SOURCE, ["sleep-in-test", "sleep-in-test"]),
    ("saq/test_x.py", TEST_SOURCE, ["sleep-in-test", "sleep-in-test"]),
    ("saq/conftest.py", TEST_SOURCE, ["sleep-in-test", "sleep-in-test"]),
    ("saq/x.py", TEST_SOURCE, ["unbounded-wait"]),
    ("tests/saq/test_y.py", "from time import sleep\n\ndef test_x():\n    sleep(1)\n", ["sleep-in-test"]),
    ("tests/saq/test_y.py", "from gevent import sleep\n\ndef test_x():\n    sleep(1)\n", []),
])
def test_scan_checks_that_depend_on_where_the_file_is(path, source, checks):
    leads = prepare.scan_python(path, source, set(range(1, 10)))

    assert [lead["check"] for lead in leads] == checks
    assert all(lead["dimension"] == LEAD_DIMENSIONS[lead["check"]] for lead in leads)


def test_scan_looks_inside_classes_and_at_calls_on_call_results():
    source = "class Pool:\n    def stop(self):\n        try:\n            self.thread().join()\n        except:\n            raise\n"

    leads = prepare.scan_python("saq/pool.py", source, {4, 5, 6})

    assert [(lead["line"], lead["check"]) for lead in leads] == [(4, "unbounded-wait"), (5, "bare-except")]
