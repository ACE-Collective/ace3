"""Tests for the /ace-review verification bookkeeping, .claude/skills/ace-review/scripts/findings.py."""

import datetime
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[2] / ".claude" / "skills" / "ace-review" / "scripts" / "findings.py"

pytestmark = pytest.mark.unit


def _load_script():
    spec = importlib.util.spec_from_file_location("ace_review_findings", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


findings = _load_script()


def finding(**fields):
    return {"dimension": "uptime", "severity": "fix-first", "origin": "new", "file": "saq/x.py", "line": 1,
            "title": "a claim", "evidence": "saq/x.py:1 does it", "impact": "it breaks", "fix": "do less", **fields}


def earlier(fid, status, **fields):
    return {**finding(**fields), "id": fid, "round": 1, "status": status}


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / "round-2"
    path.mkdir()
    (path / "target.json").write_text(json.dumps({"round": 2, "rule_changes_digest": "d1", "state_dir": str(tmp_path / "state"),
                                                  "repo": "/opt/ace", "branch": "mw/topic"}))
    return path


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def read_json(path):
    return json.loads(path.read_text())


def vote(bundle, cid, k, verdict, severity, origin="new", note=None):
    write_json(bundle / "verify" / f"{cid}-{k}.json",
               {"cid": cid, "verdict": verdict, "severity": severity, "origin": origin, "reason": f"vote {k}", "note": note})


def test_collect_plans_three_votes_for_a_blocker_and_batches_the_rest(bundle):
    write_json(bundle / "findings-uptime.json", [
        finding(severity="blocker"), finding(severity="fix-first"), finding(severity="nit"), finding(origin="pre-existing"),
    ])
    write_json(bundle / "previous.json", [earlier("R1-1", "open"), earlier("R1-2", "dismissed"), earlier("R1-3", "seen")])
    # a vote left by an earlier collect belongs to a different numbering
    vote(bundle, "C1", 1, "CONFIRMED", "blocker")

    plan = findings.collect(str(bundle))

    assert plan == {"single": [{"cid": "C1", "votes": 3}, {"cid": "C2", "votes": 1}], "batch": ["C3", "C4"], "carry": ["R1-1"], "flaws": []}
    assert read_json(bundle / "plan.json") == plan
    assert [c["source"] for c in read_json(bundle / "candidates.json")] == ["findings-uptime.json"] * 4
    assert list((bundle / "verify").iterdir()) == []


def test_collect_numbers_files_in_name_order(bundle):
    write_json(bundle / "findings-uptime.json", [finding(title="uptime one")])
    write_json(bundle / "findings-design.json", [finding(dimension="design", title="design one")])

    findings.collect(str(bundle))

    assert [(c["cid"], c["title"]) for c in read_json(bundle / "candidates.json")] == [("C1", "design one"), ("C2", "uptime one")]


def test_collect_refuses_malformed_findings(bundle):
    write_json(bundle / "findings-logging.json", [finding(dimension="logging"), finding(severity="major", evidence="")])

    with pytest.raises(SystemExit) as exit_info:
        findings.collect(str(bundle))

    assert "findings-logging.json[1]" in str(exit_info.value)
    assert "severity='major'" in str(exit_info.value)
    assert "no evidence" in str(exit_info.value)
    assert not (bundle / "plan.json").exists()


@pytest.mark.parametrize("votes, expected", [
    ([("CONFIRMED", "blocker"), ("CONFIRMED", "blocker"), ("REJECTED", "blocker")], ("blocker", "CONFIRMED")),
    ([("CONFIRMED", "blocker"), ("CONFIRMED", "fix-first"), ("CONFIRMED", "nit")], ("fix-first", "CONFIRMED")),
    ([("CONFIRMED", "blocker"), ("CONFIRMED", "blocker"), ("PLAUSIBLE", "blocker")], ("blocker", "CONFIRMED")),
    ([("PLAUSIBLE", "blocker"), ("PLAUSIBLE", "blocker"), ("CONFIRMED", "blocker")], ("fix-first", "PLAUSIBLE")),
    ([("CONFIRMED", "blocker"), ("REJECTED", "blocker"), ("REJECTED", "nit")], None),
])
def test_tally_keeps_a_blocker_only_with_a_majority_behind_it(bundle, votes, expected):
    write_json(bundle / "findings-uptime.json", [finding(severity="blocker")])
    findings.collect(str(bundle))
    for k, (verdict, severity) in enumerate(votes, 1):
        vote(bundle, "C1", k, verdict, severity)

    result = findings.tally(str(bundle))

    survivors = read_json(bundle / "survivors.json")
    if expected is None:
        assert result["rejected"] == 1 and survivors == []
        assert read_json(bundle / "rejected.json")[0]["reason"] == "vote 2; vote 3"
    else:
        assert [(s["severity"], s["verdict"]) for s in survivors] == [expected]


def test_one_vote_cannot_make_a_blocker(bundle):
    write_json(bundle / "findings-correctness.json", [finding(dimension="correctness")])
    findings.collect(str(bundle))
    vote(bundle, "C1", 1, "CONFIRMED", "blocker", note="it hangs the engine")

    findings.tally(str(bundle))

    [survivor] = read_json(bundle / "survivors.json")
    assert survivor["severity"] == "fix-first"
    assert "it hangs the engine" in survivor["note"]
    assert "1 verifier(s) argued for blocker; a blocker needs 2 of 3" in survivor["note"]


def test_the_votes_decide_the_origin(bundle):
    write_json(bundle / "findings-logging.json", [finding(dimension="logging", severity="blocker")])
    findings.collect(str(bundle))
    vote(bundle, "C1", 1, "CONFIRMED", "blocker", origin="pre-existing")
    vote(bundle, "C1", 2, "CONFIRMED", "blocker", origin="pre-existing")
    vote(bundle, "C1", 3, "CONFIRMED", "blocker")

    findings.tally(str(bundle))

    assert read_json(bundle / "survivors.json")[0]["origin"] == "pre-existing"


def test_tally_stops_at_missing_votes_unless_told_otherwise(bundle):
    write_json(bundle / "findings-uptime.json", [finding(severity="blocker"), finding(severity="nit")])
    write_json(bundle / "previous.json", [earlier("R1-1", "open")])
    findings.collect(str(bundle))
    vote(bundle, "C1", 1, "CONFIRMED", "blocker")
    vote(bundle, "C1", 2, "CONFIRMED", "blocker")

    with pytest.raises(SystemExit) as exit_info:
        findings.tally(str(bundle))
    message = str(exit_info.value)
    assert "verify/C1-3.json" in message
    assert "verify/batch.json: C2" in message
    assert "verify/batch.json: carried R1-1" in message

    result = findings.tally(str(bundle), allow_missing=True)

    # two confirmations are a majority of three even with the third vote missing; the
    # nit had no vote at all
    assert [(s["cid"], s["severity"]) for s in read_json(bundle / "survivors.json")] == [("C1", "blocker")]
    assert read_json(bundle / "rejected.json")[0]["reason"] == "no verifier vote"
    assert len(result["missing"]) == 3


def test_a_lone_vote_cast_for_a_blocker_tops_out_at_fix_first(bundle):
    write_json(bundle / "findings-uptime.json", [finding(severity="blocker")])
    findings.collect(str(bundle))
    vote(bundle, "C1", 1, "CONFIRMED", "blocker")

    findings.tally(str(bundle), allow_missing=True)

    assert read_json(bundle / "survivors.json")[0]["severity"] == "fix-first"


def test_tally_reads_the_batch_and_the_rechecked_findings(bundle):
    write_json(bundle / "findings-design.json", [finding(dimension="design", severity="nit"), finding(dimension="design", origin="pre-existing")])
    write_json(bundle / "previous.json", [earlier("R1-1", "open"), earlier("R1-4", "open")])
    findings.collect(str(bundle))
    write_json(bundle / "verify" / "batch.json", {
        "candidates": [{"cid": "C1", "verdict": "REJECTED", "reason": "a formatter would fix it"},
                       {"cid": "C2", "verdict": "CONFIRMED", "severity": "fix-first", "origin": "pre-existing", "reason": "real"}],
        "carried": [{"id": "R1-1", "status": "fixed", "reason": "the timeout is there now"},
                    {"id": "R1-4", "status": "open", "reason": "still unbounded"}],
    })

    result = findings.tally(str(bundle))

    assert result == {"survivors": 1, "rejected": 1, "carried": 2, "flaws": 0, "rejected_flaws": 0, "missing": []}
    assert read_json(bundle / "rejected.json") == [{
        "cid": "C1", "dimension": "design", "severity": "nit", "file": "saq/x.py", "line": 1, "title": "a claim",
        "reason": "a formatter would fix it",
    }]
    assert [c["status"] for c in read_json(bundle / "carried.json")] == ["fixed", "open"]


def test_survivors_are_ranked_by_origin_severity_and_dimension(bundle):
    write_json(bundle / "findings-a.json", [
        finding(dimension="design", severity="nit"),
        finding(dimension="design", origin="pre-existing", severity="nit"),
        finding(dimension="design", severity="fix-first"),
        finding(dimension="logging", severity="fix-first"),
    ])
    findings.collect(str(bundle))
    vote(bundle, "C3", 1, "CONFIRMED", "fix-first")
    vote(bundle, "C4", 1, "CONFIRMED", "fix-first")
    write_json(bundle / "verify" / "batch.json", {"candidates": [
        {"cid": "C1", "verdict": "CONFIRMED", "severity": "nit"},
        {"cid": "C2", "verdict": "CONFIRMED", "severity": "nit", "origin": "pre-existing"},
    ]})

    findings.tally(str(bundle))

    assert [s["cid"] for s in read_json(bundle / "survivors.json")] == ["C4", "C3", "C1", "C2"]


def test_finish_drops_repeats_numbers_the_rest_and_counts_what_is_still_open(bundle):
    write_json(bundle / "previous.json", [earlier("R1-1", "open", severity="blocker"), earlier("R1-2", "seen", severity="nit")])
    write_json(bundle / "carried.json", [{"id": "R1-1", "status": "open"}])
    write_json(bundle / "rejected.json", [{"cid": "C9"}])
    write_json(bundle / "ranked.json", [
        finding(title="new one", cid="C1"),
        finding(title="the old nit again", severity="nit", repeats="R1-2"),
        finding(title="old code", origin="pre-existing", severity="nit"),
    ])

    summary = findings.finish(str(bundle))

    verified = read_json(bundle / "verified.json")
    assert [(f["id"], f["title"]) for f in verified] == [("R2-1", "new one"), ("R2-2", "old code")]
    assert all("repeats" not in f for f in verified)
    assert read_json(bundle / "summary.json") == summary
    assert datetime.datetime.fromisoformat(summary.pop("finished_at")).tzinfo is not None
    assert summary == {
        "round": 2,
        "new": {"blocker": 0, "fix-first": 1, "nit": 0},
        "pre_existing": 1,
        "still_open": [{"id": "R1-1", "severity": "blocker", "file": "saq/x.py", "line": 1, "title": "a claim"}],
        "fixed": [],
        "not_repeated": 1,
        "rejected": 1,
        "verdict_floor": "rework",
        "flaws": [],
    }


@pytest.mark.parametrize("ranked, carried, floor", [
    ([finding(severity="nit")], [], "ship"),
    ([finding(severity="blocker", origin="pre-existing")], [], "ship"),
    ([], [{"id": "R1-1", "status": "fixed"}], "ship"),
    ([], [{"id": "R1-1", "status": "open"}], "fix-first"),
])
def test_the_verdict_floor_counts_only_new_and_still_open_findings(bundle, ranked, carried, floor):
    write_json(bundle / "previous.json", [earlier("R1-1", "open")])
    write_json(bundle / "carried.json", carried)
    write_json(bundle / "ranked.json", ranked)

    assert findings.finish(str(bundle))["verdict_floor"] == floor


def test_finish_refuses_malformed_ranked_findings(bundle):
    write_json(bundle / "ranked.json", [finding(origin="old")])

    with pytest.raises(SystemExit, match=r"ranked.json\[0\]: origin='old'"):
        findings.finish(str(bundle))
    assert not (bundle / "summary.json").exists()


def test_answer_records_one_answer_per_finding(bundle):
    write_json(bundle / "verified.json", [{**finding(), "id": "R2-1"}])
    write_json(bundle / "previous.json", [earlier("R1-1", "open")])

    findings.answer(str(bundle), "R2-1", "wrong")
    findings.answer(str(bundle), "R2-1", "intentional", note="the retry is bounded by the caller")
    findings.answer(str(bundle), "R1-1", "fixed")

    assert read_json(bundle / "answers.json") == [
        {"id": "R2-1", "answer": "intentional", "note": "the retry is bounded by the caller"},
        {"id": "R1-1", "answer": "fixed"},
    ]


def test_answer_on_the_rules_records_the_digest_it_decides(bundle):
    findings.answer(str(bundle), "rules", "accepted")

    assert read_json(bundle / "answers.json") == [{"id": "rules", "answer": "accepted", "digest": "d1"}]


@pytest.mark.parametrize("fid, value, message", [
    ("R9-9", "wrong", "no finding R9-9"),
    ("R2-1", "maybe", "the answer is one of"),
    ("rules", "wrong", "the answer for rules is one of"),
])
def test_answer_refuses_what_it_cannot_record(bundle, fid, value, message):
    write_json(bundle / "verified.json", [{**finding(), "id": "R2-1"}])

    with pytest.raises(SystemExit, match=message):
        findings.answer(str(bundle), fid, value)
    assert not (bundle / "answers.json").exists()


def test_the_command_line_runs_a_round_from_findings_to_answers(bundle, monkeypatch, capsys):
    def run(*args):
        monkeypatch.setattr(sys, "argv", ["findings.py", *args])
        findings.main()
        return json.loads(capsys.readouterr().out)

    write_json(bundle / "findings-uptime.json", [finding(severity="blocker")])
    assert run("collect", str(bundle)) == {"single": [{"cid": "C1", "votes": 3}], "batch": [], "carry": [], "flaws": []}
    for k in (1, 2, 3):
        vote(bundle, "C1", k, "CONFIRMED", "blocker")
    assert run("tally", str(bundle), "--allow-missing")["survivors"] == 1
    write_json(bundle / "ranked.json", read_json(bundle / "survivors.json"))
    assert run("finish", str(bundle))["verdict_floor"] == "rework"
    assert run("answer", str(bundle), "R2-1", "didn't matter", "--note", "cosmetic") == {
        "id": "R2-1", "answer": "didn't matter", "note": "cosmetic"
    }


def flaw(**fields):
    return {"dimension": "design", "title": "the tree has no hook for X", "flaw": "saq/analysis/root.py has no event for X",
            "area": "analysis tree", "workaround": "polls the root for X", "file": "saq/y.py", "line": 7, "fix_size": "large",
            "fix": "add the hook", "recommendation": "keep going", "why": "contained", **fields}


def flaws_through_tally(bundle, flaws, votes):
    write_json(bundle / "flaws-design.json", flaws)
    plan = findings.collect(str(bundle))
    write_json(bundle / "verify" / "batch.json", {"flaws": votes})
    findings.tally(str(bundle))
    return plan


def ledger(bundle):
    return read_json(Path(read_json(bundle / "target.json")["state_dir"]) / "design-flaws.json")


def finish_with_flaws(bundle, flaws):
    write_json(bundle / "ranked.json", [])
    write_json(bundle / "flaws.json", flaws)
    return findings.finish(str(bundle))


def test_collect_numbers_the_design_flaws_for_the_batch_verifier(bundle):
    write_json(bundle / "flaws-correctness.json", [flaw(dimension="correctness")])
    write_json(bundle / "flaws-design.json", [flaw(), flaw(title="another")])

    plan = findings.collect(str(bundle))

    assert plan["flaws"] == ["F1", "F2", "F3"]
    assert [(f["fid"], f["source"]) for f in read_json(bundle / "flaw-candidates.json")] == [
        ("F1", "flaws-correctness.json"), ("F2", "flaws-design.json"), ("F3", "flaws-design.json"),
    ]


def test_collect_refuses_malformed_flaws(bundle):
    write_json(bundle / "flaws-design.json", [flaw(fix_size="huge", workaround="")])

    with pytest.raises(SystemExit, match=r"flaws-design.json\[0\]: fix_size='huge', no workaround"):
        findings.collect(str(bundle))


def test_tally_keeps_the_flaws_the_verifier_found_real_with_its_judgment(bundle):
    flaws_through_tally(bundle, [flaw(), flaw(title="not a flaw")], [
        {"fid": "F1", "verdict": "PLAUSIBLE", "known": "D2", "fix_size": "small", "recommendation": "stop", "why": "a day's work", "reason": "real"},
        {"fid": "F2", "verdict": "REJECTED", "reason": "the change could fix it itself"},
    ])

    [kept] = read_json(bundle / "flaws.json")
    assert {k: kept[k] for k in ("fid", "verdict", "known", "fix_size", "recommendation", "why")} == {
        "fid": "F1", "verdict": "PLAUSIBLE", "known": "D2", "fix_size": "small", "recommendation": "stop", "why": "a day's work",
    }
    assert read_json(bundle / "rejected-flaws.json") == [{"fid": "F2", "title": "not a flaw", "reason": "the change could fix it itself"}]


def test_tally_waits_for_the_flaw_votes(bundle):
    write_json(bundle / "flaws-design.json", [flaw()])
    findings.collect(str(bundle))

    with pytest.raises(SystemExit, match="verify/batch.json: flaw F1"):
        findings.tally(str(bundle))
    assert findings.tally(str(bundle), allow_missing=True)["rejected_flaws"] == 1


def test_finish_adds_new_flaws_to_the_ledger_undecided(bundle):
    summary = finish_with_flaws(bundle, [flaw()])

    assert summary["verdict_floor"] == "ship"
    assert summary["flaws"] == [{"id": "D1", "title": "the tree has no hook for X", "new": True, "status": "undecided", "fix_size": "large",
                                 "recommendation": "keep going", "why": "contained", "workarounds": 1}]
    [entry] = ledger(bundle)
    assert {k: entry[k] for k in ("id", "flaw", "area", "fix_size", "fix", "status")} == {
        "id": "D1", "flaw": "saq/analysis/root.py has no event for X", "area": "analysis tree", "fix_size": "large",
        "fix": "add the hook", "status": "undecided",
    }
    assert [(w["repo"], w["branch"], w["round"], w["file"], w["line"], w["what"]) for w in entry["workarounds"]] == [
        ("/opt/ace", "mw/topic", 2, "saq/y.py", 7, "polls the root for X"),
    ]


def test_a_known_flaw_counts_one_workaround_per_branch(bundle, tmp_path):
    finish_with_flaws(bundle, [flaw()])
    findings.answer_flaw(str(tmp_path / "state"), "D1", "defer")
    # the same branch's next round finds it again, and so does another branch
    later = tmp_path / "round-3"
    later.mkdir()
    write_json(later / "target.json", {**read_json(bundle / "target.json"), "round": 3})
    other = tmp_path / "other" / "round-1"
    write_json(other / "target.json", {**read_json(bundle / "target.json"), "round": 1, "branch": "jd/other"})

    finish_with_flaws(later, [flaw(known="D1", workaround="polls again", line=9)])
    summary = finish_with_flaws(other, [flaw(known="D1", title="worded differently")])

    assert summary["flaws"] == [{"id": "D1", "title": "the tree has no hook for X", "new": False, "status": "deferred",
                                 "fix_size": "large", "recommendation": "keep going", "why": "contained", "workarounds": 2}]
    [entry] = ledger(bundle)
    assert [(w["branch"], w["round"], w["line"]) for w in entry["workarounds"]] == [("mw/topic", 3, 9), ("jd/other", 1, 7)]


def test_rerunning_finish_replaces_what_the_round_recorded(bundle):
    finish_with_flaws(bundle, [flaw(), flaw(title="dropped on the rerun")])

    summary = finish_with_flaws(bundle, [flaw()])

    assert [f["id"] for f in summary["flaws"]] == ["D1"]
    assert [(e["id"], len(e["workarounds"])) for e in ledger(bundle)] == [("D1", 1)]


def test_rerunning_finish_keeps_an_answered_flaw(bundle, tmp_path):
    finish_with_flaws(bundle, [flaw()])
    findings.answer_flaw(str(tmp_path / "state"), "D1", "address", note="small after all")

    summary = finish_with_flaws(bundle, [flaw()])

    assert summary["flaws"][0]["status"] == "addressing" and not summary["flaws"][0]["new"]
    [entry] = ledger(bundle)
    assert (entry["status"], entry["note"], len(entry["workarounds"])) == ("addressing", "small after all", 1)


def test_answer_flaw_refuses_what_it_cannot_record(bundle, tmp_path):
    finish_with_flaws(bundle, [flaw()])

    with pytest.raises(SystemExit, match="no design flaw D9"):
        findings.answer_flaw(str(tmp_path / "state"), "D9", "defer")
    with pytest.raises(SystemExit, match="one of defer, address, fixed, wrong"):
        findings.answer_flaw(str(tmp_path / "state"), "D1", "later")
    assert ledger(bundle)[0]["status"] == "undecided"


def test_the_flaw_list_puts_open_flaws_with_the_most_workarounds_first(tmp_path, monkeypatch, capsys):
    def entry(fid, status, workarounds):
        return {"id": fid, "title": fid, "status": status, "workarounds": [{"branch": f"b{n}"} for n in range(workarounds)]}

    state = tmp_path / "state"
    write_json(state / "design-flaws.json", [entry("D1", "deferred", 1), entry("D2", "fixed", 5), entry("D3", "deferred", 3),
                                            entry("D4", "undecided", 1), entry("D5", "addressing", 1), entry("D6", "wrong", 1)])

    assert [e["id"] for e in findings.list_flaws(str(state))] == ["D4", "D5", "D3", "D1"]
    monkeypatch.setattr(sys, "argv", ["findings.py", "flaws", "--all", "--state", str(state)])
    findings.main()
    assert [e["id"] for e in json.loads(capsys.readouterr().out)] == ["D4", "D5", "D3", "D1", "D2", "D6"]
    assert findings.stats(str(state))["design_flaws"] == {"addressing": 1, "deferred": 2, "fixed": 1, "undecided": 1, "wrong": 1}


@pytest.mark.parametrize("step, message", [(findings.tally, "run collect first"), (findings.finish, "no ranked.json")])
def test_a_step_run_out_of_order_says_what_comes_first(bundle, step, message):
    with pytest.raises(SystemExit, match=message):
        step(str(bundle))


def test_answer_on_the_rules_needs_rule_changes(bundle):
    write_json(bundle / "target.json", {"round": 2, "rule_changes_digest": None})

    with pytest.raises(SystemExit, match="no rule changes"):
        findings.answer(str(bundle), "rules", "accepted")


def git(repo, *args):
    command = ["git", "-C", str(repo), "-c", "user.name=test", "-c", "user.email=test@example.com", *args]
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def history(tmp_path):
    """A branch at two commits: forty lines, then line 10 rewritten. Returns (repo, trees)."""
    repo = tmp_path / "ace"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "mw/topic")
    lines = [f"line {n}" for n in range(1, 41)]
    (repo / "w.py").write_text("\n".join(lines) + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "one")
    first = git(repo, "rev-parse", "HEAD^{tree}")
    lines[9] = "line 10, rewritten"
    (repo / "w.py").write_text("\n".join(lines) + "\n")
    git(repo, "commit", "-q", "-am", "two")
    return repo, first, git(repo, "rev-parse", "HEAD^{tree}")


def reviewed(state, key, number, target, verified=(), finished_at="2026-10-01T09:00:00+00:00", **files):
    """A finished round as the skill leaves it."""
    path = state / key / f"round-{number}"
    write_json(path / "target.json", target)
    write_json(path / "verified.json", list(verified))
    write_json(path / "summary.json", {"finished_at": finished_at})
    for name, data in files.items():
        write_json(path / f"{name}.json", data)
    return path


def at(fid, line, **fields):
    return {**finding(file="w.py", line=line, **fields), "id": fid}


@pytest.fixture
def state(tmp_path, history):
    repo, first, second = history
    state = tmp_path / "state"
    branch = {"repo": str(repo), "branch": "mw/topic", "includes_uncommitted": True}
    reviewed(state, "ace-mw-topic", 1, {**branch, "tree": first},
             [at("R1-1", 3), at("R1-2", 10, dimension="design", severity="nit"), at("R1-3", 20),
              at("R1-4", 30, severity="nit"), at("R1-5", 5, origin="pre-existing")],
             leads=[{"file": "w.py", "line": 3, "check": "bare-except"}, {"file": "w.py", "line": 30, "check": "local-import"}],
             rejected=[{"dimension": "uptime", "severity": "blocker"}, {"dimension": "design", "severity": "nit"}],
             answers=[{"id": "R1-1", "answer": "wrong"}])
    reviewed(state, "ace-mw-topic", 2, {**branch, "tree": second}, [at("R2-1", 12)], finished_at="2026-10-20T09:00:00+00:00",
             carried=[{"id": "R1-3", "status": "fixed"}])
    # an unfinished round counts for nothing
    write_json(state / "ace-mw-topic" / "round-3" / "target.json", {**branch, "tree": second})
    # a branch whose snapshot was pruned and whose ref is gone: nothing later to compare
    reviewed(state, "ace-mw-gone", 1, {"repo": str(repo), "branch": "mw/gone", "includes_uncommitted": True,
                                       "tree": "0" * 40, "head": "1" * 40}, [at("R1-1", 1)])
    return state


def test_stats_gives_each_new_finding_its_first_known_outcome(state):
    result = findings.stats(str(state))

    assert {k: result[k] for k in ("reviews", "rounds", "new_findings", "pre_existing", "rejected_by_verifiers", "blockers_rejected_by_vote")} == {
        "reviews": 2, "rounds": 3, "new_findings": 6, "pre_existing": 1, "rejected_by_verifiers": 2, "blockers_rejected_by_vote": 1,
    }
    # R1-1 answered, R1-3 rechecked, R1-2's line rewritten, R1-4's line never touched; R2-1 has
    # nothing after it yet and the pruned branch nothing at all
    assert result["outcomes"] == {"fixed (rechecked)": 1, "lines changed": 1, "unchanged": 1, "unknown": 2, "wrong": 1, "acted_on": "2 of 4"}
    assert result["by_dimension"]["design"] == {"lines changed": 1, "rejected": 1, "acted_on": "1 of 1"}
    assert result["by_dimension"]["uptime"] == {
        "fixed (rechecked)": 1, "rejected": 1, "unchanged": 1, "unknown": 2, "wrong": 1, "acted_on": "1 of 3"
    }
    assert result["by_severity"]["nit"] == {"lines changed": 1, "unchanged": 1, "acted_on": "1 of 2"}
    assert result["by_lead"] == {"bare-except": {"wrong": 1, "acted_on": "0 of 1"}, "local-import": {"unchanged": 1, "acted_on": "0 of 1"}}


def test_stats_since_counts_only_the_rounds_finished_from_then(state, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["findings.py", "stats", str(state), "--since", "2026-10-10"])

    findings.main()

    result = json.loads(capsys.readouterr().out)
    assert {k: result[k] for k in ("since", "reviews", "rounds", "new_findings")} == {"since": "2026-10-10", "reviews": 1, "rounds": 1, "new_findings": 1}
    assert result["outcomes"] == {"unknown": 1, "acted_on": "no known outcomes"}


def test_a_finding_reopened_by_a_later_recheck_is_not_counted_as_fixed(tmp_path, history):
    repo, first, second = history
    state = tmp_path / "state"
    branch = {"repo": str(repo), "branch": "mw/topic", "includes_uncommitted": True}
    reviewed(state, "ace-mw-topic", 1, {**branch, "tree": first}, [at("R1-1", 30)])
    reviewed(state, "ace-mw-topic", 2, {**branch, "tree": first}, carried=[{"id": "R1-1", "status": "fixed"}])
    reviewed(state, "ace-mw-topic", 3, {**branch, "tree": second}, carried=[{"id": "R1-1", "status": "open"}])
    # a review that never finished a round is not a review yet
    write_json(state / "ace-mw-other" / "round-1" / "target.json", branch)

    result = findings.stats(str(state))

    assert result["reviews"] == 1
    assert result["outcomes"] == {"unchanged": 1, "acted_on": "0 of 1"}


def test_stats_on_no_reviews_counts_nothing(tmp_path):
    result = findings.stats(str(tmp_path / "missing"))

    assert result["reviews"] == 0 and result["new_findings"] == 0
    assert result["outcomes"] == {"acted_on": "no known outcomes"}
    assert result["by_dimension"] == {}


@pytest.mark.parametrize("path, line, expected", [
    ("w.py", 10, True),
    ("w.py", 12, True),
    ("w.py", 13, False),
    ("w.py", 30, False),
    ("w.py", None, True),
    ("other.py", 10, False),
])
def test_touched_means_a_change_within_two_lines(history, path, line, expected):
    repo, first, second = history

    assert findings.touched(str(repo), first, second, path, line) is expected
