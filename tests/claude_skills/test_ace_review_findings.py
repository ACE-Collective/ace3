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
# the gh the tests replace with FakeGitHub, kept for the tests of gh itself
REAL_GH = findings.gh


def finding(**fields):
    return {"dimension": "uptime", "severity": "fix-first", "origin": "new", "file": "saq/x.py", "line": 1,
            "title": "a claim", "evidence": "saq/x.py:1 does it", "impact": "it breaks", "fix": "do less", **fields}


def earlier(fid, status, **fields):
    return {**finding(**fields), "id": fid, "round": 1, "status": status}


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / "round-2"
    path.mkdir()
    (path / "target.json").write_text(json.dumps({"round": 2, "rule_changes_digest": "d1",
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
        "flaws_error": None,
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


class FakeGitHub:
    """The gh commands findings.py runs, against issues kept in memory."""

    def __init__(self):
        self.issues = {}
        self.next_id = 100
        self.calls = []
        self.down = False
        # GitHub's list shows a new issue only some time later; these it doesn't show yet
        self.unlisted = set()

    def add(self, title, state="OPEN", reason="", assignees=(), labels=("design flaw",), body="the flaw"):
        number = self.next_id
        self.next_id += 1
        self.issues[number] = {"number": number, "title": title, "body": body, "state": state, "stateReason": reason,
                               "assignees": list(assignees), "labels": list(labels), "comments": [],
                               "url": f"https://github.com/o/r/issues/{number}"}
        return number

    def comment(self, number, body):
        url = f"https://github.com/o/r/issues/{number}#issuecomment-{self.next_id}"
        self.next_id += 1
        self.issues[number]["comments"].append({"body": body, "url": url})
        return url

    @staticmethod
    def as_gh(issue):
        return {**issue, "assignees": [{"login": a} for a in issue["assignees"]], "labels": [{"name": label} for label in issue["labels"]]}

    def workarounds(self, number):
        return [c["body"] for c in self.issues[number]["comments"] if c["body"].startswith("<!-- ace-review workaround")]

    def writes(self):
        return [call for call in self.calls if call[:2] not in (("issue", "list"), ("issue", "view"))]

    def find_comment(self, path):
        url_end = f"#issuecomment-{path.rsplit('/', 1)[1]}"
        return next((i, c) for i in self.issues.values() for c in i["comments"] if c["url"].endswith(url_end))

    def __call__(self, *args, stdin=None):
        if self.down:
            raise RuntimeError("gh issue list failed: could not connect")
        self.calls.append(args)
        match args:
            case ("issue", "list", "--label", label, "--state", "all", "--limit", _, "--json", _):
                return json.dumps([self.as_gh(i) for n, i in self.issues.items() if label in i["labels"] and n not in self.unlisted])
            case ("issue", "create", "--label", label, "--title", title, "--body-file", "-"):
                number = self.add(title, labels=(label,), body=stdin)
                self.unlisted.add(number)
                return self.issues[number]["url"] + "\n"
            case ("issue", "comment", number, "--body-file", "-"):
                return self.comment(int(number), stdin) + "\n"
            case ("issue", "view", number, "--json", _):
                return json.dumps(self.as_gh(self.issues[int(number)]))
            case ("issue", "reopen", number):
                self.issues[int(number)].update(state="OPEN", stateReason="REOPENED")
            case ("issue", "close", number, "--reason", reason):
                self.issues[int(number)].update(state="CLOSED", stateReason="NOT_PLANNED" if reason == "not planned" else "COMPLETED")
            case ("issue", "edit", number, "--add-assignee", "@me"):
                self.issues[int(number)]["assignees"].append("me")
            case ("issue", "edit", number, "--remove-assignee", login):
                self.issues[int(number)]["assignees"].remove(login)
            case ("api", "-X", "PATCH", path, "-f", body):
                self.find_comment(path)[1]["body"] = body.removeprefix("body=")
            case ("api", "-X", "DELETE", path):
                issue, comment = self.find_comment(path)
                issue["comments"].remove(comment)
            case _:
                raise AssertionError(f"unexpected gh call {args}")
        return ""


@pytest.fixture(autouse=True)
def github(monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(findings, "gh", fake)
    return fake


def flaw(fid="F1", **fields):
    return {"dimension": "design", "title": "the tree has no hook for X", "flaw": "saq/analysis/root.py has no event for X",
            "area": "analysis tree", "workaround": "polls the root for X", "file": "saq/y.py", "line": 7, "fix_size": "large",
            "fix": "add the hook", "recommendation": "keep going", "why": "contained", "fid": fid, **fields}


def flaws_through_tally(bundle, flaws, votes):
    write_json(bundle / "flaws-design.json", [{k: v for k, v in f.items() if k != "fid"} for f in flaws])
    plan = findings.collect(str(bundle))
    write_json(bundle / "verify" / "batch.json", {"flaws": votes})
    findings.tally(str(bundle))
    return plan


def finish_with_flaws(bundle, flaws):
    write_json(bundle / "ranked.json", [])
    write_json(bundle / "flaws.json", flaws)
    return findings.finish(str(bundle))


def later_round(bundle, tmp_path, **fields):
    path = tmp_path / f"round-{fields.get('round', 3)}"
    write_json(path / "target.json", {**read_json(bundle / "target.json"), "round": 3, **fields})
    return path


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
        {"fid": "F1", "verdict": "CONFIRMED", "known": None, "fix_size": "small", "recommendation": "stop", "why": "one function", "reason": "real"},
        {"fid": "F2", "verdict": "REJECTED", "reason": "the change could fix it itself"},
    ])

    [kept] = read_json(bundle / "flaws.json")
    assert (kept["fid"], kept["fix_size"], kept["recommendation"], kept["why"], kept["verdict"]) == ("F1", "small", "stop", "one function", "CONFIRMED")
    assert read_json(bundle / "rejected-flaws.json") == [{"fid": "F2", "title": "not a flaw", "reason": "the change could fix it itself"}]


def test_a_verifier_that_finds_no_known_flaw_overrides_the_reviewers_match(bundle, github):
    other = github.add("something else")
    flaws_through_tally(bundle, [flaw(known=other)], [
        {"fid": "F1", "verdict": "CONFIRMED", "known": None, "reason": "a different flaw"},
    ])

    assert read_json(bundle / "flaws.json")[0]["known"] is None
    summary = finish_with_flaws(bundle, read_json(bundle / "flaws.json"))
    assert [(f["id"], f["issue"], f["new"], f["status"]) for f in summary["flaws"]] == [("F1", None, True, "undecided")]
    assert github.writes() == []


def test_tally_waits_for_the_flaw_votes(bundle):
    write_json(bundle / "flaws-design.json", [flaw()])
    findings.collect(str(bundle))

    with pytest.raises(SystemExit, match="verify/batch.json: flaw F1"):
        findings.tally(str(bundle))
    assert findings.tally(str(bundle), allow_missing=True)["rejected_flaws"] == 1


def test_known_snapshots_the_flaws_a_reviewer_may_match(bundle, github):
    deferred = github.add("deferred one")
    github.comment(deferred, '<!-- ace-review workaround {"repo": "ace", "branch": "jd/a", "round": 1} -->\nhere')
    github.comment(deferred, "a plain comment is no workaround")
    addressing = github.add("addressing one", assignees=["me"])
    wrong = github.add("wrong one", state="CLOSED", reason="NOT_PLANNED")
    github.add("fixed one", state="CLOSED", reason="COMPLETED")
    github.add("not a flaw", labels=("bug",))

    assert findings.known(str(bundle)) == {"known": 3}

    assert [(f["id"], f["status"], f["workarounds"]) for f in read_json(bundle / "known-flaws.json")] == [
        (deferred, "deferred", 1), (addressing, "addressing", 0), (wrong, "wrong", 0),
    ]


def test_known_lets_the_review_go_on_without_github(bundle, github):
    github.down = True

    assert findings.known(str(bundle)) == {"known": 0, "error": "gh issue list failed: could not connect"}
    assert read_json(bundle / "known-flaws.json") == []


def test_finish_leaves_a_new_flaw_undecided_and_off_github(bundle, github):
    summary = finish_with_flaws(bundle, [flaw()])

    assert summary["verdict_floor"] == "ship" and summary["flaws_error"] is None
    assert summary["flaws"] == [{"id": "F1", "issue": None, "url": None, "title": "the tree has no hook for X", "new": True,
                                 "status": "undecided", "fix_size": "large", "recommendation": "keep going", "why": "contained",
                                 "workarounds": 1, "posted": False}]
    assert github.writes() == []


def test_finish_comments_once_per_branch_on_a_known_flaw(bundle, tmp_path, github):
    number = github.add("no hook for X")
    finish_with_flaws(bundle, [flaw(known=number)])
    [comment] = github.workarounds(number)
    assert comment.startswith('<!-- ace-review workaround {"repo": "ace", "branch": "mw/topic", "round": 2} -->\n')
    assert "`saq/y.py:7`:\n\npolls the root for X" in comment

    # the branch's next round edits its comment; another branch adds its own
    finish_with_flaws(later_round(bundle, tmp_path), [flaw(known=f"#{number}", workaround="polls again", line=9)])
    other = tmp_path / "other" / "round-1"
    write_json(other / "target.json", {**read_json(bundle / "target.json"), "round": 1, "branch": "jd/other"})
    summary = finish_with_flaws(other, [flaw(known=number, title="worded differently")])

    assert [(f["issue"], f["new"], f["status"], f["workarounds"], f["posted"]) for f in summary["flaws"]] == [
        (number, False, "deferred", 2, True)]
    assert summary["flaws"][0]["title"] == "no hook for X"
    mine, theirs = github.workarounds(number)
    assert '"branch": "mw/topic", "round": 3' in mine and "polls again" in mine
    assert '"branch": "jd/other"' in theirs


def test_two_flaws_of_a_round_on_one_issue_make_one_comment(bundle, github):
    number = github.add("no hook for X")

    summary = finish_with_flaws(bundle, [flaw(known=number), flaw("F2", known=number, title="same thing")])

    assert len(github.workarounds(number)) == 1
    assert [f["workarounds"] for f in summary["flaws"]] == [1, 1]


def test_a_review_of_another_repo_posts_nothing_until_answered(bundle, github):
    number = github.add("no hook for X")
    write_json(bundle / "target.json", {**read_json(bundle / "target.json"), "kind": "integration", "repo": "/opt/ace/integrations/acme"})

    summary = finish_with_flaws(bundle, [flaw(known=number)])

    assert [(f["issue"], f["posted"]) for f in summary["flaws"]] == [(number, False)]
    assert github.writes() == []
    findings.answer_flaw("F1", "defer", str(bundle))
    assert '"repo": "acme"' in github.workarounds(number)[0]


@pytest.mark.parametrize("delta, left", [(False, 0), (True, 1)])
def test_a_full_round_deletes_the_workarounds_the_branch_no_longer_has(bundle, tmp_path, github, delta, left):
    number = github.add("no hook for X")
    finish_with_flaws(bundle, [flaw(known=number)])

    finish_with_flaws(later_round(bundle, tmp_path, delta=delta), [])

    # a full round looked at all of the change; a delta round only at what changed since
    assert len(github.workarounds(number)) == left


def test_rerunning_finish_replaces_what_the_round_posted(bundle, github):
    kept, dropped = github.add("kept"), github.add("dropped")
    write_json(bundle / "target.json", {**read_json(bundle / "target.json"), "delta": True})
    finish_with_flaws(bundle, [flaw(known=kept), flaw("F2", known=dropped)])

    finish_with_flaws(bundle, [flaw(known=kept)])

    assert (len(github.workarounds(kept)), len(github.workarounds(dropped))) == (1, 0)


def test_finish_without_github_reports_why_and_posts_nothing(bundle, github):
    number = github.add("no hook for X")
    github.down = True

    summary = finish_with_flaws(bundle, [flaw(known=number), flaw("F2")])

    assert summary["flaws_error"] == "gh issue list failed: could not connect"
    assert [(f["issue"], f["status"], f["posted"]) for f in summary["flaws"]] == [(number, "unknown", False), (None, "unknown", False)]


def test_finish_with_no_flaws_and_nothing_posted_before_leaves_github_alone(bundle, github):
    github.down = True

    assert finish_with_flaws(bundle, [])["flaws_error"] is None


def test_answering_a_new_flaw_files_its_issue_once(bundle, github):
    finish_with_flaws(bundle, [flaw()])

    assert findings.answer_flaw("F1", "defer", str(bundle))["status"] == "deferred"
    [number] = github.issues
    issue = github.issues[number]
    assert (issue["title"], issue["labels"], issue["state"], issue["assignees"]) == ("the tree has no hook for X", ["design flaw"], "OPEN", [])
    assert issue["body"].startswith("saq/analysis/root.py has no event for X\n\n**Real fix** (large): add the hook")
    assert len(github.workarounds(number)) == 1
    assert read_json(bundle / "filed-flaws.json") == {"F1": number}

    # changing the answer, and rerunning finish, work on the same issue, though GitHub doesn't list it yet
    assert number in github.unlisted
    assert findings.answer_flaw("F1", "address", str(bundle), note="small after all") == {
        "id": "F1", "issue": number, "url": issue["url"], "status": "addressing"}
    summary = finish_with_flaws(bundle, [flaw()])
    assert list(github.issues) == [number]
    assert (issue["assignees"], len(github.workarounds(number))) == (["me"], 1)
    assert issue["comments"][-1]["body"] == "addressing: small after all\n"
    assert [(f["issue"], f["new"], f["status"], f["posted"]) for f in summary["flaws"]] == [(number, False, "addressing", True)]


@pytest.mark.parametrize("answer, closed", [("wrong", False), ("fixed", False), ("defer", True), ("address", True)])
def test_an_answer_sets_the_issue_state_that_is_the_flaws_status(github, answer, closed):
    number = github.add("no hook", state="CLOSED" if closed else "OPEN", reason="NOT_PLANNED" if closed else "",
                        assignees=[] if answer == "address" else ["me"])

    findings.answer_flaw(str(number), answer)

    assert findings.flaw_status(github.issues[number]) == findings.FLAW_ANSWERS[answer]


def test_answer_flaw_refuses_what_it_cannot_record(bundle, github):
    finish_with_flaws(bundle, [flaw()])
    bug = github.add("a bug", labels=("bug",))

    with pytest.raises(SystemExit, match="one of defer, address, wrong, fixed"):
        findings.answer_flaw("F1", "later", str(bundle))
    with pytest.raises(SystemExit, match="no design flaw F9"):
        findings.answer_flaw("F9", "defer", str(bundle))
    with pytest.raises(SystemExit, match="needs --bundle"):
        findings.answer_flaw("F1", "defer")
    with pytest.raises(SystemExit, match=f"issue #{bug} is not labeled 'design flaw'"):
        findings.answer_flaw(f"#{bug}", "wrong")
    assert github.writes() == []


def test_the_flaw_list_puts_open_flaws_with_the_most_workarounds_first(github, monkeypatch, capsys):
    numbers = {}
    for name, state, reason, assignees, workarounds in (("a", "OPEN", "", [], 1), ("b", "OPEN", "", [], 3), ("d", "OPEN", "", ["me"], 1),
                                                        ("e", "CLOSED", "NOT_PLANNED", [], 1)):
        numbers[name] = github.add(name, state=state, reason=reason, assignees=assignees)
        for n in range(workarounds):
            github.comment(numbers[name], f'<!-- ace-review workaround {{"repo": "ace", "branch": "b{n}", "round": 1}} -->\nx')

    assert [e["id"] for e in findings.list_flaws()] == [numbers[n] for n in "dba"]
    assert findings.list_flaws()[1]["workarounds"][0] == {"repo": "ace", "branch": "b0", "round": 1,
                                                          "url": github.issues[numbers["b"]]["comments"][0]["url"]}
    monkeypatch.setattr(sys, "argv", ["findings.py", "flaws", "--all"])
    findings.main()
    assert [e["id"] for e in json.loads(capsys.readouterr().out)] == [numbers[n] for n in "dbae"]


def test_the_command_line_says_why_github_failed(github, monkeypatch):
    github.down = True
    monkeypatch.setattr(sys, "argv", ["findings.py", "flaws"])

    with pytest.raises(SystemExit, match="could not connect"):
        findings.main()


@pytest.mark.parametrize("outcome, message", [
    (subprocess.CompletedProcess([], 1, "", "HTTP 401\n"), "gh issue list failed: HTTP 401"),
    (subprocess.TimeoutExpired("gh", 60), "gh issue list: Command 'gh' timed out"),
    (FileNotFoundError("gh"), "gh issue list: gh"),
])
def test_gh_turns_every_failure_into_one_error(monkeypatch, outcome, message):
    def run(*args, **kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    monkeypatch.setattr(findings.subprocess, "run", run)

    with pytest.raises(RuntimeError, match=message):
        REAL_GH("issue", "list")


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
