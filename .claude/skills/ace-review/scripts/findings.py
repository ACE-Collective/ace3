#!/usr/bin/env python3
"""Bookkeeping for /ace-review's verify step and for rounds: votes, ids and statuses are
counted here, not judged.

    findings.py collect BUNDLE             number the findings, print the verification plan
    findings.py tally BUNDLE [--allow-missing]
                                           count the votes into survivors.json and rejected.json
    findings.py finish BUNDLE              number ranked.json into verified.json, write summary.json
    findings.py answer BUNDLE ID ANSWER [--note TEXT]
                                           record the user's answer to a finding
    findings.py known BUNDLE               snapshot the design flaw issues into known-flaws.json
    findings.py file BUNDLE FID            file a new design flaw as a GitHub issue
    findings.py stats [STATE_DIR] [--since YYYY-MM-DD]
                                           what became of the findings of every finished round

collect reads findings-*.json into candidates.json and plan.json. A new blocker gets
BLOCKER_VOTES verifiers and stays a blocker only if a majority confirms it at that
severity; a new fix-first gets one verifier; nits and pre-existing findings share the
batch verifier, which also rechecks each open finding of earlier rounds (previous.json).
Verifiers write verify/<cid>-<k>.json, and the batch verifier verify/batch.json.
collect also numbers the design flaws the reviewers found (flaws-*.json) F<n> into
flaw-candidates.json; the batch verifier judges those too.

tally writes survivors.json, rejected.json and carried.json (the earlier findings
rechecked: fixed or open), and the flaws the batch verifier kept into flaws.json. It stops at missing votes unless --allow-missing, which
counts only the votes cast.

finish reads ranked.json: the survivors after duplicates are merged, each one that is
an earlier finding again marked "repeats": "<id>". It drops the repeats, numbers the rest
R<round>-<n> into verified.json, and writes summary.json, whose verdict_floor counts
earlier findings still open like new ones. summary.json marks the round finished.
The design flaws are GitHub issues labeled "design flaw" in core's repo, whatever repo is
reviewed. known writes the ones a reviewer may match a flaw to (open, or closed as not
planned, which is a flaw found wrong) to known-flaws.json, numbered by issue. finish
lists each flaw of the round in summary.json with its issue, or none for a new flaw, and
never writes to GitHub. A flaw never changes the verdict floor.

file files a new flaw (its F<n> in flaws.json) as an issue, once the user has answered
it: the only write to GitHub the review makes. The issue's body is the flaw, the real
fix and the workaround that ran into it, and the review never changes the issue again;
its state is the user's to keep.

ANSWER is fixed, wrong, intentional or "didn't matter"; for ID "rules", the rule changes
in target.json, it is accepted or rejected.

stats walks STATE_DIR (default $SAQ_HOME/local/ace-review) and gives each new finding one
outcome, the first that applies: the user's answer; "fixed (rechecked)" when a later
round's verifier found it fixed; "lines changed" or "unchanged" by whether the code within
NEARBY lines of it changed between its round and where the branch is now (the branch tip,
or the last round's tree once the branch is gone); "unknown" when there is nothing later
to compare. "lines changed" and "unchanged" are inferred, not confirmed: code also moves
for other reasons. Outcomes are counted overall, by dimension, by severity and by the
mechanical check that led to the finding, next to what the verifiers rejected. --since
counts only rounds finished on or after that date.
"""

import argparse
import collections
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys

SEVERITIES = ("blocker", "fix-first", "nit")
DIMENSIONS = ("uptime", "logging", "tests", "performance", "correctness", "design")
ORIGINS = ("new", "pre-existing")
ANSWERS = ("fixed", "wrong", "intentional", "didn't matter")
RULE_ANSWERS = ("accepted", "rejected")
FLAW_SIZES = ("small", "medium", "large")
FLAW_RECOMMENDATIONS = ("stop", "keep going")
FLAW_LABEL = "design flaw"
GH_TIMEOUT = 60
BLOCKER_VOTES = 3
SAQ_HOME = os.environ.get("SAQ_HOME", "/opt/ace")
STATE_DIR = os.path.join(SAQ_HOME, "local", "ace-review")
ACTED_ON = ("fixed", "fixed (rechecked)", "lines changed")
NEARBY = 2
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? ")


def load(path: str, default=None):
    if not os.path.exists(path):
        return default
    with open(path) as fp:
        return json.load(fp)


def dump(path: str, data) -> None:
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)


def rank(finding: dict) -> tuple:
    return (finding["origin"] != "new", SEVERITIES.index(finding["severity"]), DIMENSIONS.index(finding["dimension"]))


def problems(finding: dict) -> list[str]:
    found = [f"{field}={finding.get(field)!r}" for field, allowed in
             (("severity", SEVERITIES), ("origin", ORIGINS), ("dimension", DIMENSIONS)) if finding.get(field) not in allowed]
    found += [f"no {field}" for field in ("file", "title", "evidence") if not finding.get(field)]
    return found


def flaw_problems(flaw: dict) -> list[str]:
    found = [f"{field}={flaw.get(field)!r}" for field, allowed in
             (("fix_size", FLAW_SIZES), ("recommendation", FLAW_RECOMMENDATIONS)) if flaw.get(field) not in allowed]
    return found + [f"no {field}" for field in ("title", "flaw", "workaround", "file") if not flaw.get(field)]


def collect(bundle: str) -> dict:
    candidates, flaws, bad = [], [], []
    for path in sorted(glob.glob(os.path.join(bundle, "flaws-*.json"))):
        for index, flaw in enumerate(load(path, [])):
            if issues := flaw_problems(flaw):
                bad.append(f"{os.path.basename(path)}[{index}]: {', '.join(issues)}")
            flaws.append({**flaw, "fid": f"F{len(flaws) + 1}", "source": os.path.basename(path)})
    for path in sorted(glob.glob(os.path.join(bundle, "findings-*.json"))):
        for index, finding in enumerate(load(path, [])):
            if issues := problems(finding):
                bad.append(f"{os.path.basename(path)}[{index}]: {', '.join(issues)}")
            candidates.append({**finding, "cid": f"C{len(candidates) + 1}", "source": os.path.basename(path)})
    if bad:
        sys.exit("malformed findings, fix them and collect again:\n" + "\n".join(bad))

    plan = {"single": [], "batch": [], "carry": [f["id"] for f in load(os.path.join(bundle, "previous.json"), []) if f["status"] == "open"],
            "flaws": [f["fid"] for f in flaws]}
    for candidate in candidates:
        if candidate["origin"] == "new" and candidate["severity"] in ("blocker", "fix-first"):
            votes = BLOCKER_VOTES if candidate["severity"] == "blocker" else 1
            plan["single"].append({"cid": candidate["cid"], "votes": votes})
        else:
            plan["batch"].append(candidate["cid"])
    # votes from an earlier collect belong to other candidate numbers
    shutil.rmtree(os.path.join(bundle, "verify"), ignore_errors=True)
    os.makedirs(os.path.join(bundle, "verify"))
    dump(os.path.join(bundle, "candidates.json"), candidates)
    dump(os.path.join(bundle, "flaw-candidates.json"), flaws)
    dump(os.path.join(bundle, "plan.json"), plan)
    return plan


def decide(candidate: dict, votes: list[dict], expected: int) -> dict:
    """The candidate as the votes leave it, with verdict REJECTED when too few found it real."""
    real = [v for v in votes if v.get("verdict") in ("CONFIRMED", "PLAUSIBLE")]
    confirmed = [v for v in real if v["verdict"] == "CONFIRMED"]
    need = expected // 2 + 1 if len(votes) == expected else len(votes) // 2 + 1
    if not votes or len(real) < need:
        reasons = "; ".join(v.get("reason", "") for v in votes if v not in real) or "no verifier vote"
        return {**candidate, "verdict": "REJECTED", "reason": reasons}

    # the most severe level that a majority supports: a vote for X supports X and below
    severity = candidate["severity"]
    proposed = [SEVERITIES.index(v.get("severity", severity)) for v in real]
    for level in range(len(SEVERITIES)):
        if sum(p <= level for p in proposed) >= need:
            severity = SEVERITIES[level]
            break
    origins = [v.get("origin", candidate["origin"]) for v in real]
    origin = max(ORIGINS, key=lambda o: (origins.count(o), o == candidate["origin"]))
    verdict = "CONFIRMED" if len(confirmed) >= need else "PLAUSIBLE"
    notes = [v["note"] for v in real if v.get("note")]
    # an unconfirmed mechanism tops out at fix-first, and a blocker needs a majority of
    # BLOCKER_VOTES behind it however many votes were cast
    majority = BLOCKER_VOTES // 2 + 1
    for_blocker = proposed.count(0)
    if severity == "blocker" and verdict == "PLAUSIBLE":
        severity = "fix-first"
    elif severity == "blocker" and for_blocker < majority:
        notes.append(f"{for_blocker} verifier(s) argued for blocker; a blocker needs {majority} of {BLOCKER_VOTES}")
        severity = "fix-first"
    return {**candidate, "severity": severity, "origin": origin, "verdict": verdict,
            "votes": f"{len(confirmed)} of {len(votes)} confirmed", "note": "; ".join(notes)}


def tally(bundle: str, allow_missing: bool = False) -> dict:
    candidates = load(os.path.join(bundle, "candidates.json"))
    plan = load(os.path.join(bundle, "plan.json"))
    if candidates is None or plan is None:
        sys.exit(f"run collect first: no candidates.json/plan.json in {bundle}")
    votes: dict[str, list[dict]] = {}
    expected = {item["cid"]: item["votes"] for item in plan["single"]}
    expected.update({cid: 1 for cid in plan["batch"]})
    missing = []
    for item in plan["single"]:
        for k in range(1, item["votes"] + 1):
            vote = load(os.path.join(bundle, "verify", f"{item['cid']}-{k}.json"))
            if vote is None:
                missing.append(f"verify/{item['cid']}-{k}.json")
            else:
                votes.setdefault(item["cid"], []).append(vote)
    flaw_plan = plan.get("flaws", [])
    batch = load(os.path.join(bundle, "verify", "batch.json"), {}) if plan["batch"] or plan["carry"] or flaw_plan else {}
    for vote in batch.get("candidates", []):
        votes.setdefault(vote.get("cid"), []).append(vote)
    carried = [c for c in batch.get("carried", []) if c.get("status") in ("fixed", "open")]
    missing += [f"verify/batch.json: {cid}" for cid in plan["batch"] if cid not in votes]
    missing += [f"verify/batch.json: carried {fid}" for fid in plan["carry"] if fid not in {c["id"] for c in carried}]
    flaw_votes = {v.get("fid"): v for v in batch.get("flaws", [])}
    missing += [f"verify/batch.json: flaw {fid}" for fid in flaw_plan if fid not in flaw_votes]
    if missing and not allow_missing:
        sys.exit("missing votes, relaunch these verifiers (or pass --allow-missing):\n" + "\n".join(missing))

    survivors, rejected = [], []
    for candidate in candidates:
        result = decide(candidate, votes.get(candidate["cid"], []), expected[candidate["cid"]])
        if result["verdict"] == "REJECTED":
            rejected.append({k: result.get(k) for k in ("cid", "dimension", "severity", "file", "line", "title", "reason")})
        else:
            survivors.append(result)
    survivors.sort(key=rank)

    kept_flaws, rejected_flaws = [], []
    for flaw in load(os.path.join(bundle, "flaw-candidates.json"), []):
        result = flaw_votes.get(flaw["fid"], {})
        if result.get("verdict") not in ("CONFIRMED", "PLAUSIBLE"):
            rejected_flaws.append({"fid": flaw["fid"], "title": flaw["title"], "reason": result.get("reason", "no verifier vote")})
            continue
        # the verifier's judgment of the fix and of whether to stop wins over the reviewer's,
        # and so does its known, even null: that is the verifier saying it is no known flaw
        kept_flaws.append({**flaw, **{k: result[k] for k in ("fix_size", "recommendation", "why") if result.get(k)},
                           **({"known": result["known"]} if "known" in result else {}),
                           "verdict": result["verdict"], "reason": result.get("reason", "")})
    dump(os.path.join(bundle, "survivors.json"), survivors)
    dump(os.path.join(bundle, "rejected.json"), rejected)
    dump(os.path.join(bundle, "carried.json"), carried)
    dump(os.path.join(bundle, "flaws.json"), kept_flaws)
    dump(os.path.join(bundle, "rejected-flaws.json"), rejected_flaws)
    return {"survivors": len(survivors), "rejected": len(rejected), "carried": len(carried),
            "flaws": len(kept_flaws), "rejected_flaws": len(rejected_flaws), "missing": missing}


def gh(*args: str, stdin: str | None = None) -> str:
    """gh run in core, whose GitHub repo holds the design flaws whatever repo is reviewed."""
    try:
        result = subprocess.run(["gh", *args], cwd=SAQ_HOME, input=stdin, capture_output=True, text=True, timeout=GH_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"gh {' '.join(args)}: {e}") from e
    if result.returncode:
        raise RuntimeError(f"gh {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def known(bundle: str) -> dict:
    """Write the flaws a reviewer may match one to; a review goes on without them if GitHub is down."""
    path, error_path = os.path.join(bundle, "known-flaws.json"), os.path.join(bundle, "known-flaws-error.txt")
    try:
        issues = json.loads(gh("issue", "list", "--label", FLAW_LABEL, "--state", "all", "--limit", "1000",
                               "--json", "number,title,body,state,stateReason,url"))
    except RuntimeError as e:
        dump(path, [])
        # kept, so that file refuses a flaw the reviewers could not match to its issue
        with open(error_path, "w") as fp:
            fp.write(f"{e}\n")
        return {"known": 0, "error": str(e)}
    if os.path.exists(error_path):
        os.remove(error_path)
    # a flaw closed as not planned was found wrong, and the reviewers skip it; a fixed one is gone
    entries = [{"id": i["number"], "title": i["title"], "status": "open" if i["state"] == "OPEN" else "wrong",
                "url": i["url"], "body": i["body"]}
               for i in sorted(issues, key=lambda i: i["number"]) if i["state"] == "OPEN" or i.get("stateReason") == "NOT_PLANNED"]
    dump(path, entries)
    return {"known": len(entries)}


def issue_number(value) -> int | None:
    match = re.fullmatch(r"#?(\d+)", str(value or "").strip())
    return int(match.group(1)) if match else None


def flaw_issues(bundle: str, flaws: list[dict]) -> list[dict]:
    """How each of the round's flaws stands: the issue it was matched to or filed as, or none if new."""
    issues = {f["id"]: f for f in load(os.path.join(bundle, "known-flaws.json"), [])}
    filed = load(os.path.join(bundle, "filed-flaws.json"), {})
    recorded = []
    for flaw in flaws:
        # a known id with no issue behind it is a new flaw
        issue = filed.get(flaw["fid"]) or issues.get(issue_number(flaw.get("known")), {})
        recorded.append({"id": flaw["fid"], "issue": issue.get("id"), "url": issue.get("url"), "title": issue.get("title", flaw["title"]),
                         "new": not issue, "status": issue.get("status", "undecided"), "fix_size": flaw["fix_size"],
                         "recommendation": flaw["recommendation"], "why": flaw.get("why", "")})
    return recorded


def issue_body(target: dict, flaw: dict) -> str:
    # the repo by name: the checkout's path is different on every machine
    repo, branch = os.path.basename(target.get("repo", "")), target.get("branch", "")
    where = f"{flaw['file']}:{flaw['line']}" if flaw.get("line") else flaw["file"]
    return (f"{flaw['flaw']}\n\n**Real fix** ({flaw['fix_size']}): {flaw.get('fix') or 'not sketched yet'}\n\n"
            f"**Area:** {flaw.get('area') or 'unknown'}\n\n"
            f"**Worked around** in `{repo}` branch `{branch}`, `{where}`:\n\n{flaw['workaround']}\n\n"
            "<sub>Filed by /ace-review.</sub>\n")


def file_flaw(bundle: str, fid: str) -> dict:
    """File a new flaw as an issue. It is the review's only write to GitHub, and the issue is never changed after."""
    flaw = {f["fid"]: f for f in load(os.path.join(bundle, "flaws.json"), [])}.get(fid)
    if flaw is None:
        sys.exit(f"no design flaw {fid} in {bundle}")
    if os.path.exists(error_path := os.path.join(bundle, "known-flaws-error.txt")):
        with open(error_path) as fp:
            sys.exit(f"the reviewers had no known flaws to match {fid} to ({fp.read().strip()}); "
                     "run known again and check it is not one of them before filing it")
    [standing] = flaw_issues(bundle, [flaw])
    if not standing["new"]:
        return {"id": fid, "issue": standing["issue"], "url": standing["url"], "filed": False}
    url = gh("issue", "create", "--label", FLAW_LABEL, "--title", flaw["title"], "--body-file", "-",
             stdin=issue_body(load(os.path.join(bundle, "target.json"), {}), flaw)).strip()
    issue = {"id": issue_number(url.rsplit("/", 1)[1]), "url": url, "title": flaw["title"], "status": "open"}
    path = os.path.join(bundle, "filed-flaws.json")
    dump(path, {**load(path, {}), fid: issue})
    return {"id": fid, "issue": issue["id"], "url": url, "filed": True}


def finish(bundle: str) -> dict:
    target = load(os.path.join(bundle, "target.json"), {})
    ranked = load(os.path.join(bundle, "ranked.json"))
    if ranked is None:
        sys.exit(f"no ranked.json in {bundle}")
    if bad := [f"ranked.json[{i}]: {', '.join(p)}" for i, f in enumerate(ranked) if (p := problems(f))]:
        sys.exit("malformed ranked findings:\n" + "\n".join(bad))
    previous = {f["id"]: f for f in load(os.path.join(bundle, "previous.json"), [])}
    carried = {c["id"]: c["status"] for c in load(os.path.join(bundle, "carried.json"), [])}

    verified, repeats = [], 0
    for finding in ranked:
        if finding.get("repeats") in previous:
            repeats += 1
            continue
        verified.append({**{k: v for k, v in finding.items() if k != "repeats"}, "id": f"R{target.get('round', 1)}-{len(verified) + 1}"})
    still_open = [previous[fid] for fid, status in carried.items() if status == "open" and fid in previous]
    blocking = [f for f in verified if f["origin"] == "new"] + still_open
    severities = {f["severity"] for f in blocking}
    floor = "rework" if "blocker" in severities else "fix-first" if "fix-first" in severities else "ship"
    summary = {
        "round": target.get("round", 1),
        "new": {s: sum(1 for f in verified if f["origin"] == "new" and f["severity"] == s) for s in SEVERITIES},
        "pre_existing": sum(1 for f in verified if f["origin"] == "pre-existing"),
        "still_open": [{"id": f["id"], "severity": f["severity"], "file": f.get("file"), "line": f.get("line"), "title": f["title"]} for f in still_open],
        "fixed": sorted(fid for fid, status in carried.items() if status == "fixed"),
        "not_repeated": repeats,
        "rejected": len(load(os.path.join(bundle, "rejected.json"), [])),
        "verdict_floor": floor,
        "flaws": flaw_issues(bundle, load(os.path.join(bundle, "flaws.json"), [])),
        "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }
    dump(os.path.join(bundle, "verified.json"), verified)
    dump(os.path.join(bundle, "summary.json"), summary)
    return summary


def answer(bundle: str, fid: str, value: str, note: str | None = None) -> dict:
    target = load(os.path.join(bundle, "target.json"), {})
    if fid == "rules":
        if value not in RULE_ANSWERS:
            sys.exit(f"the answer for rules is one of {', '.join(RULE_ANSWERS)}")
        if not target.get("rule_changes_digest"):
            sys.exit("this round has no rule changes to answer")
        entry = {"id": fid, "answer": value, "digest": target["rule_changes_digest"]}
    else:
        known = {f["id"] for name in ("verified.json", "previous.json") for f in load(os.path.join(bundle, name), [])}
        if fid not in known:
            sys.exit(f"no finding {fid} in this round or an earlier one")
        if value not in ANSWERS:
            sys.exit(f"the answer is one of {', '.join(ANSWERS)}")
        entry = {"id": fid, "answer": value}
    if note:
        entry["note"] = note
    path = os.path.join(bundle, "answers.json")
    dump(path, [a for a in load(path, []) if a["id"] != fid] + [entry])
    return entry


def tree_of(repo: str, *revs: str | None) -> str | None:
    """The tree of the first rev that still exists; git gc prunes a round's snapshot in time."""
    for rev in revs:
        if rev:
            result = subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{tree}}"],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
    return None


def touched(repo: str, before: str, after: str, path: str, line) -> bool:
    """Whether going from tree before to tree after changes path within NEARBY lines of line."""
    diff = subprocess.run(["git", "-C", repo, "diff", "--no-ext-diff", "-U0", before, after, "--", path],
                          capture_output=True, text=True, errors="replace").stdout
    hunks = [m for m in map(HUNK.match, diff.splitlines()) if m]
    if not isinstance(line, int) or not hunks:
        return bool(hunks)
    for hunk in hunks:
        start, count = int(hunk.group(1)), int(hunk.group(2) or 1)
        # a count of 0 is a pure insertion after line start
        if start <= line + NEARBY and start + max(count, 1) - 1 >= line - NEARBY:
            return True
    return False


def outcome(finding: dict, answers: dict[str, str], fixed: set[str], repo: str, before: str | None, later: str | None) -> str:
    if finding["id"] in answers:
        return answers[finding["id"]]
    if finding["id"] in fixed:
        return "fixed (rechecked)"
    if not before or not later or before == later:
        return "unknown"
    return "lines changed" if touched(repo, before, later, finding["file"], finding.get("line")) else "unchanged"


def stats(state: str = STATE_DIR, since: str | None = None) -> dict:
    groups: dict[str, dict[str, collections.Counter]] = {"by_dimension": {}, "by_severity": {}, "by_lead": {}}
    totals = collections.Counter()
    counts = collections.Counter()

    def count(group: str, key: str, what: str) -> None:
        groups[group].setdefault(key, collections.Counter())[what] += 1

    for key in sorted(os.listdir(state)) if os.path.isdir(state) else []:
        rounds = []
        for path in glob.glob(os.path.join(state, key, "round-*")):
            match = re.fullmatch(r"round-(\d+)", os.path.basename(path))
            if match and os.path.exists(os.path.join(path, "summary.json")):
                rounds.append((int(match.group(1)), path))
        rounds.sort()
        if not rounds:
            continue
        answers, fixed = {}, set()
        for _, path in rounds:
            answers.update({a["id"]: a["answer"] for a in load(os.path.join(path, "answers.json"), [])})
            for carried in load(os.path.join(path, "carried.json"), []):
                if carried["status"] == "fixed":
                    fixed.add(carried["id"])
                else:
                    fixed.discard(carried["id"])
        last = load(os.path.join(rounds[-1][1], "target.json"), {})
        repo = last.get("repo", "")
        tip = f"refs/heads/{last['branch']}" if last.get("includes_uncommitted") and last.get("branch", "HEAD") != "HEAD" else None
        later = tree_of(repo, tip, last.get("tree"), last.get("head"))

        counted = [path for _, path in rounds if not since or load(os.path.join(path, "summary.json"), {}).get("finished_at", "") >= since]
        counts["reviews"] += bool(counted)
        for path in counted:
            counts["rounds"] += 1
            target = load(os.path.join(path, "target.json"), {})
            before = tree_of(repo, target.get("tree"), target.get("head"))
            leads = {(lead["file"], lead["line"]): lead["check"] for lead in load(os.path.join(path, "leads.json"), [])}
            for rejected in load(os.path.join(path, "rejected.json"), []):
                counts["rejected_by_verifiers"] += 1
                counts["blockers_rejected_by_vote"] += rejected.get("severity") == "blocker"
                count("by_dimension", rejected.get("dimension", "?"), "rejected")
            for finding in load(os.path.join(path, "verified.json"), []):
                if finding["origin"] != "new":
                    counts["pre_existing"] += 1
                    continue
                result = outcome(finding, answers, fixed, repo, before, later)
                totals[result] += 1
                count("by_dimension", finding["dimension"], result)
                count("by_severity", finding["severity"], result)
                if lead := leads.get((finding["file"], finding.get("line"))):
                    count("by_lead", lead, result)

    def summarize(counter: collections.Counter) -> dict:
        known = sum(n for what, n in counter.items() if what not in ("unknown", "rejected"))
        acted = sum(counter[what] for what in ACTED_ON)
        return {**dict(sorted(counter.items())), "acted_on": f"{acted} of {known}" if known else "no known outcomes"}

    return {
        "state_dir": state,
        "since": since,
        **{k: counts[k] for k in ("reviews", "rounds", "pre_existing", "rejected_by_verifiers", "blockers_rejected_by_vote")},
        "new_findings": sum(totals.values()),
        "outcomes": summarize(totals),
        **{group: {k: summarize(c) for k, c in sorted(found.items())} for group, found in groups.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("collect", "tally", "finish", "answer", "known"):
        command = sub.add_parser(name)
        command.add_argument("bundle")
    sub.choices["tally"].add_argument("--allow-missing", action="store_true")
    sub.choices["answer"].add_argument("id")
    sub.choices["answer"].add_argument("answer")
    sub.choices["answer"].add_argument("--note")
    command = sub.add_parser("file")
    command.add_argument("bundle")
    command.add_argument("id")
    command = sub.add_parser("stats")
    command.add_argument("state", nargs="?", default=STATE_DIR)
    command.add_argument("--since", help="only rounds finished on or after this date, YYYY-MM-DD")
    args = parser.parse_args()

    try:
        if args.command == "collect":
            result = collect(args.bundle)
        elif args.command == "tally":
            result = tally(args.bundle, args.allow_missing)
        elif args.command == "finish":
            result = finish(args.bundle)
        elif args.command == "stats":
            result = stats(args.state, args.since)
        elif args.command == "known":
            result = known(args.bundle)
        elif args.command == "file":
            result = file_flaw(args.bundle, args.id)
        else:
            result = answer(args.bundle, args.id, args.answer, args.note)
    except RuntimeError as e:
        # gh failed; its stderr says why, a traceback would not
        sys.exit(str(e))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
