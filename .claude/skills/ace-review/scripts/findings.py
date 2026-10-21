#!/usr/bin/env python3
"""Bookkeeping for /ace-review's verify step and for rounds: votes, ids and statuses are
counted here, not judged.

    findings.py collect BUNDLE             number the findings, print the verification plan
    findings.py tally BUNDLE [--allow-missing]
                                           count the votes into survivors.json and rejected.json
    findings.py finish BUNDLE              number ranked.json into verified.json, write summary.json
    findings.py answer BUNDLE ID ANSWER [--note TEXT]
                                           record the user's answer to a finding
    findings.py stats [STATE_DIR] [--since YYYY-MM-DD]
                                           what became of the findings of every finished round

collect reads findings-*.json into candidates.json and plan.json. A new blocker gets
BLOCKER_VOTES verifiers and stays a blocker only if a majority confirms it at that
severity; a new fix-first gets one verifier; nits and pre-existing findings share the
batch verifier, which also rechecks each open finding of earlier rounds (previous.json).
Verifiers write verify/<cid>-<k>.json, and the batch verifier verify/batch.json.

tally writes survivors.json, rejected.json and carried.json (the earlier findings
rechecked: fixed or open). It stops at missing votes unless --allow-missing, which
counts only the votes cast.

finish reads ranked.json: the survivors after duplicates are merged, each one that is
an earlier finding again marked "repeats": "<id>". It drops the repeats, numbers the rest
R<round>-<n> into verified.json, and writes summary.json, whose verdict_floor counts
earlier findings still open like new ones. summary.json marks the round finished.

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
BLOCKER_VOTES = 3
STATE_DIR = os.path.join(os.environ.get("SAQ_HOME", "/opt/ace"), "local", "ace-review")
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


def collect(bundle: str) -> dict:
    candidates, bad = [], []
    for path in sorted(glob.glob(os.path.join(bundle, "findings-*.json"))):
        for index, finding in enumerate(load(path, [])):
            if issues := problems(finding):
                bad.append(f"{os.path.basename(path)}[{index}]: {', '.join(issues)}")
            candidates.append({**finding, "cid": f"C{len(candidates) + 1}", "source": os.path.basename(path)})
    if bad:
        sys.exit("malformed findings, fix them and collect again:\n" + "\n".join(bad))

    plan = {"single": [], "batch": [], "carry": [f["id"] for f in load(os.path.join(bundle, "previous.json"), []) if f["status"] == "open"]}
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
    batch = load(os.path.join(bundle, "verify", "batch.json"), {}) if plan["batch"] or plan["carry"] else {}
    for vote in batch.get("candidates", []):
        votes.setdefault(vote.get("cid"), []).append(vote)
    carried = [c for c in batch.get("carried", []) if c.get("status") in ("fixed", "open")]
    missing += [f"verify/batch.json: {cid}" for cid in plan["batch"] if cid not in votes]
    missing += [f"verify/batch.json: carried {fid}" for fid in plan["carry"] if fid not in {c["id"] for c in carried}]
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
    dump(os.path.join(bundle, "survivors.json"), survivors)
    dump(os.path.join(bundle, "rejected.json"), rejected)
    dump(os.path.join(bundle, "carried.json"), carried)
    return {"survivors": len(survivors), "rejected": len(rejected), "carried": len(carried), "missing": missing}


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
    for name in ("collect", "tally", "finish", "answer"):
        command = sub.add_parser(name)
        command.add_argument("bundle")
    sub.choices["tally"].add_argument("--allow-missing", action="store_true")
    sub.choices["answer"].add_argument("id")
    sub.choices["answer"].add_argument("answer")
    sub.choices["answer"].add_argument("--note")
    command = sub.add_parser("stats")
    command.add_argument("state", nargs="?", default=STATE_DIR)
    command.add_argument("--since", help="only rounds finished on or after this date, YYYY-MM-DD")
    args = parser.parse_args()

    if args.command == "collect":
        result = collect(args.bundle)
    elif args.command == "tally":
        result = tally(args.bundle, args.allow_missing)
    elif args.command == "finish":
        result = finish(args.bundle)
    elif args.command == "stats":
        result = stats(args.state, args.since)
    else:
        result = answer(args.bundle, args.id, args.answer, args.note)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
