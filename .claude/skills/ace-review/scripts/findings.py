#!/usr/bin/env python3
"""Bookkeeping for /ace-review's verify step and for rounds: votes, ids and statuses are
counted here, not judged.

    findings.py collect BUNDLE             number the findings, print the verification plan
    findings.py tally BUNDLE [--allow-missing]
                                           count the votes into survivors.json and rejected.json
    findings.py finish BUNDLE              number ranked.json into verified.json, write summary.json
    findings.py answer BUNDLE ID ANSWER [--note TEXT]
                                           record the user's answer to a finding
    findings.py flaw ID ANSWER [--note TEXT] [--dir FLAW_DIR]
                                           record the user's decision on a design flaw
    findings.py flaws [--all] [--dir FLAW_DIR]
                                           the design flaws, open ones first
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
finish also records each flaw in flaws.json in core's docs/design-flaws/ (target.json's
flaw_dir), one <id>.yaml per flaw, so the flaws are shared through the repo: a flaw the
verifier matched to a file there ("known": "<id>") adds this branch as one more
workaround of it, any other becomes a new file named after its title, undecided. One
branch counts once per flaw: a rerun of finish replaces what its round recorded, a full
round everything the branch recorded before, and a delta round the branch's earlier
workaround of each flaw it finds again. A flaw never changes the
verdict floor.

ANSWER is fixed, wrong, intentional or "didn't matter"; for ID "rules", the rule changes
in target.json, it is accepted or rejected. A flaw's answer is defer (keep going, fix it
later), address (stop and fix it first), wrong, or fixed, which removes its file.

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

import yaml

SEVERITIES = ("blocker", "fix-first", "nit")
DIMENSIONS = ("uptime", "logging", "tests", "performance", "correctness", "design")
ORIGINS = ("new", "pre-existing")
ANSWERS = ("fixed", "wrong", "intentional", "didn't matter")
RULE_ANSWERS = ("accepted", "rejected")
FLAW_SIZES = ("small", "medium", "large")
FLAW_RECOMMENDATIONS = ("stop", "keep going")
# fixed has no status: a fixed flaw's file is removed, and git history keeps it
FLAW_ANSWERS = {"defer": "deferred", "address": "addressing", "wrong": "wrong", "fixed": None}
OPEN_FLAWS = ("undecided", "addressing", "deferred")
BLOCKER_VOTES = 3
SAQ_HOME = os.environ.get("SAQ_HOME", "/opt/ace")
STATE_DIR = os.path.join(SAQ_HOME, "local", "ace-review")
FLAW_DIR = os.path.join(SAQ_HOME, "docs", "design-flaws")
FLAW_HEADER = "# A flaw in ACE's design that a change had to work around; see README.md in this directory.\n"
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


def flaw_slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60].rstrip("-") or "flaw"


def load_flaws(directory: str) -> dict[str, dict]:
    flaws = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.yaml"))):
        with open(path) as fp:
            flaws[os.path.basename(path)[:-len(".yaml")]] = yaml.safe_load(fp)
    return flaws


def save_flaw(directory: str, fid: str, entry: dict) -> None:
    # written whole and renamed, so a review that dies mid-write leaves the old file
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{fid}.yaml")
    with open(path + ".tmp", "w") as fp:
        fp.write(FLAW_HEADER)
        yaml.safe_dump(entry, fp, sort_keys=False, allow_unicode=True, width=100)
    os.replace(path + ".tmp", path)


def record_flaws(target: dict, flaws: list[dict]) -> list[dict]:
    """Add this round's flaws to docs/design-flaws/ and return how each one stands there."""
    directory = target.get("flaw_dir") or FLAW_DIR
    entries = load_flaws(directory)
    repo, branch, number = os.path.basename(target.get("repo", "")), target.get("branch", ""), target.get("round", 1)
    # a rerun of finish replaces what its round recorded. A full round looked at the whole
    # change, so it also replaces what the branch's earlier rounds recorded; a delta round
    # never saw the code they found their flaws in
    def replaced(w: dict) -> bool:
        return (w["repo"], w["branch"]) == (repo, branch) and (w["round"] == number or not target.get("delta"))

    changed = set()
    for fid, entry in entries.items():
        kept = [w for w in entry["workarounds"] if not replaced(w)]
        if len(kept) != len(entry["workarounds"]):
            entry["workarounds"] = kept
            changed.add(fid)
    today = datetime.date.today().isoformat()

    recorded = []
    for flaw in flaws:
        fid = flaw["known"] if flaw.get("known") in entries else flaw_slug(flaw["title"])
        entry = entries.get(fid)
        new = entry is None or (entry["status"] == "undecided" and not entry["workarounds"])
        if entry is None:
            entry = entries[fid] = {"title": flaw["title"], "status": "undecided", "area": flaw.get("area", ""),
                                    "fix_size": flaw["fix_size"], "flaw": flaw["flaw"], "fix": flaw.get("fix", ""),
                                    "first_seen": today, "workarounds": []}
        entry["workarounds"] = [w for w in entry["workarounds"] if (w["repo"], w["branch"]) != (repo, branch)]
        entry["workarounds"].append({"repo": repo, "branch": branch, "round": number, "file": flaw["file"],
                                     "line": flaw.get("line"), "what": flaw["workaround"], "seen": today})
        changed.add(fid)
        recorded.append({"id": fid, "title": entry["title"], "new": new, "status": entry["status"], "fix_size": flaw["fix_size"],
                         "recommendation": flaw["recommendation"], "why": flaw.get("why", ""),
                         "workarounds": len(entry["workarounds"]), "path": os.path.join(directory, f"{fid}.yaml")})
    for fid in sorted(changed):
        if entries[fid]["status"] == "undecided" and not entries[fid]["workarounds"]:
            # only this round's earlier run, or the branch's earlier rounds, had found it
            os.remove(os.path.join(directory, f"{fid}.yaml"))
        else:
            save_flaw(directory, fid, entries[fid])
    return recorded


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
        "flaws": record_flaws(target, load(os.path.join(bundle, "flaws.json"), [])),
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


def answer_flaw(directory: str, fid: str, value: str, note: str | None = None) -> dict:
    entry = load_flaws(directory).get(fid)
    if entry is None:
        sys.exit(f"no design flaw {fid} in {directory}")
    if value not in FLAW_ANSWERS:
        sys.exit(f"the answer for a design flaw is one of {', '.join(FLAW_ANSWERS)}")
    if FLAW_ANSWERS[value] is None:
        os.remove(os.path.join(directory, f"{fid}.yaml"))
        return {"id": fid, "status": "fixed", "removed": True}
    entry["status"] = FLAW_ANSWERS[value]
    entry["decided"] = datetime.date.today().isoformat()
    if note:
        entry["note"] = note
    save_flaw(directory, fid, entry)
    return {"id": fid, **entry}


def list_flaws(directory: str, everything: bool = False) -> list[dict]:
    """Open flaws, the ones with the most workarounds first: each workaround is more to undo later."""
    order = {status: n for n, status in enumerate(OPEN_FLAWS)}
    shown = [{"id": fid, **e} for fid, e in load_flaws(directory).items() if everything or e["status"] in order]
    return sorted(shown, key=lambda e: (order.get(e["status"], len(order)), -len(e["workarounds"]), e["id"]))


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
    command = sub.add_parser("flaw")
    command.add_argument("id")
    command.add_argument("answer", choices=sorted(FLAW_ANSWERS))
    command.add_argument("--note")
    command.add_argument("--dir", default=FLAW_DIR)
    command = sub.add_parser("flaws")
    command.add_argument("--all", action="store_true", help="include the flaws marked wrong")
    command.add_argument("--dir", default=FLAW_DIR)
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
    elif args.command == "flaw":
        result = answer_flaw(args.dir, args.id, args.answer, args.note)
    elif args.command == "flaws":
        result = list_flaws(args.dir, args.all)
    else:
        result = answer(args.bundle, args.id, args.answer, args.note)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
