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
    findings.py flaw ID ANSWER [--bundle BUNDLE] [--note TEXT]
                                           record the user's decision on a design flaw
    findings.py flaws [--all]              the design flaws, open ones first
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
planned, which is a flaw found wrong) to known-flaws.json, numbered by issue. Each
workaround is one comment on its issue, one per repo and branch, carrying a marker so
later rounds edit or delete it. The issue's state is the flaw's status: open is
deferred, open and assigned is addressing, closed as not planned is wrong, and closed as
completed is fixed.

finish posts the workaround of each flaw that has an issue ("known": <number>), but only
in a review of core, whose branch goes to that public repo anyway. A full round of core
also deletes the comments of the branch's earlier rounds on flaws it no longer finds, a
delta round only those of the same round (a rerun). A flaw with no issue stays
undecided in the bundle until the user answers it, and so does the workaround of a flaw
found in another repo: the answer files the issue and posts the comment. If GitHub
can't be reached, summary.json says why in flaws_error and nothing is posted. A flaw
never changes the verdict floor.

ANSWER is fixed, wrong, intentional or "didn't matter"; for ID "rules", the rule changes
in target.json, it is accepted or rejected. A flaw's answer is defer (keep going, fix it
later), address (stop and fix it first), wrong, or fixed; its ID is an issue number, or
the F<n> of a flaw in --bundle's flaws.json.

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
FLAW_ANSWERS = {"defer": "deferred", "address": "addressing", "wrong": "wrong", "fixed": "fixed"}
OPEN_FLAWS = ("addressing", "deferred")
FLAW_LABEL = "design flaw"
FLAW_FIELDS = "number,title,body,state,stateReason,assignees,comments,url"
WORKAROUND = re.compile(r"^<!-- ace-review workaround (\{.*?\}) -->")
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
        raise RuntimeError(f"gh {' '.join(args[:2])}: {e}") from e
    if result.returncode:
        raise RuntimeError(f"gh {' '.join(args[:2])} failed: {result.stderr.strip()}")
    return result.stdout


def flaw_status(issue: dict) -> str:
    if issue["state"] == "OPEN":
        return "addressing" if issue["assignees"] else "deferred"
    return "wrong" if issue.get("stateReason") == "NOT_PLANNED" else "fixed"


def flaw_entry(issue: dict) -> dict:
    workarounds = []
    for comment in issue["comments"]:
        if match := WORKAROUND.match(comment["body"]):
            # the url ends in #issuecomment-<id>, the id the REST API edits it by
            workarounds.append({**json.loads(match.group(1)), "comment": int(comment["url"].rsplit("-", 1)[1]), "url": comment["url"]})
    return {"title": issue["title"], "body": issue["body"], "status": flaw_status(issue), "url": issue["url"], "workarounds": workarounds}


def fetch_flaws() -> dict[int, dict]:
    issues = json.loads(gh("issue", "list", "--label", FLAW_LABEL, "--state", "all", "--limit", "1000", "--json", FLAW_FIELDS))
    return {issue["number"]: flaw_entry(issue) for issue in issues}


def fetch_filed(issues: dict[int, dict], filed: dict[str, int]) -> None:
    """Add the issues the answers filed to issues: GitHub's list shows a new issue only some time later."""
    for number in set(filed.values()) - set(issues):
        issues[number] = flaw_entry(json.loads(gh("issue", "view", str(number), "--json", FLAW_FIELDS)))


def known(bundle: str) -> dict:
    """Write the flaws a reviewer may match one to; a review goes on without them if GitHub is down."""
    path = os.path.join(bundle, "known-flaws.json")
    try:
        flaws = fetch_flaws()
    except RuntimeError as e:
        dump(path, [])
        return {"known": 0, "error": str(e)}
    entries = [{"id": number, "title": f["title"], "status": f["status"], "workarounds": len(f["workarounds"]),
                "url": f["url"], "body": f["body"]} for number, f in sorted(flaws.items()) if f["status"] != "fixed"]
    dump(path, entries)
    return {"known": len(entries)}


def issue_number(value) -> int | None:
    match = re.fullmatch(r"#?(\d+)", str(value or "").strip())
    return int(match.group(1)) if match else None


def branch_of(target: dict) -> tuple[str, str]:
    # the repo by name: the checkout's path is different on every machine
    return os.path.basename(target.get("repo", "")), target.get("branch", "")


def issue_body(flaw: dict) -> str:
    return (f"{flaw['flaw']}\n\n**Real fix** ({flaw['fix_size']}): {flaw.get('fix') or 'not sketched yet'}\n\n"
            f"**Area:** {flaw.get('area') or 'unknown'}\n\n"
            "<sub>Recorded by /ace-review. Each of its workaround comments is one branch that works around this flaw, "
            "so their count is the cost of leaving it unfixed.</sub>\n")


def workaround_comment(target: dict, flaw: dict) -> str:
    repo, branch = branch_of(target)
    marker = json.dumps({"repo": repo, "branch": branch, "round": target.get("round", 1)})
    where = f"{flaw['file']}:{flaw['line']}" if flaw.get("line") else flaw["file"]
    return (f"<!-- ace-review workaround {marker} -->\n"
            f"Worked around in `{repo}` branch `{branch}` (review round {target.get('round', 1)}, "
            f"{datetime.date.today().isoformat()}), `{where}`:\n\n{flaw['workaround']}\n")


def delete_comment(comment: int) -> None:
    gh("api", "-X", "DELETE", f"repos/{{owner}}/{{repo}}/issues/comments/{comment}")


def post_workaround(number: int, entry: dict, target: dict, flaw: dict) -> None:
    """One comment per branch: a later round edits the branch's comment rather than adding one."""
    mine = [w for w in entry["workarounds"] if (w["repo"], w["branch"]) == branch_of(target)]
    body = workaround_comment(target, flaw)
    if mine:
        gh("api", "-X", "PATCH", f"repos/{{owner}}/{{repo}}/issues/comments/{mine[0]['comment']}", "-f", f"body={body}")
        for extra in mine[1:]:
            delete_comment(extra["comment"])
    else:
        gh("issue", "comment", str(number), "--body-file", "-", stdin=body)


def posted_before(bundle: str) -> bool:
    """Whether an earlier round of this branch posted a workaround that this one may have to delete."""
    rounds = glob.glob(os.path.join(os.path.dirname(os.path.abspath(bundle)), "round-*", "summary.json"))
    return any(f.get("posted") for path in rounds for f in load(path, {}).get("flaws", []))


def record_flaws(bundle: str, target: dict, flaws: list[dict]) -> tuple[list[dict], str | None]:
    """Post this round's workarounds of the flaws that have an issue, and return how each flaw stands.

    A failure to read the issues leaves them unposted (the answer posts them); a failure
    after that stops finish, which a rerun completes, since it edits its own comments."""
    filed = load(os.path.join(bundle, "filed-flaws.json"), {})
    post = target.get("kind", "core") == "core"
    error = None
    issues: dict[int, dict] = {}
    if flaws or (post and posted_before(bundle)):
        try:
            issues = fetch_flaws()
            fetch_filed(issues, filed)
        except RuntimeError as e:
            error, post = str(e), False
    numbers = {flaw["fid"]: filed.get(flaw["fid"]) or issue_number(flaw.get("known")) for flaw in flaws}
    if error is None:
        # a known id with no issue behind it is a new flaw
        numbers = {fid: n if n in issues else None for fid, n in numbers.items()}

    if post:
        # a full round looked at the whole change, so the branch no longer works around a flaw
        # it didn't find; a delta round never saw the code its earlier rounds found theirs in
        found = set(numbers.values())
        for number, entry in issues.items():
            for w in list(entry["workarounds"]):
                if (w["repo"], w["branch"]) == branch_of(target) and number not in found and (
                        w["round"] == target.get("round", 1) or not target.get("delta")):
                    delete_comment(w["comment"])
                    entry["workarounds"].remove(w)

    recorded, posted = [], set()
    for flaw in flaws:
        number = numbers[flaw["fid"]]
        entry = issues.get(number, {"status": "unknown" if error else "undecided", "workarounds": []})
        # two of the round's flaws can be one known flaw; the branch gets one comment on it
        if number and post and number not in posted:
            post_workaround(number, entry, target, flaw)
            posted.add(number)
        others = [w for w in entry["workarounds"] if (w["repo"], w["branch"]) != branch_of(target)]
        recorded.append({"id": flaw["fid"], "issue": number, "url": entry.get("url"), "title": entry.get("title", flaw["title"]),
                         "new": number is None, "status": entry["status"], "fix_size": flaw["fix_size"],
                         "recommendation": flaw["recommendation"], "why": flaw.get("why", ""),
                         "workarounds": len(others) + 1, "posted": number in posted})
    return recorded, error


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
    flaws, flaws_error = record_flaws(bundle, target, load(os.path.join(bundle, "flaws.json"), []))
    summary = {
        "round": target.get("round", 1),
        "new": {s: sum(1 for f in verified if f["origin"] == "new" and f["severity"] == s) for s in SEVERITIES},
        "pre_existing": sum(1 for f in verified if f["origin"] == "pre-existing"),
        "still_open": [{"id": f["id"], "severity": f["severity"], "file": f.get("file"), "line": f.get("line"), "title": f["title"]} for f in still_open],
        "fixed": sorted(fid for fid, status in carried.items() if status == "fixed"),
        "not_repeated": repeats,
        "rejected": len(load(os.path.join(bundle, "rejected.json"), [])),
        "verdict_floor": floor,
        "flaws": flaws,
        "flaws_error": flaws_error,
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


def answer_flaw(fid: str, value: str, bundle: str | None = None, note: str | None = None) -> dict:
    """Apply the user's decision to a flaw's issue, filing the issue first if the flaw has none."""
    if value not in FLAW_ANSWERS:
        sys.exit(f"the answer for a design flaw is one of {', '.join(FLAW_ANSWERS)}")
    number = issue_number(fid)
    if number is None:
        if bundle is None:
            sys.exit(f"{fid} is no issue number; a flaw of a review needs --bundle")
        flaw = {f["fid"]: f for f in load(os.path.join(bundle, "flaws.json"), [])}.get(fid)
        if flaw is None:
            sys.exit(f"no design flaw {fid} in {bundle}")
        target = load(os.path.join(bundle, "target.json"), {})
        path = os.path.join(bundle, "filed-flaws.json")
        filed = load(path, {})
        issues = fetch_flaws()
        fetch_filed(issues, filed)
        number = filed.get(fid) or issue_number(flaw.get("known"))
        if number not in issues:
            url = gh("issue", "create", "--label", FLAW_LABEL, "--title", flaw["title"], "--body-file", "-", stdin=issue_body(flaw))
            number = issue_number(url.strip().rsplit("/", 1)[1])
            issues[number] = {"workarounds": []}
        # recorded before anything else can fail, so answering again never files a second issue
        dump(path, {**filed, fid: number})
        post_workaround(number, issues[number], target, flaw)

    issue = json.loads(gh("issue", "view", str(number), "--json", "state,assignees,labels,url"))
    if FLAW_LABEL not in {label["name"] for label in issue["labels"]}:
        sys.exit(f"issue #{number} is not labeled {FLAW_LABEL!r}")
    if value in ("defer", "address"):
        if issue["state"] == "CLOSED":
            gh("issue", "reopen", str(number))
        if value == "address" and not issue["assignees"]:
            gh("issue", "edit", str(number), "--add-assignee", "@me")
        for assignee in issue["assignees"] if value == "defer" else []:
            gh("issue", "edit", str(number), "--remove-assignee", assignee["login"])
    elif issue["state"] == "OPEN":
        gh("issue", "close", str(number), "--reason", "not planned" if value == "wrong" else "completed")
    if note:
        gh("issue", "comment", str(number), "--body-file", "-", stdin=f"{FLAW_ANSWERS[value]}: {note}\n")
    return {"id": fid, "issue": number, "url": issue["url"], "status": FLAW_ANSWERS[value]}


def list_flaws(everything: bool = False) -> list[dict]:
    """Open flaws, the ones with the most workarounds first: each workaround is more to undo later."""
    order = {status: n for n, status in enumerate(OPEN_FLAWS)}
    shown = [{"id": number, "title": f["title"], "status": f["status"], "url": f["url"],
              "workarounds": [{k: w[k] for k in ("repo", "branch", "round", "url")} for w in f["workarounds"]]}
             for number, f in fetch_flaws().items() if everything or f["status"] in order]
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
    for name in ("collect", "tally", "finish", "answer", "known"):
        command = sub.add_parser(name)
        command.add_argument("bundle")
    sub.choices["tally"].add_argument("--allow-missing", action="store_true")
    sub.choices["answer"].add_argument("id")
    sub.choices["answer"].add_argument("answer")
    sub.choices["answer"].add_argument("--note")
    command = sub.add_parser("flaw")
    command.add_argument("id")
    command.add_argument("answer", choices=sorted(FLAW_ANSWERS))
    command.add_argument("--bundle")
    command.add_argument("--note")
    command = sub.add_parser("flaws")
    command.add_argument("--all", action="store_true", help="include the flaws found wrong and the fixed ones")
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
        elif args.command == "flaw":
            result = answer_flaw(args.id, args.answer, args.bundle, args.note)
        elif args.command == "flaws":
            result = list_flaws(args.all)
        else:
            result = answer(args.bundle, args.id, args.answer, args.note)
    except RuntimeError as e:
        # gh failed; its stderr says why, a traceback would not
        sys.exit(str(e))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
