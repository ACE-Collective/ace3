#!/usr/bin/env python3
"""validate-yara: ask ACE to validate a change to YARA rules, wait for it, and summarize it.

Run from a checkout of the rule repository in its CI (docs/SVS_VALIDATION.md, *Requesting a
validation*). ACE replays every graded sample under the pull request's merge base and its head and
reports what the change does; this prints (and with --summary-file writes, as Markdown) the counts,
the rules involved and the link to the report. The key needs only svs:validate, which reads counts
and rule names: no sample leaves ACE.

Validation warns and never blocks: whatever the validation found, and even when it failed or is
still running at --timeout, this exits 0. It exits 2 when it could not ask at all (bad arguments,
git, the connection, or a key ACE refused), so a broken setup is noticed.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from typing import Callable, Optional

import requests

from hunt_compiler.ace_client import Connection, add_connection_arguments, validate_connection_arguments

API_PATH = "/api/v2/svs/yara/validations/"

EXIT_OK = 0
EXIT_ERROR = 2

_FULL_SHA = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")

# the report's bands as the summary names them, most urgent first
CATEGORY_HEADINGS = {
    "regression": "Regressions",
    "regression_unconfirmed": "Regressions on unconfirmed labels",
    "new_fp": "New false positives",
    "new_fp_other_rule": "New false positives on another rule's sample",
    "rule_removed": "Samples of rules this change removes",
    "scan_error": "Scan errors",
    "recovered": "Recovered",
    "improvement": "Improvements",
    "already_broken": "Already broken on base",
    "new_match_real_hit": "New matches on files that are a real hit for another rule",
    "unlabeled_change": "Unlabeled changes",
}

# what a band's reader should know before acting on it
CATEGORY_HINTS = {
    "regression_unconfirmed": "Check that each sample was ever a real hit for the rule: its label is only inherited.",
    "new_fp_other_rule": "The files are graded false positives for other rules.",
}

# the categories that need the author's attention
ATTENTION = ("regression", "regression_unconfirmed", "new_fp", "new_fp_other_rule", "rule_removed", "scan_error")


class ValidateError(Exception):
    """The validation could not be requested or followed; the message says why."""


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ask ACE to validate a change to YARA rules against its graded samples (warn only).")
    add_connection_arguments(parser)
    parser.add_argument(
        "--repository",
        default=os.environ.get("ACE_SVS_REPOSITORY"),
        help="The repository's name in ACE (a git_repo_<name> section listed in svs.yara.repositories)",
    )
    parser.add_argument(
        "--head", default="HEAD",
        help="The commit to validate (default: HEAD)",
    )
    parser.add_argument(
        "--base", default=None,
        help="The commit to compare against (default: the merge base of --head and origin/<--target-branch>)",
    )
    parser.add_argument(
        "--target-branch", default=os.environ.get("GITHUB_BASE_REF") or "main",
        help="The branch the change merges into, for the default --base (default: $GITHUB_BASE_REF or main)",
    )
    parser.add_argument(
        "--branch", default=os.environ.get("GITHUB_HEAD_REF") or None,
        help="The branch --head is on (default: $GITHUB_HEAD_REF, else the checkout's current branch)",
    )
    parser.add_argument("--pr-url", default=None, help="The pull request, for the report's link back")
    parser.add_argument("--git-dir", default=".", help="The rule repository's checkout (default: .)")
    parser.add_argument("--timeout", type=int, default=3600, help="How long to wait for the validation, in seconds")
    parser.add_argument("--poll-interval", type=int, default=15, help="How often to ask, in seconds")
    parser.add_argument("--summary-file", default=None, help="Also write the summary to this file, as Markdown")
    parser.add_argument("--json", action="store_true", default=False, help="Print the final status as JSON")
    return parser.parse_args(argv)


def _git(git_dir: str, *args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=git_dir, check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as e:
        stderr = getattr(e, "stderr", "") or ""
        raise ValidateError(f"git {' '.join(args)} failed: {stderr.strip() or e}") from None


def resolve_commit(ref: str, git_dir: str) -> str:
    """The full commit id of ref; a full id is taken as given."""
    if _FULL_SHA.match(ref.lower()):
        return ref.lower()
    return _git(git_dir, "rev-parse", "--verify", f"{ref}^{{commit}}")


def resolve_commits(args: argparse.Namespace) -> tuple[str, str, str]:
    """(base, head, branch) as full commit ids and a branch name."""
    head = resolve_commit(args.head, args.git_dir)
    if args.base is not None:
        base = resolve_commit(args.base, args.git_dir)
    else:
        base = _git(args.git_dir, "merge-base", f"origin/{args.target_branch}", head)

    branch = args.branch or _git(args.git_dir, "rev-parse", "--abbrev-ref", "HEAD")
    if branch == "HEAD":
        raise ValidateError("the checkout is on a detached HEAD: pass --branch")
    return base, head, branch


def _answer(response: requests.Response) -> dict:
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = response.text[:500]
        raise ValidateError(f"ACE answered {response.status_code}: {detail}")
    return response.json()


def request_validation(connection: Connection, repository: str, base: str, head: str, branch: str,
                       pr_url: Optional[str]) -> dict:
    body = {"repository": repository, "base_sha": base, "head_sha": head, "branch": branch}
    if pr_url:
        body["pr_url"] = pr_url
    try:
        return _answer(connection.request("POST", API_PATH, json=body))
    except requests.exceptions.RequestException as e:
        raise ValidateError(f"unable to reach ACE: {e}") from None


def wait_for(connection: Connection, status: dict, timeout: float, poll_interval: float,
             sleep: Callable[[float], None] = time.sleep,
             clock: Callable[[], float] = time.monotonic) -> dict:
    """Polls the validation's status until it is completed or failed, or timeout passes. A
    connection error while polling is retried; a refusal from ACE is not."""
    deadline = clock() + timeout
    while status["state"] in ("queued", "running") and clock() < deadline:
        sleep(min(poll_interval, max(deadline - clock(), 0)))
        try:
            status = _answer(connection.request("GET", f"{API_PATH}{status['uuid']}/status"))
        except requests.exceptions.RequestException as e:
            print(f"unable to reach ACE, retrying: {e}", file=sys.stderr)
    return status


def _duration(seconds: float) -> str:
    return f"{int(seconds // 60)} minutes" if seconds >= 120 else f"{int(seconds)} seconds"


def _short(sha: str) -> str:
    return sha[:12]


def summarize(status: dict, ui_host: str, timeout: float) -> str:
    """The validation as Markdown, for the pull request."""
    link = f"https://{ui_host}{status['report_path']}"
    lines = [
        f"## SVS YARA validation: {status['state']}",
        "",
        f"`{_short(status['base_sha'])}..{_short(status['head_sha'])}` of {status['repository']} "
        f"({status['branch']}). [The report in ACE]({link})",
        "",
    ]
    state = status["state"]
    if state == "failed":
        lines += [f"The validation could not run: {status.get('error') or 'no reason given'}", ""]
    elif state != "completed":
        lines += [f"The validation is still {state} after {_duration(timeout)}; the report will be at the link "
                  "above.", ""]
    else:
        if status.get("ruleset_error"):
            lines += ["**These rules would not load together**, so the yara service would keep its previous rules: "
                      f"{status['ruleset_error']}", ""]
        if status.get("compile_errors"):
            lines += ["### Rule files that do not compile (their rules are dropped)", ""]
            lines += [f"- `{problem['file']}`: {problem['error']}" for problem in status["compile_errors"]]
            lines.append("")

        counts = status.get("counts") or {}
        attention = [category for category in ATTENTION if counts.get(category)]
        if not status.get("diffed"):
            lines += ["Nothing was compared, because one of the commits' rules would not load.", ""]
        elif not attention:
            lines += ["No regressions and no new false positives.", ""]

        for category, heading in CATEGORY_HEADINGS.items():
            rules = status.get("rules", {}).get(category)
            if not counts.get(category) or not rules:
                continue
            lines += [f"### {heading}: {counts[category]}", ""]
            if category in CATEGORY_HINTS:
                lines += [CATEGORY_HINTS[category], ""]
            lines += [f"- {rule['rule_name']} (`{rule['rule_uuid']}`): {rule['count']} sample(s)" for rule in rules]
            lines.append("")

    lines.append("_This check only warns; it never blocks the pull request._")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        if not args.repository:
            raise ValidateError("--repository is required (or set ACE_SVS_REPOSITORY)")
        try:
            validate_connection_arguments(args)
        except ValueError as e:
            raise ValidateError(str(e)) from None

        base, head, branch = resolve_commits(args)
        connection = Connection.from_args(args)
        status = request_validation(connection, args.repository, base, head, branch, args.pr_url)
        print(f"validation {status['uuid']} of {_short(base)}..{_short(head)} is {status['state']}", file=sys.stderr)
        status = wait_for(connection, status, args.timeout, args.poll_interval)
    except ValidateError as e:
        print(f"validate-yara: {e}", file=sys.stderr)
        return EXIT_ERROR

    summary = summarize(status, args.ui_host, args.timeout)
    if args.summary_file:
        with open(args.summary_file, "w") as fp:
            fp.write(summary)

    print(json.dumps(status, indent=2) if args.json else summary)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
