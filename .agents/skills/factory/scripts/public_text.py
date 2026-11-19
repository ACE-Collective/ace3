#!/usr/bin/env python3
"""Check text bound for a public ace3 surface against the internal repos' denylists.

    public_text.py [--core PATH] [--require REPO ...] [--file PATH ...]
    public_text.py [--core PATH] [--require REPO ...] --range A..B --repo PATH [--branch NAME]

Each internal repo in the checkout (signatures/, integrations/<name>/) commits
.factory/public-denylist.toml, the terms it knows to be internal:

    [[term]]
    text = "Example Corp"           # matched case-insensitively, anywhere
    reason = "company name"

    [[term]]
    regex = '\\bcorp-[a-z]+\\d+\\b'   # a Python regex, case-insensitive
    reason = "internal hostnames"

The first form reads the text from each --file, or from stdin. The second reads the
commit messages and the added lines of A..B in the repo at --repo, plus --branch.

Prints JSON. Exit 0: nothing matched. Exit 1: something matched; each hit names the
term's reason and where it was, never the matched text, so the output itself can be
pasted anywhere. Exit 2: the check could not run, which counts as a failure: no denylist
was found at all, a repo named with --require has none, or a denylist is malformed.

Stdlib only, so it runs on the host as well as in the dev container.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib

DENYLIST = os.path.join(".factory", "public-denylist.toml")
GIT_TIMEOUT = 60
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class CheckError(Exception):
    """The check could not run, so nothing may be published."""


def internal_repos(core: str) -> dict[str, str]:
    """The internal repos in the checkout, by name: signatures and each integration."""
    repos = {}
    if os.path.isdir(os.path.join(core, "signatures")):
        repos["signatures"] = os.path.join(core, "signatures")
    integrations = os.path.join(core, "integrations")
    if os.path.isdir(integrations):
        for name in sorted(os.listdir(integrations)):
            path = os.path.join(integrations, name)
            if os.path.isdir(path) and os.path.exists(os.path.join(path, ".git")):
                repos[name] = path
    return repos


def load_terms(core: str, required: list[str]) -> list[dict]:
    repos = internal_repos(core)
    terms, found = [], []
    for name, path in repos.items():
        denylist = os.path.join(path, DENYLIST)
        if not os.path.exists(denylist):
            continue
        found.append(name)
        try:
            with open(denylist, "rb") as fp:
                entries = tomllib.load(fp).get("term", [])
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise CheckError(f"{name}: cannot read {DENYLIST}: {e}") from e
        for index, entry in enumerate(entries):
            where = f"{name}: {DENYLIST} term {index + 1}"
            if not entry.get("reason"):
                raise CheckError(f"{where} has no reason")
            if ("text" in entry) == ("regex" in entry):
                raise CheckError(f"{where} needs exactly one of text or regex")
            try:
                pattern = re.compile(re.escape(entry["text"]) if "text" in entry else entry["regex"], re.IGNORECASE)
            except re.error as e:
                raise CheckError(f"{where}: bad regex: {e}") from e
            terms.append({"repo": name, "reason": entry["reason"], "pattern": pattern})
    missing = [name for name in required if name not in found]
    if missing:
        raise CheckError(f"no {DENYLIST} in {', '.join(missing)}")
    if not found:
        raise CheckError(f"no {DENYLIST} in any internal repo under {core}; nothing may be published until one exists")
    return terms


def scan(terms: list[dict], text: str, source: str, first_line: int = 1) -> list[dict]:
    hits = []
    for offset, line in enumerate(text.splitlines()):
        for term in terms:
            if term["pattern"].search(line):
                hits.append({"source": source, "line": first_line + offset, "repo": term["repo"], "reason": term["reason"]})
    return hits


def git(repo: str, *args: str) -> str:
    try:
        result = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=GIT_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CheckError(f"git {' '.join(args)}: {e}") from e
    if result.returncode:
        raise CheckError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def scan_range(terms: list[dict], repo: str, range_: str, branch: str | None) -> list[dict]:
    hits = []
    if branch:
        hits += scan(terms, branch, "branch name")
    for sha in git(repo, "rev-list", range_).split():
        hits += scan(terms, git(repo, "log", "-1", "--format=%B", sha), f"commit {sha[:12]} message")
    path, line = None, 0
    for text in git(repo, "diff", "--no-color", "--no-ext-diff", "-M", range_).splitlines():
        if text.startswith("+++ "):
            path = text[6:] if text.startswith("+++ b/") else None
        elif match := HUNK.match(text):
            line = int(match.group(1))
        elif path and text.startswith("+"):
            hits += scan(terms, text[1:], path, line)
            line += 1
        elif path and not text.startswith("-"):
            line += 1
    return hits


def default_core() -> str:
    try:
        return git(os.getcwd(), "rev-parse", "--show-toplevel").strip()
    except CheckError:
        return os.getcwd()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--core", help="the ace3 checkout whose internal repos hold the denylists (default: the current one)")
    parser.add_argument("--require", action="append", default=[], help="an internal repo that must have a denylist")
    parser.add_argument("--file", action="append", default=[], help="a file of text to check (default: stdin)")
    parser.add_argument("--range", help="check the commits A..B: their messages and added lines")
    parser.add_argument("--repo", help="the repo --range is in")
    parser.add_argument("--branch", help="a branch name to check with --range")
    args = parser.parse_args()
    if args.range and not args.repo:
        parser.error("--range needs --repo")

    try:
        terms = load_terms(args.core or default_core(), args.require)
        if args.range:
            hits = scan_range(terms, args.repo, args.range, args.branch)
        elif args.file:
            hits = []
            for path in args.file:
                with open(path, encoding="utf-8", errors="replace") as fp:
                    hits += scan(terms, fp.read(), path)
        else:
            hits = scan(terms, sys.stdin.read(), "stdin")
    except (CheckError, OSError) as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return 2
    print(json.dumps({"ok": not hits, "terms": len(terms), "hits": hits}, indent=2))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
