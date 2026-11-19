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
    regex = '\\bcorp-[a-z]+\\d+\\b'   # a Python regex, case-insensitive; write \\s+, not a space
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
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


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
                # a phrase's spaces match any run of whitespace, a line break included
                text = r"\s+".join(re.escape(word) for word in entry["text"].split()) if "text" in entry else None
                pattern = re.compile(text or entry["regex"], re.IGNORECASE)
            except re.error as e:
                raise CheckError(f"{where}: bad regex: {e}") from e
            terms.append({"repo": name, "reason": entry["reason"], "pattern": pattern})
    missing = [name for name in required if name not in found]
    if missing:
        raise CheckError(f"no {DENYLIST} in {', '.join(missing)}")
    if not found:
        raise CheckError(f"no {DENYLIST} in any internal repo under {core}; nothing may be published until one exists")
    return terms


def scan(terms: list[dict], text: str, source: str, first_line: int = 1, lines: list[int] | None = None) -> list[dict]:
    """Each term matched against the whole text, so a phrase that wraps onto the next line still
    matches; a hit is reported on the line its match starts. lines, when given, is the real line
    number of each line of text (the added lines of a file are not consecutive)."""
    hits = []
    for term in terms:
        for match in term["pattern"].finditer(text):
            index = text.count("\n", 0, match.start())
            line = lines[index] if lines else first_line + index
            hit = {"source": source, "line": line, "repo": term["repo"], "reason": term["reason"]}
            if hit not in hits:
                hits.append(hit)
    return sorted(hits, key=lambda h: h["line"])


def git(repo: str, *args: str) -> str:
    try:
        # bytes, not text: text mode turns a lone CR into a line break, which would split a line of content
        result = subprocess.run(["git", "-C", repo, *args], capture_output=True, timeout=GIT_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CheckError(f"git {' '.join(args)}: {e}") from e
    if result.returncode:
        raise CheckError(f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout.decode("utf-8", "replace")


# the output of git diff pinned against the user's config: unquoted UTF-8 paths, a/ and b/ prefixes
DIFF = ["-c", "core.quotePath=false", "diff", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", "-M"]


def added_lines(diff: str) -> dict[str, list[tuple[int, str]]]:
    """The added lines of each file in a diff, with their line numbers. Hunks are read by the
    counts in their @@ header, so a line that only looks like a header is still read as content;
    a header this cannot read stops the check rather than skip what follows it."""
    files: dict[str, list[tuple[int, str]]] = {}
    path, line, old_left, new_left = None, 0, 0, 0
    # split on \n alone: splitlines() also breaks at \f, \v, \x1c-\x1e and U+2028, which can be content
    for text in diff.split("\n"):
        if old_left > 0 or new_left > 0:
            if text.startswith("\\"):
                continue
            kind, content = text[:1], text[1:]
            if kind not in ("+", "-", " "):
                raise CheckError("cannot read a line of the diff inside a hunk; nothing may be published unchecked")
            if kind == "+":
                if path is not None:
                    files.setdefault(path, []).append((line, content))
                line, new_left = line + 1, new_left - 1
            elif kind == "-":
                old_left -= 1
            else:
                line, old_left, new_left = line + 1, old_left - 1, new_left - 1
            continue
        if text.startswith("+++ "):
            if text == "+++ /dev/null":
                path = None
            elif text.startswith("+++ b/"):
                path = text[6:]
            else:
                raise CheckError(f"cannot read the diff header {text[:4]!r}...; nothing may be published unchecked")
        elif match := HUNK.match(text):
            line = int(match.group(3))
            old_left = int(match.group(2)) if match.group(2) is not None else 1
            new_left = int(match.group(4)) if match.group(4) is not None else 1
    return files


def scan_range(terms: list[dict], repo: str, range_: str, branch: str | None) -> list[dict]:
    hits = []
    if branch:
        hits += scan(terms, branch, "branch name")
    for sha in git(repo, "rev-list", range_).split():
        hits += scan(terms, git(repo, "log", "-1", "--format=%B", sha), f"commit {sha[:12]} message")
    # a file's name is the matched text, so its hits do not say which file
    for name in git(repo, *DIFF, "--name-only", "-z", "--diff-filter=ACR", range_).split("\0"):
        if name:
            hits += [{**h, "line": 0} for h in scan(terms, name, "file name")]
    for path, lines in added_lines(git(repo, *DIFF, range_)).items():
        hits += scan(terms, "\n".join(text for _, text in lines), path, lines=[number for number, _ in lines])
    return hits


def default_core() -> str:
    try:
        return git(os.getcwd(), "rev-parse", "--show-toplevel").strip()
    except CheckError:
        # outside a git checkout, the directory it was run from is the core
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
