#!/usr/bin/env python3
"""
Update CHANGELOG.md with merged PRs for a GitHub milestone.

Usage:
    update-changelog.py --milestone 3.0.91
"""

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"


def run_gh(args: list[str]) -> str:
    """Run a gh CLI command and return stdout. Exit on failure."""
    result = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "gh command failed"
        print(f"error: {message}", file=sys.stderr)
        sys.exit(1)
    return result.stdout


def get_repo_name_with_owner() -> str:
    """Resolve owner/name for the current git repo via gh."""
    return run_gh(
        ["repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"]
    ).strip()


def section_exists(changelog_text: str, milestone: str) -> bool:
    """Return True if CHANGELOG.md already has a ## [milestone] heading."""
    pattern = re.compile(
        rf"^## \[{re.escape(milestone)}\]",
        re.MULTILINE,
    )
    return pattern.search(changelog_text) is not None


def fetch_merged_prs(repo: str, milestone: str) -> list[dict]:
    """Fetch merged PRs for the given milestone via gh search."""
    stdout = run_gh(
        [
            "search",
            "prs",
            "--repo",
            repo,
            "--milestone",
            milestone,
            "--merged",
            "--limit",
            "1000",
            "--json",
            "number,title,url",
        ]
    )
    return json.loads(stdout)


def is_version_bump_pr(title: str, milestone: str) -> bool:
    """True for release bump PRs titled v{milestone} or {milestone}."""
    return title in (f"v{milestone}", milestone)


def build_section(milestone: str, prs: list[dict], date: datetime.date) -> str:
    """Build a Keep a Changelog section for the milestone.

    Ends with a blank line so there is a newline between the last entry and
    the following section heading.
    """
    lines = [f"## [{milestone}] - {date.strftime('%Y-%m-%d')}", ""]
    for pr in prs:
        lines.append(f"- [{pr['title']}]({pr['url']})")
    # Trailing blank line between this section and the previous one.
    lines.append("")
    return "\n".join(lines) + "\n"


def insert_section(changelog_text: str, section: str) -> str:
    """Insert section after the preamble, before the first ## heading."""
    match = re.search(r"^## ", changelog_text, re.MULTILINE)
    if not match:
        # No existing sections — append after trailing newline.
        text = changelog_text.rstrip("\n") + "\n\n" + section
        if not text.endswith("\n"):
            text += "\n"
        return text

    insert_at = match.start()
    return changelog_text[:insert_at] + section + changelog_text[insert_at:]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update CHANGELOG.md with merged PRs for a GitHub milestone."
    )
    parser.add_argument(
        "--milestone",
        required=True,
        help="GitHub milestone title (e.g. 3.0.91)",
    )
    args = parser.parse_args()
    milestone = args.milestone

    if not CHANGELOG_PATH.is_file():
        print(f"error: changelog not found: {CHANGELOG_PATH}", file=sys.stderr)
        sys.exit(1)

    changelog_text = CHANGELOG_PATH.read_text()
    if section_exists(changelog_text, milestone):
        print(
            f"error: section for milestone {milestone!r} already exists in "
            f"{CHANGELOG_PATH.name}; update it manually",
            file=sys.stderr,
        )
        sys.exit(1)

    repo = get_repo_name_with_owner()
    prs = fetch_merged_prs(repo, milestone)
    prs = [pr for pr in prs if not is_version_bump_pr(pr["title"], milestone)]
    if not prs:
        print(
            f"error: no merged PRs found for milestone {milestone!r} "
            f"(after excluding version-bump PRs)",
            file=sys.stderr,
        )
        sys.exit(1)

    prs.sort(key=lambda pr: pr["number"], reverse=True)
    section = build_section(milestone, prs, datetime.date.today())
    updated = insert_section(changelog_text, section)
    CHANGELOG_PATH.write_text(updated)
    print(f"Added section for {milestone} with {len(prs)} PR(s) to {CHANGELOG_PATH}")


if __name__ == "__main__":
    main()
