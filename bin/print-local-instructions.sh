#!/usr/bin/env bash
#
# Prints the main checkout's AGENTS.local.md, a maintainer's untracked instructions, for the
# SessionStart hooks in .claude/settings.json and .codex/hooks.json to hand to the agent as
# context. Codex loads no local instructions file, and Claude Code loads CLAUDE.local.md only from
# the checkout it runs in, never from the main checkout when it runs in a worktree, so the hook is
# how a session in the main checkout or any of its worktrees, in either tool, gets the same file.
#
# Prints nothing, and succeeds, outside a git repository or when there is no such file: a failing
# hook shows as an error at the start of every session.

common_dir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || exit 0
file=$(dirname "$common_dir")/AGENTS.local.md
[ -f "$file" ] && cat "$file"
exit 0
