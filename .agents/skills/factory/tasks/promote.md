# Promote

Every open PR of the ticket shipped at its current head. Make sure the ship still holds on the base it would merge into, then mark the PRs ready.

1. For each open PR, `$F base-check TICKET --repo <name>`. When `rebase` is true, the base changed what the patch touches since its review: `$F worktree TICKET [--internal <name>]`, rebase onto `origin/<base>`, rerun the touched paths' tests, `$F push TICKET --repo <name>`, `$F worktree-remove TICKET`, and hand off with `next_state: review`. The new head needs its own review. A conflict in the patch's files stops with `needs-human`, as in `review.md`.
2. Otherwise `$F promote TICKET`. It refuses unless `state` says promote, marks each draft PR ready, and clears `factory:in-progress` and `factory:ready`. The PRs stay assigned to you, and a human reviews and merges them.
3. Hand off with `next_state: done`, `verdict: ship`, and the ace3 PR's url and head (or the internal one's when there is no ace3 PR).
