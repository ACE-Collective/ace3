# Review

The driver runs this task itself (`SKILL.md`, *The driver*). `state` names the repo whose PR needs the review; review one repo's PR per run.

## 1. Worktree and the base

1. `$F worktree TICKET [--internal <name>]` to get the worktree back, on the pushed branch.
2. `$F base-check TICKET --repo <name>`. Rebase onto `origin/<base>` when it is the PR's first review and `behind` is above 0, or, on any later round, only when `rebase` is true (the base changed a file the patch touches, or a merge conflicts). Each rebase moves the merge-base, and `/ace-review` then reviews the whole change again instead of only the fixes, so don't rebase without a reason.
3. After a rebase, rerun the tests of the touched paths. A conflict in a file the patch touches, or tests the rebase broke, stops the run: `$F release TICKET --to needs-human --repo <name> --body-file <file>`. Don't resolve a conflict in the patch's own files on a guess.
4. `$F push TICKET --repo <name>` after a rebase. The review must be of the head the PR shows.

## 2. Review

Run the `ace-review` skill in its *Factory mode* (`--factory TICKET`) on that repo in the worktree. It runs the tests, its reviewers and its verifiers, writes the report, and you end the round as that section says:

```bash
bin/exec-in-container.sh /venv/bin/python .agents/skills/ace-review/scripts/findings.py factory $B --verdict <ship|fix-first|rework>
python3 $F post-review TICKET --repo <name> --bundle $B
```

`post-review` refuses when the PR's head moved since the review; push and review again. It refuses a report that would put internal detail on the public PR: fix the report's wording (a reviewer quoted something internal), never the denylist.

## 3. Hand off

`python3 $F state TICKET` now says what comes next: `rework` for fix-first or rework, `promote` once every open PR has shipped, `review` for another repo's PR, or `needs-human` when this was the third round without a ship. On `needs-human`, write a stop comment: the round count, the findings still open, and the one thing a human has to decide, and run `$F release TICKET --to needs-human --repo <name> --body-file <file>`, so the stop lands on this PR and its round count starts again from there.

`$F worktree-remove TICKET`, then the handoff, with `head_sha` the reviewed head, `verdict` the round's, and `findings_open` from `$B/factory.json`.
