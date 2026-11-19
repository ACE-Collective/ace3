# Review

The driver runs this task itself (`SKILL.md`, *The driver*). `state` names the repo whose PR needs the review; review one repo's PR per run.

## 1. Worktree and the base

1. `$F worktree TICKET [--internal <name>]` to get the worktree back, on the pushed branch.
2. `$F base-check TICKET --repo <name>`. Rebase onto `origin/<base>` when it is the PR's first review and `behind` is above 0, or, on any later round, only when `rebase` is true (the base changed a file the patch touches, or a merge conflicts). Each rebase moves the merge-base, and `/ace-review` then reviews the whole change again instead of only the fixes, so don't rebase without a reason.
3. After a rebase, rerun the tests of the touched paths. A conflict in a file the patch touches, or tests the rebase broke, stops the run: `$F release TICKET --to needs-human --repo <name> --body-file <file>`. Don't resolve a conflict in the patch's own files on a guess.
4. `$F push TICKET --repo <name>` after a rebase. The review must be of the head the PR shows.

## 2. Review

Run the `ace-review` skill in its *Factory mode* (`--factory TICKET`) on that repo in the worktree. It runs the tests, its reviewers and its verifiers. After its `findings.py finish`, and before you write the report, file the backlog (below). Then write the report and end the round as that section says:

```bash
bin/exec-in-container.sh /venv/bin/python .agents/skills/ace-review/scripts/findings.py factory $B --verdict <ship|fix-first|rework>
python3 $F post-review TICKET --repo <name> --bundle $B
```

`post-review` refuses when the PR's head moved since the review; push and review again. It refuses a report that would put internal detail on the public PR: fix the report's wording (a reviewer quoted something internal), never the denylist.

### File the backlog

Each round's pre-existing findings (`P` ids) and the design flaws no issue has yet go in a tracker, so nothing the review found waits on a human reading the comment. Each one goes where the code it is about lives:

- A pre-existing finding in ace3 is an ace3 issue, labeled with its dimension where the repo has that label (`logging`, `performance`, `tests`) and `bug` otherwise. One in an internal repo is a Bug work item in that repo's Azure DevOps project, tagged `factory:backlog`.
- A design flaw found reviewing ace3 is an ace3 issue labeled `design flaw`. One found reviewing an internal repo is either: an ace3 issue when the flaw is in core and the internal change only works around it, written in core's terms, or a Bug work item tagged `design flaw` in the internal repo's project when the flaw is in that repo's own code. You decide which by reading the flaw.

1. `python3 $F backlog TICKET --repo <name> --bundle $B` lists the candidates. Each names its possible `trackers` and, for each, the issues or work items a search by its file name turned up, open and closed (by its area for an ace3 search on an internal repo's flaw, so no internal file name goes to GitHub). A flaw the verifier already matched to a known ace3 issue is not a candidate.
2. Judge each one against those hits, reading any that might match (`gh issue view N`, `az boards work-item show --id N`). It is a duplicate when an existing issue describes the same defect in the same code, open or closed: a closed one was fixed, or decided against, and filing it again undoes that decision. Write `$B/backlog.json`, one entry per candidate: `{"id": "P1-1"}` to file it, or `{"id": "P1-1", "duplicate": "#1283"}` (`ado:<id>` for a work item) to record the existing one. A flaw with two trackers also names its `tracker` (`"ace3"`, or the internal repo's name). An entry may carry `title` and `body` to replace the generated ones.
3. `python3 $F file-backlog TICKET --repo <name> --bundle $B` files the new ones and records every outcome in `$B/filed-backlog.json`, so a second run files nothing twice. It needs a decision, and a tracker where there is a choice, for every candidate before it writes anything. A write that the public-text check refuses comes back under `refused` and the others still go through: rewrite that entry's `title` or `body` in generic terms and run it again. When GitHub or Azure DevOps is down, go on without it and say in the report which candidates are not filed.
4. Run `findings.py finish $B` again (from the worktree, through `bin/exec-in-container.sh`), so `summary.json` names each flaw's issue.

The report links each one where it lists it: the design flaw's issue under *Design flaws*, each `P` id's issue or work item under *Pre-existing*. A maintainer who thinks a filed flaw is wrong closes it as not planned, and one who wants it fixed before the PR says `address` on the PR.

## 3. Hand off

`python3 $F state TICKET` now says what comes next: `rework` for fix-first or rework, `promote` once every open PR has shipped, `review` for another repo's PR, or `needs-human` when this was the third round without a ship. On `needs-human`, write a stop comment: the round count, the findings still open, and the one thing a human has to decide, and run `$F release TICKET --to needs-human --repo <name> --body-file <file>`, so the stop lands on this PR and its round count starts again from there.

`$F worktree-remove TICKET`, then the handoff, with `head_sha` the reviewed head, `verdict` the round's, and `findings_open` from `$B/factory.json`.
