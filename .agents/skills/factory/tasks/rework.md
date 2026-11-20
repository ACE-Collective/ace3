# Rework

Fix what the last review asked for and what maintainers said since, and nothing else. `state` names the repo. To stop with `needs-human` below is to write why into a file and run `$F release TICKET --to needs-human --repo <name> --body-file <file>`, so the stop lands on this repo's PR.

## 1. What to answer

1. `$F worktree TICKET [--internal <name>]`.
2. The last review comment on the PR: its marker names the round, the open finding ids, and the round's `bundle`, a path under `local/ace-review/` in the main checkout (the worktree's `local` is a link to it). That directory is `$B` below, and its `verified.json` has the full findings. Each `act on` finding, and each id in the marker's `open` list, is yours to fix. Consider, noted and pre-existing (`P` ids) findings are not, unless a maintainer comment asks for one.
3. `$F comments TICKET --repo <name>`: the maintainer comments since the factory last spoke. Each one is answered, by doing what it asks or by replying why not. A maintainer comment is never answered "wrong". When one asks for something you can't do (it contradicts AGENTS.md, needs a design decision, or reaches beyond the ticket), stop with `needs-human` and say which comment and why.
4. A design flaw in the review is filed as an issue (`review.md`, *File the backlog*), and what to do about it is the maintainer's decision. Don't act on it.

## 2. Fix

Follow `ace-review`'s step 7, *Fixing findings*: one finding at a time, the smallest change its *Fix* describes, a test seen to fail without the fix for each behavior (the `tdd` skill). After each one, record it from the worktree:

```bash
bin/exec-in-container.sh /venv/bin/python .agents/skills/ace-review/scripts/findings.py answer $B <id> fixed
```

A finding you are sure is wrong is answered `wrong` (or `intentional`) with `--note` holding the evidence: a run, a test, or `file:line` of the code that settles it. No evidence, no answer: fix it. When two fixes in a row for the same finding each produced a new finding (ace-review's *Step back*), stop with `needs-human`.

Then the definition of done from `implement.md`, step 5, for what changed, with the tests run in the background as `implement.md` says: `prepare.py --check`, the touched paths' tests, the live check when its area changed.

## 3. Push, update, reply

1. Commit (messages say which finding or comment each fixes, by id), then `$F push TICKET --repo <name>`.
2. Update the PR body's Testing section with this round's runs: `$F pr-body TICKET --repo <name> --body-file <file>`. When the rework changed what kind of change the PR is or what it touches, fix its labels too: `$F pr-labels TICKET --repo <name> --add <label> --remove <label>` (`implement.md`, step 6).
3. Reply on the PR with one comment: for each finding and comment, its id or link and what you did (fixed in which commit, or answered and why): `$F comment TICKET --repo <name> --kind reply --body-file <file>`. The reply is what tells the next review, and `state`, that the comments are answered, so post it even when every answer was a reply rather than a commit.
4. `$F worktree-remove TICKET`, then the handoff with `next_state: review`.
