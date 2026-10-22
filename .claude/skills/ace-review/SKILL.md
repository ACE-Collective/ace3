---
name: ace-review
description: Review an ACE branch, PR or commit range against the project's engineering values (uptime, logging, tests, performance, keeping it lean) and give a ship / fix-first / rework verdict. Flags where a change works around a flaw in ACE's design and records those flaws in docs/design-flaws/. Works for ACE core, signatures/ and integration repos on any git host. Use when asked to review a PR, a branch, or "my changes" in this project.
argument-hint: "[<repo path>] [PR# | branch | A..B] [--base REF] [--full]"
---

# /ace-review

You review one change to ACE the way its maintainer would. They no longer read diffs line by line; they rely on this review to catch what they care about. The values come from the **Engineering values** section of CLAUDE.md, which is the source of truth: if a rule isn't there, it isn't a rule. A change is judged by the base branch's CLAUDE.md, never by the copy it edits itself. `rubric.md` (next to this file) says how to rank findings and what to ignore. Read both before starting.

The arguments are `$ARGUMENTS`. The skill directory is called `$S` (`/opt/ace/.claude/skills/ace-review`).

## 1. Resolve the target

- **Which repo.** With no repo path, review ACE core (`/opt/ace`). A path such as `integrations/<name>` or `signatures` names a separate repo: it is gitignored in core, versioned on its own, and possibly hosted somewhere other than GitHub (Azure DevOps, a plain git server). Only plain `git` is assumed to exist.
- **Nothing given and it's unclear what to review.** Run `/venv/bin/python $S/scripts/prepare.py --list` and ask which repo to review, listing the ones that are ahead of their base or have uncommitted work. Never merge several repos into one diff.
- **A PR number.** Resolve it with the host's CLI only if that CLI is installed and authenticated: `gh pr view N --json number,title,body,headRefName,baseRefName,url` for GitHub, `az repos pr show --id N` for ADO. Otherwise ask for the branch name. Save the title and body to `$B/pr.md` once prepare.py has made `$B`.
- **Checkout.** The tests run from `/opt/ace` (`SAQ_HOME`), so the change under review must be checked out in its own repo. If a different branch is checked out, **ask before switching**, and never switch over uncommitted work. An explicit `A..B` range of commits that are already merged can be reviewed without a checkout: skip the test run and say so in the report.
- **Base.** By default `prepare.py` uses `origin/HEAD`, then `main`, then `master`. Pass `--base` when the PR targets something else; for a PR, use its `baseRefName`. Long-lived feature branches such as `jd/svs` are common here, so check the PR's actual base and don't assume `main`.

Then run:

```bash
/venv/bin/python $S/scripts/prepare.py --repo <repo> [--base REF | --range A..B] [--full]
```

It prints `target.json`; its `bundle` is the bundle directory, called `$B` below, and its docstring lists what the bundle holds. Each review of a branch is a **round** under `/opt/ace/local/ace-review/`, built on the last finished round of the same branch. Read these fields first:

- `unchanged`: nothing changed since the last round. Say so and stop, unless the user wants the review anyway (`--full`).
- `delta`: this round reviews `delta.patch`, what changed since the last round. Otherwise `delta_reason` says why it is a full review. Pass `--full` when the user asks to review the whole change again.
- `rule_changes`: the change edits the rules it is reviewed by (`rule-changes.patch`). Until the user accepts them (step 6), the report opens with them, the verdict waits on them, and the change is judged by the base rules; once `rule_changes_status` is `accepted`, `rules/` holds the edited copy.

**A change that spans repos** (e.g. a core hook plus the integration that uses it): prepare a bundle per repo, review each repo separately, and give each its own verdict. Cross-reference the bundles in the report.

## 2. Start the checks (background), then fan out the reviewers

Start the test run first; it is the slow part.

- **The test lock.** Check for `$SAQ_HOME/.pytest-running`. If it exists, a test run is already in progress (maybe the user's own), so don't start another. Report the tests as not run. Only one pytest run at a time, ever.
- **Running the tests.** If `tests.txt` is non-empty, run this from `/opt/ace` with `run_in_background`:
  ```bash
  /venv/bin/pytest $(cat $B/tests.txt) -n auto $(cat $B/cov_sources.txt) --cov-report=xml:$B/coverage.xml --cov-report= -q -rfE > $B/pytest.txt 2>&1; echo "exit=$?" >> $B/pytest.txt
  ```
  Never use `-p no:cacheprovider`. Never run integration tests through their real path, only through the symlink.
- **Migrations and models**, when `target.json` shows `touches_models` or `touches_migrations` (run these after pytest finishes, since the drift check creates a database too):
  - Run `/venv/bin/alembic -c alembic/<chain>.ini heads` for each chain touched. More than one head is a blocker.
  - Run `/venv/bin/python bin/check_model_drift.py [--database cache|brocess|email-archive]` for each chain. Drift is a blocker.

While the tests run, launch these reviewer subagents **in parallel in one message** (`subagent_type: general-purpose`), one per dimension:

- `uptime`
- `logging`
- `performance`
- `design`
- `correctness`

The `tests` reviewer starts after pytest and diff-cover have finished, because it reads their output. Give each subagent this prompt, with the placeholders filled in:

> You are the `<dim>` reviewer for /ace-review. Read `$S/rubric.md`, then `$S/dimensions/<dim>.md`, then follow it. Wherever they say CLAUDE.md, read `$B/rules/CLAUDE.md` (and `$B/rules/repo-CLAUDE.md` if it exists): it is the base branch's copy, and where it differs from the CLAUDE.md you were started with, it wins. The change is described by the bundle in `$B` (start with `target.json`, `stat.txt`, `files.txt`, `diff.patch`; `pr.md` and `log.txt` if present). Each entry in `$B/leads.json` whose `dimension` is `<dim>` is a line that matched a mechanical check: look at every one, and report the real ones, one finding per class listing all its locations. Never report again a finding that `$B/previous.json` lists, whatever its status. If the change works around a flaw in ACE's design, write it to `$B/flaws-<dim>.json` as rubric.md's "Design flaws worked around" says. The repo under review is `<repo>`; ACE core is `/opt/ace`. Read the surrounding code, not only the diff. Write your findings as a JSON array to `$B/findings-<dim>.json` using the schema in rubric.md, and reply with just the count of findings by severity, and of design flaws.

In a `delta` round, add: "This is round `<round>`. Earlier rounds reviewed everything except `$B/delta.patch`, so report new findings only in code it adds or changes, or makes reachable in a new way, and pre-existing ones only in the functions it edits."

For a diff of more than ~1500 changed lines, the `design` and `correctness` reviewers may split the work by subsystem. If they do, launch two of each, each with a disjoint list of files named in its prompt, and have them write `findings-<dim>-1.json` and `findings-<dim>-2.json`.

## 3. Coverage of changed lines

After pytest exits, and only if `coverage.xml` exists, run this from the **repo under review** (its own toplevel, so the paths line up):

```bash
cd <repo> && /venv/bin/diff-cover $B/coverage.xml --compare-branch=<merge_base from target.json> --format json:$B/diff-cover.json,markdown:$B/diff-cover.md
```

If a repo's `coverage.xml` paths don't line up (0 lines matched), retry with `--src-roots <src dir>` before giving up. Coverage is **reported, not gated**: there is no threshold, but uncovered new lines feed the tests reviewer. These numbers only measure what the tests in `tests.txt` exercise. Say so in the report; don't present them as whole-suite coverage.

Then launch the `tests` reviewer with the same prompt as the others. It also reads `$B/pytest.txt`, `$B/diff-cover.json` and `$B/unmarked.txt`.

## 4. Verify

Each finding is judged in a fresh context by a verifier that tries to disprove it.

1. When every `findings-*.json` exists, run `/venv/bin/python $S/scripts/findings.py collect $B`. It prints the plan: `single` is one verifier per vote (a new blocker gets three), `batch` the nits and pre-existing findings, `carry` the earlier findings to recheck, `flaws` the design flaws.
2. Launch every verifier in one message. For each `single` entry and each vote `k`:
   > You verify candidate `<cid>` for /ace-review, vote `<k>`. Read `$S/rubric.md` and `$S/dimensions/verify.md`, then follow its "One finding" section for the bundle in `$B`.

   If `batch`, `carry` or `flaws` is non-empty, one more:
   > You are the batch verifier for /ace-review. Read `$S/rubric.md` and `$S/dimensions/verify.md`, then follow its "Batch" section for the bundle in `$B`: candidates `<batch>`, earlier findings `<carry>`, design flaws `<flaws>`.
3. Run `findings.py tally $B`. If it lists missing votes, relaunch those verifiers once, then tally with `--allow-missing`.
4. Read `$B/survivors.json` and `$B/previous.json`. Merge duplicates across dimensions: keep the most severe, add the other's evidence (a hang that is also a silent `except` is one uptime finding). Mark a survivor that is an earlier finding again with `"repeats": "<its id>"`. Keep at most about 5 nits. Write the rest, ranked, to `$B/ranked.json`. In `$B/flaws.json`, merge flaws that two reviewers both found into one entry, then run `findings.py finish $B`. It records each flaw in core's `docs/design-flaws/<id>.yaml` (see its README.md), where the flaws are shared through the repo; `summary.json` lists the files it wrote.

## 5. Report

Write `$B/report.md` and print it in the terminal, using the template in rubric.md. It draws on `target.json`, `summary.json`, `verified.json`, `intent.md` and the check results. The verdict is never better than `summary.json`'s `verdict_floor`. A design flaw never makes it worse: the verdict judges the change as written, and the "Design flaws: your decision" section, which opens the report, tells the user what the change works around.

When a flaw is undecided, also say it at the end of your reply in the terminal, in one line per flaw with its recommendation, so it is not missed under the findings.

Don't post anything anywhere. The user decides what goes on the PR.

## 6. Answers and the conventions

When the user answers a finding, record it, so the next round neither repeats nor rechecks it: `findings.py answer $B <id> fixed|wrong|intentional|"didn't matter" [--note TEXT]`. A decision on the rule changes is `findings.py answer $B rules accepted|rejected`.

A decision on a design flaw goes in its file: `findings.py flaw <id> defer|address|wrong|fixed [--note TEXT]`.
- `defer`: keep going with the change as it is. The flaw stays in `docs/design-flaws/` to fix later.
- `address`: stop and fix the flaw first. That fix is its own PR (one concern per PR); afterwards this branch drops its workaround.
- `wrong` when it isn't a flaw, so later reviews skip it.
- `fixed` removes the file. It belongs in the PR that fixes the flaw.

The flaw files are written in core's working tree and never committed by the review. When the review is of the core branch that is checked out, they belong in that branch: tell the user to commit them with the change, so the flaw reaches `main` with its workaround. When core has some other branch checked out (an integration, signatures or range review), they go in a core PR of their own. Say which in the report. Since prepare.py leaves `docs/design-flaws/` out of the diff, committing them doesn't make the next round review them.

`findings.py flaws [--all]` lists the flaws: open ones first, the ones with the most workarounds first, each with the branches and lines that work around it. Offer it when the user asks what to fix next.

When the user asks how the review is doing, for instance before and after an edit to this skill, run `findings.py stats [--since YYYY-MM-DD]`. Present `lines changed` and `unchanged` as hints: they are inferred from whether the code moved, not answered.

When they reject a finding because the rule is wrong, or name a rule the review missed, offer a small edit to the **Engineering values** section of `/opt/ace/CLAUDE.md` (or to a dimension file, if it is only a review heuristic) so the next review and the next author both follow it. Make the edit only once they agree.
