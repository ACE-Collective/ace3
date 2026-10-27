---
name: ace-review
description: Review an ACE branch, PR or commit range against the project's engineering values (uptime, logging, tests, performance, keeping it lean) and give a ship / fix-first / rework verdict. Flags where a change works around a flaw in ACE's design and tracks those flaws as GitHub issues labeled "design flaw". Works for ACE core, signatures/ and integration repos on any git host. Use when asked to review a PR, a branch, or "my changes" in this project.
argument-hint: "[<repo path>] [PR# | branch | A..B] [--base REF] [--full]"
---

# /ace-review

You review one change to ACE the way its maintainer would. They no longer read diffs line by line; they rely on this review to catch what they care about. The values come from the **Engineering values** section of CLAUDE.md, which is the source of truth: if a rule isn't there, it isn't a rule. A change is judged by the base branch's CLAUDE.md, never by the copy it edits itself. `rubric.md` (next to this file) says how to rank findings and what to ignore. Read both before starting.

The arguments are `$ARGUMENTS`. The skill directory is called `$S` (`/opt/ace/.claude/skills/ace-review`).

## 1. Resolve the target

- **Which repo.** With no repo path, review ACE core (`/opt/ace`). A path such as `integrations/<name>` or `signatures` names a separate repo, versioned on its own and possibly hosted somewhere other than GitHub. Only plain `git` is assumed to exist.
- **Nothing given and it's unclear what to review.** Run `/venv/bin/python $S/scripts/prepare.py --list` and ask which repo to review, listing the ones that are ahead of their base or have uncommitted work. Never merge several repos into one diff.
- **A PR number.** Resolve it with the host's CLI only if that CLI is installed and authenticated: `gh pr view N --json number,title,body,headRefName,baseRefName,url` for GitHub, `az repos pr show --id N` for ADO. Otherwise ask for the branch name. Save the title and body to `$B/pr.md` once prepare.py has made `$B`.
- **Checkout.** The tests run from `/opt/ace` (`SAQ_HOME`), so the change under review must be checked out in its own repo. If a different branch is checked out, **ask before switching**, and never switch over uncommitted work. An explicit `A..B` range of commits that are already merged can be reviewed without a checkout: skip the test run and say so in the report.
- **Base.** Pass `--base` when the PR targets anything but the default branch (its `baseRefName`). Long-lived feature branches such as `jd/svs` are common here.

Then run:

```bash
/venv/bin/python $S/scripts/prepare.py --repo <repo> [--base REF | --range A..B] [--full]
```

It prints `target.json`; its `bundle` is the bundle directory, called `$B` below. Each review of a branch is a **round** under `/opt/ace/local/ace-review/`, built on the last finished round of the same branch. Read these fields first:

- `unchanged`: nothing changed since the last round. Say so and stop, unless the user wants the review anyway (`--full`).
- `delta`: this is a **fix round** over `delta.patch`, what changed since the last round. Otherwise `delta_reason` says why it is a full review. Pass `--full` only when the user asks to review the whole change again.
- `rule_changes`: the change edits the rules it is reviewed by (`rule-changes.patch`). Until the user accepts them (step 6), the report opens with them, the verdict waits on them, and the change is judged by the base rules; once `rule_changes_status` is `accepted`, `rules/` holds the edited copy.

Then run `/venv/bin/python $S/scripts/findings.py known $B`, which writes the known design flaws to `$B/known-flaws.json`. If it reports an `error`, go on with no known flaws, and say so in the report.

**A change that spans repos** (e.g. a core hook plus the integration that uses it): prepare a bundle per repo, review each repo separately, and give each its own verdict. Cross-reference the bundles in the report.

## 2. Start the checks (background), then fan out the reviewers

Start the test run first; it is the slow part.

- **The test lock.** If `$SAQ_HOME/.pytest-running` or, in the `dev` container, `/tmp/ace-pytest-running` exists, a test run is in progress (maybe the user's own): don't start another, and report the tests as not run.
- **Running the tests.** If `tests.txt` is non-empty, run this from `/opt/ace` with `run_in_background`:
  ```bash
  /venv/bin/pytest $(cat $B/tests.txt) -n auto $(cat $B/cov_sources.txt) --cov-report=xml:$B/coverage.xml --cov-report= -q -rfE > $B/pytest.txt 2>&1; echo "exit=$?" >> $B/pytest.txt
  ```
- **Migrations and models**, when `target.json` shows `touches_models` or `touches_migrations` (run these after pytest finishes, since the drift check creates a database too):
  - Run `/venv/bin/alembic -c alembic/<chain>.ini heads` for each chain touched. More than one head is a blocker.
  - Run `/venv/bin/python bin/check_model_drift.py [--database cache|brocess|email-archive]` for each chain. Drift is a blocker.

**A full round.** While the tests run, launch these reviewer subagents **in parallel in one message** (`subagent_type: general-purpose`), one per dimension: `uptime`, `logging`, `performance`, `design`, `correctness`. The `tests` reviewer starts after pytest and diff-cover have finished, because it reads their output. Give each subagent this prompt, with the placeholders filled in:

> You are the `<dim>` reviewer for /ace-review. Read `$S/rubric.md`, then `$S/dimensions/<dim>.md`, then follow it. Wherever they say CLAUDE.md, read `$B/rules/CLAUDE.md` (and `$B/rules/repo-CLAUDE.md` if it exists): it is the base branch's copy, and where it differs from the CLAUDE.md you were started with, it wins. The change is described by the bundle in `$B` (start with `target.json`, `stat.txt`, `files.txt`, `diff.patch`; `pr.md` and `log.txt` if present). Each entry in `$B/leads.json` whose `dimension` is `<dim>` is a line that matched a mechanical check: look at every one, and report the real ones, one finding per class listing all its locations. Never report again a finding that `$B/previous.json` lists, whatever its status. If the change works around a flaw in ACE's design, write it to `$B/flaws-<dim>.json` as rubric.md's "Design flaws worked around" says. The repo under review is `<repo>`; ACE core is `/opt/ace`. Read the surrounding code, not only the diff. Write your findings as a JSON array to `$B/findings-<dim>.json` using the schema in rubric.md, and reply with just the count of findings by severity, and of design flaws.

Over ~1500 changed lines, `design` and `correctness` may each run as two reviewers on disjoint file lists, writing `findings-<dim>-1.json` and `-2.json`.

**A fix round** (`delta`) checks the fixes instead of searching again. Use `delta-files.txt`, the new commits in `log.txt` and `previous.json` to split the delta into fixes (step 3) and new work. Launch the five reviewers above on just the new-work files, adding to their prompt "This is round `<round>`. Review only `<files>` in `$B/delta.patch`: report findings in code it adds or changes, or makes reachable in a new way, and no pre-existing ones." With no new work, launch none.

## 3. Coverage of changed lines

After pytest exits, and only if `coverage.xml` exists, run this from the **repo under review** (its own toplevel, so the paths line up):

```bash
cd <repo> && /venv/bin/diff-cover $B/coverage.xml --compare-branch=<merge_base from target.json> --format json:$B/diff-cover.json,markdown:$B/diff-cover.md
```

If a repo's `coverage.xml` paths don't line up (0 lines matched), retry with `--src-roots <src dir>` before giving up. Coverage is reported, not gated, and it measures only the tests in `tests.txt`.

Then launch the `tests` reviewer with the same prompt as the others (in a fix round, only for new work). It also reads `$B/pytest.txt`, `$B/diff-cover.json` and `$B/unmarked.txt`.

In a fix round, launch the `fixes` reviewer **last**, once every other reviewer has finished, because it edits files to probe the tests: the same prompt with `<dim>` set to `fixes`, plus "The new-work files, which other reviewers have: `<files or none>`."

## 4. Verify, then judge

Each finding is judged in a fresh context by a verifier that tries to disprove it.

1. When every `findings-*.json` exists, run `/venv/bin/python $S/scripts/findings.py collect $B`. It prints the plan.
2. Launch every verifier in one message. For each `single` entry and each vote `k`:
   > You verify candidate `<cid>` for /ace-review, vote `<k>`. Read `$S/rubric.md` and `$S/dimensions/verify.md`, then follow its "One finding" section for the bundle in `$B`.

   If `batch`, `carry` or `flaws` is non-empty, one more:
   > You are the batch verifier for /ace-review. Read `$S/rubric.md` and `$S/dimensions/verify.md`, then follow its "Batch" section for the bundle in `$B`: candidates `<batch>`, earlier findings `<carry>`, design flaws `<flaws>`.
3. Run `findings.py tally $B`. If it lists missing votes, relaunch those verifiers once, then tally with `--allow-missing`.
4. Read `$B/survivors.json` and `$B/previous.json`. Merge duplicates across dimensions: keep the most severe, add the other's evidence. Mark a survivor that is an earlier finding again with `"repeats": "<its id>"`. Then judge each new survivor as the lead, by rubric.md's "Lead judgment": a `bucket` and a one-line `judgment`. Write them, ranked, to `$B/ranked.json`. In `$B/flaws.json`, merge flaws that two reviewers both found into one entry, then run `findings.py finish $B`, which refuses a bucket the rubric forbids. `summary.json` lists each flaw with the `issue` the verifier matched it to, or null for a new one. finish writes nothing to GitHub.

## 5. Report

Write `$B/report.md` and print it in the terminal, using the template in rubric.md. It draws on `target.json`, `summary.json`, `verified.json`, `intent.md` and the check results. The verdict is never better than `summary.json`'s `verdict_floor`, and a design flaw never makes it worse.

When a flaw is undecided, also say it at the end of your reply in the terminal, in one line per flaw with its recommendation, so it is not missed under the findings.

Don't post anything anywhere. The user decides what goes on the PR.

## 6. Answers and the conventions

When the user answers a finding, record it, so the next round neither repeats nor rechecks it: `findings.py answer $B <id> fixed|wrong|intentional|"didn't matter" [--note TEXT]`. A decision on the rule changes is `findings.py answer $B rules accepted|rejected`.

Design flaws are GitHub issues labeled `design flaw` in core's repo (ACE-Collective/ace3), whatever repo is reviewed. The review files a new flaw's issue and never changes an issue after that. Its state is the user's: open is a known flaw, closed as not planned is a flaw found wrong (reviewers skip it), closed as completed is fixed.

A new flaw is filed only when the user answers it:
- `defer` (keep going) or `address` (pause this branch and fix the flaw first): run `findings.py file $B F<n>`, which files the issue and prints its link. The fix for `address` is never made in this branch: it is its own PR, which closes the issue with `Fixes #<n>`, and this branch rebases onto it and drops its workaround.
- `wrong` when it isn't a flaw: nothing is filed.

A known flaw already has its issue; whether to stop or keep going is the user's call.

Before filing a flaw found in an integration or signatures review, show the user its title and body: the issue is public. `file` refuses while `known-flaws-error.txt` is in the bundle: run `findings.py known $B` again and check the flaw against `known-flaws.json` first.

Offer `gh issue list --label "design flaw"` when the user asks what to fix next. When they ask how the review is doing, run `findings.py stats [--since YYYY-MM-DD]`; its `lines changed` and `unchanged` are inferred from whether the code moved, not answered.

When they reject a finding because the rule is wrong, or name a rule the review missed, offer a small edit to the **Engineering values** section of `/opt/ace/CLAUDE.md` (or to a dimension file, if it is only a review heuristic). Make it only once they agree.

## 7. Fixing findings

Whoever fixes findings follows this, so the next round finds nothing new in the fixes:

- Fix the **act on** findings, or the ones the user names. A consider or noted finding is fixed only when named. Fix one at a time, with the smallest change its *Fix* describes, and nothing else in that edit.
- A `P` id is pre-existing and is never fixed in this branch. Offer to file it as an issue, or as a `local/TODO.md` line for an integration or signatures. A design flaw goes through step 6.
- A test written for a finding must be seen to fail without the fix (the `tdd` skill), with both runs in the PR description's Testing section.
- Ask before a fix that reaches past the finding's function or changes behavior it didn't name.
- A chain two fixes deep (Step back names it) means the fixes share a wrong premise: recommend taking them out of the branch, not a third fix.
- Record each with `findings.py answer $B <id> fixed`, and run `prepare.py --check` until it prints nothing. Run the next round only when the user asks.
