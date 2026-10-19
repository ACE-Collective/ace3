---
name: ace-review
description: Review an ACE branch, PR or commit range against the project's engineering values (uptime, logging, tests, performance, keeping it lean) and give a ship / fix-first / rework verdict. Works for ACE core, signatures/ and integration repos on any git host. Use when asked to review a PR, a branch, or "my changes" in this project.
argument-hint: "[<repo path>] [PR# | branch | A..B] [--base REF]"
---

# /ace-review

You review one change to ACE the way its maintainer would. They no longer read diffs line by line; they rely on this review to catch what they care about. The values come from the **Engineering values** section of `/opt/ace/CLAUDE.md`, which is the source of truth: if a rule isn't there, it isn't a rule. `rubric.md` (next to this file) says how to rank findings and what to ignore. Read both before starting.

The arguments are `$ARGUMENTS`.

Work in a bundle directory under your scratchpad, e.g. `<scratchpad>/ace-review/<repo-name>-<short-sha>/`. Below it's called `$B`, and the skill directory is called `$S` (`/opt/ace/.claude/skills/ace-review`).

## 1. Resolve the target

- **Which repo.** With no repo path, review ACE core (`/opt/ace`). A path such as `integrations/<name>` or `signatures` names a separate repo: it is gitignored in core, versioned on its own, and possibly hosted somewhere other than GitHub (Azure DevOps, a plain git server). Only plain `git` is assumed to exist.
- **Nothing given and it's unclear what to review.** Run `/venv/bin/python $S/scripts/prepare.py --list` and ask which repo to review, listing the ones that are ahead of their base or have uncommitted work. Never merge several repos into one diff.
- **A PR number.** Resolve it with the host's CLI only if that CLI is installed and authenticated: `gh pr view N --json number,title,body,headRefName,baseRefName,url` for GitHub, `az repos pr show --id N` for ADO. Otherwise ask for the branch name. Save the title and body to `$B/pr.md`.
- **Checkout.** The tests run from `/opt/ace` (`SAQ_HOME`), so the change under review must be checked out in its own repo. If a different branch is checked out, **ask before switching**, and never switch over uncommitted work. An explicit `A..B` range of commits that are already merged can be reviewed without a checkout: skip the test run and say so in the report.
- **Base.** By default `prepare.py` uses `origin/HEAD`, then `main`, then `master`. Pass `--base` when the PR targets something else; for a PR, use its `baseRefName`. Long-lived feature branches such as `jd/svs` are common here, so check the PR's actual base and don't assume `main`.

Then run:

```bash
/venv/bin/python $S/scripts/prepare.py --repo <repo> [--base REF | --range A..B] --out $B
```

It writes the following into `$B`:

| File | Contents |
|---|---|
| `target.json` | repo, kind (core/integration/signatures), merge-base, flags for model and migration changes |
| `diff.patch` | the diff, including uncommitted and untracked work when reviewing the checked-out branch |
| `stat.txt`, `files.txt`, `log.txt` | diff stat, changed files, commit messages |
| `tests.txt` | test paths, mapped through the `tests/test_external_integration_<name>` symlinks for integrations |
| `unmarked.txt` | tests in the changed test files that have no run marker |
| `cov_sources.txt` | the `--cov` arguments to use |

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

> You are the `<dim>` reviewer for /ace-review. Read `$S/rubric.md`, then `$S/dimensions/<dim>.md`, then follow it. The change is described by the bundle in `$B` (start with `target.json`, `stat.txt`, `files.txt`, `diff.patch`; `pr.md` and `log.txt` if present). The repo under review is `<repo>`; ACE core is `/opt/ace`. Read the surrounding code, not only the diff. Write your findings as a JSON array to `$B/findings-<dim>.json` using the schema in rubric.md, and reply with just the count of findings by severity.

For a diff of more than ~1500 changed lines, the `design` and `correctness` reviewers may split the work by subsystem. If they do, launch two of each, each with a disjoint list of files named in its prompt, and have them write `findings-<dim>-1.json` and `findings-<dim>-2.json`.

## 3. Coverage of changed lines

After pytest exits, and only if `coverage.xml` exists, run this from the **repo under review** (its own toplevel, so the paths line up):

```bash
cd <repo> && /venv/bin/diff-cover $B/coverage.xml --compare-branch=<merge_base from target.json> --format json:$B/diff-cover.json,markdown:$B/diff-cover.md
```

If a repo's `coverage.xml` paths don't line up (0 lines matched), retry with `--src-roots <src dir>` before giving up. Coverage is **reported, not gated**: there is no threshold, but uncovered new lines feed the tests reviewer. These numbers only measure what the tests in `tests.txt` exercise. Say so in the report; don't present them as whole-suite coverage.

Then launch the `tests` reviewer with the same prompt as the others. It also reads `$B/pytest.txt`, `$B/diff-cover.json` and `$B/unmarked.txt`.

## 4. Verify

When every `findings-*.json` exists, launch **one** verifier subagent:

> You are the verifier for /ace-review. Read `$S/rubric.md` and `$S/dimensions/verify.md`, then follow it for the bundle in `$B`. Write `$B/verified.json`.

## 5. Report

Write `$B/report.md` and print it in the terminal, using the template in rubric.md:

1. Verdict and a short rationale.
2. Check results: tests, changed-line coverage, migrations and drift.
3. Findings from `verified.json`, ranked.
4. The non-blocking **Pre-existing, nearby** section.

Don't post anything anywhere. The user decides what goes on the PR.

## 6. Feed back into the conventions

When the user rejects a finding because the rule is wrong, or names a rule the review missed, offer a small edit to the **Engineering values** section of `/opt/ace/CLAUDE.md` (or to a dimension file, if it is only a review heuristic) so the next review and the next author both follow it. Make the edit only once they agree.
