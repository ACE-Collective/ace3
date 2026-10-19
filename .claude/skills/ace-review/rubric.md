# /ace-review rubric

## Who this review is for

The maintainer wants to know whether a change can ship and what must change first. They have stopped reading diffs. Every finding costs them attention, so a finding has to be about something they care about, be backed by the code, and say concretely what goes wrong.

Their priorities, in order: **uptime > logging > tests > performance**, then keeping the code lean. A correctness bug ranks by what it does to one of those. A bug that hangs a service is an uptime blocker; a wrong value shown on one GUI page is a fix-first.

## Severity

- **blocker**: the change must not merge as is.
  - It can take ACE (or one of its services) down, hang it, or keep it from restarting.
  - It can lose or corrupt data, or deadlock or long-lock a live table.
  - A migration forks the chain or drifts from the model.
  - It hides a failure from operators on a path that matters.
  - Tests fail.
  - New behavior has no tests at all.
  - It is a security hole: missing permission check, injection, XSS, or secrets in logs.
- **fix-first**: merge after fixing.
  - A caught exception doesn't go through `log_loop_exception()`, or is silent with no justifying comment.
  - A failure path is untested, or a test has no marker.
  - It's an N+1 query, OFFSET paging, or per-request heavy work on a user-facing path.
  - It re-implements a helper that already exists.
  - It contains unrelated scope.
  - It breaks an established pattern in `CLAUDE.md`: Flask instead of aceapi_v2, raw SQL instead of the ORM, a hand-written migration, an integration leaking into core, a config key with no schema field.
  - It's a real bug with limited blast radius.
- **nit**: worth one line, never blocks. Examples: a comment or docstring that only restates the code, a needless module or exception class, a small duplication, a misleading name.

Keep nits few. Report at most about 5 per review, and pick the ones that best illustrate a habit worth correcting.

## Verdict

- **rework**: any verified blocker, or the change is so far from the conventions that fixing it item by item is the wrong approach (e.g. a whole new Flask API).
- **fix-first**: any verified fix-first finding.
- **ship**: everything else. A review may be "ship" with nits.

When the tests weren't run (lock held, range not checked out), the verdict may not be "ship". Say "fix-first: tests not verified" unless the change has no code (docs only).

## Do not report

- GUI implementation style: template structure, JS idiom, CSS. GUI code is reviewed only for broken behavior, performance and security.
- Software-engineering purism: SOLID, layering, "should be a class", dependency injection, function length, naming taste.
- Log message formatting (f-string vs `%s` vs `.format()`).
- `typing.List`/`Optional` vs `list` / `X | None` in lines the change didn't write.
- Anything a formatter would fix: whitespace, quote style, import order (there is no formatter configured).
- Hypothetical problems with no path in this codebase ("if someone later calls this with None..."). Name the caller or input that triggers it, or drop it.
- Files under `etc/saq.yaml` (dev-only overlay) or `etc/saq.unittest.default.yaml`, judged as if they were production config.

## New vs pre-existing

A finding is **new** if the change introduced or modified the offending lines, or if the change made pre-existing code reachable in a new way (e.g. it now calls an old function with a new input that breaks it).

A finding is **pre-existing** if the offending code was already there and the change only touches the same function or file. Pre-existing findings go in their own report section, never affect the verdict, and are limited to the functions the change edits (not the whole file). They're for the maintainer's backlog, not for the author.

## Findings schema

Each reviewer writes a JSON array to `$B/findings-<dim>.json`:

```json
[
  {
    "dimension": "uptime | logging | tests | performance | design | correctness",
    "severity": "blocker | fix-first | nit",
    "origin": "new | pre-existing",
    "file": "path relative to the repo under review",
    "line": 123,
    "title": "one line, the claim (<= 80 chars)",
    "evidence": "what the code does, quoting or citing file:line, including the caller/input that triggers it",
    "impact": "what happens in production because of it",
    "fix": "the smallest change that resolves it; name the existing helper to use if there is one"
  }
]
```

Write `[]` if there's nothing. Don't pad.

## Report template

```markdown
# /ace-review: <repo kind> <branch or range> (<short sha>, base <base>)

**Verdict: <SHIP | FIX-FIRST | REWORK>**: <2-4 sentences: the one or two things that decide it>

## Checks
- Tests: <N passed, M failed, K skipped, exit code / "not run: <reason>">, <files run>
- Changed-line coverage (from the tests above): <X% of N lines>; uncovered: <file:lines, top few>
- Unmarked tests: <none | list>
- Migrations: <n/a | single head per chain | FORKED: ...>; model drift: <n/a | clean | DRIFT: ...>
- PR description Testing section: <present | missing>

## Findings
### Blockers
1. **<title>** (`file:line`, <dimension>): <evidence>. *Impact:* <impact>. *Fix:* <fix>
### Fix first
...
### Nits
...

## Pre-existing, nearby (not blocking)
- `file:line` (<dimension>): <title>, <one line>

<sub>Dropped as unverified: N. Bundle: $B</sub>
```

Leave out an empty section's heading rather than writing "none", except under Checks.
