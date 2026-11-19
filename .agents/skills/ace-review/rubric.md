# /ace-review rubric

## Who this review is for

The maintainer has stopped reading diffs and wants to know whether a change can ship and what must change first. Every finding costs their attention, so it is about something they care about, backed by the code, and says what goes wrong. Their priorities: **uptime > logging > tests > performance**, then lean code. A correctness bug ranks by what it does to one of those. A bug that hangs a service is an uptime blocker; a wrong value shown on one GUI page is a fix-first.

## Severity

- **blocker**: the change must not merge as is.
  - It can take ACE (or one of its services) down, hang it, or keep it from restarting.
  - It can lose or corrupt data, or deadlock or long-lock a live table.
  - A migration forks the chain or drifts from the model.
  - It hides a failure from operators on a path that matters.
  - It can drop an event that should alert on a path that runs in production: a filter, exclusion or suppression that matches too much, or a cached answer one of them reads after the data behind it changed.
  - Tests fail.
  - New behavior has no tests at all.
  - It is a security hole: missing permission check, injection, XSS, or secrets in logs.
- **fix-first**: merge after fixing.
  - A caught exception is logged without its traceback (`logging.exception()` or `log_loop_exception()`), or is silent with no justifying comment.
  - A failure path is untested, or a test has no marker.
  - It's an N+1 query, OFFSET paging, or per-request heavy work on a user-facing path.
  - It re-implements a helper that already exists.
  - It contains unrelated scope.
  - It breaks an established pattern in `CLAUDE.md`: Flask instead of aceapi_v2, raw SQL instead of the ORM, a hand-written migration, an integration leaking into core, a config key with no schema field.
  - It doesn't do what its description says, or a bug fix has no test that fails without it.
  - It's a real bug with limited blast radius.
- **nit**: worth one line, never blocks. Examples: a comment or docstring that only restates the code, a needless module or exception class, a small duplication, a misleading name.

## Lead judgment

Severity says how bad a finding would be; whether it holds the PR is the lead's call. After verification each new survivor goes in one bucket, with a one-line `judgment`:

- **act on**: it holds the PR. Every confirmed blocker. A fix-first whose impact names harm on a path the change makes run in production (a hang or crash, a lost or wrong record, a dropped alert, a failure nobody hears about), or a test gap that would let this change's own fix or new behavior break unseen.
- **consider**: real, and fixing it now is the user's call. Every PLAUSIBLE finding, since its trigger isn't shown. A fix-first on a path nothing reaches today, or whose fix costs more than the harm it prevents.
- **noted**: the nits. Keep about 5, the ones that best show a habit worth correcting.

Six reviewers each fill a list, so some findings are always left over. A round whose survivors are all consider and noted is a ship: say so.

## Verdict

- **rework**: an act-on blocker, or the change is so far from the conventions that fixing it item by item is the wrong approach (e.g. a whole new Flask API), or a bug fix works around a symptom whose cause can be found and fixed within the change.
- **fix-first**: an act-on finding, or one from an earlier round still open.
- **ship**: everything else, consider and noted findings included.

When the tests weren't run (lock held, range not checked out), the verdict may not be "ship". Say "fix-first: tests not verified" unless the change has no code (docs only). Likewise, while `rule_changes_status` is `pending` say "fix-first: rule changes need your decision", and when it is `rejected` the rule changes are a fix-first finding of their own.

## Design flaws worked around

Sometimes a change is shaped by a flaw in ACE's design rather than by a mistake of its own. The maintainer hears about every such flaw and decides whether to stop or keep going; either way it becomes a `design flaw` issue in core's repo. A flaw never holds the change up by itself.

A design flaw is in the code on the base branch, not in the change, and fixing it is a piece of work of its own, beyond what this change should take on. Signs of one:
- The change special-cases a type, mode, module or caller because a shared abstraction doesn't fit it.
- It copies or re-derives state because the model doesn't record it, or records it in the wrong place.
- It polls, sleeps or re-reads because there is no event, hook or persisted value to use instead.
- It catches an exception that an API raises for an ordinary condition, or checks for a value that an API should never return.
- It adds a lock, retry or ordering rule because ownership of some state is unclear.
- It reaches into another subsystem's internals because the extension point it needs doesn't exist.
- It is the second or third copy of the same workaround in the tree. Search for the others.

Keep the categories apart:
- A bug or a convention broken by the change itself is a **finding**.
- A symptom whose cause the change could fix itself is a finding (and a rework, per the verdict above), not a flaw.
- A flaw is reported **as well as** any finding on the workaround. The workaround is judged as code like anything else: a clean workaround of a real flaw has no finding at all.

For each flaw, size the real fix:
- **small**: one subsystem, no data migration, a day or so.
- **medium**: several modules or a migration, but bounded.
- **large**: cross-cutting, many callers, or migrating existing data.

Then recommend **stop** (pause this branch and fix the flaw first, in its own PR, never here) or **keep going**:
- Recommend stop when the fix is small, when the workaround would spread (other code will copy it, it is a pattern other authors will follow), or when it writes data in a shape that is costly to migrate later.
- Recommend keep going when the fix is medium or large and the workaround is contained and easy to remove once the flaw is fixed.

Read the known flaws before reporting one: `$B/known-flaws.json`, one entry per issue, with its `id` (the issue number), `status` (`open` or `wrong`) and `body`. A flaw already there is reported again with its id in `known`. Skip a flaw whose status is `wrong`.

Report only flaws that this change actually works around, with the code that does it. A flaw you happen to notice in code nearby, which the change doesn't depend on, isn't one.

## Do not report

- GUI implementation style: template structure, JS idiom, CSS. GUI code is reviewed only for broken behavior, performance and security.
- Software-engineering purism: SOLID, layering, "should be a class", dependency injection, function length, naming taste.
- Log message formatting (f-string vs `%s` vs `.format()`).
- `typing.List`/`Optional` vs `list` / `X | None` in lines the change didn't write.
- Anything a formatter would fix: whitespace, quote style, import order (there is no formatter configured).
- Hypothetical problems with no path in this codebase ("if someone later calls this with None..."). Name the caller or input that triggers it, or drop it. The consumer the PR description names counts as a caller, and so does the usage the change's own docs or examples recommend. A problem that appears when someone follows them is not hypothetical.
- Files under `etc/saq.yaml` (dev-only overlay) or `etc/saq.unittest.default.yaml`, judged as if they were production config.

## New vs pre-existing

A finding is **new** if the change introduced or modified the offending lines, or if the change made pre-existing code reachable in a new way (e.g. it now calls an old function with a new input that breaks it).

A finding is **pre-existing** if the offending code was already there and the change only touches the same function or file. Pre-existing findings are limited to the functions the change edits (not the whole file), get `P` ids, never affect the verdict, and are never fixed in the branch: they are filed for the maintainer's backlog. A fix round reports none.

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

In a fix round, `answers` names the earlier finding whose fix put the code there. Write `[]` if there's nothing. Don't pad.

A reviewer that finds a design flaw also writes `$B/flaws-<dim>.json`, an array of:

```json
[
  {
    "dimension": "the reviewer's dimension",
    "title": "one line, the flaw in ACE, not the change (<= 80 chars)",
    "flaw": "what is wrong in ACE's design and where (files, subsystem), and how it forces the workaround",
    "area": "subsystem, e.g. engine, analysis tree, cas, gui alert page",
    "workaround": "what the change does because of the flaw",
    "file": "path in the repo under review where the workaround is",
    "line": 123,
    "fix_size": "small | medium | large",
    "fix": "a sketch of the real fix",
    "recommendation": "stop | keep going",
    "why": "one line: why stop or keep going",
    "known": "the issue number when known-flaws.json already has it, else omit"
  }
]
```

Write no file when there are none.

## Dismissals

A reviewer that saw a harm in the change and decided not to report it writes it to `$B/dismissed-<dim>.json`: a trade-off it took to be someone else's choice, a problem it judged to have no caller yet, a cost it judged too small. List only those, not every check that came up clean; most rounds have none. The batch verifier tries to show each dismissal wrong, the way it tries a finding, and a dismissal it overturns comes back as a finding.

```json
[
  {
    "dimension": "the reviewer's dimension",
    "file": "path relative to the repo under review",
    "line": 123,
    "title": "one line, the problem seen (<= 80 chars)",
    "harm": "what would go wrong, for whom, and what triggers it",
    "why_not": "why it was not reported"
  }
]
```

Write no file when there are none.

## Report template

```markdown
# /ace-review: <repo kind> <branch or range> (<short sha>, base <base>), round <N>

## Rule changes: your decision
<only while rule_changes_status is pending: what each entry in rule_changes does, from rule-changes.patch, one line each. The change was judged by the base branch's rules.>

## Design flaws: your decision
<one entry per flaw in summary.json whose status is undecided:>
- **<id>: <title>** (<fix_size> fix, <"new" | the issue link>): <the flaw, one or two lines>. *Here:* <what the change does around it, `file:line`>. *Real fix:* <fix>. *Recommend:* **<stop | keep going>**, <why>.
<then one line per flaw that already has an issue: "Also works around #<issue>: <title>. *Recommend:* **<stop | keep going>**, <why>.">
<end with: "Answer each new one with defer (keep going, fix it later), address (pause this branch; the fix is its own PR, which lands first) or wrong; defer and address file it as a public issue in ACE-Collective/ace3." When `known` reported an error, say that the reviewers had no known flaws to match against, so a flaw listed as new may already have an issue.>

**Verdict: <SHIP | FIX-FIRST | REWORK>**: <2-4 sentences: the one or two things that decide it>

**Step back:** <when a chain in summary.json is 2 or more deep: its ids, and that its fixes share a wrong premise, so take them out of this branch and give the first finding its own PR rather than a third fix. Otherwise only from round 4 on, when the verdict isn't ship: the new findings per round from target.json's history, and the part of the change that keeps producing them.>

**Intent:** <intent.md in one or two lines (a fix round with no correctness reviewer reuses the last round's): the stated problem, whether the change solves it at its cause, and whether that cause is shown or argued>

## Checks
- Tests: <N passed, M failed, K skipped, exit code / "not run: <reason>">, <files run>
- Changed-line coverage (from the tests above): <X% of N lines>; uncovered: <file:lines, top few>
- Unmarked tests: <none | list>
- Migrations: <n/a | single head per chain | FORKED: ...>; model drift: <n/a | clean | DRIFT: ...>
- PR description Testing section: <present | missing>
- Review: <full | fix round since round N-1, new work: <files | none> | full, because <delta_reason>>

## Still open from earlier rounds
- **<id>: <title>** (`file:line`, <severity>)

## Act on
1. **<id>: <title>** (`file:line`, <severity>, <dimension>; <"from the fix for <answers>" when set>; <"dismissed by the <dimension> reviewer, overturned" when it has a dismissal>): <evidence>. *Impact:* <impact>. *Fix:* <fix>. *Why it holds the PR:* <judgment>
## Consider
<the same, ending *Why it can wait:* <judgment>>
## Noted
...

## Pre-existing, for the backlog
- **<P id>** `file:line` (<dimension>): <title>, <one line>
<end with: "These are not for this branch. File them as issues?">

<sub>Dropped as unverified: N (and N design flaws). Dismissals: N upheld, N overturned. Not repeated from earlier rounds: N. Fixed since the last round: <ids>. Bundle: $B</sub>
```

Number each finding with its `id` from `verified.json`, so the user can answer it by id. Leave out an empty section's heading rather than writing "none", except under Checks.
