---
name: bug-fix
description: "Fix an ACE bug at its cause: make it fail on demand, prove the mechanism by running code, then fix it with a test that fails without the fix. Use when asked to fix, debug, diagnose or investigate a bug, a crash, a hang, a wrong result, a regression, a flaky test or a production error in ACE, or when /ace-review says a fix works around a symptom. Covers building a check that goes red, ranking falsifiable hypotheses, production evidence (logs, error and crash reports), finding the release a regression started in, design flaws that block a correct fix, and what the PR must show. For writing the test itself use tdd."
---

# Fixing a bug at its cause

The fix is usually the easy part. The hard parts come first: a check that fails on this bug, and a mechanism proven by running code. Skip them and the fix rests on a guess. Then every review round spends its time on code built around that guess. Every line that ships traces back to evidence. A backstop added because it "might help" is a hypothesis, and it doesn't ship.

Adapted from Matt Pocock's `diagnosing-bugs` skill and the bug-fix playbook and root-cause principles of Lauren Tan's pstack (MIT, see `LICENSE`).

## Ask in this order

1. **Can you make it fail on demand?** Build the check first. Nothing else starts until it fails, or until you have told the user why you can't build it.
2. **What is the mechanism, and what proves it?** A run that flips the check, not a reading of the code.
3. **Where is the first wrong decision?** That is where the fix goes.
4. **Does the correct fix belong in this change?** If it needs ACE's design to change, it is a design flaw.
5. **Does the regression test fail without the fix?**

## 1. A check that goes red

Build one command that drives the real code path and asserts the symptom that was reported. Run it once and keep the output. It has to fail on this bug, give the same result every run, and finish in seconds. Some ways to build one, roughly best first:

- a pytest that reaches the bug (the `tdd` skill's *Where to test*);
- a real `ace` command, or an HTTP request against the dev stack;
- a captured input replayed: a file, an email, a request body. Never copy customer data into `tests/` (CLAUDE.md § Test data): build the smallest input that has the same structure;
- a throwaway script that calls the function with the bad input;
- for a bug that happens only sometimes: loop the trigger, add threads or load, and shorten timeouts until it fails often enough to work with.

`ace correlate` runs observables through the local engine. It changes the engine's state, so ask before running it.

Then shrink the check. Cut inputs, config and steps one at a time and rerun after each cut, until every part left is needed for the failure. The shrunk check becomes the regression test.

If you can't build a check, stop and say what you tried. Ask for access to where it reproduces, for the logs, error report or crash report, or for permission to add instrumentation. Don't start theorizing without a check.

## 2. Evidence from where it happened

- **Logs.** Records carry their identifiers as `extra={}` fields: root uuid, observable, module, path, `crash_id`.
- **Error reports.** `data/error_reports/` has one for each record logged at ERROR with a traceback.
- **Crash reports.** For an analysis module that failed or hung, `data/crash_reports/YYYY/MM/DD/<crash_id>/` holds the traceback, the analysis tree and the file. For a hang it holds every thread's stack instead of a traceback. From another node, use `GET /api/v2/crashes/{crash_id}/download` (`docs/CRASH_REPORTS.md`).
- **When it started.** A regression has a first release. Compare how often it happens before and after each release; `CHANGELOG.md` lists each release's PRs. Read the diff of the release where it starts for code on the failing path. Over a wide window, run `git bisect run` with the check.

## 3. Hypotheses

Write 3 to 5 ranked hypotheses before testing any of them. Each one makes a prediction: "if X is the cause, changing Y makes the failure go away" (or "changing Z makes it worse"). A hypothesis without a prediction is a guess: sharpen it or drop it. Show the list to the user if they're around, since they often know which one it is. Don't wait for them if they aren't.

Change one thing at a time. Instrument where the hypotheses disagree: use a debugger or REPL in the `dev` container, or temporary log lines with one unique tag (`[DBG-7f3a]`) so a single grep removes them all.

The mechanism is proven when changing what the hypothesis names flips the check. Code that "would" do it doesn't count until it has.

## 4. Fix the first wrong decision

Ask "why" at each step until the answer is a decision in the code, not a consequence of an earlier one. Then ask whether the state that broke the code is legitimate:

- If ACE can be in that state, the code that broke on it is the cause, and handling the state there is the fix.
- If the state should never exist, a check where it broke only hides the bug. Find what produced the state.

A symptom fix is usually a guard, a retry, a swallowed exception, a clamped value or a broader `except`. Find every place with the same fault and fix them all.

**No correct place in this change.** Sometimes the correct fix is a change to how ACE works: a hook that doesn't exist, state recorded in the wrong place, or no way for a test to reach the bug. That is a design flaw. Check `gh issue list --label "design flaw"`, and if an issue matches, follow the workaround it describes. Otherwise tell the user, and let them choose between fixing the flaw first in its own PR and a contained workaround now.

**Two fixes on one premise failed.** Stop. Write down in one sentence the premise both fixes assumed, and test it directly before you write a third.

## 5. The regression test and the PR

Turn the shrunk check into a test with the `tdd` loop. Watch it fail on the unfixed code for the reason that was reported, apply the fix, and watch it pass. Then rerun the original check, before it was shrunk. If the only test you can write is too shallow to reach the real pattern (one caller, when the bug needs two), say so: that gap is a finding of its own.

Before asking for a review:
- remove the tagged log lines and throwaway scripts (grep the tag);
- run `prepare.py --check` (the `tdd` skill's last section) until it prints nothing;
- write the PR description so it states the mechanism and how it was proven, shows the failing and then passing test output, and lists anything left unfixed.

## Traps

- **Cached analysis.** A fix to a module with `cache_ttl` set doesn't reach observables already in the analysis result cache: the key holds the `version` in the module's YAML block, not its code. Bump `version` (`docs/ANALYSIS_CACHING.md`).
- **Persisted state.** A failure that shows only after a restart or rebuild usually comes from persisted state: data volumes, the dev-only `etc/saq.yaml`, a stale alembic stamp. Check those first.
- **The wrong bug.** A check that fails, but not with the reported symptom, is a different bug nearby, and fixing it leaves the reported one in place.
- **A fix that moves the failure.** Turning a hang into a restart loop, or an exception into a silent `None`, changes the symptom but leaves the bug. Run the original check again, and read what the fixed code now does on the failing input.
