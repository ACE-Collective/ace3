---
name: tdd
description: "Write ACE tests that can fail: red before green, one behavior at a time, through the interface the behavior is used by. Use when writing, changing or judging a test, adding a regression test for a bug, building a feature test-first, answering a tests finding from /ace-review, or when asked for TDD, red-green or a failing test. Covers proving a test can fail by breaking the code it guards, the two-edit check for a test worth keeping, tautological and mock-only assertions, where to test each kind of ACE code, and what to mock. To find a bug's cause before fixing it use bug-fix."
---

# Tests that can fail

A test is a claim about what the code does for the code, user or service that calls it. Nobody has evidence for that claim until they have seen the test fail. Most of the test findings /ace-review raises are of two kinds: tests that still pass with the code they cover removed, and failure branches that no test runs. This loop prevents both. Write the test, watch it fail for the reason you expect, make it pass, and put the failure in the PR.

CLAUDE.md § Testing says how to run tests: in the `dev` container, through `bin/exec-in-container.sh` from the host or a worktree, with run markers, one run at a time. § Engineering values → Tests says what must be covered.

Adapted from Matt Pocock's `tdd` skill and the `tdd` and `principle-test-behavior-not-implementation` skills of Lauren Tan's pstack (MIT, see `LICENSE`).

## The loop

1. **List the behaviors and where they are seen.** Write one line for each behavior the change adds or fixes, and name the interface a caller sees it through (see *Where to test* below). Failure paths are behaviors too: each new `except`, refusal, timeout and fallback gets a line. Ask the user only when the code doesn't make the interface clear.
2. **Red.** Write the test for one behavior and run only that test:
   ```bash
   bin/exec-in-container.sh /venv/bin/pytest tests/saq/path/test_x.py::test_name -q
   ```
   It must fail on an assertion about that behavior. An ImportError, a fixture error or a typo doesn't count. A test that passes before the code exists is testing something else.
3. **Green.** Write only the code that test needs. Run it again and see it pass.
4. **Next behavior.** Don't write all the tests first. Tests written before you know the code test the shape you imagined, not the behavior.
5. **The whole set**, at the end: the changed test files and the tests of the changed modules, with `-n auto`.

For a bug fix, the red run is against the unfixed code: the test fails on the bug, then the fix makes it pass.

## Prove that a test can fail

This applies when the code already exists: a test added after it, a test written to answer a review finding, or a test you inherited.

1. Break what the test guards. Revert the fix, delete the line the test is about, invert the condition, or return a wrong value.
2. Run only that test, and see it fail with an assertion about the behavior.
3. Restore the code, see the test pass, and check with `git diff` that the break is gone.

If the test still passes with the behavior broken, fix the test. The usual causes:
- the assertion is looser than the contract;
- the expected value comes from the code under test;
- the test asserts on data it built itself, or on a mock it set up;
- `assert x, 1` is written where `assert x == 1` was meant (the `1` is the failure message).

Record each break in the PR description's Testing section: the edit, the command, the failing result and the passing result after the restore. The review looks for it.

## A test worth keeping

Check every test against two imagined edits:

- **Break the behavior:** a wrong value, a skipped effect, or the effect done twice. The test must fail.
- **Change the internals** and keep every result a caller can see. The test must still pass. One that fails here is tied to the implementation: it breaks on every refactor and catches no bug.

Take expected values from the requirement and write them as literals. Don't compute them by calling the code, or by repeating the code's arithmetic. Assert what the contract promises. Don't pin more than that, such as an exact error message that no caller reads. Don't check less, such as only that nothing raised.

## Where to test

| What the change touches | Test it through | Assert on |
|---|---|---|
| an analysis module | the standard analysis-module test in CLAUDE.md: the engine in single-shot mode, then `load_root` from disk | the analysis details, observables, tags and detection points on the reloaded root |
| an `aceapi_v2` endpoint | the `client` fixture in `tests/aceapi_v2/conftest.py` | the status, the body, and what a later read returns |
| a service or a loop | start and stop it, then `wait_for_condition` / `wait_for_log_count` | the effect and its log record |
| database code | the real per-session database, with an `integration` marker | what the public function returns, or what a later read sees |
| a failure path | make the dependency fail (monkeypatch it to raise) | the log record (`caplog`, `search_log`), the fallback taken, and what the caller gets |
| an `ace` command | its entry point with `argv` | the exit code, the output and the effect |

Mock only what ACE doesn't own: network peers and outside services, the clock, randomness, and a tool that isn't installed. Use the real database in integration tests. Use `monkeypatch` rather than `MagicMock`. Never mock the code under test or an ACE module it calls, because then the test only proves the mock.

## Traps

- **No marker.** A test without a `unit`, `integration` or `system` marker never runs under the default filter, and it fails no check.
- **The in-memory root.** An analysis-module test that asserts on the root it built, after the engine ran, isn't testing what the engine saved. Reload it with `load_root`.
- **`time.sleep`.** A test that sleeps to wait for something is flaky. Use `wait_for_condition` or `wait_for_log_count` from `tests/saq/helpers.py`.
- **Order.** The suite runs in random order. New module-level state (a cache, a registry, a singleton) is reset in `global_function_setup` in `tests/conftest.py`.
- **A forked child that ends in `os._exit`.** Coverage can't record its lines. Assert on its exit code, log record or effect, and say so in the PR.
- **A copied helper.** Search `tests/saq/helpers.py` and the nearest `conftest.py` before writing a helper or a fixture. `prepare.py --check` (below) flags an exact copy.
- **The test lock.** While another run holds it, a single-test run exits with code 4. Wait for that run to finish. A marker left by a killed run is cleared with the `rm` the message prints.

## Before asking for a review

```bash
bin/exec-in-container.sh /venv/bin/python .claude/skills/ace-review/scripts/prepare.py --check
```

It lists the lines the branch adds that ACE's review flags (a missing traceback, an unbounded wait, a sleep in a test, a copied function, an unmarked test), each with the fix it expects. Fix them or add the comment it asks for, then run it again until it prints nothing.
