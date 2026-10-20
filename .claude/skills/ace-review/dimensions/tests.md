# Tests reviewer

CI does not run the test suite, so this review is the only place tests get checked. The goal is coverage close to 100%. You judge whether the change is tested well enough that a later change breaking it would be caught.

Read first: `CLAUDE.md` § Testing and § Engineering values → Tests. Then read these files in `$B`:

| File | Contents |
|---|---|
| `pytest.txt` | the run of the selected tests, with the exit code on its last line |
| `diff-cover.json` / `diff-cover.md` | coverage of changed lines; this file is absent if no tests ran |
| `unmarked.txt` | tests in the changed test files that have no run marker |
| `tests.txt` | what was selected: the changed test files, plus the tests that mirror the changed source files |
| `pr.md` | the PR description, if there is one |

## Look for

**Test results.**
- Any failure or error in `pytest.txt` is a blocker. Quote the failing test ids and the first line of the error.
- A missing `pytest.txt` means the tests weren't run. Say why if `SKILL.md` recorded it.

**Coverage.**
- List the uncovered changed lines that matter: error branches, fallbacks, shutdown handling, permission checks, migrations of data.
- Uncovered lines that are trivially safe (a log line inside an already-tested branch, `__repr__`, type stubs) are not worth a finding.
- New production code with no test at all is a blocker.
- The coverage numbers only measure the selected tests. If changed source looks uncovered and the test for it most likely lives elsewhere, find that test (search `tests/` for the function name). If one exists but wasn't selected, say so, and don't report the line as untested.

**Markers.** Every entry in `unmarked.txt` is fix-first, because a test with no `unit`, `integration` or `system` marker never runs under the default `-m` filter. Confirm that the marker isn't applied some other way, such as a conftest hook.

**What the tests prove.**
- **Failure paths.** For each new `except`, refusal, conflict, timeout or fallback, is there a test that triggers it? Is there a test that asserts its log record (`caplog`, `search_log`, `wait_for_log_count`)?
- **Assertions that can't fail.** `assert x, 1` (the `1` is the failure message, not a comparison), `assert True`, a test with no assertion, or assertions only on mocks the test itself set up.
- **Over-mocking.** A test that mocks the code under test, or mocks the database in an `integration` test that could use the real one. In this repo integration tests use the real DB, and `monkeypatch` is preferred over `MagicMock`.
- **Analysis module tests** follow the standard shape in CLAUDE.md: run the engine, then reload from disk with `load_root` before asserting. Asserting on the in-memory root after an engine run is wrong.

**Flakiness.**
- `time.sleep` used to wait for something. Use `wait_for_condition` or `wait_for_log_count` from `tests/saq/helpers.py`.
- Tests that depend on order. pytest-randomly shuffles the order.
- Fixed ports or paths outside the per-slot data dir. Wall-clock comparisons without tolerance.
- New module-level state in production code (a cache, a registry, a singleton) that `global_function_setup` in `tests/conftest.py` doesn't reset.

**Fixture hygiene.** Customer data, production GUIDs, Message-IDs or tenant ids in fixtures. This repo is public, so that is a blocker. Live malware samples added without need.

**PR description.** If `pr.md` exists and has no Testing section (the command run, its results, any manual checks), that is a nit. If the stated results contradict `pytest.txt`, that is fix-first.

## Calibration

Rank untested code by the dimension it would hurt. An untested shutdown or failure path ranks with uptime; an untested GUI label is a nit at most.
