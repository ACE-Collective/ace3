# ACE Engine — Design Notes

Observations about the engine (`saq/engine/` and the code it drives), each
verified against the code at the time it was written. Every entry is a candidate
for improvement rather than a description of intended behavior, which is why they
live here and not in `docs/ENGINE.md`.

Entries marked **fixed** were resolved; the write-up records what was wrong, what
the fix does, which alternatives were rejected and why, what was deliberately left
alone, and the regression guard that pins it. Unmarked entries are still open.

`docs/ENGINE.md` is the descriptive reference for how the engine works and links
here from its §19 index. **Cross-references:** a bare `§N` or `§N.M` — `§16.5`,
`§13.1`, `§12.2` — is a section of `docs/ENGINE.md`; a `§19.x` reference is
another entry in this file. The `19.x` numbering is preserved from that document
so the `see docs/ENGINE.md §19.x` comments scattered through the tests and source
still resolve.

**Contents**

- [19.1 The mid-analysis disposition throttle never engaged](#191-the-mid-analysis-disposition-throttle-never-engaged--fixed)
- [19.2 Engine-level observable exclusions were dead](#192-engine-level-observable-exclusions-were-dead--fixed)
- [19.3 The idle backoff never reset](#193-the-idle-backoff-never-reset--fixed)
- [19.4 A failed delayed-analysis insert still marked the analysis delayed](#194-a-failed-delayed-analysis-insert-still-marked-the-analysis-delayed--fixed)
- [19.5 `EngineAdapter` and `EngineInterface` were stale](#195-engineadapter-and-engineinterface-were-stale--fixed)
- [19.6 `total_analysis_time_seconds` never accumulated](#196-total_analysis_time_seconds-never-accumulated--fixed)
- [19.7 `root.save()` per module invocation](#197-rootsave-per-module-invocation--fixed)
- [19.8 `_check_for_outstanding_work` ran up to three times](#198-_check_for_outstanding_work-ran-up-to-three-times--fixed)
- [19.9 Keepalive failure leaked the claim](#199-keepalive-failure-leaked-the-claim--fixed)
- [19.10 Only the first active dependency is ever examined](#1910-only-the-first-active-dependency-is-ever-examined) — *open*
- [19.11 Worker restart drops the execution mode](#1911-worker-restart-drops-the-execution-mode--fixed)
- [19.12 Tracking files are racy and process-global by name](#1912-tracking-files-are-racy-and-process-global-by-name--fixed)
- [19.13 `WorkStack` could not actually hold `Analysis`](#1913-workstack-could-not-actually-hold-analysis--fixed)
- [19.14 `ORDER BY RAND() ... LIMIT 128` on the workload query](#1914-order-by-rand--limit-128-on-the-workload-query) — *open*
- [19.15 Two context objects for one execution](#1915-two-context-objects-for-one-execution--fixed)
- [19.16 Config reload on SIGHUP is not implemented](#1916-config-reload-on-sighup-is-not-implemented) — *open*

---

## 19.1 The mid-analysis disposition throttle never engaged — **fixed**

*Original observation.* `AnalysisExecutionContext.last_disposition_check` (the
class since merged into `EngineExecutionContext` — §19.15) was set
once in `__init__` (`executor.py:189`) and only ever read in
`_check_for_alert_disposition` — it was never updated. The method's docstring
claimed it "Returns: The (new) last time we checked", but it returned nothing and
assigned nothing.

Consequence: for a root in `correlation` mode, once
`alert_disposition_check_frequency` (default 5s) had elapsed since the analysis
started, the window never closed again, so *every subsequent module invocation*
did `get_db().close()` plus a `SELECT disposition FROM alerts` instead of one
query per 5 seconds. On a large alert that is hundreds of extra round trips per
work item, each one also discarding the session.

*Fix.* `_check_for_alert_disposition` now assigns
`context.last_disposition_check = datetime.now()` inside the
`ANALYSIS_MODE_CORRELATION` branch, immediately before the `get_db().close()` and
the disposition `SELECT` — so the timestamp tracks the last time a disposition
was actually queried, and the throttle window reopens on schedule. The stale
`Returns:` docstring was corrected to describe that assignment. Placing the
assignment inside the correlation branch rather than at the top of the window
check keeps the attribute honest; no query is ever issued in other modes, so
behavior there is unchanged.

`alert_disposition_check_frequency = 0` still means "check on every module
invocation" — the comparison is `> frequency` and the elapsed time between two
consecutive calls is non-zero. `tests/saq/modules/test_alerting.py` depends on
that, and the unit test below pins it.

*Regression guard.* `tests/saq/engine/test_executor_disposition_check.py` — six
unit tests over `_check_for_alert_disposition` with `get_db` and
`get_engine_config` mocked: one query per window, the window reopening after it
passes, `frequency = 0` checking every time, no query outside correlation mode,
and the cancel / continue disposition paths still behaving. The first two failed
before the fix (10 queries where 1 was expected).

## 19.2 Engine-level observable exclusions were dead — **fixed**

*Original observation.* `EngineConfiguration.observable_exclusions` was
initialized to `{}` (`engine_configuration.py:128`) and never written to by any
code path. The `_process_observable_exclusions` branch that reads it
(`executor.py:857`) — and the `iptools.IpRange` handling for `ipv4`/`ip` inside
it — could never fire. Only *module-level* `observable_exclusions` (from
`AnalysisModuleConfig`, enforced inside `accepts()`) actually worked. A test
asserted the dict is empty (`test_configuration_manager.py:279`), which pinned
the current state rather than the intent.

This was a regression, not an unimplemented feature. `etc/saq.default.yaml`
ships a populated top-level `observable_exclusions:` block, and
`saq/configuration/schema.py` validates it — so an operator editing that block
got no error and no effect. In ACE v1 the equivalent `[observable_exclusions]`
INI section was merged into *every* module's exclusion dict by
`AnalysisModuleConfig._load_exclusions()`; that parser was dropped in the
pydantic config rewrite and nothing replaced it.

*Fix.* `EngineConfiguration._get_observable_exclusions()` now parses the
`observable_exclusions:` config section (§16.5) into the `{o_type: [o_value]}`
shape the executor reads, splitting each spec on the first colon and
de-duplicating per type; a spec with no colon is logged at ERROR and skipped
rather than raising, so one bad entry cannot take the engine down. An
`observable_exclusions=` constructor keyword overrides the config, matching how
`target_nodes` / `analysis_pools` / `local_analysis_modes` already work.

Restoring it at the *engine* level rather than re-adding the v1 per-module merge
keeps the check to once per work item instead of once per module, and the
executor branch already handles the dependency bookkeeping (a dependency being
resolved by an excluded work item is failed and advanced so its waiter is not
stranded).

The comparison itself was also wrong. `work_item.observable.value in exclusion`
is a *substring* test for non-IP types, so an exclusion of `google.com` matched
an observable of `oogle.com` but not `mail.google.com`. It is now
`work_item.observable.matches(exclusion)` — the same call the working
module-level `AnalysisModule.is_excluded` uses. `Observable.matches` is exact
equality, and `IPObservable.matches` / `IPv4Observable.matches` already
implement CIDR membership when the exclusion value contains a `/`, so the
`F_IP`/`F_IPV4` special case, the `iptools` import and the bare `except` around
the comparison were all removed.

Note that the exclusions shipped in `etc/saq.default.yaml` are now live:
`user:-`, `user:unknown`, `user:system`, `ipv4:127.0.0.1`, `ipv4:0.0.0.0`,
`fqdn:google.com` and `fqdn:youtube.com` are no longer analyzed by any module.

Still open, and out of scope here: the v1 `observable_group:<name>` indirection
inside module `exclude_*` keys was lost in the same rewrite, which is why
`exclude_internal_network: observable_group:internal` under
`analysis_module_pcap_conversation_extraction` is silently dropped by pydantic
today.

*Regression guard.* `tests/saq/engine/test_executor_observable_exclusions.py` —
thirteen unit tests over `_process_observable_exclusions` with a mocked
configuration manager: exact match, the `oogle.com` near-miss, the
`mail.google.com` subdomain, `ipv4` exact and CIDR (in and out of range), an
exclusion value containing a colon, unlisted types, the dependency-failure
bookkeeping, and the untouched `whitelisted` / `DIRECTIVE_EXCLUDE_ALL` branches.
Config parsing is covered by
`test_engine_configuration_observable_exclusions*` in
`tests/saq/engine/test_configuration_manager.py` (including
`..._shipped_observable_exclusions_are_live`, which pins that the config in
`etc/saq.default.yaml` actually reaches the engine), and the end-to-end path by
`test_global_observable_exclusion` in `tests/saq/engine/test_functionality.py`.
Eight of these failed before the fix.

## 19.3 The idle backoff never reset — **fixed**

*Original observation.* `Worker.execute()` had no `return True` — its only
`return` was the bare early return on keepalive failure. But `worker_loop` does:

```python
if self.execute(work_item):
    idle_time = 0
    continue
```

`execute()` always returned `None`, so `idle_time` was never reset. After a quiet
period a worker sat at `idle_timeout_max`, and even after processing work its
*next* empty poll waited the full maximum. The "we found work, so check again
immediately" comment above that block never applied either.

*Fix.* `execute()` now returns `True` after the `try/except/finally` around the
orchestration and `False` on the keepalive-failure path. Both branches are
deliberate: a work item that was claimed and consumed counts as processed even if
`orchestrate_analysis` returned False or raised (both are already caught and
logged inside `execute()`), because the queue moved and the next poll should
happen immediately; a lock failure analyzed nothing, so it does not reset the
backoff.

The `continue` needed a guard the original code never had to think about. With
`execute()` returning `None`, control always fell through to the
`if execution_mode == EngineExecutionMode.SINGLE_SHOT: break` below it; a truthy
`execute()` would have jumped over that break and turned `SINGLE_SHOT` ("run a
single work item and then exit", `enums.py`) into "drain the whole queue" — the
mode that ~233 test call sites reach through `start_single_threaded`. The reset
therefore skips the `continue` in `SINGLE_SHOT` mode and lets the break happen:

```python
if self.execute(work_item):
    idle_time = 0
    if execution_mode != EngineExecutionMode.SINGLE_SHOT:
        continue
```

`UNTIL_COMPLETE` is unaffected — the `continue` returns to the top of the loop,
which is where the both-queues-empty drain check lives.

*Regression guard.* `tests/saq/engine/test_worker_idle_backoff.py` — eight unit
tests driving `worker_loop` in-process against a fake workload manager, with the
orchestrator mocked and `get_engine_config` / `remove_all_sessions` patched.
`idle_time` is a local, so it is observed through the durations the loop passes
to `_immediate_shutdown_event.wait()`: three empty polls then a work item must
record `[1, 2, 3, 1]` (it recorded `[1, 2, 3, 4]` before the fix). The rest cover
the four `execute()` return paths, the `idle_timeout_max` clamp, and — as the
guard on the trap above — that `SINGLE_SHOT` still polls once and processes
exactly one work item with two queued, and that `UNTIL_COMPLETE` drains both
without ever idling. Five of the eight failed before the fix.

## 19.4 A failed delayed-analysis insert still marked the analysis delayed — **fixed**

*Original observation.* `db_add_delayed_analysis_request` returned `False` when
the INSERT failed, `True` on `IntegrityError`, and **`None` on success** (it fell
off the end after the commit). `Worker.delay_analysis` did:

```python
if self.workload_manager.add_delayed_analysis_request(...):
    analysis.delayed = True
return True                     # unconditional
```

So on the success path the worker's own assignment was skipped (harmless —
`AnalysisModule.delay_analysis` sets it), but on the *failure* path
`Worker.delay_analysis` still returned `True`, and the module set
`analysis.delayed = True` with no database row behind it. The analysis was then
permanently delayed: `root.delayed` true forever, so final analysis and post
analysis never ran for that root, and nothing would ever resume it.

*Fix.* Both halves of the contract are now honest.
`add_delayed_analysis_request` (`saq/database/util/delayed_analysis.py`) returns
`True` after the commit, so "recorded" and "not recorded" are distinguishable at
all. `Worker.delay_analysis` inverted its check: a falsy answer is logged at
ERROR and returns `False`; only a recorded request sets `analysis.delayed` and
returns `True`.

Refusing rather than raising is what the module side already knows how to
handle — it is the same answer the deadline-expiry branch just above gives.
`AnalysisModule.delay_analysis` sets the transient
`analysis.delay_analysis_timed_out`, closes the analysis out `COMPLETED`, and the
executor's cache-write gate (`executor.py`) keeps that empty result out of the
analysis cache (§10.1, §11). The attribute keeps its name: it is already the
general "the engine refused the delay" marker, and renaming it would churn the
cache-attribution `skip_reason` for no behavioral gain. The root loses one
module's analysis instead of hanging.

The `-> bool` annotation and the "True = recorded" docstring were pushed through
`WorkloadManagerInterface` / `WorkloadManagerAdapter` / `DatabaseWorkloadManager`
/ `MemoryWorkloadManager`; the memory implementation returned the
`DelayedAnalysisRequest` object it had just stored (truthy, so it worked by
accident) and now returns `True`.

*The `IntegrityError` branch stays, and the unique constraint is deliberately
not added.* The branch is still unreachable — `delayed_analysis` has only
`idx_node_delayed_until` and an index on `uuid`, so duplicate requests for the
same `(uuid, observable_uuid, analysis_module)` remain possible — but adding
that unique index would reintroduce this very bug. A module that delays again
after being resumed inserts the new row *during* `orchestrate_analysis`, while
the row for the request being resumed is only deleted afterwards, by
`clear_work_target()` in the `finally` of `Worker.execute`. Every second delay
would therefore collide, take the `IntegrityError` branch, be told `True`, and
then watch its only row be deleted — permanently delayed again. The branch is
kept because `True` is the correct answer for "a row for this target already
exists", should a constraint ever be added deliberately.

*Regression guard.* Three files, five of whose cases failed before the fix:

- `tests/saq/database/util/test_delayed_analysis.py` — four unit tests over
  `add_delayed_analysis_request` with the connection mocked: `True` on success
  (returned `None` before), `False` when the insert raises, `True` on
  `IntegrityError`, and the row parameters.
- `tests/saq/engine/test_worker_delay_analysis.py` — six unit tests over
  `Worker.delay_analysis` with a mocked workload manager: a recorded request
  marks the analysis delayed, a `False` or `None` answer refuses the delay and
  leaves `analysis.delayed` unset (both returned `True` before), an expired
  deadline refuses without attempting an insert, and — the consequence —
  a real `AnalysisModule` behind `DelayedAnalysisAdapter` closes the analysis
  out `COMPLETED` with `root.delayed` false instead of `INCOMPLETE`.
- `tests/saq/engine/test_functionality.py::test_delayed_analysis_insert_failure`
  — the end-to-end path: `execute_with_retry` is patched to raise for
  `INSERT INTO delayed_analysis` only, so the real helper takes its real failure
  branch. The root must finish with the analysis completed and not delayed, no
  `delayed_analysis` rows, and `execute_post_analysis` executed. Before the fix
  the engine logged "not entering final analysis mode (delayed analysis
  waiting)" and post analysis never ran.

## 19.5 `EngineAdapter` and `EngineInterface` were stale — **fixed**

*Original observation.* `saq/engine/adapter.py::EngineAdapter` forwarded
`shutdown`, `controlled_shutdown`, `delay_analysis`, `is_module_enabled` and
`cancel_analysis` to a wrapped `Engine`. The current `Engine`
(`saq/engine/core.py`) defines none of those — every member would
`AttributeError` if called. `EngineInterface` described an engine that no longer
exists. Both files were untouched since the v1 port.

*What the observation missed.* `EngineInterface` was not merely unused. It was
the declared return type of `AnalysisModule.get_engine()`, which returned
`self._context.engine` — and `AnalysisModuleContext` (`saq/modules/context.py`)
has no `engine` member, so the `AttributeError` landed one level *earlier* than
the adapter and the adapter was never even reached. Three module-facing APIs
raised on every call:

- `AnalysisModule.shutdown` and `AnalysisModule.controlled_shutdown` — the whole
  module-facing shutdown signal.
- `AnalysisModule.sleep()`, whose entire purpose is "sleep for N seconds without
  blocking shutdown": its loop condition opens with `not self.shutdown`, so it
  raised on the first iteration.
- `saq/modules/alerts.py::ACEAlertDispositionAnalyzer.check_disposition()`, three
  calls to `self.get_engine().cancel_analysis()`, swallowed as a module exception
  (§19.15's closing paragraph deferred this here).

*Fix.* The signal now comes from the object that actually holds shutdown state,
by the same route `DelayedAnalysisAdapter` already took:

- `saq/engine/shutdown_interface.py` — `ShutdownInterface`, a `Protocol` with the
  two properties modules genuinely need. The other three members of the old
  interface have real homes already and no engine indirection to reach them:
  `delay_analysis` through `AnalysisModule.delay_analysis()` →
  `DelayedAnalysisInterface` → `Worker`, `is_module_enabled` on
  `ConfigurationManager` (`self._context.configuration_manager.is_module_enabled()`,
  which `saq/modules/test.py` already calls), and cancellation through
  `AnalysisModule.cancel_analysis()`, which sets the per-module-instance flag the
  executor promotes onto the run-level context (§12.2).
- `saq/engine/shutdown_adapter.py` — `WorkerShutdownAdapter`, wrapping a `Worker`.
  `Worker` grew `is_immediate_shutdown()` / `is_controlled_shutdown()` predicates
  over its two existing `ACE_MP_CONTEXT.Event`s, and `is_in_shutdown_state()` is
  now expressed in terms of them. New names were required because
  `Worker.controlled_shutdown` is already the *setter*. The events are created
  before the fork, so a worker process reads what the manager set in the parent.
- `Worker._create_analysis_executor()` passes `WorkerShutdownAdapter(self)` next
  to `DelayedAnalysisAdapter(self)`; `AnalysisExecutor` carries it as an optional
  keyword and hands it to each `AnalysisModuleContext` it builds in `execute()`.
- `AnalysisModuleContext` exposes `shutdown` / `controlled_shutdown`, which
  **degrade to `False`** when no interface was injected rather than raising the
  way `root` and `configuration_manager` do — a module built outside a worker (the
  GUI, a unit test) is genuinely not shutting down. `AnalysisModule.shutdown` and
  `.controlled_shutdown` read those; `sleep()` is unchanged and starts working.

The two shutdown flags stay **separate** rather than collapsing into
`is_in_shutdown_state()`: an immediate shutdown must break a module out of
`sleep()`, while a controlled one means "finish the work item you have", which is
exactly the distinction a module in a long wait needs to make.

*Removed.* `saq/engine/adapter.py`, `saq/engine/interface.py`,
`AnalysisModule.get_engine()` and its `AnalysisModuleInterface` /
`AnalysisModuleAdapter` copies, the unused `EngineAdapter` import in
`tests/saq/engine/test_module_loader.py` (its only reference in the repo), and the
`engine_adapter:` line in `ModuleLoader.__init__`'s docstring, which documented an
argument the signature never had.

`saq/modules/alerts.py` went with them rather than being repaired.
`ACEAlertDispositionAnalyzer` and `ACEDetectionAnalyzer` were registered in no
config file and imported nowhere: the disposition check has lived in
`AnalysisExecutor._check_for_alert_disposition` since before §19.1, and the
detection → mode transition in `AnalysisOrchestrator` (§13.2, §13.3). The
orphaned `# analysis_module_alert_disposition_analyzer: no` comment in
`etc/saq.default.yaml` went too. Nothing that repairing the module would have
fixed was reachable.

The second paragraph of the original observation — `AnalysisExecutor.cancel_analysis()`
/ `.cancel_analysis_flag` as no-op stubs, and `Worker.current_execution_context`
assigned only `None` — had already been resolved by the §19.15 work; see the
*Also removed* and *Cancellation routing* notes there.

*Regression guard.* `tests/saq/engine/test_module_shutdown_signals.py` — eight
tests, four of which failed before the fix, all four with the exact
`AttributeError: 'AnalysisModuleContext' object has no attribute 'engine'`.
Three are unit tests: a module reports
`shutdown is False`, the same for `controlled_shutdown`, and `sleep(1)` returns
instead of raising on its first iteration. The integration
test is the standard analysis-module shape against a real single-shot engine:
`BasicTestAnalyzer.execute_test_engine_signals` (a new branch in
`saq/modules/test.py`) reads both flags *before* calling `create_analysis`, so
before the fix the module raised, the executor logged
`analysis module AnalysisModuleAdapter(BasicTestAnalyzer) failed ... reason
'AnalysisModuleContext' object has no attribute 'engine'` and the observable came
back with no analysis at all. The remaining four pin the new behavior: both flags
travel from an injected `ShutdownInterface` to the module, `WorkerShutdownAdapter`
tracks a real `Worker`'s two events independently, and `saq.engine.interface`,
`saq.engine.adapter`, `saq.modules.alerts` and `AnalysisModule.get_engine` are
gone.

## 19.6 `total_analysis_time_seconds` never accumulated — **fixed**

*Original observation.* `root.state["total_analysis_time_seconds"]` was
initialized to `0` in `execute()` and read once per pass in
`_execute_recursive_analysis` as the baseline for the cumulative timeout, but
nothing ever wrote a non-zero value back. The cumulative warning/fail timeouts
therefore measured only *this pass*, not the root's total analysis time across
delayed-analysis resumptions. A root that bounced through twenty delayed cycles
could never trip the cumulative fail timeout — precisely the runaway the limit
exists to catch.

*Fix.* Two absolute writes, both derived from the same per-pass baseline local
(`total_analysis_time_seconds`, read once at `executor.py:1890`), so they cannot
double count:

- `_execute_recursive_analysis` wraps the MAIN LOOP in `try`/`finally` and squares
  the budget up on the way out (`executor.py:1990`). The `finally` is load
  bearing: `AnalysisTimeoutError` (§12.4) and a cancelled analysis (§12.2) both
  leave the loop that way, and `AnalysisOrchestrator._execute_analysis` saves the
  root on both paths.
- `_execute_module_analysis` persists the running figure where `current_total_time`
  is already computed (`executor.py:1409`). The executor saves the root after
  every module invocation (§15), so this is what survives a worker killed
  mid-module — the monitor's `os._exit(1)` or the manager's `SIGKILL` (§12.5).

*The budget covers one logical analysis run, not the root's lifetime.* `execute()`
(`executor.py:431`) now seeds on `context.is_delayed_analysis`: a
`DelayedAnalysisRequest` resumption continues the budget the pass that requested
the delay started (`setdefault`, so a root saved before the key existed still
resumes), while a `RootAnalysis` work item assigns `0` and starts over.

Lifetime accumulation was considered and rejected. The same root re-enters the
engine as a `RootAnalysis` work item on every mode transition, every disposition
pass and every analyst-requested re-analysis, all of which persist through
`KEY_STATE` in the serialized root. With a 900s default fail time, a heavily
worked alert would eventually carry a baseline past the limit and *every*
subsequent pass would abort at its first module — the alert becomes permanently
un-analyzable. Resetting per run closes the delayed-cycle hole without that
failure mode.

The two state keys are now named constants — `STATE_TOTAL_ANALYSIS_TIME_SECONDS`
and `STATE_ANALYSIS_START_TIME` in `saq/constants.py`, alongside
`STATE_PRE_ANALYSIS_EXECUTED` and friends. `analysis_start_time` gets the same
per-run treatment for coherence; nothing in the repo reads it.

*Not to be confused with* the `total_analysis_time_seconds` field on the
fluent-bit metrics event (`record_execution_statistics`, `executor.py:282`),
which is the sum of per-module analysis time within one execution context.
Same name, unrelated quantity, unchanged.

*Regression guard.* `tests/saq/engine/test_cumulative_analysis_time.py` — seven
tests, five of which failed before the fix. Three unit tests drive `execute()`
with the recursive/post-analysis phases mocked out and assert the budget
lifetime: a `RootAnalysis` target resets a seeded `500` to `0` (it preserved it
before), a `DelayedAnalysisRequest` target preserves it, and a root missing the
key defaults to `0`. Four integration tests run the real engine: a single
`basic_test` pass records a non-zero total (`0` before); `test_delayed_analysis`
across two `SINGLE_SHOT` passes must come back strictly greater after the
resumption than after the initial pass (`0` and `0` before); a seeded `9999`
must be gone after a fresh root work item; and — the consequence —
`test_slow_delayed_analysis` (a new module in `saq/modules/test.py` that sleeps on
both `execute_analysis` and `continue_analysis`, since nothing existing burns time
on both) spends ~2s per pass against a 3s `maximum_cumulative_analysis_fail_time`
and must log "ACE took too long to analyze" on the *second* pass and not the
first. Before the fix the second pass measured ~2s and never tripped.

## 19.7 `root.save()` per module invocation — **fixed**

*Original observation.* §15 covers the mechanics. The executor wrote the entire
serialized tree after every single module call (plus every cache-hit replay), so
serialization cost scaled as *O(modules × tree size)* within one work item.
`docs/GUI_ALERT_PAGE_PERFORMANCE.md` measures a real alert at 1.9 MB `data.json`,
306 observables, 1230 analyses and 925 detail files; `save_to_disk` also walks
every one of those analyses calling `save_analysis_details`. The cache-hit replay
path was the worst case — the cache turns a multi-second module into a
millisecond replay, and the save straight after re-imposed the full O(tree) cost.

*What the write was actually buying.* Two things, and they do not apply to the
same work. **Alert enrichment** (`correlation` and the other alert-facing modes)
is long-running, low-volume and watched by a human: an analyst reloading the alert
page mid-run should see partial results. **Detection** (`email`, `http`, `file`,
`binary`, `yara`, …) is high-volume and fast, nobody is watching an individual
root, and restarting a crashed root from the beginning is cheaper than paying an
O(tree) serialize per module.

Nothing in the GUI polls alert *content*: `GET /analysis?direct=<uuid>` reads
`data.json` once per page load, and the only alert-page poller is a 5s
`GET /get_alert_meta` returning DB columns (disposition, owner, `is_locked`,
status). `alerts.version` and the index tables update once per work-item pass. So
even in `correlation` the mid-run disk copy is observable only by a manual page
reload, which tolerates seconds of lag comfortably.

*Fix.* The mid-pass write is now a per-mode policy, `root_save_frequency`
(§16.2/§16.4), resolved by `AnalysisExecutor._get_root_save_frequency` exactly the
way `maximum_analysis_time` is: the mode's value if set, else `global_settings`.
Unset means never write mid-pass; `0` means write after every module invocation
(the old behavior); `N` means at most once every `N` seconds. Both hot-path calls
(`executor.py`, after `analyze()` and on cache-hit replay) go through
`_save_root`, which is also the only place that consults the policy. The shipped
`etc/saq.default.yaml` sets `5` on `correlation`, `dispositioned` and `event`, and
leaves every detection mode unset.

Everything else that saves is left unconditional, and that is what makes the
policy safe: the throttle only ever *defers* a write, never drops one. Every pass
exits through `_execute_analysis`'s save — on success, timeout, error and
cancellation — while the root's lock is still held, so a delayed module's
suspension point is covered too.

Deliberately **not** done: skipping the write when `ModuleExecutionSnapshot.diff`
reports an empty delta. Narrow diffs (86 of 88 configured modules) do not capture
mutations to other pre-existing observables, in-place edits to an existing
analysis's `details`, or `root.state` writes such as the cumulative-time budget. A
time throttle defers; a delta-based skip would permanently drop.

*Consequences.* Memory is unaffected — details flushing runs off the work-stack
buffer drain, not off `root.save()`. A `SIGKILL`/`os._exit(1)` now loses up to
`root_save_frequency` seconds of completed module work in an alert-facing mode,
and the whole pass in a detection mode; those modules re-run, and any external
side effects they have may be repeated.
`root.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS]` rewinds with them. What does *not*
change is that the module which killed the worker is still skipped:
`set_analysis_failed` keys on `observable_type:observable_value` rather than uuid
(deliberately, since the crash may predate the observable reaching disk), so a
re-created observable still matches and gate 8 fires on the retry. That property
is what makes restart-from-scratch safe. One small regression: with no mid-pass
write, `copy_terminated_analysis_causes` cannot find a file observable that was
created during the lost pass, so the forensic copy silently does nothing — the
bytes are still under `files/`, only the reference is missing.

While here, the tail of a correlation pass stopped doing two full round-trips for
nothing. `_sync_alert_to_database` called `alert.load()`, parsing `data.json` into
a *second* `RootAnalysis` for `Alert.sync()` to re-serialize straight back out,
immediately after `_convert_to_alert` had already saved the live tree. It now
hands the alert the live tree via `Alert.attach_root_analysis()`, falling back to
loading when the alert's `storage_dir` does not match the root's.

*Regression guard.* `tests/saq/engine/test_root_save_frequency.py`. Unit
tests pin the resolution table (mode wins when set, else `global_settings`) and the
policy itself (unset never writes, `0` writes every time, `N` collapses a burst to
one write and reopens the window afterwards). Integration
tests run the real engine over `test_groups` under each of the three values and
assert the mid-pass write count while confirming the reloaded root still holds
every module's analysis, plus that a delayed-analysis suspension is on disk under
every policy. A system test is the counterpart to `test_timeout_root_flushed`: in
a mode with no mid-pass write, `GenerateFileAnalysis` runs *twice* after a worker
death — the cost — while `is_analysis_failed` still records the module that killed
it, so there is no crash loop.
`etc/saq.unittest.default.yaml` pins the test modes to `0` so the rest of the
suite keeps the pre-throttle behavior.

## 19.8 `_check_for_outstanding_work` ran up to three times — **fixed**

*Original observation.* `_check_outstanding_work_and_handle_detections`,
`_cleanup_if_no_outstanding_work` and `_submit_alert_for_embedding_if_complete`
each opened their own `get_db_connection()` and ran the same two queries (§13.1).
They were also not atomic with respect to each other — the answer could change
between them.

Consequence: up to three connections and three query pairs per work item for a
predicate that is stable for the duration of the pass (we hold the root's lock
throughout). Worse, one pass could act on contradictory answers. The damaging
ordering is `True` then `False`: the first evaluation says something else is
still working on the root, so `_handle_detection_points` never runs and a root
carrying detection points does not become an alert; by the time cleanup asks
again the answer has flipped, and `shutil.rmtree` deletes the storage directory
along with the detections nobody acted on.

*Fix.* `_handle_post_analysis_logic` now evaluates the predicate once, through
the new `_query_outstanding_work` (the single `get_db_connection()`, the
`lock_uuid is None` warning, and `_check_for_outstanding_work` itself unchanged),
and passes the answer to all three consumers.
`_check_outstanding_work_and_handle_detections` became
`_handle_detections_if_no_outstanding_work(ctx, has_outstanding_work)`, and
`_cleanup_if_no_outstanding_work` / `_submit_alert_for_embedding_if_complete`
take the flag instead of querying. Two details carry the semantics that the
repeated queries used to provide implicitly:

- **The reschedule.** `_handle_analysis_mode_changes` runs between the old check
  #1 and checks #2/#3, and on a mode change calls `root.schedule()` — the new
  workload row was exactly what the later queries saw. It now returns `bool`, and
  a `True` promotes `has_outstanding_work` before cleanup and embedding read it.
  Returning `True` is unconditional on a mode change, so unlike the old query a
  root whose `schedule()` raised is also not cleaned up — losing the tree of a
  root we failed to re-queue is the worse outcome.
- **The error path.** `_query_outstanding_work` returns `True` when the check
  cannot be made, which reproduces the old behavior: a database failure used to
  make all three `try` blocks bail, doing nothing.

The result is one round-trip pair per work item instead of up to three, and one
answer per pass rather than three that can disagree.

*Regression guard.* `tests/saq/engine/test_orchestrator_outstanding_work.py` —
five unit tests over `_handle_post_analysis_logic` with the collaborators mocked
(one evaluation per pass; the `True`/`False` ordering not deleting an unalerted
root; a rescheduled root and a root whose reschedule failed never being cleaned
up; a database failure taking none of the three actions) and two integration
tests counting real evaluations through a `SINGLE_SHOT` engine pass — one root in
`test_cleanup` mode, one root that alerts. Four of the unit tests and both
integration tests failed before the fix (3 evaluations where 1 was expected, 2 in
the integration cases, and the deleted-unalerted-root case).
`test_functionality.py::test_cleanup_with_delayed_analysis` still pins the
`"not cleaning up ... (found outstanding work)"` path.

## 19.9 Keepalive failure leaked the claim — **fixed**

*Original observation.* In `Worker.execute`, if `start_keepalive` fails the
method returns *before* the `try`, so the `finally` that would call
`clear_work_target()` never runs. The lock row and the workload row both
survive. The item is then blocked until `lock_timeout_seconds` passes and the
recovery path reclaims it. Rare (the lock was just acquired with the same
`lock_uuid`, so the re-acquire should succeed), but the failure mode is a silent
multi-minute stall.

*Fix.* The failure branch now gives the claim back before returning `False`:

```python
self.lock_manager.stop_keepalive()
self.lock_manager.release_lock(work_item.uuid, ignore_lock_failure=True)
```

Deliberately `release_lock` and **not** `clear_work_target()`. The two rows are
not symmetric here. The workload (or `delayed_analysis`) row *should* survive —
the item was never analyzed, and deleting it would drop the work and orphan the
root's storage directory. It is only the `locks` row that causes the stall,
because `get_work_target` selects on `locks.uuid IS NULL` (§5.2): while it
stands, no worker — including the one that just failed — can see the item.
Releasing it alone makes the item selectable again on the very next poll, which
is the outcome the original observation was asking for.

The release is safe in the case the observation calls out as unlikely but
possible, the lock genuinely having moved to another owner: `release_lock` is
ownership-scoped (`DELETE FROM locks WHERE uuid = %s AND lock_uuid = %s`), so it
deletes nothing rather than stealing someone else's claim.
`ignore_lock_failure=True` keeps that no-op from logging a misleading warning.

`stop_keepalive()` covers the second way `start_keepalive` can fail. Besides a
failed `acquire_lock`, both implementations refuse when
`self._keepalive_thread is not None` (`lock_manager/distributed.py`,
`lock_manager/local.py`) — a thread leaked by a *previous* work item. Nothing
cleared that state, so once it happened every subsequent work item on that
worker failed the same way, forever. Only one `execute()` runs at a time per
worker, so a keepalive found running here is always stale; `stop_keepalive()` is
a no-op when there is none.

*Backoff.* Releasing the claim exposes a second defect in `worker_loop`. Its
idle backoff was keyed on whether a work item was *found*, not on whether one
was *executed*, so an item returning `False` from `execute()` fell through to
the next poll with no sleep. The leaked lock used to mask this by making the
item invisible; with the claim returned correctly, a persistent keepalive
failure would re-select the same item as fast as the database could answer. The
loop now tracks an `executed` flag and takes the same `idle_time` increment and
wait for an unclaimable item as for an empty poll. Every existing path is
unchanged: a successful `execute()` still resets the backoff and `continue`s,
and `SINGLE_SHOT` still breaks after one work item.

*Regression guard.* `tests/saq/engine/test_worker_keepalive_failure.py` — seven
unit tests over `Worker.execute` and `worker_loop` with the collaborators mocked
(the lock released with the work item's uuid, the workload row *not* cleared, a
leaked keepalive stopped, no analysis attempted, the same for a
`DelayedAnalysisRequest`, the successful path still cleaning up through
`clear_work_target`, and the loop interleaving one backing-off wait per
unclaimable item) plus two integration tests against the real
`DistributedLockManager` / `DatabaseWorkloadManager`: after a failed keepalive
the `locks` row is gone while the `workload` row remains, and a second
`get_next_work_target()` returns the same item instead of `None`. Four of the
unit tests and both integration tests failed before the fix.

## 19.10 Only the first active dependency is ever examined

`_get_completed_dependency_work_item` iterates `root.active_dependencies` but
every path through the loop body returns, so only element `[0]` is ever
considered. Since `active_dependencies` is sorted by chain score this is
*probably* the intended "shortest chain first" behavior, but the loop structure
says otherwise and the `logging.debug("%s active dependencies to process")` line
implies a batch. Worth either fixing or making explicit.

## 19.11 Worker restart drops the execution mode — **fixed**

*Original observation.* `WorkerManager.restart_worker` calls
`new_worker.start()` with no `execution_mode`, defaulting to `NORMAL`. A worker
restarted during a `SINGLE_SHOT` or `UNTIL_COMPLETE` run comes back in normal
mode. The controller loop's own immediate `_controlled_stop()` masks this in
practice, but it is unsound.

`restart_workers()` — the SIGHUP path (§4.2) — had the identical bare
`worker.start()`.

The mode is only ever read inside the forked child: `worker_loop` sets the
controlled-shutdown event up front for `UNTIL_COMPLETE` and breaks after one work
item for `SINGLE_SHOT` (§4.5). A replacement started as `NORMAL` does neither, so
it idles and polls for work forever while the rest of the pool winds down.

*Fix.* The execution mode is now state of the pool rather than an argument that
exists only during the initial fork. `WorkerManager.__init__` initializes
`self.execution_mode = EngineExecutionMode.NORMAL` — the same default
`Worker.start` already carried, so a manager whose workers were never started
through `start_workers()` behaves exactly as before — `start_workers()` records
the mode it was handed, and both restart paths replay it:

```python
new_worker.start(execution_mode=self.execution_mode)   # restart_worker
worker.start(execution_mode=self.execution_mode)       # restart_workers
```

No signatures changed and no call site in `core.py` moved. This is a soundness
fix, not a behavior change any running deployment will observe: `SINGLE_SHOT`
and `UNTIL_COMPLETE` still break out of `main_controller_loop` to
`_controlled_stop()` on the first iteration, so `check_workers()` never runs in
those modes, and SIGHUP is only reachable from `NORMAL`. What it removes is the
dependency of one on the other — supervision no longer has to be unreachable for
the pool to stay in the mode it was started in.

*Regression guard.* `tests/saq/engine/test_worker_restart_execution_mode.py` —
nine unit tests, seven of which failed before the fix. Eight drive a real
`WorkerManager` over a `FakeWorker` that records the mode each `start()` was
given: the mode is retained by `start_workers()`; a replacement comes back in
`SINGLE_SHOT`, `UNTIL_COMPLETE` and `NORMAL` respectively (the `NORMAL` case
passed before and pins that the fix did not invert the default); a manager that
never called `start_workers()` still restarts as `NORMAL`; the same assertion
driven through `check_workers()`, the real caller in the controller loop; the
SIGHUP `restart_workers()` path; and name / `idle_timeout_max` /
`analysis_mode_priority` still carrying over to the replacement. The ninth uses a
real `Worker` with `ACE_MP_CONTEXT` mocked and asserts on the fork itself — both
the initial and the replacement `Process(...)` get
`kwargs={"execution_mode": UNTIL_COMPLETE}` — since those kwargs are the only
place the mode has any effect.

## 19.12 Tracking files are racy and process-global by name — **fixed**

*Original observation.* `TrackingMessageManager` wrote non-atomically (open +
`pickle.dump`) and read with a bare `except` that treated a torn read as "nothing
being tracked" — the code said so (`# XXX there are race conditions here that need
to be addressed`). `WorkerManager.check` could therefore miss a hung module for a
tick, and `_handle_failed_analysis` could miss a crash entirely. The directory was
keyed on worker *name* only, so two engines sharing a data dir would collide. The
child stamped a naive `datetime.now()` and the parent compared it against its own,
which a clock step or DST shift could skew either way. Roughly 40% of the module
was dead: `WorkTargetTrackingMessage` and all four `TRACKER_MESSAGE_TYPE_*`
constants had no references outside the file, and
`WorkTargetTrackingMessage.__init__` had a live bug where `self.target = target`
unconditionally clobbered its `DelayedAnalysisRequest` branch.

*Where the state belongs.* Not in the worker — the worker is the thing that dies.
Not in the ACE database either: it is shared by every node, and this is node-local
information consumed only by the process that spawned the worker, so writing it
centrally would mean a transaction per module invocation per worker per node. It
belongs in the **manager process**, which is the one process guaranteed to outlive
the worker.

*Fix.* `saq/engine/tracking.py` is now a client/server pair over local IPC.

- **Transport.** One `multiprocessing.Pipe(duplex=False)` per worker, opened
  immediately before the fork and with the parent's copy of the write end dropped
  immediately after — so the child inherits a live write end, no sibling's, and a
  worker restarted in place gets a fresh channel. Not a shared
  `multiprocessing.Queue`: a process killed while holding its internal write lock
  can wedge every other writer, and workers dying by `SIGKILL` is the whole premise
  here. `Connection.send`/`recv` is length-prefixed, so a worker killed mid-write
  surfaces as a read error rather than a plausible-looking half record.
- **Reader.** A dedicated thread in the manager (`multiprocessing.connection.wait`),
  not the one-second controller tick — a worker replaying many cache hits can emit
  hundreds of small messages a second and its `send()` must never block on the
  analysis critical path. It is stopped across every fork (`TrackingServer.forking`),
  because a child forked from a multi-threaded parent inherits locks — the logging
  module's included — with no thread alive to release them.
- **Store.** An in-memory dict, so the timeout check is a dict lookup instead of two
  file reads per worker per second, mirrored on every change to
  `<data_dir>/var/tracking/<node>.json`: a SHA-256 digest on the first line and the
  JSON payload after it, written to a `.tmp` sibling and atomically renamed. The
  rename makes it all-or-nothing against a crash; the checksum covers what the
  rename cannot, which is a power loss that lands the directory entry but not the
  data blocks. A file that fails to verify reads as "nothing was tracked" —
  deliberately, rather than by swallowing an exception. Not fsync'd: a power loss
  can lose the last record, and the node is restarting anyway, so we lose only the
  attribution. Keying the path on the node fixes the shared-data-dir collision.
- **Records are keyed by `root_uuid`, not by worker name.** The unit of tracking is
  the analysis, not the process doing it, so a pool that shrinks between restarts
  cannot strand anything. Pending failures live in their own map rather than as a flag
  on the in-flight one: the replacement worker normally re-claims the very root that
  killed its predecessor (that workload row was never deleted), and sharing one map
  would let the new work target overwrite the failure before anyone applied it — which
  is exactly the crash loop this subsystem exists to prevent.
- **Clock.** The manager stamps the module start on `time.monotonic()` and compares
  against its own reading, so both ends of the comparison are now taken in one
  process.
- **Handoff.** On death the manager marks the record and passes it to the
  replacement through `Process(kwargs=...)`, alongside `execution_mode` (§19.11).
  `Worker._handle_failed_analysis` takes the record as an argument instead of
  reading two pickle files, and — this is new — acknowledges it over the pipe once
  applied. The old code cleared tracking in a `finally` regardless of outcome, so a
  replacement that itself died mid-recovery lost the attribution. At engine start
  the manager reads the snapshot first and hands each leftover to a worker; a record
  still naming a module was never cleared by its owner and is unresolved by
  definition. Dispatch is deliberately not matched on worker name.

The recovery work stays in the worker on purpose: loading a large root and possibly
copying a file observable would stall the manager's supervision tick for every
other worker in the pool. The manager owns the *record*; the worker does the *work*.
`WorkerManager.check` now also has its module/target detail back in the
memory-limit-kill log line, which had been commented out with a `TODO` because the
information was not reachable.

*Not attempted.* Putting the record in the shared database so another node's
`recover_expired_locks` could attribute a failure. Storage directories are not
necessarily shared across nodes, so a remote node could not load the root to record
it anyway; the manager's startup recovery covers the case that actually happens,
which is this node's engine restarting.

*Regression guard.* `tests/saq/engine/test_tracking.py` covers the
record's serialization (the monotonic deadline never persists; unknown keys from
another build do not break a load), the state transitions, the monotonic timeout
boundary, and the failure handoff: a pending record survives until acknowledged, a
worker that died *between* modules has nothing to attribute, and a replacement
under the same name taking a different root leaves the pending record alone. On
the snapshot: a round trip through a fresh server (the full-manager-restart path),
a cleanly finished root that must not be resurrected, and a tampered payload and a
truncated file that must both read as empty rather than as garbage. On the
transport: delivery through a real pipe, a truncated frame that must not corrupt
existing state, EOF dropping the connection, and a send after close staying silent
so a worker whose manager went away never fails its analysis over it. One test pins
the re-claim case specifically — a replacement taking the same root back must not
wipe the pending failure, before or after a manager restart. Two more tests
cover what the file-based design never could — a record recovered from a snapshot
landing on the correct root by `root_uuid` and then being acknowledged, and startup
dispatch handing out a record whose original worker no longer exists after the pool
was resized. The three worker-death system tests in `test_functionality.py`
(`test_failed_analysis_module`, `test_timeout`,
`test_copy_terminated_analysis_cause`) are unchanged and remain the end-to-end
contract.

## 19.13 `WorkStack` could not actually hold `Analysis` — **fixed**

*Original observation.* `WorkStack.append` accepts `Analysis` and does nothing
with it. The whole `WorkTarget.analysis` field is annotated "(not actually
supported)", and `AnalysisModule.valid_analysis_target_type` plus the
`isinstance(obj, Observable)` guards throughout `accepts()` are vestiges of a
version of ACE that analyzed `Analysis` objects. Removing the dead branch would
simplify `accepts()` substantially.

The original design intended the engine to analyze `Analysis` objects the same
way it analyzes `Observable` objects. That was never implemented, but the
scaffolding survived everywhere the design would have touched:

- `WorkStack.append` had an `elif isinstance(item, Analysis): pass` branch, so an
  `Analysis` handed to the stack disappeared without a log line.
- `_initialize_work_stack` walked `root.all_analysis` and appended every one of
  them into that branch — a full tree walk that queued nothing — and the
  final-analysis re-push iterated the mixed `root.all` for the same reason.
- `valid_analysis_target_type` defaulted to `Observable` and documented "return
  `None` to disable the check", but nothing in the tree overrode it and it was
  not a key in `AnalysisModuleConfig` or any YAML, so an operator could not set
  it either. Since the engine's only two `accepts()` call sites pass
  `work_item.observable`, the gate could never reject anything. The documented
  escape hatch was also broken: with the check disabled, `accepts()` returned
  **True** for an `Analysis` the engine can never act on, and raised
  `AttributeError` on `obj.has_directive` as soon as the module set an
  `automation_limit` — the cooldown and automation-limit gates sat *outside*
  every `isinstance` guard.

*Fix.* `Observable` is now the engine's only unit of analysis, stated rather
than implied.

- `WorkTarget` lost its `analysis` field (no caller ever set it; nothing but
  `__str__` ever read it). `WorkStack.append` takes `WorkTarget | Observable` and
  raises `TypeError` on anything else, so a future caller that means to queue an
  `Analysis` gets an error instead of silence.
- The two dead loops in `executor.py` are gone: `_initialize_work_stack` pushes
  `root.all_observables`, and the final-analysis re-push does the same instead of
  iterating `root.all`.
- `valid_analysis_target_type` and its gate are deleted, along with all six
  `isinstance(obj, Observable)` guards inside `accepts()` — the body is now a flat
  sequence of gates at one indentation level rather than a method wrapped in a
  type test, with no change to which observables it accepts.
  `accepts`, `should_analyze`, `analyze` and `execute_final_analysis` take a
  parameter named `observable` and typed `Observable` in `base_module.py`,
  `interfaces.py` and `adapter.py`, and `analyze()`'s
  `assert isinstance(obj, Analysis) or isinstance(obj, Observable)` is now just
  `assert isinstance(observable, Observable)`. No runtime type check replaces the
  gate — the signature carries it.

One thing was deliberately kept: **`work_stack_buffer` is still mixed.** Event
listeners push both `Analysis` and `Observable` objects into it, and the
`Analysis` entries are load-bearing — the drain flushes their details to disk
(`flush_analysis_details`) before the buffer is queued. Only the *queueing* of
those entries was dead. That drain is now
`AnalysisExecutor._drain_work_stack_buffer`, extracted from the tail of
`_execute_module_analysis` so it can be tested without standing up an engine; it
skips `Analysis` items explicitly rather than relying on `WorkStack.append` to
swallow them, and keeps the existing semantics that a non-empty buffer of any
kind — analysis-only included — reopens final analysis mode.

*Regression guard.* `tests/saq/engine/test_work_stack.py` — eleven unit tests.
Six failed before the fix: `append` rejecting an `Analysis` and an unknown type,
`WorkTarget` no longer carrying an `analysis`, the two `_drain_work_stack_buffer`
tests (flush-once with a duplicated analysis, and an analysis-only buffer still
reopening final analysis mode), and a static AST scan of `saq/` asserting nothing
declares `valid_analysis_target_type`. The two that *passed* before the fix are
the proof the loops were dead: `_initialize_work_stack` and the final-analysis
re-push already produced a stack of exactly `len(root.all_observables)` items
from a tree containing four `Analysis` objects.

## 19.14 `ORDER BY RAND() ... LIMIT 128` on the workload query

Randomization is the only contention strategy. It forces MySQL to materialize and
sort the entire filtered workload set on every poll from every worker on every
node — with N workers polling at up to 1 Hz each when idle. It also means there
is no FIFO ordering, no aging, and no way to express intra-mode priority. A
`SKIP LOCKED`-style claim (or an explicit claim column with an indexed
`ORDER BY insert_date`) would be cheaper and give ordering guarantees.

## 19.15 Two context objects for one execution — **fixed**

*Original observation.* `EngineExecutionContext` and `AnalysisExecutionContext`
both held `root`, `total_analysis_time` and a cancel flag, were created for the
same work item at two layers, and were not synchronized.
`EngineExecutionContext.cancel_analysis()` in particular set a flag nothing read
— real cancellation went through `AnalysisExecutor.cancel_current_analysis()`.

*What that actually cost.* The split was not merely redundant. The orchestrator
handed the executor the *work item* rather than the context it already had:

```python
def _execute_analysis(self, execution_context: EngineExecutionContext):
    context = self.analysis_executor.execute(execution_context.work_item)
```

so `execute()` built a second context — and then opened with a guard on it:

```python
context = AnalysisExecutionContext(analysis_target)   # built here
self._current_context = context
...
# don't even start if we're already cancelled
if not context.cancel_analysis_flag:                  # ← could never be True
    self._execute_recursive_analysis(context)
```

That guard was dead, because the only object it could read was one `execute()`
had constructed two lines earlier. Cancellation therefore had to travel sideways
— `Worker._handle_lock_lost` → `AnalysisOrchestrator.cancel_current_analysis` →
`AnalysisExecutor.cancel_current_analysis` → `self._current_context` — and
`_current_context` is non-`None` **only while `execute()` is running**, which is
exactly the window that was already covered by the main loop's own checks.

Everything before that was a hole. A lock lost during `Worker.execute`'s setup,
during `_process_work_item` (`root.load()` / `DelayedAnalysisRequest.load()` —
real disk I/O) or during `_check_disposition` (a database round trip) was logged
and then silently discarded, and the full analysis ran on a root this worker no
longer owned. That window is where a keepalive failure is *most* likely to be
noticed, because it is the first thing that happens after the claim.

*Fix.* One context per work item. `EngineExecutionContext` absorbed everything
`AnalysisExecutionContext` held — the per-module timing and cache counters, the
work stack and its event buffer, `first_pass`, `last_disposition_check`,
`final_analysis_mode`, `last_analyze_time_warning`, `is_delayed_analysis`,
`record_cache_lookup()` and `record_execution_statistics()` — and
`AnalysisExecutionContext` was deleted with no alias. `AnalysisExecutor.execute`
now takes the context instead of building one:

```python
def execute(self, context: EngineExecutionContext) -> None:
```

which makes the `if not context.cancel_analysis_flag` guard live. That single
line is the behavioral fix; nothing else in the recursive algorithm changed.

`root` and `delayed_analysis_request` stayed **properties** rather than becoming
the snapshot attributes `AnalysisExecutionContext` used, and that is load-bearing
rather than cosmetic. The context is now built in `Worker.execute`, *before*
`_process_work_item` calls `DelayedAnalysisRequest.load()` — and `load()` is what
*constructs* the `RootAnalysis` (`delayed_analysis.py`: `self.root` is `None`
until then). A value captured in `__init__` would be `None` for the entire life
of every delayed-analysis pass. The property returns `None` before the load,
which is what `orchestrate_analysis`'s existing `if execution_context.root is
None` guard already expects, and the real root after it; the annotation was
widened to `Optional[RootAnalysis]` to say so. `execute()`'s
`assert isinstance(context.root, RootAnalysis)` is the place that demands a
loaded root, and it stays.

*Cancellation routing.* `AnalysisExecutor._current_context` and both
`cancel_current_analysis()` delegators are gone. The worker owns the context and
cancels it directly:

```python
def _handle_lock_lost(self):
    context = self.current_execution_context
    if context is None:
        logging.warning("lost lock but no work item is in flight")
        return
    context.cancel_analysis()
```

`Worker.current_execution_context` already existed but was only ever *assigned*
`None` (in the keepalive-failure branch and in the `finally`) and was never
declared in `__init__` — a vestige of the design this restores. It is now
initialized there and published in `execute()` **before** `start_keepalive`
registers the callback, so the keepalive thread can never fire into a `None` for
an item that is in flight. Both existing clears are unchanged: dropping the
reference when the item is done also releases the whole `RootAnalysis` tree
during idle. The read-plus-`bool`-store is atomic under the GIL, the same
property the old `_current_context` relied on.

*Also removed*, all provably unreachable: `AnalysisExecutor.cancel_analysis()`
and `.cancel_analysis_flag` (documented no-op / always-`False` back-compat
stubs), and `AnalysisExecutor.total_analysis_time` / `._cancel_analysis_flag`
(instance attributes nothing read). `AnalysisExecutor` now holds no state for the
run in progress at all — what it is working on lives on the context the worker
publishes.

*Deliberately left alone.* `AnalysisModuleContext.cancel_analysis_flag`
(`saq/modules/context.py`) is a genuinely separate signal, not a third copy of
this one: it is per module *instance*, reset with every fresh
`AnalysisModuleContext`, and read by `AnalysisModule.sleep()` as well as by the
executor. `_execute_module_analysis` promotes it into the run-level flag right
after the call returns, which is the correct bridge (§12.2). Separately,
`saq/modules/alerts.py::ACEAlertDispositionAnalyzer` called
`self.get_engine().cancel_analysis()` against an `AnalysisModuleContext` with no
`engine` member, raising `AttributeError` on every disposition it meant to stop
on. That was §19.5's stale `EngineAdapter`, not this, and §19.5 has since deleted
the module.

*Behavior change to expect.* A keepalive failure now produces a partially
analyzed root that stays queued, instead of a fully analyzed one racing whoever
took the lock. `_execute_post_analysis` and `_handle_post_analysis_logic` still
run on that path, identically to a cancel that lands mid-loop.

*Regression guard.* `tests/saq/engine/test_execution_context_merge.py` — twelve
tests, **all twelve of which failed before the fix**, and for the documented
reasons rather than on a renamed API (every one is written against
`AnalysisOrchestrator.orchestrate_analysis`, `Worker.execute` or the context
itself, none of whose signatures changed). Eight unit tests: the orchestrator
hands the executor the context it already has (previously the work item, so an
identity check failed); a context cancelled before `execute()` skips the
recursive analysis but still runs post-analysis; the uncancelled path still
analyzes, and does so with *that* context object; a cancel fired from inside
`_process_work_item` — the keepalive noticing during `root.load()` — reaches the
executor (previously it was recorded on an object nothing read and every module
ran); `_handle_lock_lost` cancels the worker's context; `_handle_lock_lost` on a
worker with nothing in flight is a no-op rather than an `AttributeError`; and the
`root` / `delayed_analysis_request` / `is_delayed_analysis` property set for both
work-item kinds, including that `root` *returns* `None` before the load rather
than raising. Four integration tests against a real single-threaded engine pass,
capturing the contexts by spying on `orchestrate_analysis`: a cancel injected
after `_process_work_item` leaves the observable with zero analysis (it had one);
`BasicTestAnalyzer.execute_test_cancel`'s module-level cancel is visible on the
worker's context (asserting the merge from the inside out); `total_analysis_time`
is populated and keyed by module name (it was permanently `{}`); and a delayed
analysis run produces exactly two passes whose second context resolves `root`
through the property to the tree `load()` built — the guard against merging in
the other direction.

The existing suites came along unchanged in substance:
`test_work_stack.py`'s delayed-request case now builds its context from a real
`DelayedAnalysisRequest` work item, since `delayed_analysis_request` is a derived
property and no longer assignable, and `test_functionality.py`'s
`record_execution_statistics` tests patch `saq.engine.execution_context` rather
than `saq.engine.executor` now that the method lives there.

## 19.16 Config reload on SIGHUP is not implemented

`main_controller_loop` handles SIGHUP by restarting workers, with the actual
`load_configuration()` call commented out and a `TODO`. Since workers re-import
and re-instantiate every module on start, module *code* and module *config*
changes do take effect — but only because the fork re-reads the already-parsed
config in a fresh process. The parent's `CONFIG` is never refreshed.
