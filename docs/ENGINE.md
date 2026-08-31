# The ACE Engine

How a `RootAnalysis` gets from "someone asked for it to be analyzed" to "analysis
is finished, the tree is on disk, and an alert may exist".

This document is a deep reference for the code under `saq/engine/` plus the
pieces it drives (`saq/modules/base_module.py`, `saq/analysis/`,
the `workload` / `delayed_analysis` / `locks` / `nodes` tables). It is written to
support design work: every claim below is anchored to a file and, where useful,
a symbol, so a proposed change can be traced back to the code that implements the
current behavior.

Related documents:

- `docs/ENGINE_DESIGN_NOTES.md` — the design observations indexed in §19: what
  was wrong, what the fix does, and what is still open. This document describes the
  engine as it behaves; that one records why parts of it behave that way.
- `docs/ANALYSIS_CACHING.md` — the per-module delta capture/replay cache the
  executor consults. This document covers *where* the cache plugs into the
  execution path; that one covers how it works.
- `docs/OBSERVABLE_TYPE_INHERITANCE.md` — the type hierarchy `accepts()` uses.
- `docs/OBSERVABLE_MODIFIER_RULES.md`, `docs/OBSERVABLE_DETECTIONS.md` — two
  subsystems that ride on the module/observable machinery described here.
- `docs/SERVICES.md` — the service lifecycle the engine is one instance of.

**Contents**

1. [Vocabulary](#1-vocabulary)
2. [The big picture](#2-the-big-picture)
3. [How work arrives](#3-how-work-arrives)
4. [Process topology and lifecycle](#4-process-topology-and-lifecycle)
5. [Claiming work](#5-claiming-work)
6. [The per-work-item pipeline](#6-the-per-work-item-pipeline)
7. [The recursive analysis algorithm](#7-the-recursive-analysis-algorithm)
8. [The per-module gauntlet](#8-the-per-module-gauntlet)
9. [Dependencies](#9-dependencies)
10. [Delayed analysis](#10-delayed-analysis)
11. [Where the analysis cache plugs in](#11-where-the-analysis-cache-plugs-in)
12. [Timeouts, cancellation and failure](#12-timeouts-cancellation-and-failure)
13. [Completion, detection, alerting and cleanup](#13-completion-detection-alerting-and-cleanup)
14. [Multi-node behavior](#14-multi-node-behavior)
15. [Persistence and I/O profile](#15-persistence-and-io-profile)
16. [Configuration reference](#16-configuration-reference)
17. [Observability](#17-observability)
18. [Testing the engine](#18-testing-the-engine)
19. [Design observations](#19-design-observations)
20. [File map](#20-file-map)

---

## 1. Vocabulary

| Term | Meaning | Code |
|---|---|---|
| **RootAnalysis** | The unit of work and the root of the analysis tree. Serialized to a storage directory (`<storage_dir>/data.json` plus `.ace/` details files and a `files/` + hardcopy tree). | `saq/analysis/root.py` |
| **Observable** | A piece of data that can be analyzed (`ipv4`, `url`, `file`, `email_address`, …). Carries tags, directives, relationships, dependencies, detection points. | `saq/analysis/observable.py` |
| **Analysis** | The output of one analysis module applied to one observable. Has a summary, `summary_details`, a free-form `details` blob stored out-of-line, and any observables it produced. | `saq/analysis/analysis.py` |
| **analysis mode** | A named set of analysis modules (`correlation`, `email`, `analysis`, `cli`, `dispositioned`, …). The mode on the `RootAnalysis` decides which modules are eligible. A mode is registered under its `name:` field, *not* its section key — the two must agree. | `analysis_mode_<name>:` in YAML |
| **work item / work target** | What a worker pulls off the queue: either a `RootAnalysis` (from the `workload` table) or a `DelayedAnalysisRequest` (from the `delayed_analysis` table). | `saq/engine/worker.py` |
| **WorkTarget** | An *inner*-loop item: one observable, optionally pinned to one module and/or one dependency. Not the same thing as a work item. | `saq/engine/work_stack.py` |
| **detection point** | A marker anywhere in the tree that says "this is worth an analyst's time". Any detection point promotes the analysis to an alert. | `saq/analysis/detection_point.py` |
| **alert** | A `RootAnalysis` in `correlation` mode with a row in the `alerts` table. | `saq/database/model.py::Alert` |

One context object exists per work item: `EngineExecutionContext`
(`saq/engine/execution_context.py`). The `Worker` creates it the moment it claims
the item and publishes it on `Worker.current_execution_context`; the
`AnalysisOrchestrator` and the `AnalysisExecutor` are handed that same object.
It wraps the work item and derives `root` from it lazily (a delayed request has
no root until it is loaded); it carries the `analysis_aborted` /
`analysis_skipped` flags the orchestrator's post-analysis logic reads, the work
stack and event buffer, per-module timing and cache counters,
`final_analysis_mode`, and the cancel flag the analysis loop tests. Nothing below
the worker holds run state of its own — see §19.15 for what this replaced.

---

## 2. The big picture

```
  submitters                                 database                  engine process tree
  ──────────                                 ────────                  ───────────────────

  collectors ──┐
  ace_api      │  root.save()          ┌───────────────┐          ┌──────────────────────────┐
  /api/submit  ├─ + ──────────────────►│   workload    │◄────────►│  Engine (controller)     │
  GUI actions  │  root.schedule()      │  (uuid, mode, │  poll    │   main_controller_loop() │
  ace correlate│                       │   node_id)    │          │   ├─ NodeManager         │
  disposition ─┘                       └───────────────┘          │   └─ WorkerManager       │
                                       ┌───────────────┐          │        ├─ Worker proc 1  │
                                       │delayed_analysis│◄────────│        ├─ Worker proc 2  │
                                       │ (delayed_until)│         │        └─ Worker proc N  │
                                       └───────────────┘          └──────────────────────────┘
                                       ┌───────────────┐                        │
                                       │     locks     │◄───── keepalive ───────┤
                                       └───────────────┘                        │
                                       ┌───────────────┐                        │
                                       │     nodes     │◄── heartbeat/status ───┘
                                       └───────────────┘
```

Inside one worker process, one work item flows through:

```
Worker.worker_loop
  └─ WorkloadManager.get_next_work_target()      claim + lock
  └─ Worker.execute(work_item)
       ├─ LockManager.start_keepalive()
       ├─ (optional) relocate storage to work_dir
       └─ AnalysisOrchestrator.orchestrate_analysis(EngineExecutionContext)
            ├─ _process_work_item()              load root / delayed request
            ├─ _check_disposition()              bail if analyst dispositioned
            ├─ _execute_analysis()
            │    └─ AnalysisExecutor.execute(the same EngineExecutionContext)
            │         ├─ _execute_pre_analysis()
            │         ├─ _initialize_work_stack()
            │         ├─ _execute_recursive_analysis()   ◄── the main loop
            │         └─ _execute_post_analysis()
            └─ finally: _handle_post_analysis_logic()
                 ├─ _query_outstanding_work()         one evaluation for the pass
                 ├─ _handle_detections_if_no_outstanding_work()
                 ├─ _handle_analysis_mode_changes()   (→ alert, → reschedule)
                 ├─ _handle_cleanup()
                 └─ _submit_alert_for_embedding_if_complete()
       └─ finally: stop_keepalive(); clear_work_target()
```

---

## 3. How work arrives

### 3.1 The contract

There is exactly one way to ask the engine to analyze something:

1. Write a `RootAnalysis` to a storage directory (`root.save()`).
2. Insert a row into the `workload` table (`root.schedule()` →
   `saq/database/util/workload.py::add_workload`).

`add_workload` fills the node id (calling `initialize_node()` if needed),
defaults the analysis mode to the engine default with a warning if unset, and
does an `INSERT ... ON DUPLICATE KEY UPDATE uuid=uuid`. The unique key is
`(uuid, analysis_mode)` — so the same root can legitimately be queued once per
mode, and re-queuing the same root in the same mode is a no-op.

The engine never reaches back to a submitter. Everything it needs is the
storage directory plus the row.

### 3.2 Every entry point

| Path | Code | Notes |
|---|---|---|
| Collector → local node | `saq/collectors/remote_node.py::submit_local` | duplicates the root, moves it to the node storage dir, `ALERT()` if mode is `correlation`, then `schedule()`. |
| Collector → remote node | `saq/collectors/remote_node.py::submit_remote` → `ace_api.upload(sync=True)` | the *target* node's `/engine/upload` calls `root.schedule()`. |
| `POST /api/analysis/submit` | `aceapi/analysis.py` | saves the root, `ALERT()` if `correlation`, then `schedule()`. |
| `GET /api/analysis/resubmit/<uuid>` | `aceapi/analysis.py` | `root.reset()` then `schedule()`. |
| `GET /api/engine/upload` (`sync=1`) | `aceapi/engine.py` | used by node-to-node transfer and by drain. Returns the target-computed `storage_dir`. |
| Hunts | `aceapi/hunt.py`, `saq/cli/commands/hunt.py` | `new_root.schedule()`. |
| GUI analyst actions | `app/analysis/views/**` | typically `request_analyst_analysis(root)` (mode → `correlation`, sets `STATE_ANALYST_REQUESTED_ANALYSIS`) then `add_workload()`. |
| Disposition | `saq/database/util/alert.py::set_dispositions` / `set_disposition_reviews` | bulk `INSERT IGNORE INTO workload ... analysis_mode = 'dispositioned'`, joined against `nodes` on `alerts.location = nodes.name`. Skipped when the disposition is `IGNORE`. |
| CLI `ace correlate` | `saq/cli/commands/correlate.py` | builds a `LOCAL` engine (memory workload, local locks) and calls `worker.workload_manager.add_workload(root)` directly. |
| The engine itself | `saq/engine/analysis_orchestrator.py::_handle_analysis_mode_changes` | when the analysis mode changes mid-flight, the root is re-scheduled under the new mode. |

### 3.3 Delayed analysis requests

The second queue. A module that needs to come back later calls
`self.delay_analysis(...)`, which inserts a row into `delayed_analysis`
(`uuid`, `observable_uuid`, `analysis_module`, `delayed_until`, `node_id`,
`storage_dir`). See §10.

### 3.4 The analyst-requested-analysis escape hatch

`request_analyst_analysis()` (`saq/database/util/workload.py`) exists because an
alert an analyst has already dispositioned sits in a mode that enables almost
nothing (`dispositioned`), *and* the engine short-circuits analysis of
dispositioned alerts (§6.3). It flips the mode back to `correlation` and sets
`STATE_ANALYST_REQUESTED_ANALYSIS` in `root.state`. The orchestrator pops that
flag (consume-once) and proceeds.

---

## 4. Process topology and lifecycle

### 4.1 Service entry

`ace service start engine` → `saq/service.py` resolves `service_engine:` →
`saq.engine.core.EngineService` → `Engine()` → `Engine.start()` →
`main_controller_loop()`.

`Engine.__init__` (`saq/engine/core.py`):

- builds `EngineConfiguration` from the `service_engine:` YAML block plus
  optional constructor overrides;
- builds `ConfigurationManager` (module registry; does *not* load modules yet);
- builds the node manager via `create_node_manager()` — `DistributedNodeManager`
  for `EngineType.DISTRIBUTED` (the default), `LocalNodeManager` (a no-op) for
  `EngineType.LOCAL`;
- builds `WorkerManager`;
- creates `stats_dir` and `work_dir`;
- calls `node_manager.initialize_node()` — inserts/loads the `nodes` row, writes
  `node_modes` / `node_modes_excluded`, **deletes every lock whose `lock_owner`
  starts with `<node name>-`** (leftovers from a previous run), sets `is_primary`
  from `ACE_IS_PRIMARY_NODE`, and sets node status to `starting`.

### 4.2 The controller loop

`Engine.main_controller_loop()` runs in the parent process:

1. installs SIGHUP/SIGTERM/SIGINT handlers (they only set flags);
2. `worker_manager.initialize_workers()` then `start_workers(execution_mode)`,
   which forks every worker and blocks until each sets its startup event;
3. sets state `RUNNING`, node status `running`, `started_event`;
4. loops on a 1-second `loop_control_event.wait(1.0)`:
   - `SINGLE_SHOT` / `UNTIL_COMPLETE` → `_controlled_stop()` and break immediately
     (the workers were told the mode at fork time and are already winding down);
   - `SIGINT` → controlled stop (drain then exit); `SIGTERM` → immediate stop;
   - `node_manager.update_node_status_and_execute_primary_routines()` (§14);
   - `worker_manager.check_workers()` (§4.4);
   - `SIGHUP` → `worker_manager.restart_workers()`. Config reload is stubbed out
     (commented) — HUP recycles worker processes only.
5. on exit sets state `STOPPED` and node status `stopped`.

### 4.3 Worker pools

`WorkerManager.initialize_workers()`:

- single-threaded mode → exactly one worker (`any-0`, no priority);
- otherwise one worker per `(mode, index)` for each entry in
  `analysis_pools`. Pool sizes may be integers or percentages of `cpu_count()`
  (`engine_configuration.py::compute_pool_size`, `max(1, …)` for any non-zero
  percentage). A pool for a mode not in `local_analysis_modes` is rejected;
- if that yields no workers at all → `cpu_count()` workers with no priority,
  capped by `pool_size_limit`.

A worker's `analysis_mode_priority` is a *preference*, not a restriction — a
`correlation-3` worker will happily take `email` work if no correlation work is
available (§5.2).

### 4.4 Worker supervision

`WorkerManager.check(worker)` runs once per controller second and returns
`DEAD` when:

- `worker.process` is `None` or has an exit code (process died / auto-refreshed);
- `worker.analysis_has_timed_out(record)` — the tracking record the manager just
  read off disk for this worker (§12.5) says a module started more than its
  `maximum_analysis_time` ago. The deadline is on `CLOCK_MONOTONIC`, which is
  system-wide, so the manager compares it against its own reading. It `SIGKILL`s
  the whole process tree;
- RSS exceeds `global_settings.memory_limit_kill` (MB → bytes in
  `EngineConfiguration`). `SIGKILL`. A warning is logged above
  `memory_limit_warning`.

`restart_worker()` promotes the dead worker's tracking record to a pending failure,
removes the worker, creates a replacement with the same name/priority/idle
timeout, starts it **in the execution mode the pool was started in** (§19.11)
*and with that pending record* (§12.5), and then does an awkward dance to close
the dead `multiprocessing.Process` (falling back to poking `_popen.finalizer()`),
with an `XXX` acknowledging it does not handle signal-killed processes cleanly.

### 4.5 The worker loop

`Worker.worker_loop(execution_mode)` (`saq/engine/worker.py`) is the child
process entry point:

1. fresh logging transaction id (forked children inherit the parent's);
2. **`configuration_manager.load_modules()`** — this is where analysis modules
   are actually imported and instantiated, once per worker process. A failure
   here exits the worker;
3. set the startup event;
4. compute `_next_auto_refresh_time` if `auto_refresh_frequency > 0`;
5. `UNTIL_COMPLETE` → set the controlled-shutdown event up front;
6. `_handle_failed_analysis(pending_failure)` — record the failure of a previous
   incarnation that died mid-module, from the record the manager forked us with
   (§12.5);
7. loop:
   - immediate-shutdown event set → break;
   - past auto-refresh time → break (the manager forks a fresh worker, which
     re-imports every module — the point of the feature);
   - controlled-shutdown set *and* both queues empty → break;
   - `get_next_work_target()`; if it returned a work item, write the target to
     the worker's tracking file, `execute(work_item)`, clear it. Then, on `execute()`'s
     answer:
     - True (a work item was processed) → the backoff resets (`idle_time = 0`)
       and the loop polls again immediately — except in `SINGLE_SHOT`, which
       falls through to the break below;
     - False (nothing found, or a work item that could not be claimed —
       `execute()` returns False and hands the claim back when the keepalive
       cannot be started, §19.9) → `idle_time = min(idle_time + 1,
       idle_timeout_max)` and wait that long on the immediate-shutdown event;
   - `SINGLE_SHOT` → break;
   - `finally: remove_all_sessions()` (SQLAlchemy session hygiene per iteration).

### 4.6 Single-threaded and single-shot modes

Three axes, often confused:

| Axis | Values | Effect |
|---|---|---|
| `EngineType` | `DISTRIBUTED` (default) / `LOCAL` | picks `DatabaseWorkloadManager` + `DistributedLockManager` vs `MemoryWorkloadManager` + `LocalLockManager`, and `DistributedNodeManager` vs `LocalNodeManager`. |
| `single_threaded_mode` | bool | one worker, run **in-process** (no fork), and **no lock keepalive thread**. |
| `EngineExecutionMode` | `NORMAL` / `SINGLE_SHOT` / `UNTIL_COMPLETE` | run forever / one work item / drain the queues then exit. |

`Engine.start_single_threaded()` sets `single_threaded_mode`, builds one
`Worker`, and calls `worker.single_threaded_start(execution_mode)` directly —
this is what nearly every module test uses:

```python
engine = Engine()
engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
```

Note that the *default* `Engine()` is still `DISTRIBUTED`, so tests exercise the
real database workload manager and the real `locks` table.

---

## 5. Claiming work

`DatabaseWorkloadManager` (`saq/engine/workload_manager/database.py`) is the
production implementation; `MemoryWorkloadManager` mirrors it in-process for
`ace correlate` and tests. Both sit behind `WorkloadManagerAdapter`.

### 5.1 Order of preference

`get_next_work_target()`:

1. `get_delayed_analysis_work_target()` — **always first**;
2. if this worker has a priority mode: `get_work_target(priority=True, local=True)`,
   then `get_work_target(priority=True, local=False)`;
3. `get_work_target(priority=False, local=True)`;
4. `get_work_target(priority=False, local=False)`.

Delayed analysis outranks everything, and a worker will reach across nodes for
its own priority mode before taking local work of another mode.

### 5.2 The workload query

```sql
SELECT workload.id, uuid, analysis_mode, insert_date, node_id, storage_dir, RAND() AS random_sort
FROM workload LEFT JOIN locks ON workload.uuid = locks.uuid
WHERE (locks.uuid IS NULL)
  AND (workload.analysis_mode = :priority)?           -- when priority=True
  AND (workload.node_id = :me)  |  (workload.company_id = :company)   -- local vs remote
  AND (workload.analysis_mode IN (:local_modes))      -- or NOT IN (:excluded_modes)
  AND (workload.node_id IN (SELECT id FROM nodes WHERE name IN (:target_nodes)))?
ORDER BY random_sort
LIMIT 128
```

Then, for each candidate row in order:

1. `lock_manager.acquire_lock(uuid)` — skip on failure (someone else got it);
2. re-`SELECT uuid FROM workload WHERE id = %s` to confirm the row still exists
   (the list and the lock are two steps; the item can complete in between). If
   it is gone, release and continue;
3. if `node_id != my node` → `transfer_work_target()` (§14.3);
4. otherwise return `RootAnalysis(uuid=…, storage_dir=…, analysis_mode=…)` —
   *unloaded*. The mode from the workload row is carried separately from the
   mode saved in `data.json`, which matters in §6.2.

`ORDER BY RAND()` is the contention-avoidance strategy: N workers polling the
same queue land on different rows instead of all colliding on the oldest one.
There is no FIFO guarantee and no notion of age or priority within a mode.

A non-`running` node (draining, drained, …) refuses remote work
(`get_node_status_cached()` check at the top of `get_work_target`) but still
takes its own local work.

### 5.3 The delayed-analysis query

```sql
SELECT id, uuid, observable_uuid, analysis_module, delayed_until, storage_dir
FROM delayed_analysis LEFT JOIN locks ON delayed_analysis.uuid = locks.uuid
WHERE node_id = :me AND locks.uuid IS NULL AND NOW() >= delayed_until
ORDER BY delayed_until ASC
```

First lockable row wins. Delayed analysis is **pinned to the node** that created
it (no cross-node pull) — which is why draining a node has to push these
explicitly (§14.4).

### 5.4 Locking

The `locks` table is keyed on `uuid` (PK) with `lock_uuid`, `lock_owner`,
`lock_time`, `node_id`.

`acquire_lock()` (`saq/database/util/locking.py`) tries a plain `INSERT`. On
`IntegrityError` it falls back to an `UPDATE ... WHERE uuid = ? AND lock_uuid = ?`
(refresh my own lock) — or, when `allow_expired_takeover=True`, `WHERE uuid = ?
AND (lock_uuid = ? OR TIMESTAMPDIFF(SECOND, lock_time, NOW()) >= lock_timeout)`.
It then re-reads the row to confirm ownership. Expired-lock takeover is reserved
for the recovery path; workers never pass the flag.

Each worker's lock owner is `"<node>-worker-<name>"`. That prefix is load-bearing:
`DistributedNodeManager.initialize_node()` clears leftovers with
`DELETE FROM locks WHERE lock_owner LIKE CONCAT(<node>, '-%')`.

The `DistributedLockManager` keepalive thread re-`acquire_lock`s every
`global_settings.lock_keepalive_frequency` seconds. If a refresh fails, it sets
`_lock_lost` and fires the `on_lock_lost` callback — `Worker._handle_lock_lost`,
which cancels `Worker.current_execution_context`, the one context for the work
item. The running analysis loop stops at its next check; if analysis has not
started yet, it never starts (§12.2, §19.15).

`stop_keepalive()` deliberately does **not** release the lock; release is owned by
`clear_work_target()`.

`LocalLockManager` is the in-process equivalent backed by a class-level registry
of `threading.RLock`s. Its keepalive thread does nothing but log — an in-process
lock cannot be stolen.

---

## 6. The per-work-item pipeline

### 6.1 `Worker.execute`

```python
with transaction_id(work_item.uuid):            # every log line correlated to the root
    execution_context = EngineExecutionContext(work_item)
    self.current_execution_context = execution_context   # before the keepalive: §19.15
    if not single_threaded_mode:
        if not lock_manager.start_keepalive(uuid, on_lock_lost=self._handle_lock_lost):
            return                              # NOTE: returns without clearing work target
    try:
        if (isinstance(work_item, RootAnalysis)
                and work_item.analysis_mode not in (correlation, dispositioned)
                and engine work_dir is configured
                and work_item.storage_dir == storage_dir_from_uuid(uuid)):
            work_item.load()
            orchestrator._relocate_storage_directory(workload_storage_dir(uuid), ctx)
            tracking.track_current_work_target(work_item)
        orchestrator.orchestrate_analysis(execution_context)
    finally:
        lock_manager.stop_keepalive()
        workload_manager.clear_work_target(work_item)   # DELETE row + release lock
```

The `work_dir` relocation exists so non-alert analysis can churn on a different
(faster/scratch) filesystem; alerts always live under the main data dir.
`_relocate_storage_directory` also repoints `workload.storage_dir` and
`delayed_analysis.storage_dir`.

`clear_work_target` deletes `WHERE uuid = %s AND analysis_mode = %s` using
`root.original_analysis_mode` — so a root that changed mode mid-flight has its
*old* row removed while the newly-scheduled row for the new mode survives.

### 6.2 `_process_work_item`

- If the storage directory is missing → warn "already processed?" and bail.
- `DelayedAnalysisRequest` → `load(configuration_manager)`: loads the root,
  resolves the observable, resolves the module by config name, resolves the
  in-flight `Analysis`. Any missing piece fails the work item. Then
  `work_item.analysis.delayed = False`.
- `RootAnalysis` → remember the mode from the workload row, `root.load()`, and if
  the loaded mode differs from the workload mode, `override_analysis_mode(workload
  mode)`. This is the disposition case: the alert on disk says `correlation`, the
  workload row says `dispositioned`. `override_analysis_mode` sets both
  `_analysis_mode` and `_original_analysis_mode`, which is what makes the later
  "did the mode change?" test meaningful.

### 6.3 `_check_disposition`

Only for `correlation` mode. Consumes `STATE_ANALYST_REQUESTED_ANALYSIS` first
(if set, analysis proceeds regardless of disposition). Otherwise reads
`alerts.disposition` and stops if:

- `stop_analysis_on_any_alert_disposition` is true and the disposition is set and
  is not `OPEN`; or
- the disposition is in `stop_analysis_on_dispositions`
  (default `FALSE_POSITIVE`, `IGNORE`, `UNKNOWN`, `WEAPONIZATION`).

Stopping sets `analysis_skipped = True` and returns early — but the `finally`
block in `orchestrate_analysis` still runs the whole post-analysis path, because
`work_item_processed` is already true. `analysis_skipped` is what suppresses the
otherwise-pointless alert re-sync in `_sync_alert_to_database`.

### 6.4 `_execute_analysis`

Times the executor call, then `root.save()`, then emits per-module metrics if
`metrics_logging.enabled`.

On any exception it saves whatever it has, sets `analysis_aborted = True`, clears
every outstanding `delayed_analysis` row for the root, and re-raises.
`analysis_aborted` matters because abandoning the delayed rows leaves
`root.delayed` stale — without forcing an index rebuild, the alert's observables
would never reach `observable_mapping` and the alert would be unsearchable by
them.

---

## 7. The recursive analysis algorithm

Everything below is `saq/engine/executor.py::AnalysisExecutor`.

### 7.1 `execute()` setup

1. take the `EngineExecutionContext` the worker built for this work item — the
   executor constructs nothing and keeps no state of its own (§19.15);
2. build a `StateRepository` for the root and hand every loaded module a fresh
   `AnalysisModuleContext` (delayed-analysis interface, root, configuration
   manager, filesystem adapter, state repository). **Modules are long-lived
   objects re-pointed at each root** — module instance state persists across work
   items within a worker process;
3. ensure `root.state[STATE_PRE_ANALYSIS_EXECUTED]` and
   `[STATE_POST_ANALYSIS_EXECUTED]` dicts exist (these make pre/post analysis
   idempotent across multiple passes over the same root);
4. attach a `FileHandler` writing `<storage_dir>/saq.log` — every log line
   produced while analyzing this root also lands next to the root;
5. seed `root.state["total_analysis_time_seconds"]` and
   `root.state["analysis_start_time"]` — reset for a `RootAnalysis` work item,
   carried forward for a delayed-analysis resumption, so the cumulative budget
   spans one logical analysis run (§19.6);
6. `_execute_recursive_analysis()`;
7. if `not root.delayed` → `_execute_post_analysis()`;
8. on `AnalysisTimeoutError`, still run `_execute_post_analysis()` before
   re-raising;
9. always remove the log handler.

### 7.2 Pre-analysis

`_execute_pre_analysis` runs `execute_pre_analysis()` on every module in the
mode, sorted by `priority`, **skipped entirely for delayed-analysis work items**.
Results are recorded per module name in `root.state[STATE_PRE_ANALYSIS_EXECUTED]`
so a module runs pre-analysis at most once per root, even across passes. A
module that raises is recorded as `False` and never retried.

### 7.3 Building the work stack

`_initialize_work_stack`:

- **Delayed request** → the stack contains exactly one `WorkTarget(observable,
  analysis_module)`. Anything else is a hard error.
- **Otherwise** → push every `Observable` in the tree, deduplicated by uuid. An
  `Observable` is the engine's only unit of analysis; `WorkStack.append` raises
  `TypeError` on anything but a `WorkTarget` or an `Observable` (§19.13).

Then it wires an event-driven feedback loop. Listeners are registered on the root,
every existing analysis, and every existing observable:

| Source | Events |
|---|---|
| `Analysis` | `OBSERVABLE_ADDED`, `TAG_ADDED`, `DETAILS_UPDATED`, `ANALYSIS_MARKED_COMPLETED` |
| `Observable` | `ANALYSIS_ADDED`, `TAG_ADDED`, `DIRECTIVE_ADDED`, `RELATIONSHIP_ADDED` |

Every one of those appends the changed object to `context.work_stack_buffer`.
`OBSERVABLE_ADDED` and `ANALYSIS_ADDED` additionally register listeners on the
newly created object, so the tree stays fully instrumented as it grows.

This is the engine's definition of "the tree changed": if a module tags an
observable, adds a directive, updates details, or produces a new observable, that
object goes back into the queue and every eligible module gets another look at it.

### 7.4 The main loop

```python
while not context.cancel_analysis_flag:
    if len(work_stack) == 0 and len(root.active_dependencies) == 0:
        if final_analysis_mode:
            break                                   # truly done
        if not root.delayed:
            final_analysis_mode = True
            for o in root.all_observables: work_stack.append(o)   # one more pass
            continue
        break                                       # delayed work outstanding; stop here

    work_item = (_get_delayed_analysis_work_item(ctx)        # the pinned delayed target
              or _get_completed_dependency_work_item(ctx)    # dependency resolution
              or _get_next_work_item(ctx))                   # normal stack pop
    if not work_item or not work_item.observable:
        continue

    if _process_observable_exclusions(work_item) is EXCLUDED:
        continue

    for module in sorted(get_analysis_modules_for_work_item(work_item, mode),
                         key=attrgetter("priority")):
        if context.cancel_analysis_flag: break
        _execute_module_analysis(ctx, root, work_item, work_stack,
                                 work_stack_buffer, module, start_time,
                                 total_analysis_time_seconds)
```

Termination is "the tree stopped changing": modules stop producing events, the
buffer stops refilling the stack, the stack empties, no dependency is active.

**Final analysis mode.** When the stack first empties with no outstanding delayed
work, the entire tree is pushed back on and every module is invoked with
`final_analysis=True` → `execute_final_analysis()`. This is the hook for modules
that need to see the completed tree. If final-analysis work produces anything,
the tail of `_execute_module_analysis` clears `final_analysis_mode` and the
normal loop resumes — so a module can bounce the engine out of final analysis.

**Work-item selection order** is a strict priority: a pinned delayed target first
(only on `first_pass`), then dependency work, then the stack.

`_get_next_work_item` pops until it finds an item whose observable has no
unresolved, unfailed dependency. Items skipped this way are *dropped* from the
stack — they come back only via the dependency-resolution path, which re-queues
the waiting source observable (§9).

### 7.5 Observable exclusions

`_process_observable_exclusions` drops a work item when the observable is:

- `whitelisted` (any observable tagged `whitelisted` also makes the whole root
  whitelisted — `RootAnalysis.whitelisted`);
- matched by `self.config.observable_exclusions[type]`, the globally excluded
  observables from the `observable_exclusions:` config section (§16.5).
  Comparison is `Observable.matches()` — exact for most types, CIDR membership
  for `ip`/`ipv4`;
- carrying `DIRECTIVE_EXCLUDE_ALL`.

In every case, if the work item was resolving a dependency, that dependency is
failed and advanced so its waiter is not stranded.

### 7.6 Choosing modules for a work item

`get_analysis_modules_for_work_item`:

1. start with every module mapped to the root's analysis mode (unknown mode →
   the engine default, with a warning);
2. if the observable declares `limited_analysis` (and this is not dependency
   work) → only those named modules, with an error logged for unknown names;
3. else if the work item pins a module (dependency or delayed work) → just that
   module.

Then the caller sorts by `AnalysisModuleConfig.priority` (lower runs first).

### 7.7 Result processing

`_process_generated_analysis` runs after every successful module call:

- module returned something other than `INCOMPLETE` and produced no analysis →
  `observable.add_no_analysis(...)` writes the `False` sentinel, which
  `accepts()` reads later to avoid re-running the module;
- analysis exists and result is `COMPLETED` and it is not delayed →
  `analysis.completed = True`;
- dependency bookkeeping (§9.2).

Then the tail of `_execute_module_analysis`:

- if the observable is now `whitelisted` → clear the buffer and cancel the entire
  analysis;
- otherwise `_drain_work_stack_buffer`: the buffer is deliberately mixed, so every
  `Analysis` in it is flushed (`analysis_tree_manager.flush_analysis_details` —
  writes `details` to its own file and drops it from memory) and *not* queued,
  while every `Observable` moves onto the work stack. A non-empty buffer of any
  kind — analysis-only included — reopens final analysis mode;
- accumulate per-module wall time and invocation count into the context.

---

## 8. The per-module gauntlet

`_execute_module_analysis` is where one module meets one observable. The gates, in
execution order — this ordering is the contract:

| # | Gate | Where | Effect when it fails |
|---|---|---|---|
| 1 | alert disposition re-check (throttled) | `_check_for_alert_disposition` | cancels the whole analysis |
| 2 | cumulative analysis time | `_check_for_analysis_timeout` | warns, then raises `AnalysisTimeoutError` |
| 3 | module generates no analysis type | `generated_analysis_type is None` | return (pre/post-only modules) |
| 4 | `module.accepts(observable)` | `base_module.py::accepts` | return; fails any dependency |
| 5 | this module's analysis is already delayed | `_check_module_acceptance` | return |
| 6 | declared dependencies unmet | `_seed_declared_dependencies` | seed dependency edges, defer |
| 7 | `module.custom_requirement(observable)` | inline | return **without** a no-analysis sentinel, so the module is reconsidered later |
| 8 | previous execution recorded a failure | `root.is_analysis_failed` | raise `AnalysisFailedException` |
| 9 | analysis cache hit | `get_cached_delta` | replay the delta, `root.save()`, return |
| 10 | — | `NetworkSemaphore(semaphore_name)` | blocks until a slot is free |
| 11 | **`module.analyze(observable, final_analysis, delayed_analysis)`** | | |

`accepts()` (gate 4) is itself a long list, worth knowing because it is where
most "why didn't my module run?" answers live:

`requires_detection_path` → `valid_observable_types`
(subtype-aware via `get_type_hierarchy()` unless `valid_observable_subtypes = False`)
→ `valid_queues` / `invalid_queues` → `invalid_alert_types` → `DIRECTIVE_EXCLUDE_ALL`
→ module-level `observable_exclusions` → observable-level exclusions →
`required_directives` → `required_tags` → already-analyzed check (including the
`False` sentinel, and the `allow_reanalysis_on_failure` retry path that *deletes* a
failed analysis) → `file_size_limit` → cooldown bookkeeping → `automation_limit`
(bypassed by `DIRECTIVE_IGNORE_AUTOMATION_LIMITS`) → `should_analyze()`.

`custom_requirement` is deliberately **not** in `accepts()`. It runs at gate 7
so it can inspect the results of the module's declared dependencies and can raise
`WaitForAnalysisException` to wait on a *different* observable's analysis.

### 8.1 The call itself

```python
monitor = AnalysisModuleMonitor(root, module, work_item, maximum_analysis_time)
monitor.start()
snapshot_before = ModuleExecutionSnapshot.narrow|wide(root, observable, module)
result = module.analyze(observable, final_analysis_mode, is_resuming_delayed_module)
snapshot_after = ...
delta = ModuleExecutionSnapshot.diff(before, after, module, observable, resuming)
root.record_module_execution(delta.without_analysis_details())   # if non-empty
_maybe_write_cache_delta(...)
root.save()
monitor.stop()
```

`AnalysisModule.analyze()` (`base_module.py`) dispatches:

- `final_analysis=True` → `execute_final_analysis(obj)`;
- `delayed_analysis=True` and an existing analysis is present →
  `continue_analysis(obj, existing)`;
- otherwise → `execute_analysis(obj)`.

`is_resuming_delayed_module` is computed narrowly — it is true only for the module
the `DelayedAnalysisRequest` actually names, never for other modules invoked
during the same resumption pass. Passing it broadly would route unrelated modules
with persisted incomplete analyses into `continue_analysis()`, which they do not
implement.

`AnalysisModuleMonitor` is a daemon thread that waits
`min(mode maximum_analysis_time, module maximum_analysis_time)` and then warns
every 5 seconds; once elapsed time passes the *module's* limit it calls
`os._exit(1)`, killing the worker process outright. Recovery is §12.5.

---

## 9. Dependencies

Two mechanisms produce the same data structure (`AnalysisDependency`) and share
one resolution loop.

### 9.1 Sources

**Dynamic — `wait_for_analysis()`.** A module calls
`self.wait_for_analysis(observable, SomeAnalysis, instance=...)`. If that analysis
is absent or present-but-not-completed, it raises `WaitForAnalysisException`,
which the executor catches and turns into
`observable.add_dependency(source_type, source_instance, target_observable,
target_type, target_instance)`. If the requested module is not loaded, the
executor raises `RuntimeError` instead — waiting on a disabled module is a
configuration error, not a runtime condition.

**Declared — the `dependencies:` config list.** Resolved at module-load time by
`ConfigurationManager.build_and_validate_dependency_graph()`, which caches
`module name → [module objects]` and runs a DFS cycle check that raises
`RuntimeError` at startup on a cycle. Unresolvable names (module disabled or
absent) are logged and treated as vacuously satisfied.

At runtime `_seed_declared_dependencies` seeds exactly the same dependency edge
`wait_for_analysis` would have, for each declared dependency that is not yet
satisfied on this observable. Satisfied means: the dependency module does not
accept this observable; or an existing edge is completed/resolved/failed; or the
target analysis is present as a completed `Analysis` or the `False` sentinel. A
present-but-delayed target is *not* satisfied.

### 9.2 The state machine

`ready → completed → resolved`, plus a terminal `failed`
(`saq/analysis/dependency.py`).

- `ready` — the target analysis has not been produced yet.
- `completed` — the target analysis exists; the *source* still needs re-running.
- `resolved` — the source has been re-run; the edge is done.
- `failed` — anywhere in the chain. `failed` and `delayed` both walk the
  `.next` chain, so one broken link fails/delays the whole chain.

`increment_status()` advances one step. `AnalysisDependencyManager._link_dependencies`
wires `.next`/`.prev` when one edge's target matches another's source, and
`score` (chain length) is the sort key for `active_dependencies` — shortest
chains first.

`active_dependencies` excludes failed, delayed and resolved edges.

### 9.3 Resolution

`_get_completed_dependency_work_item` looks at `root.active_dependencies` and:

- if the first edge is `ready`: if the target analysis already exists (including
  the `False` sentinel) it advances the edge; otherwise it returns a `WorkTarget`
  pinned to (target observable, target module, this dependency);
- otherwise (the edge is `completed`) it returns a `WorkTarget` pinned to
  (source observable, source module, this dependency) to re-run the waiter.

`_process_generated_analysis` closes the loop after the pinned run:

- target produced no analysis → fail the edge, advance it, and `appendleft` the
  source observable so it gets re-analyzed immediately;
- target produced non-delayed analysis → advance the edge and `appendleft` the
  source;
- target produced *delayed* analysis → do nothing; wait;
- if the run was the *source* of a `completed` edge → advance to `resolved`.

`AnalysisDependencyManager._check_circular_dependency` walks the existing edges
on every `add_dependency` and raises `RuntimeError` on a cycle, so dynamic cycles
fail loudly too.

---

## 10. Delayed analysis

### 10.1 Requesting

Module code:

```python
return self.delay_analysis(observable, analysis, seconds=30, timeout_minutes=10)
```

`AnalysisModule.delay_analysis` (defaults to 10 seconds if no interval is given)
calls the delayed-analysis interface →
`DelayedAnalysisAdapter` → `Worker.delay_analysis`, which:

1. warns if `analysis.delayed` is already set;
2. checks the *timeout* — `root.initialize_delayed_analysis_start_time(observable,
   module)` records (once, keyed `<module name>:<observable uuid>`) when delaying
   started; if `start + timeout` has passed, it returns `False`;
3. otherwise inserts the `delayed_analysis` row: `True` if the row was written,
   `False` if the insert failed (§19.4) — a delay nothing recorded is refused
   rather than reported as scheduled.

Back in `AnalysisModule.delay_analysis`:

- returned `True` → `analysis.completed = False`, `analysis.delayed = True`,
  return `INCOMPLETE`;
- returned `False` (deadline expired, or the request could not be recorded) →
  set the transient `analysis.delay_analysis_timed_out = True`,
  `analysis.completed = True`, `analysis.delayed = False`, return `COMPLETED`.
  The analysis is closed out empty and the executor's cache-write gate refuses
  to cache it.

`root.delayed` is *computed*: true if any analysis anywhere in the tree has
`delayed` set. Its setter is a deliberate no-op (the serialized value is
discarded on load).

### 10.2 Resuming

The `delayed_until` timestamp comes due; a worker on the *same node* picks the
row up (§5.3), locks the root uuid, and `DelayedAnalysisRequest.load()` rebuilds
the (root, observable, module, analysis) tuple. `_process_work_item` clears
`analysis.delayed`. The work stack contains exactly that one pinned target, and
`analyze()` is called with `delayed_analysis=True` → `continue_analysis()`.

A module may delay again; each cycle inserts a new row.

### 10.3 Interaction with completion

Three places consult `root.delayed`:

- the main loop refuses to enter final analysis mode while anything is delayed;
- `execute()` skips `_execute_post_analysis` while anything is delayed;
- `_sync_alert_to_database` skips the index rebuild while anything is delayed
  (a later non-delayed pass does the final rebuild) — unless the analysis was
  aborted, in which case it forces the rebuild.

`_check_for_outstanding_work` (§13.1) additionally excludes the delayed row
currently being processed (`AND id != %s`) so a resuming request does not see
itself as outstanding work.

---

## 11. Where the analysis cache plugs in

Two hooks in `_execute_module_analysis`, both gated on
`module.cache_ttl is not None and config.analysis_cache.enabled`:

**Read (gate 9).** `get_cached_delta(observable, module, blob_store)`. On a hit,
`_apply_cached_delta` replays the delta into the tree, records a
`from_cache_hit=True` attribution entry on `root._module_executions`, bumps
`cache_hit_count` and the lookup-latency accumulators, calls the module's
`on_cache_hit()` hook (failures swallowed), then runs the normal
`_process_generated_analysis` + `root.save()` and returns. The live path is
skipped entirely — including `analysis_covered()` time grouping, which is why
`cache_ttl` and `is_grouped_by_time` are mutually exclusive at the config level.

The read is skipped when resuming a delayed module: the observable already holds
that module's in-flight analysis, and replay would collide with it.

Replay failures deliberately fall through to the live run without re-raising, so
the outer handler does not treat a cache problem as a module failure.

**Write.** `_maybe_write_cache_delta` after a successful run, gated on
`analysis_result == COMPLETED` and `not delay_analysis_timed_out`. When the run
is the final cycle of a delayed module, earlier cycles' deltas for the same
`(module_path, observable_uuid)` are merged in first so a replay reproduces the
whole contribution.

Everything else — key derivation, storage, refusal rules, blob spilling — is
`docs/ANALYSIS_CACHING.md`.

---

## 12. Timeouts, cancellation and failure

### 12.1 The timeout layers

| Layer | Limit | Enforced by | Effect |
|---|---|---|---|
| One module invocation | mode `maximum_analysis_time`, else `global_settings.maximum_analysis_time` (warning threshold) and module `maximum_analysis_time` (kill threshold) | `AnalysisModuleMonitor` thread | warns every 5s, then `os._exit(1)` on the worker process |
| One module invocation (external view) | module `maximum_analysis_time` | `WorkerManager.check` against the worker's tracking file | `SIGKILL` the worker process tree |
| Whole run, warning | mode `maximum_cumulative_analysis_warning_time`, else global | `_check_for_analysis_timeout` | warning, rate-limited to one per 10s |
| Whole run, fail | mode `maximum_cumulative_analysis_fail_time`, else global | `_check_for_analysis_timeout` | `AnalysisTimeoutError`; modes in `analysis_modes_ignore_cumulative_timeout` are exempt |
| Delayed analysis | `timeout_hours/minutes/seconds` passed to `delay_analysis` | `Worker.is_delayed_analysis_timed_out` | refuses further delay; analysis closed out empty |
| Worker memory | `global_settings.memory_limit_kill` | `WorkerManager.check` | `SIGKILL` |
| Worker lifetime | `auto_refresh_frequency` | `Worker.worker_loop` | clean exit; manager forks a replacement |

The two cumulative limits measure `root.state["total_analysis_time_seconds"]`:
this pass plus every earlier pass of the same logical analysis run — the initial
`RootAnalysis` work item and the delayed-analysis resumptions that follow it. A
new root work item (mode transition, disposition pass, analyst-requested
analysis) starts the budget over. See §19.6.

### 12.2 Cancellation

`EngineExecutionContext.cancel_analysis()` sets a flag the main loop tests at the
top of each iteration and between modules. Four things set it:

- an analyst dispositioned the alert mid-analysis (`_check_for_alert_disposition`);
- the module itself called `cancel_analysis()` (checked via
  `module.is_canceled_analysis()` right after the call);
- an observable came back `whitelisted`;
- the lock was lost (`Worker._handle_lock_lost` → `context.cancel_analysis()`).

Because the context is created by the worker when it claims the item rather than
by the executor when it starts analyzing, the flag is live for the whole work
item. A cancel arriving during `Worker.execute`'s setup, during
`_process_work_item`'s `root.load()`, or during `_check_disposition`'s database
round trip is honored: `AnalysisExecutor.execute` opens with
`if not context.cancel_analysis_flag` and simply never enters the loop (§19.15).
`_execute_post_analysis` still runs, exactly as it does for a cancel that lands
mid-loop.

Cancellation is cooperative — a module already inside `execute_analysis` runs to
completion.

`AnalysisModuleContext.cancel_analysis_flag` (`saq/modules/context.py`) is a
*different*, deliberately separate flag: it is per module instance, reset with
every fresh `AnalysisModuleContext`, set by `AnalysisModule.cancel_analysis()`
and also read by `AnalysisModule.sleep()`. `_execute_module_analysis` promotes it
into the run-level flag above right after the call returns.

### 12.3 Module exceptions

Caught per-module in `_execute_module_analysis`:

| Exception | Handling |
|---|---|
| `WaitForAnalysisException` | create the dependency edge and move on (§9.1) |
| `ExcessiveFileDataSizeError` | re-raised — aborts the whole work item |
| `AnalysisFailedException` | logged as a warning (expected on retry after a kill), fails any dependency |
| anything else | logged as a **warning** plus `report_exception()`; the dependency (if any) is failed; with `copy_analysis_on_error` the whole storage dir is copied next to the error report; with `copy_file_on_error` a file observable is copied too |

Note that a module blowing up does not fail the work item — the loop continues
with the next module.

### 12.4 `AnalysisTimeoutError` unwinding

`AnalysisExecutor.execute` catches it, still runs `_execute_post_analysis`, and
re-raises. `AnalysisOrchestrator._execute_analysis` saves the partial tree, sets
`analysis_aborted`, deletes the root's `delayed_analysis` rows, and re-raises.
`orchestrate_analysis` catches it, logs a warning, returns `False` — and the
`finally` still runs the full post-analysis path.

### 12.5 Worker death recovery

Two independent mechanisms:

**Local fast path.** Every worker writes what it is doing to its own file under
`data/var/tracking/<node>/` (`saq/engine/tracking.py`). `TrackingWriter` keeps the
live `TrackingRecord` — `root_uuid`, `storage_dir`, `worker_name`, `pid`,
`module_path`, the observable's uuid/type/value, `maximum_analysis_time` and a
monotonic module start — in memory and flushes it to `worker-<name>.json` on every
change: once per work target and twice per module invocation. Each flush is a
`.tmp` sibling plus an `os.replace`, so the manager never reads a torn record, and
nothing is fsync'd — a power loss costs the attribution on a node that is
restarting anyway. The worker being the thing that dies is not a reason to keep
the state elsewhere: the file outlives the process. It is deliberately not in the
shared database, which every node shares, because this is node-local information
consumed only by the process that spawned the worker.

`WorkerManager.check` reads that file once per worker per tick — that is the only
read on the happy path, and it feeds both the timeout check and the memory-limit
log lines. `module_start_monotonic` is on `CLOCK_MONOTONIC`, which is system-wide
on Linux, so the manager compares it against its own reading; there is no
cross-process wall-clock comparison to be skewed by a clock step or a DST shift.

When a worker dies, `restart_worker` calls `TrackingReader.claim_failure`, which
promotes a record still naming a module to `pending/<root_uuid>.json` and removes
the worker file, and forks the replacement with the record as a `Process` kwarg.
Pending failures are keyed on `root_uuid` and live in their own directory rather
than as a flag on the in-flight record: the replacement normally re-claims the very
root that killed its predecessor, and sharing one file would let that new work
target overwrite the failure before anyone applied it — which is exactly the crash
loop this subsystem exists to prevent. A record naming no module means the worker
exited cleanly between modules, so there is nothing to attribute.

`Worker._handle_failed_analysis(record)` loads the root at `record.storage_dir`,
optionally copies the offending file + a `details-*` note to
`data/review/failed_analysis/YYYY/MM/DD/<uuid>/`
(`copy_terminated_analysis_causes`), calls
`root.set_analysis_failed(module_path, obs_type, obs_value, "process died
unexpectedly")`, saves, force-releases the lock *scoped to the lock_uuid it
actually observes* so it can never delete a live worker's lock, and finally
**deletes the pending file** — deleting it is the acknowledgement, so a replacement
that dies mid-recovery leaves the attribution in place for the next one. It also
resolves the record when `storage_dir` no longer exists, since a root that is gone
can never be attributed and the file would otherwise be immortal. The workload row
was never deleted (the `finally` never ran), so the item is immediately
re-claimable — and gate 8 (`is_analysis_failed`) skips the module that killed it.

At engine start `TrackingReader.recover_pending_failures` promotes any leftover
`worker-*.json` that still names a module — never cleared by its owner, so
unresolved by definition — discards the rest, and hands each pending record to a
worker. Dispatch is not matched on worker name, so a pool that shrank since the
last run cannot strand one. Keying the directory on the node keeps two engines
sharing a data directory apart.

**Lock-expiry recovery.** `saq/engine/recovery.py::recover_expired_locks` lists
locks older than `lock_timeout_seconds`, re-acquires each with
`allow_expired_takeover=True` (which fails if a live owner has since taken it),
and releases it. That frees the still-queued workload item. Every node runs this
for its own `node_id` on each status-update tick
(`execute_node_recovery_routines`); the primary node also runs it globally
(`execute_primary_node_routines`).

Note that lock-expiry recovery alone cannot attribute a failure — it frees the work
item but has no idea which module killed the worker, so that module runs again.
Tracking is the only carrier of that knowledge, which is why it matters most in
analysis modes that do not write mid-pass (§19.7).

---

## 13. Completion, detection, alerting and cleanup

`AnalysisOrchestrator._handle_post_analysis_logic` runs in the `finally` of
`orchestrate_analysis` — on success, on timeout, and on error.

### 13.1 "Is anything else still working on this root?"

`_check_for_outstanding_work(cursor, ctx)`:

```sql
SELECT uuid FROM workload WHERE uuid = :root AND analysis_mode != :original_mode
UNION SELECT uuid FROM locks WHERE uuid = :root AND lock_uuid != :my_lock
LIMIT 1
```
then
```sql
SELECT uuid FROM delayed_analysis WHERE uuid = :root [AND id != :this_request]
```

Both exclusions matter: our own workload row is still present (it is deleted in
`Worker.execute`'s `finally`, after all of this) and our own lock is still held.

The predicate gates three decisions — detections, cleanup, embedding submission —
and is evaluated **once per work item**. `_query_outstanding_work` opens the one
`get_db_connection()` at the top of `_handle_post_analysis_logic` and the answer
is passed to all three (§19.8). Two things follow from that:

- if the check itself fails, `_query_outstanding_work` returns `True`, so none of
  the three act;
- `_handle_analysis_mode_changes` runs in between and, on a mode change, calls
  `root.schedule()` — a new workload row under the new mode, which is outstanding
  work by definition. It returns `True` in that case and the answer is promoted
  before cleanup and embedding see it. That return is unconditional on a mode
  change, so a root whose `schedule()` *failed* is also never cleaned up.

### 13.2 Detection → alert

`_handle_detection_points` runs only when there is no outstanding work, and skips:

- roots whose mode is in `non_detectable_modes` (default `correlation`,
  `dispositioned`, `event` — this is what stops an alert from re-alerting);
- whitelisted roots (unless `forced_alerts`).

If `root.has_detections()` (or `forced_alerts`) and `alerting_enabled`, the mode
is set to `correlation`. Just before that, `_apply_detection_queue` may reroute
the alert: if the root is still on `QUEUE_DEFAULT` and **every** detection point
(tree-wide plus the root's own) carries a `queue`, the alert is routed to the
lowest-sorting requested queue. One plain detection anywhere keeps the default
queue — the reasoning being that a "real" detection should stay where analysts
look.

### 13.3 Mode transitions

`_handle_analysis_mode_changes`:

- mode changed:
  - and the new mode is `correlation` → `_convert_to_alert()`: save, move the
    storage dir to `storage_dir_from_uuid(uuid)` if it is elsewhere (repointing
    `workload.storage_dir` and `delayed_analysis.storage_dir`), then `ALERT(root)`
    → `Alert.create_from_root_analysis()` + `alert.sync()`;
  - either way → `root.schedule()`, queueing a new workload row under the new
    mode. The old row is deleted by `clear_work_target` using
    `original_analysis_mode`.
- mode unchanged and the mode is `correlation` → `_sync_alert_to_database()`:
  reload the `Alert`, `alert.load()`, `alert.sync(build_index=…)` where
  `build_index = (not root.delayed) or analysis_aborted`. Skipped entirely when
  `analysis_skipped and not analysis_aborted` (nothing ran; nothing to sync).

The alert lifecycle in mode terms:

```
<submission mode> ──detections──► correlation ──analyst disposition──► dispositioned
       │                              ▲                                     │
       └── no detections ─► cleanup   └──── analyst-requested analysis ──────┘
```

### 13.4 Cleanup

If the mode's `cleanup: true` **and** there is no outstanding work,
`shutil.rmtree(root.storage_dir)`. This is why `analysis`, `email`, `file`, `http`,
`yara`, `binary` modes leave nothing behind while `correlation`, `dispositioned`
and `event` (`cleanup: false`) persist.

### 13.5 Embedding

`_submit_alert_for_embedding_if_complete` — `correlation` mode, no outstanding
work → `saq.llm.embedding.service.submit_embedding_task(uuid)`.

---

## 14. Multi-node behavior

### 14.1 The `nodes` table

`(id, name, location, company_id, last_update, is_primary, any_mode, status)`
plus `node_modes` / `node_modes_excluded`. Status is an enum:
`starting | running | draining | draining_collectors | drained | stopped`.

Every `node_status_update_frequency` seconds the controller loop calls
`update_node_status_and_execute_primary_routines()`, which updates
`last_update`/`location` and then runs drain routines, node recovery routines and
(if primary) primary routines.

`ACE_IS_PRIMARY_NODE` (default `"1"`) decides primary status; it is mirrored into
`nodes.is_primary` at startup. Primary routines are `recover_expired_locks()`
globally and `reconcile_stale_node_statuses(node_status_update_frequency * 4)`.

### 14.2 Mode routing

`local_analysis_modes` and `excluded_analysis_modes` are mutually exclusive —
setting both is a fatal misconfiguration (`sys.exit(1)` in
`EngineConfiguration._validate_analysis_mode_configuration`). They control:

- which module sections the module loader even bothers with;
- the `WHERE analysis_mode IN/NOT IN` clause on the workload query;
- the `node_modes` / `node_modes_excluded` rows other nodes and collectors read.

`target_nodes` restricts which nodes this engine pulls *from*; the special value
`LOCAL` is translated to this node's own name.

### 14.3 Work transfer

If the winning workload row belongs to another node, `transfer_work_target`:

1. acquire the lock (bail if taken);
2. create the local target dir (bail if it already exists);
3. look up `nodes.location`, `ace_api.download(uuid, target_dir, remote_host=…)`;
4. repoint `workload`, `delayed_analysis` and `alerts` rows at this node and
   storage dir; commit;
5. load the root, set `root.location` to this node, save;
6. best-effort `ace_api.clear(uuid, lock_uuid, remote_host=…)` to delete the
   remote copy — failures are logged and ignored, since the database already
   points here.

On failure the target dir is removed and the lock released.

### 14.4 Draining

`saq/engine/node_manager/drain.py`. A draining node takes no new remote work
(§5.2) but finishes what it has. Delayed analysis is the problem case: it is
pinned to the node and `delayed_until` can be far in the future. So the drain
routine finds roots that have *only* delayed analysis outstanding (no workload
row, no lock), picks the least-loaded compatible running node using the same mode
compatibility rules collectors use, `ace_api.upload(..., sync=False, move=True)`
to push the storage dir, repoints the `delayed_analysis` rows, and removes the
local directory. At most 16 per pass.

Delayed analysis with no compatible target does not block the drain — it stays
put and resumes when the node restarts. The status machine is
`draining_collectors → draining → drained`, with revert paths in both directions
if a collector's backlog reappears or new work races in.

Restarting a node always resets its status to `starting`, which cancels a drain.

---

## 15. Persistence and I/O profile

Understanding where the writes are is essential to any performance work.

**`root.save()` frequency.** `RootAnalysisSerializer.save_to_disk` serializes
every analysis's `details` to its own file, then writes the whole tree as one
JSON document to `data.json.tmp` and `shutil.move`s it into place. It is called:

- **per module invocation** (`_execute_module_analysis`, after `analyze()`) and
  per **cache hit** replay — both through `AnalysisExecutor._save_root`, which
  applies the analysis mode's `root_save_frequency` policy (§16.2, §19.7). Unset
  (every detection mode by default) writes nothing here; `0` writes every time;
  `N` writes at most once every `N` seconds;
- once at the end of `_execute_analysis`, on success *and* on failure — this is
  the unconditional boundary write that makes the policy above safe to defer;
- again in `_convert_to_alert`;
- again inside `Alert.sync()`.

So a root that runs 40 module invocations in `correlation` (5 seconds) writes the
full document a handful of times rather than 40+, and in a detection mode writes
it only at the boundary. For a large alert tree — 1.9 MB, 306 observables, 1230
analyses on the alert profiled in `docs/GUI_ALERT_PAGE_PERFORMANCE.md` — this was
the dominant I/O cost. `saq/analysis/io_tracking.py` instruments it
(`_track_writes`/`_track_reads`); `tests/saq/engine/test_functionality.py::test_io_count`
and friends assert on the counts, though they are all currently `@pytest.mark.skip`.
`tests/saq/engine/test_root_save_frequency.py` counts the mid-pass writes directly
instead.

**Details flushing.** Analysis `details` blobs live out-of-line. When a module
produces or updates an analysis, the workflow event puts it in the buffer, and
the buffer flush calls `flush_analysis_details` — writing details to disk and
dropping them from memory. `load_details()` pulls them back on demand. This is
the memory-control mechanism for large trees.

**Database round trips per work item.** Roughly: 1–4 workload/delayed SELECTs to
claim, 1 lock INSERT, one `acquire_lock` UPDATE per keepalive tick, 1 disposition
SELECT per `_check_disposition` plus at most one per
`alert_disposition_check_frequency` seconds of analysis (§19.1),
1 `_check_for_outstanding_work`
round-trip pair in post-analysis, `Alert.sync()` + `build_index()`, 1 workload
DELETE, 1 lock DELETE.

**Per-work-item log file.** Every work item attaches a `FileHandler` on the
*root* logger writing `<storage_dir>/saq.log`. In a multi-threaded worker this
captures unrelated thread output too, and the handler is per-execution rather
than per-process.

---

## 16. Configuration reference

### 16.1 `service_engine:` (`EngineServiceConfig`, `saq/engine/core.py`)

| Key | Meaning |
|---|---|
| `analysis_pools` | `{mode: count-or-percent}`. Empty → `cpu_count()` unpinned workers. |
| `pool_size_limit` | cap on the default pool size. |
| `target_nodes` | pull work only from these nodes; `LOCAL` means this node. |
| `auto_refresh_frequency` | seconds before a worker exits so a fresh one is forked. `0` disables. |
| `default_analysis_mode` | fallback for missing/unknown modes. |
| `local_analysis_modes` / `excluded_analysis_modes` | mode allow-list / deny-list. Mutually exclusive. |
| `node_status_update_frequency` | heartbeat + maintenance tick, seconds. |
| `copy_analysis_on_error` / `copy_file_on_error` / `copy_terminated_analysis_causes` | forensic copies on failure. Disk-hungry. |
| `work_dir` | scratch storage for non-alert analysis. |
| `alert_disposition_check_frequency` | throttle for the mid-analysis disposition poll, seconds. `0` polls on every module invocation. |
| `non_detectable_modes` | modes that never promote to an alert. |
| `stop_analysis_on_any_alert_disposition`, `stop_analysis_on_dispositions` | when a disposition halts analysis. |
| `analysis_modes_ignore_cumulative_timeout` | modes exempt from the cumulative fail timeout. |
| `log_analysis_timeout_as_warning` | declared in the schema; not read by the engine code. |
| `alerting_enabled` | master switch for detection → alert. |
| `metrics_logging` | fluent-bit destination for per-module metrics. |

### 16.2 `analysis_mode_<name>:` (`AnalysisModeConfig`)

`module_groups`, `enabled_modules`, `disabled_modules`, `cleanup`, and optional
per-mode `maximum_cumulative_analysis_warning_time`,
`maximum_cumulative_analysis_fail_time`, `maximum_analysis_time`,
`root_save_frequency` (each falls back to `global_settings`).

`root_save_frequency` is how often the in-flight tree is written to disk *during*
a pass (§19.7). Omitted/`null` never writes mid-pass — correct for detection modes,
where nobody is watching an individual root; `0` writes after every module
invocation; `N` writes at most once every `N` seconds. The shipped config sets `5`
on `correlation`, `dispositioned` and `event`, the modes an analyst may be looking
at while they run. It never affects the unconditional writes at the pass
boundaries.

A mode is registered under its **`name:` field**, not its `analysis_mode_<name>:`
section key (`ACEConfig.load_analysis_mode_configs`). The two must agree — a block
whose key and `name:` disagree silently defines a mode under the wrong identity and
leaves nothing behind under the expected one. `service_engine.default_analysis_mode`
must name a defined mode: every fallback path lands there (a submission with no
mode, an unknown mode, a module declaring no modes), and if it does not resolve, all
of them get an empty module list and `get_analysis_mode_config()` raises later in the
pass. `EngineConfiguration._validate_analysis_mode_configuration` logs an error when
it does not, and `tests/saq/configuration/test_analysis_mode_config.py` guards both
invariants against the shipped config.

Resolution (`saq/engine/module_loader.py::_build_analysis_mode_mapping`): union of
every module in every `module_group`, plus `enabled_modules`, minus
`disabled_modules`, plus locally-mapped test modules. Every referenced module name
is validated to exist.

### 16.3 `analysis_module_<name>:` (`AnalysisModuleConfig`, `saq/modules/config.py`)

Engine-relevant fields: `enabled`, `priority` (execution order, ascending),
`maximum_analysis_time`, `semaphore_name`, `dependencies`, `required_directives`,
`required_tags`, `requires_detection_path`, `valid_observable_types`,
`valid_queues` / `invalid_queues`, `invalid_alert_types`, `observable_exclusions`,
`automation_limit`, `file_size_limit`, `is_grouped_by_time` +
`observation_grouping_time_range`, `cooldown_period`, `instance`, `version`,
`wide_diff`, `cache_ttl`.

Two validators reject incoherent combinations: `cache_ttl` with `wide_diff`, and
`cache_ttl` with `is_grouped_by_time`.

### 16.4 `global_settings:`

`lock_keepalive_frequency`, `maximum_cumulative_analysis_warning_time`,
`maximum_cumulative_analysis_fail_time`, `maximum_analysis_time`,
`root_save_frequency` (the fallback for modes that do not set their own — see
§16.2; shipped unset), `memory_limit_warning`, `memory_limit_kill` (both MB).

Also global runtime settings (not YAML): `lock_timeout_seconds`, `saq_node`,
`saq_node_id`, `company_id`, `forced_alerts`, `semaphores_enabled`.

### 16.5 `observable_exclusions:`

A flat top-level map of arbitrary names to `<o_type>:<o_value>` specs — the
observables the engine never analyzes, in any mode (§7.5):

```yaml
observable_exclusions:
  exclude_loopback: ipv4:127.0.0.1
  exclude_internal: ipv4:10.0.0.0/8
  exclude_user: user:-
```

The name on the left is documentation only; it just has to be unique so the
layered config can override or add entries. The value splits on the *first*
colon, so an `o_value` may itself contain colons. `EngineConfiguration` parses
this into `{o_type: [o_value]}` at construction
(`_get_observable_exclusions`); a spec with no colon is logged at ERROR and
skipped. This is separate from the per-module `observable_exclusions:` under an
`analysis_module_<name>:` block (§16.3), which uses the already-parsed
`{o_type: [o_value]}` shape and gates only that one module.

---

## 17. Observability

| Signal | Where |
|---|---|
| Per-root log | `<storage_dir>/saq.log`, attached for the duration of the work item |
| Log correlation | every line during a work item carries `transaction_id = root uuid` (`Worker.execute`) |
| What a worker is doing right now | `data/var/tracking/<node>/worker-<name>.json`, written by the worker itself |
| Per-`(root, module)` metrics | fluent-bit event per module with `analysis_time_seconds`, `percentage`, `exec_count`, `cache_hit_count`, `cache_miss_count`, `cache_write_count_insert`, lookup/write latency sums and maxima, compressed/uncompressed byte sums, `alert_type`, `is_alert`, `queue` (`EngineExecutionContext.record_execution_statistics`) |
| Module attribution | `root._module_executions` — one `ModuleExecutionDelta` per non-empty module run plus one per cache hit, persisted in `data.json` with `details` stripped |
| Node health | `nodes.last_update`, `nodes.status` |

---

## 18. Testing the engine

`tests/saq/engine/` — 120 tests in `test_functionality.py` alone, plus focused
files for the orchestrator, configuration manager, module loader, workers, node
manager, drain, recovery, workload transfer, delayed analysis, distributed
locking, cache-hit behavior, the disposition-check throttle
(`test_executor_disposition_check.py`), the global observable exclusions
(`test_executor_observable_exclusions.py`), the single per-work-item
execution context (`test_execution_context_merge.py`) and the module-facing
shutdown signal (`test_module_shutdown_signals.py`).

The standard shape (also in `CLAUDE.md`):

```python
@pytest.mark.integration
def test_x(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    o = root_analysis.add_observable_by_spec(F_COMMAND_LINE, "...")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(o.uuid).get_and_load_analysis(CommandLineAnalysis)
```

Reloading from disk is mandatory: the engine analyzed in a different execution
context and the only shared state is the serialized root.

`ConfigurationManager.enable_module(name, mode)` is the test hook — it appends to
`locally_enabled_modules` and `locally_mapped_analysis_modes` and rebuilds the
`ModuleLoader`. Once *any* module is locally enabled, `_should_load_module`
switches to allow-list semantics and only locally-enabled modules load.

Behaviors worth reading the tests for: `test_wait_for_analysis*` (the whole
dependency matrix including chained, circular, delayed source/target),
`test_declared_dependency_*`, `test_custom_requirement_*`,
`test_maximum_cumulative_analysis_*`, `test_final_analysis*`, `test_io_count*`,
`test_delayed_analysis_*`, `test_cleanup_*`.

---

## 19. Design observations

Behaviors that were verified against the code and found to be defects or
candidates for improvement, rather than descriptions of intended behavior. They
are kept out of the descriptive sections above on purpose.

The write-ups live in **[`docs/ENGINE_DESIGN_NOTES.md`](ENGINE_DESIGN_NOTES.md)** —
for each one: what was wrong, what the fix does, which alternatives were rejected,
what was deliberately left alone, and the regression guard that pins it. The
numbering below is the numbering used there and in the `see docs/ENGINE.md §19.x`
comments throughout the tests and source.

| # | Observation | Status |
|---|---|---|
| [19.1](ENGINE_DESIGN_NOTES.md#191-the-mid-analysis-disposition-throttle-never-engaged--fixed) | The mid-analysis disposition throttle never engaged | fixed |
| [19.2](ENGINE_DESIGN_NOTES.md#192-engine-level-observable-exclusions-were-dead--fixed) | Engine-level observable exclusions were dead | fixed |
| [19.3](ENGINE_DESIGN_NOTES.md#193-the-idle-backoff-never-reset--fixed) | The idle backoff never reset | fixed |
| [19.4](ENGINE_DESIGN_NOTES.md#194-a-failed-delayed-analysis-insert-still-marked-the-analysis-delayed--fixed) | A failed delayed-analysis insert still marked the analysis delayed | fixed |
| [19.5](ENGINE_DESIGN_NOTES.md#195-engineadapter-and-engineinterface-were-stale--fixed) | `EngineAdapter` and `EngineInterface` were stale | fixed |
| [19.6](ENGINE_DESIGN_NOTES.md#196-total_analysis_time_seconds-never-accumulated--fixed) | `total_analysis_time_seconds` never accumulated | fixed |
| [19.7](ENGINE_DESIGN_NOTES.md#197-rootsave-per-module-invocation--fixed) | `root.save()` per module invocation | fixed |
| [19.8](ENGINE_DESIGN_NOTES.md#198-_check_for_outstanding_work-ran-up-to-three-times--fixed) | `_check_for_outstanding_work` ran up to three times | fixed |
| [19.9](ENGINE_DESIGN_NOTES.md#199-keepalive-failure-leaked-the-claim--fixed) | Keepalive failure leaked the claim | fixed |
| [19.10](ENGINE_DESIGN_NOTES.md#1910-only-the-first-active-dependency-is-ever-examined) | Only the first active dependency is ever examined | **open** |
| [19.11](ENGINE_DESIGN_NOTES.md#1911-worker-restart-drops-the-execution-mode--fixed) | Worker restart drops the execution mode | fixed |
| [19.12](ENGINE_DESIGN_NOTES.md#1912-tracking-files-were-racy-and-process-global-by-name--fixed) | Tracking files were racy and process-global by name | fixed |
| [19.13](ENGINE_DESIGN_NOTES.md#1913-workstack-could-not-actually-hold-analysis--fixed) | `WorkStack` could not actually hold `Analysis` | fixed |
| [19.14](ENGINE_DESIGN_NOTES.md#1914-order-by-rand--limit-128-on-the-workload-query) | `ORDER BY RAND() ... LIMIT 128` on the workload query | **open** |
| [19.15](ENGINE_DESIGN_NOTES.md#1915-two-context-objects-for-one-execution--fixed) | Two context objects for one execution | fixed |
| [19.16](ENGINE_DESIGN_NOTES.md#1916-config-reload-on-sighup-is-not-implemented) | Config reload on SIGHUP is not implemented | **open** |

---

## 20. File map

```
saq/engine/
  core.py                     Engine, EngineService, EngineServiceConfig, controller loop
  enums.py                    EngineState, EngineExecutionMode, EngineType, WorkerStatus
  engine_configuration.py     EngineConfiguration (YAML + overrides → runtime settings)
  configuration_manager.py    module registry, mode→module mapping, declared-dependency graph
  module_loader.py            resolve mode configs → module section names → loaded modules
  worker_manager.py           fork/supervise/restart/shutdown the worker pool
  worker.py                   worker process loop, work-item execution, delayed-analysis API,
                              crash recovery from the manager's tracking record, current_execution_context,
                              the two shutdown events WorkerShutdownAdapter reports
  analysis_orchestrator.py    per-work-item lifecycle: load, disposition, execute,
                              detections, mode transitions, alerting, cleanup
  executor.py                 the recursive analysis algorithm, per-module gauntlet,
                              cache integration, per-module AnalysisModuleContext
                              (stateless -- state lives on the context)
  execution_context.py        EngineExecutionContext: the one per-work-item context
                              (work item, root, cancel flag, work stack, timing +
                              cache counters, metrics emission)
  work_stack.py               WorkTarget, WorkStack
  delayed_analysis.py         DelayedAnalysisRequest
  delayed_analysis_adapter.py / delayed_analysis_interface.py
  tracking.py                 TrackingWriter / TrackingReader (what a worker is doing,
                              written by the worker to a file the manager reads)
  recovery.py                 expired-lock recovery
  errors.py                   AnalysisTimeoutError, AnalysisFailedException,
                              WaitForAnalysisException
  shutdown_interface.py / shutdown_adapter.py
                              ShutdownInterface / WorkerShutdownAdapter: the shutdown state
                              modules read as self.shutdown / self.controlled_shutdown (§19.5)
  workload_manager/
    interface.py, adapter.py
    database.py               production: workload/delayed_analysis/locks tables
    memory.py                 in-process equivalent for LOCAL engines and tests
  lock_manager/
    interface.py, adapter.py
    distributed.py            locks table + keepalive thread + on_lock_lost
    local.py                  threading.RLock registry
  node_manager/
    node_manager_interface.py, node_manager_factory.py, node_manager_adapter.py
    distributed_node_manager.py  heartbeat, primary routines, drain routines
    local_node_manager.py        no-op
    drain.py                     delayed-analysis transfer during drain

supporting:
  saq/modules/base_module.py            AnalysisModule: accepts(), analyze(), delay_analysis(),
                                        wait_for_analysis(), the lifecycle hooks
  saq/modules/config.py                 AnalysisModuleConfig
  saq/modules/adapter.py                load_module_from_config()
  saq/analysis/root.py                  RootAnalysis: schedule/save/load/state/delayed/detections
  saq/analysis/observable.py            Observable
  saq/analysis/analysis.py              Analysis
  saq/analysis/dependency.py            AnalysisDependency state machine
  saq/analysis/dependency_manager.py    edge tracking, linking, cycle detection, ordering
  saq/analysis/snapshot.py              ModuleExecutionSnapshot (delta capture)
  saq/analysis/cache.py                 get_cached_delta / put_cached_delta / apply_delta
  saq/database/util/workload.py         add_workload(), request_analyst_analysis()
  saq/database/util/delayed_analysis.py add/clear delayed analysis rows
  saq/database/util/locking.py          acquire/release/force_release/expired locks
  saq/database/util/node.py             node registration, status, mode assignment
  saq/database/util/alert.py            ALERT(), set_dispositions() (→ dispositioned workload)
```
