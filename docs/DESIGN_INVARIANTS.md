# ACE design invariants

These are the assumptions the code depends on. Breaking one breaks something else, often
silently: nothing fails at the change, and the damage shows up in another subsystem or on another
node. Before changing a subsystem, read its section here.

Each entry states the rule, why it holds, the code that relies on it or enforces it, and where
the rule is written down:

- **[AGENTS.md]** is stated in AGENTS.md.
- **[docs/*.md]** is stated in the doc it names.
- **[#N]** is recorded only in that GitHub issue.
- **[undocumented]** is written down nowhere else; the code just depends on it.
- **[partial]** is mentioned somewhere but not stated as a rule.

An entry tagged **[undocumented]** or **[partial]** belongs in the doc of its subsystem. When it
is written there, change the tag to point at it.

## Keeping this current

- Code is cited as `path::Name` (`saq/engine/worker.py::Worker.execute`), never by line number.
  `tests/test_design_invariants.py` fails when a cited file, function, class, method or
  module-level name no longer exists. A non-Python file is cited by path and a string to grep
  for.
- A change that breaks or changes a rule here updates its entry in the same change, the same way
  a change that renames a name updates the doc lines that name it.
- A rule found the hard way, when something broke because nobody wrote it down, gets an entry.
- A rule that a test enforces cites the test.

---

## 1. Process environment and initialization

- **Every ACE process runs with cwd = `SAQ_HOME`.** Storage paths are relative paths built with
  `relpath(..., start=get_base_dir())`, so in any other cwd they resolve to the wrong place.
  Only `ace` runs `chdir` (`saq/cli/cli_main.py::main`). The uwsgi and uvicorn entry points
  (`ace_uwsgi.py`, `api_uvicorn.py`) rely on the image's `WORKDIR /opt/ace` (`Dockerfile`).
  `saq/util/uuid.py::storage_dir_from_uuid` and `saq/observables/file.py::FileObservable.full_path`
  rely on it, and sandboxed tools run in the same cwd so they can take ACE's paths as they are
  (`saq/modules/base_module.py::AnalysisModule.run_sandboxed_tool`).
  [docs/PROCESS_ENVIRONMENT.md, docs/TOOL_SANDBOX.md; #1119]
- **Path bases are mixed and only agree when cwd = `SAQ_HOME`.** `config:` includes and
  `SAQ_CONFIG_PATHS` resolve against the cwd. `file:` values resolve against `SAQ_HOME`. Inside a
  storage dir, `json_path` is joined to the base dir, but `file_dir` and `submission_json_path`
  are not. A missing include is skipped with only an INFO record. See
  `saq/configuration/yaml_parser.py::YAMLConfig.resolve_references`,
  `saq/configuration/yaml_parser.py::_read_file_value`,
  `saq/configuration/loader.py::_env_config_paths` and
  `saq/analysis/file_manager/local_file_manager.py::LocalFileManager.file_dir`. [docs/PROCESS_ENVIRONMENT.md]
- **`GlobalRuntimeSettings` holds hard-coded defaults until the line of
  `initialize_environment()` that sets each field.** The defaults are `/opt/ace` paths,
  instance type `DEV`, node `None` and the system temp dir. Code that runs earlier reads the
  wrong values; #1285 (`SAQ_ENC` is never removed in production) is one case. See
  `saq/environment.py::GlobalRuntimeSettings` and `saq/environment.py::initialize_environment`.
  [docs/PROCESS_ENVIRONMENT.md; #1285]
- **`initialize_environment()` deletes `http(s)_proxy` and `ftp_proxy`, in both cases, for the
  whole process and its children.** Every client that needs a proxy configures it explicitly.
  See `saq/environment.py::initialize_environment`. [docs/PROCESS_ENVIRONMENT.md]
- **App hosts, the OS and MySQL sessions all run on UTC.** Naive datetimes are compared against
  the database's `NOW()`, and CAS and YARA QA hold expiries are naive local time on purpose
  (`saq/yara_qa/store.py::record_qa_match_or_raise`). DB sessions set no `time_zone`
  (`saq/database/pool.py::_build_engine_options`, `saq/database/pool.py::_database_pool`).
  The only enforcement is `TZ=UTC` in the `Dockerfile` and a warning in
  `saq/environment.py::initialize_environment`. [docs/PROCESS_ENVIRONMENT.md]
- **`start.sh` must `exec` the ace command so Python is PID 1.** bash does not forward SIGTERM.
  See `docker/startup/start.sh` (`exec "$@"`). [docs/SHUTDOWN.md]

## 2. Node identity and clustering

- **A node's name (`global.node=AUTO`, which means `getfqdn()`) is stable, and it is the same in
  every container of the node.** That is why every ACE service in compose has `hostname: ace`
  (`docker-compose.yml`). The name is part of every storage path, and peers find a root by
  recomputing `storage_dir_from_uuid`. Renaming a node makes transfers return 404 and orphans its
  node row and lock prefix. See `saq/environment.py::initialize_environment` and
  `aceapi_v2/engine/service.py::_existing_target_dir`.
  [docs/ENGINE.md §14.1, docs/SERVICES.md]
- **Lock owners are named `<node>-worker-<name>`.** Engine startup and shutdown delete
  `<node>-%`. A lock named any other way is never cleared on restart. Two engines must never
  share a node name, and until #1286 is fixed no node name may be another's name plus `-`. See
  `saq/engine/worker.py::Worker._create_lock_manager` and
  `saq/engine/node_manager/distributed_node_manager.py::DistributedNodeManager.clear_node_locks`.
  [docs/ENGINE.md §5.4; the collision is #1286]
- **Each node's API certificate verifies against `SSL.ca_chain_path` under the name stored in
  `nodes.location`.** Work transfer, remote submission and drain all verify by default. See
  `ace_api.py::_execute_api_call`. [#1018]
- **All nodes run the same version.** Node-to-node routes have no fallback, so a rolling upgrade
  sees 404s on paths only one side has. Upgrade by draining, stopping everything, then starting
  everything. [docs/FLASK_API_MIGRATION.md]
- **Only `DistributedNodeManager.initialize_node` resets a node's status to `starting` or
  `online`, never `saq.database.util.node.initialize_node`.** Every process calls the latter,
  so if it reset the status, any `ace` command would cancel a drain. See
  `saq/engine/node_manager/distributed_node_manager.py::DistributedNodeManager.initialize_node`
  and `saq/database/util/node.py::initialize_node`. [docs/ENGINE.md §14.4]
- **Shared-state maintenance runs on the primary node only.** This covers `cas gc`, `verify`
  and `orphans`, partition maintenance, cron tasks that change shared state, blob GC and the
  `service_svs` timers. Elsewhere they exit 0 (`ACE_IS_PRIMARY_NODE`, default 1). See
  `saq/database/util/node.py::is_primary_node`, `saq/cli/commands/cas.py::_primary_or_forced`
  and `saq/cli/commands/partitions.py::cli_maintain`. [AGENTS.md; docs/CRON.md, docs/CAS.md]
- **A node-local backend (`local`) means a single-node install.** On a cluster, every pool needs
  a backend every node can reach, including pools that are not in use. Otherwise the primary's
  GC deletes rows for bytes that sit on other nodes' disks. See `saq/cas/health.py::pool_health`
  and `saq/configuration/schema.py::CASPoolConfig._check`.
  [AGENTS.md; docs/CAS.md, docs/SVS_SAMPLES.md]
- **Delayed analysis stays on the node that created it.** Only drain moves it, explicitly. See
  `saq/engine/workload_manager/database.py::DatabaseWorkloadManager.get_delayed_analysis_work_target`.
  [docs/ENGINE.md §5.3]
- **A node that is not running normally (draining, for example) never pulls work from other
  nodes.** See `saq/engine/workload_manager/database.py::DatabaseWorkloadManager.get_work_target`.
  [docs/ENGINE.md]

## 3. Storage layout and files

- **A `storage_dir` string is an identity key.** It is always the exact `SAQ_HOME`-relative
  relpath that `storage_dir_from_uuid` produces. `alerts`, `workload` and `delayed_analysis`
  match it by string equality, so an absolute path or a `./` form silently misses. Changing
  `global.data_dir` orphans every stored value. See
  `saq/database/model.py::load_alert_by_storage_dir`, `saq/engine/worker.py::Worker.execute` and
  `saq/engine/analysis_orchestrator.py::AnalysisOrchestrator._sync_alert_to_database`;
  `saq/cli/commands/alerts.py::reset_alerts` works around this by trying both forms.
  [docs/ENGINE.md §15]
- **A storage dir is self-contained.** Everything `data.json` references is relative to the dir,
  because work transfer tars it to another node and `move()` re-roots it. See
  `aceapi_v2/engine/service.py::create_download_tar` and
  `saq/analysis/persistence_manager.py::AnalysisDetailsPersistenceManager.save`.
  [docs/ENGINE.md §15]
- **Stored file bytes are immutable.** `files/` entries are hardlinks to
  `hardcopies/<sha256>`, and the analysis cache and CAS share those inodes across alerts. An
  in-place edit corrupts every copy and invalidates the sha256. See
  `saq/analysis/file_manager/local_file_manager.py::LocalFileManager.store_file`.
  [docs/ENGINE.md §15]
- **A file observable's value is its sha256, and its copy lives at
  `<storage_dir>/hardcopies/<sha256>`.** Crash reports find the bytes by value alone. See
  `saq/crash_report.py::_resolve_file_source`. [docs/CRASH_REPORTS.md]
- **A module writes a file named after analyzed content through `root.create_output_file()`.**
  It runs a sandboxed tool's output through the hostile-output rules (§16). See
  `saq/analysis/root.py::RootAnalysis.create_output_file`. [AGENTS.md]

## 4. Serialization and the analysis tree

- **An Analysis's `MODULE_PATH` (`module:Class[:instance]`) is persisted as its key in every
  alert.** Renaming or moving the class or its module, or changing a module's `instance`, turns
  every stored copy into `UnknownAnalysis`. There is no alias mechanism. See
  `saq/analysis/module_path.py::MODULE_PATH` and
  `saq/analysis/analysis.py::load_analysis_from_module_path`.
  [docs/ENGINE.md §15, §16.6]
- **Every Analysis subclass is constructible with no arguments.** Loading calls `Class()`. See
  `saq/analysis/analysis.py::load_analysis_from_module_path`. [docs/ENGINE.md §15]
- **An analysis class that cannot be imported loads as a read-only `UnknownAnalysis`, logged at
  ERROR unless it is in `deprecated_modules`. An observable class that cannot be imported
  raises.** Falling back to the generic class would drop the class's state on the next save.
  See `saq/analysis/analysis.py::UnknownAnalysis`,
  `saq/analysis/analysis.py::load_analysis_from_module_path` and
  `saq/observables/generator.py::get_observable_class`. [docs/ENGINE.md §16.6]
- **Every `data.json` key is optional on read, and a new field defaults when it is absent.**
  Old alerts, and roots transferred from nodes on other versions, go through the same code. See
  `saq/analysis/serialize/root_serializer.py::RootAnalysisSerializer.deserialize`. [docs/ENGINE.md §15]
- **`details`, `state` and extensions go through `_JSONEncoder` and come back as plain JSON.**
  Datetimes come back as strings, bytes are decoded lossily, and an unknown type raises at
  save. See `saq/json_encoding.py::_JSONEncoder.default`. [#999]
- **`Analysis.details` is `{}` on a loaded root until `load_details()` is called**, and calling
  it marks the details modified. See `saq/analysis/analysis.py::Analysis.__init__` and
  `saq/analysis/persistence_manager.py::AnalysisDetailsPersistenceManager.load_details`.
  [docs/ENGINE.md §15; #1196]
- **`root.delayed` is derived from the tree.** Its setter does nothing and the serialized value
  is ignored. It gates final analysis, post-analysis and index rebuild. See
  `saq/analysis/root.py::RootAnalysis.delayed`. [docs/ENGINE.md §10]
- **`Analysis.error` is never the empty string; the setter raises.** A set error means "not
  cached, shown as failed". See `saq/analysis/analysis.py::Analysis.error`.
  [docs/ENGINE.md §12.4]
- **ACE never stores an observable with an empty value.** See
  `saq/analysis/observable_registry.py::ObservableRegistry.record`. [docs/OBSERVABLE_TYPE_INHERITANCE.md]
- **When a module fails without creating its analysis, the failure goes in
  `root.analysis_failures` and no Analysis is synthesized.** Readers take an existing analysis
  as the module's result. [docs/ENGINE.md §12.4; #1176]

## 5. Observables and identity

- **In-tree dedup is by (exact type, `_compare_value`, and time when either side has one). A
  file's identity is (sha256, file_path).** A parent type and a subtype with the same value
  are separate observables, which is why email subtypes exist. See
  `saq/analysis/observable.py::Observable.__eq__` and
  `saq/observables/file.py::FileObservable.__eq__`.
  [docs/OBSERVABLE_TYPE_INHERITANCE.md]
- **Database identity is (type, sha256 of the UTF-8 value with errors ignored); a file uses its
  content hash.** Changing a type's normalization or its type string orphans its detections,
  comments and mappings. See `saq/analysis/observable.py::Observable._initialize_sha256_hasher`,
  `saq/database/util/sync.py::sync_observable` and
  `saq/database/model.py::Observable.__table_args__`. [docs/OBSERVABLE_TYPE_INHERITANCE.md, docs/SEARCH.md]
- **Lookups normalize a value through the observable class before hashing.** Hashing the raw
  value finds rows the engine never matches. This applies to search, `/observables/lookup` and
  observable detections. See
  `saq/database/util/observable_detection.py::resolve_observable_identity`.
  [docs/SEARCH.md, docs/FLASK_API_MIGRATION.md]
- **The observable type, directive, disposition and analysis mode strings in `saq/constants.py`
  are persisted and are never renamed.** They live in `data.json`, DB columns, workload rows,
  hunts, integrations and Splunk exports. [docs/ENGINE.md §15]
- **Code tests an observable's type through the hierarchy with `observable.is_a()`, never with
  `==`.** Dispatch is by subtype, so `observable.type == F_X` is false for every subtype. Older
  `==` comparisons remain in `saq/modules`. See `saq/analysis/observable.py::Observable.is_a`.
  [AGENTS.md; docs/OBSERVABLE_TYPE_INHERITANCE.md]
- **A FileObservable's type is always exactly `file`.** More than 40 `== F_FILE` checks depend
  on it. See `saq/observables/file.py::FileObservable.__init__` and
  `saq/analysis/cache.py::_apply_observable_spec`. [#1243]
- **The deployment's observable-types file replaces the built-in file; it does not layer on
  it.** The Python class map lives in `observable_types.classes`, never in that file. A reload
  that fails (missing file, bad YAML, a cycle) keeps the previous hierarchy. See
  `saq/observables/type_hierarchy.py::TypeHierarchy.load_yaml_config` and
  `saq/observables/type_hierarchy.py::TypeHierarchy._maybe_reload`.
  [docs/OBSERVABLE_TYPE_INHERITANCE.md, docs/IMPORTS.md]
- **Engine detection matches the exact type, case-sensitively, as `{type}:{value}` in
  node-local redis.** The yara export collapses to the parent type. The Splunk export keeps the
  exact type plus `type_path`. Expiration lookups walk ancestors, nearest first. See
  `saq/modules/observable_detection.py::ObservableDetectionAnalyzer.execute_analysis`,
  `saq/observables/export/base.py::select_detections` and
  `saq/observables/export/yara.py::YaraObservableExport.build_export_list`.
  [docs/OBSERVABLE_DETECTIONS.md, docs/OBSERVABLE_TYPE_INHERITANCE.md]
- **File names in the tree may be surrogate-escaped strings, so every UTF-8 boundary uses
  `utf8_safe`.** That covers logging, MySQL, yara and JSON. See `saq/logging.py::utf8_safe`.
  [#1235]
- **An email part's role (body or attachment) and content type are read from
  `EmailAnalysis.details["parts"]`, and from its generated file name only for an email analyzed
  before that record existed.** So the `<email>.unknown_<type>_<subtype>_NNN<ext>` names, numbered
  per type from `_000`, cannot change: old alerts tell their body parts by them, and
  observable-modifier rules match on them. See
  `saq/modules/email/rfc822.py::EmailAnalysis._body_part_types` and
  `saq/modules/email/rfc822.py::_body_part_type_from_name`. [#1241]

## 6. Engine: claiming, locking, workload

- **The workload unique key is `(uuid, analysis_mode)`, and inserts use `ON DUPLICATE KEY UPDATE
  uuid=uuid`.** Mode transitions need the old row and the new row to exist side by side. See
  `saq/database/util/workload.py::add_workload`. [docs/ENGINE.md §3.1]
- **`clear_work_target` deletes the workload row by `root.original_analysis_mode`, not the
  current mode.** See
  `saq/engine/workload_manager/database.py::DatabaseWorkloadManager.clear_work_target`.
  [docs/ENGINE.md §6.1]
- **`stop_keepalive()` never releases the lock; only `clear_work_target()` releases it, after
  post-analysis.** See `saq/engine/lock_manager/distributed.py::DistributedLockManager.stop_keepalive`.
  [docs/ENGINE.md §5.4]
- **When keepalive fails, only the `locks` row is released, scoped to its owner.** The workload
  or delayed row survives. See `saq/engine/worker.py::Worker.execute`.
  [docs/ENGINE_DESIGN_NOTES.md §19.9]
- **`current_execution_context` is published before `start_keepalive` registers
  `on_lock_lost`, and one context object exists for the whole work item.** See
  `saq/engine/worker.py::Worker.execute`. [docs/ENGINE_DESIGN_NOTES.md §19.15]
- **Expired-lock takeover is only for the recovery path, and it is scoped to the observed
  `lock_uuid`.** Workers never take over an expired lock. See
  `saq/engine/recovery.py::recover_lost_root`. [docs/ENGINE.md §12.6]
- **`delayed_analysis` deliberately has no unique index on (uuid, observable, module).** A
  re-delay inserts its new row before the resumed row is deleted. See
  `saq/database/util/delayed_analysis.py::add_delayed_analysis_request`.
  [docs/ENGINE_DESIGN_NOTES.md §19.4]
- **A delay is marked only when `add_delayed_analysis_request` returned True.** See
  `saq/database/util/delayed_analysis.py::add_delayed_analysis_request` and
  `saq/engine/worker.py::Worker.delay_analysis`. [docs/ENGINE_DESIGN_NOTES.md §19.4]
- **A transferred work item runs in the workload row's mode, not the mode saved in
  `data.json`.** See
  `saq/engine/workload_manager/database.py::DatabaseWorkloadManager.transfer_work_target`.
  [docs/ENGINE.md §14.3]
- **Queue-service row locks expire on a timer that workers never refresh.** Remediation and
  file collection therefore need one instance per cluster. A queue service releases a row only
  where the row still holds the collector's lock. See
  `saq/queue_service.py::QueueCollector.collect_work_items`. [docs/SERVICES.md; #1213]

## 7. Engine: one work item

- **The "outstanding work" predicate is evaluated once per pass and shared by detection,
  cleanup and search indexing.** A failed check counts as True, and a mode change forces True.
  See `saq/engine/analysis_orchestrator.py::AnalysisOrchestrator._handle_post_analysis_logic`.
  [docs/ENGINE_DESIGN_NOTES.md §19.8]
- **The outstanding-work SQL excludes the work item's own workload row, its own lock and the
  delayed row being resumed.** Otherwise a work item always sees itself and never alerts. See
  `saq/engine/analysis_orchestrator.py::AnalysisOrchestrator._check_for_outstanding_work`.
  [docs/ENGINE.md §13.1]
- **The search index task is submitted only after `clear_work_target()` has released the
  lock.** See `saq/engine/worker.py::Worker.execute`.
  [AGENTS.md; docs/SEARCH.md, docs/ENGINE.md §13.5]
- **`execute_post_analysis` is idempotent, because it runs on every pass that leaves nothing
  delayed.** Its recorded result is never read. See
  `saq/engine/executor.py::AnalysisExecutor.execute`.
  [AGENTS.md for SVS capture; docs/ENGINE_DESIGN_NOTES.md §19.17]
- **Pre-analysis runs at most once per module per root. A module that raises in pre-analysis is
  never retried.** See `saq/engine/executor.py::AnalysisExecutor._execute_pre_analysis`.
  [docs/ENGINE.md §7.2]
- **Analysis module instances live across work items in a worker.** State kept on an instance
  leaks between alerts unless the module clears it. [docs/ENGINE.md §7.1]
- **A new `AnalysisModule` property that the executor reads is also delegated on
  `AnalysisModuleAdapter`.** See `saq/modules/adapter.py::AnalysisModuleAdapter`.
  [docs/ANALYSIS_CACHING.md]
- **The order of the gates in `_execute_module_analysis` is a contract.** `accepts()` and the
  eligibility filters run before the cache lookup, and the config hash depends on that. See
  `saq/engine/executor.py::AnalysisExecutor._execute_module_analysis`. [docs/ENGINE.md §8]
- **`is_resuming_delayed_module` is true only for the module the delayed request names.** See
  `saq/engine/executor.py::AnalysisExecutor._execute_module_analysis`. [docs/ENGINE.md §8.1]
- **The `root_save_frequency` throttle may defer saves but never skip them.** The save at the
  end of `_execute_analysis` runs on every exit path, even when the delta is empty. See
  `saq/engine/executor.py::AnalysisExecutor._save_root` and
  `saq/engine/analysis_orchestrator.py::AnalysisOrchestrator._execute_analysis`.
  [docs/ENGINE_DESIGN_NOTES.md §19.7]
- **`set_analysis_failed` keys on `type:value`, not on the observable's uuid.** A crash can
  re-create the observable with a new uuid. See `saq/analysis/root.py::RootAnalysis.set_analysis_failed`.
  [docs/ENGINE_DESIGN_NOTES.md §19.7]
- **A failed analysis is deleted for retry only immediately before the module reruns, at most
  once per work item, and never inside `accepts()`.** See
  `saq/engine/executor.py::AnalysisExecutor._retry_used_up`. [docs/ENGINE.md §12.4]
- **The cumulative time budget resets for each new work item and carries over only to a
  delayed resumption.** See `saq/engine/executor.py::AnalysisExecutor.execute`.
  [docs/ENGINE_DESIGN_NOTES.md §19.6]
- **The work stack holds only `WorkTarget` and `Observable`, but `work_stack_buffer` stays
  mixed.** See `saq/engine/work_stack.py::WorkStack.append`.
  [docs/ENGINE_DESIGN_NOTES.md §19.13]

## 8. Processes, forking, shutdown

- **Every worker leads its own process group, and a kill is one `killpg(SIGKILL)`.** The
  controller becomes a child subreaper before the first fork and reaps adopted processes by
  pid, never with `waitpid(-1)`. See `saq/engine/worker.py::Worker.start`,
  `saq/engine/worker.py::Worker.kill`, `saq/engine/worker_manager.py::WorkerManager.become_subreaper`
  and `saq/engine/worker_manager.py::_reap`. [AGENTS.md; docs/ENGINE.md §4.4]
- **A worker never starts a child that runs Python before it execs.** That rules out
  `preexec_fn`, `os.fork()` and fork-context multiprocessing. Use `setpriv --pdeathsig`.
  [AGENTS.md]
- **Every module-level client, connection or singleton is reset in a forked child through
  `os.register_at_fork`, with a hook that only assigns.** No logging, locks or frees. See
  `saq/database/pool.py::_after_fork_in_child`, `saq/storage/factory.py::reset_storage_system`,
  `saq/cas/registry.py::reset_cas` and `saq/cas/metrics.py::reset`. [docs/PROCESS_ENVIRONMENT.md; #982]
- **`gc.freeze()` right before the fork and `gc.unfreeze()` right after it stay a pair.** See
  `saq/engine/worker.py::Worker.start`. [AGENTS.md; docs/IMPORTS.md]
- **Worker shutdown flags are lock-free shared `c_bool`s, never `mp.Event`.** The fork-visible
  shutdown mirror is a shared byte created before any fork. See
  `saq/engine/worker.py::Worker.__init__`, `saq/shutdown.py::ShutdownCoordinator.__init__` and
  `saq/shutdown.py::wait_for_shared_flag`. [docs/SHUTDOWN.md, docs/ENGINE.md §20]
- **A replacement worker inherits its pool's execution mode.** See
  `saq/engine/worker_manager.py::WorkerManager.restart_worker`. [docs/ENGINE_DESIGN_NOTES.md §19.11]
- **Tracking files are node-local, written as a temp file and then `os.replace`d, and timed
  with `CLOCK_MONOTONIC`.** Pending failures live in their own `pending/<uuid>.json`, which is
  deleted only after recovery succeeds. See `saq/engine/tracking.py::get_tracking_dir`,
  `saq/engine/tracking.py::_write_atomic` and `saq/engine/tracking.py::TrackingWriter`.
  [docs/ENGINE.md §12.6]
- **Every process's shutdown deadline is shorter than its container's `stop_grace_period`,
  enforced by an `os._exit` watchdog.** See `saq/shutdown.py::ShutdownCoordinator._watchdog_loop`.
  [AGENTS.md; docs/SHUTDOWN.md]
- **A signal handler only sets an Event and assigns attributes.** A `shutdown-observer` thread
  does the rest, and services never install handlers. See `saq/shutdown.py::ShutdownCoordinator`.
  [AGENTS.md; docs/SHUTDOWN.md]
- **At shutdown, in-flight analysis is abandoned and requeued, then node locks are cleared, and
  only then is the node marked `stopped`.** See `saq/engine/core.py::Engine.main_controller_loop`.
  [docs/SHUTDOWN.md]
- **No unbounded wait, join, lock or network call on a run, stop or shutdown path.** [AGENTS.md]
- **Code on the crash, shutdown or monitoring path never raises.** That includes CAS monitor
  records and alert routers. [AGENTS.md]

## 9. Database

- **A thread's `get_db()` session and its `get_db_connection()` cursors are separate
  connections and separate transactions.** `acquire_lock` and `add_workload` commit on their
  own and cannot see uncommitted ORM writes. See `saq/database/pool.py::get_db_connection`.
  [#1040, closed as not planned]
- **Every long-running loop calls `remove_all_sessions()` after each item.** Otherwise one
  failed commit makes every later item raise `PendingRollbackError`. See
  `saq/database/pool.py::remove_all_sessions`, `saq/queue_service.py::QueueCollector.collection_loop`
  and `saq/queue_service.py::QueueWorker.worker_loop`. [docs/SERVICES.md, docs/ENGINE.md; #852]
- **A transaction that may deadlock runs through `run_private_transaction` or
  `execute_with_retry`, and the function it runs has no outside effects.** [AGENTS.md]
- **Four Alembic chains are kept apart only by disjoint `MetaData`, each chain has one head, and
  migrations are autogenerated from `model.py`.** [AGENTS.md]
- **Deletes and updates on a growing table are batched by primary key, and comparisons use the
  database's `NOW()`.** [AGENTS.md]
- **A managed partitioned table's partition column is in every unique key, including the
  primary key, and the table has no foreign keys.** It is created with only `p_catchall`, or
  partitioned while it is still empty. `p_catchall` stays empty, maintenance refuses to split
  one holding more than 10,000 rows, and partition DDL runs with a short `lock_wait_timeout`.
  See `saq/database/partitions.py::CATCHALL_SPLIT_MAX_ROWS`,
  `saq/database/partitions.py::get_managed_tables` and
  `saq/database/partitions.py::partition_connection`. [AGENTS.md; docs/DATABASE_PARTITIONS.md]
- **A partition's retention is at least the longest TTL of the data in it.** That means
  `email_archive.partition_retention_days >= ttl_days`
  (`saq/configuration/schema.py::ACEConfig._archive_rows_outlive_their_emails`) and
  `cas_touches` retention computed from its pools (`saq/database/partitions.py::get_managed_tables`).
  The analysis cache's floor, `minimum_retention_days=31` in the same function, is hard-coded:
  `saq/configuration/schema.py::AnalysisCacheConfig.partition_retention_days` says it must exceed
  the longest module `cache_ttl`, and nothing checks that.
  [docs/DATABASE_PARTITIONS.md, docs/ANALYSIS_CACHING.md §A8]
- **`ALERT()` is the single function every alert insert goes through.** Pre-insert routing runs
  there before the row exists. See `saq/database/util/alert.py::ALERT`. [docs/INTEGRATIONS.md]
- **`alerts.updated_at` is set by the server (`ON UPDATE CURRENT_TIMESTAMP(6)`), and
  `changed_since` pages by `(updated_at, id)` with a 5-second settle margin.** See
  `saq/database/model.py::Alert.updated_at`,
  `aceapi_v2/common/listing.py::CHANGED_SINCE_SETTLE_SECONDS` and
  `aceapi_v2/common/listing.py::settled`. [docs/SVS_API.md]

## 10. Configuration

- **The layer order is fixed: lists append, scalars override, later files win.** Integrations
  depend on appending to add query sources, command types and alert routers.
  [AGENTS.md; docs/INTEGRATIONS.md]
- **An integration is off only through the merged `enabled:` of its `integration_*:` sections,
  and when it is off only those sections and its `observable_types.classes` are merged of its
  files.** A later layer can change `enabled:`, so the loader merges every layer, then merges again
  without the files of the integrations whose every section is disabled. A top-level key such an
  integration's files declared before any other file did, and no enabled integration declares, is
  then removed with what later layers set on it, since a site overlay's part of a block does not
  validate alone. Its `src/` stays on `sys.path` and its classes stay mapped so that saved alerts
  still load its analysis and observable classes. See
  `saq/configuration/loader.py::load_configuration`,
  `saq/configuration/yaml_parser.py::_disabled_integration_sections` and
  `saq/integration/integration_manager.py::is_integration_dir_enabled`. [docs/INTEGRATIONS.md]
- **`analysis_module_*` blocks register under their `name:` field, not the section key, and a
  duplicate name silently wins last.** See
  `saq/configuration/lazy_registry.py::LazyConfigRegistry.add_raw` and
  `saq/configuration/schema.py::ACEConfig._index_analysis_module_config`.
  [docs/ENGINE.md §16.3]
- **An analysis mode's `name:` equals its `analysis_mode_<name>` key, and
  `default_analysis_mode` resolves to a defined mode.** See
  `saq/configuration/schema.py::ACEConfig.load_analysis_mode_configs` and
  `saq/engine/engine_configuration.py::EngineConfiguration._validate_analysis_mode_configuration`.
  [docs/ENGINE.md §16.2]
- **`local_analysis_modes` and `excluded_analysis_modes` are mutually exclusive.** See
  `saq/engine/engine_configuration.py::EngineConfiguration._validate_analysis_mode_configuration`.
  [docs/ENGINE.md §14.2]
- **Most config sections ignore unknown keys, so removing a key needs a reject validator of its
  own.** Analysis module blocks (`saq/modules/config.py::AnalysisModuleConfig`) and some
  sections forbid extra keys; the top level and most sections do not. [#1247]
- **Optional-service callers use `find_service_config()` and never catch `ValueError` from
  `get_service_config()`.** pydantic's `ValidationError` is a `ValueError`. See
  `saq/configuration/config.py::find_service_config`. [docs/SERVICES.md]
- **`env:` and `file:` references resolve when a section is first validated, not at load.** A
  process needs only the variables of the sections it reads. [AGENTS.md]

## 11. Imports

- **A package `__init__.py` imports nothing heavy, re-exports through `lazy_getattr`, and never
  under a name a submodule also has.** See `saq/analysis/__init__.py::__getattr__`.
  [AGENTS.md; docs/IMPORTS.md]
- **Core never imports the web layer, and integrations name their router and blueprint in
  config.** [AGENTS.md]
- **The engine-API container imports `aceapi_v2.app_factory`, never
  `aceapi_v2.application`.** See `api_engine_uvicorn.py` (`from aceapi_v2.app_factory`).
  [docs/IMPORTS.md]
- **An analysis module imports its analyzer's libraries inside the method that uses them.**
  [AGENTS.md]
- **`phishkit/` and `js_deobfuscator/` never import `saq`.** See the header comment of
  `js_deobfuscator/js_deobfuscator.py`. [AGENTS.md]

## 12. Crypto

- **The wrapped data key lives in the main database's `config` table.** Every node uses the
  same `SAQ_ENC` password, and the main DB must be reachable before encrypted config values
  resolve. See `saq/crypto.py::encryption_key_set`. [docs/PROCESS_ENVIRONMENT.md]
- **`encrypt()` writes the v0 format by default; only the CAS uses v1.** The v0 chunk layout
  never changes, because `encrypted_passwords` rows and `.gz.e` archives are read across nodes.
  See `saq/crypto.py::encrypt` and `saq/cas/pool.py::CASPool.put`. [AGENTS.md; docs/CAS.md]
- **Decryption never releases unverified bytes.** The tag or sha256 is checked first, and
  output goes to a temp file that is renamed only after verification. See
  `saq/crypto.py::decrypt` and `saq/crypto.py::decrypt_stream`. [docs/CAS.md]

## 13. Content-addressed storage

- **The index tables are authoritative.** Backends are dumb byte stores that only the orphan
  sweep lists. [AGENTS.md; docs/CAS.md]
- **Only `saq/cas/index.py` writes `cas_objects`, `cas_holds`, `cas_purges` and `cas_touches`,
  and every CAS operation runs in a private session.** See `saq/cas/index.py::transaction`.
  [AGENTS.md]
- **`put` uses `INSERT ... ON DUPLICATE KEY UPDATE` (never `INSERT IGNORE`), locks the row `FOR
  UPDATE`, and writes the bytes while it holds the lock.** See
  `saq/cas/index.py::insert_object_if_absent`. [docs/CAS.md]
- **GC deletes only after one conditional UPDATE flips the row from present to deleting, with
  `NOT EXISTS` a live hold.** See `saq/cas/index.py::flip_to_deleting`. [AGENTS.md]
- **The digest is the sha256 of the uncompressed plaintext, and dedup is per pool.**
  [docs/CAS.md]
- **A `ttl` pool's index is never in the main chain.** See
  `saq/configuration/schema.py::CASPoolConfig._check`. [AGENTS.md]
- **Encrypted or compressed pools are never hardlinked or read in place, and read-cache
  consumers take an open file, never a path.** See `saq/cas/pool.py::CASPool._direct` and
  `saq/cas/cache.py::ReadCache`. [docs/CAS.md]
- **`purge` is the only way to delete a held object, and it refuses while a legal hold exists.**
  See `saq/cas/pool.py::CASPool.purge`. [docs/CAS.md]
- **The email archive puts the object in the pool before it writes the `archived_messages` row,
  and `email_archive.target` accepts only `local`.** See
  `saq/email_archive/archive.py::archive_email` and
  `saq/configuration/schema.py::ACEConfig._reject_removed_email_archive_target`.
  [AGENTS.md; docs/EMAIL_ARCHIVE.md]

## 14. Analysis cache

- **The cache key is a sha256 over length-prefixed fields: format, type, value, module,
  version, config hash and sorted `ext:` pairs.** `observable.time` is excluded. Bumping the
  format constant is the migration. See `saq/analysis/cache.py::CACHE_KEY_FORMAT` and
  `saq/analysis/cache.py::generate_cache_key`. [docs/ANALYSIS_CACHING.md §8]
- **The config hash leaves out operational fields (including `cache_ttl`) and eligibility
  filters.** That is safe only because the filters run before the lookup. See
  `saq/analysis/cache.py::CONFIG_HASH_EXCLUDED_FIELDS`. [docs/ANALYSIS_CACHING.md §8]
- **A cacheable module's output is a pure function of (type, value, version, config,
  `extended_version`).** Every other input is content-hashed (never an mtime) into
  `extended_version`. See `saq/modules/tool_version.py::file_content_version`.
  [docs/ANALYSIS_CACHING.md §A1, §A5]
- **Cacheable modules are monotonic.** A cache write is refused for removals, out-of-scope
  relationships, empty deltas, results other than COMPLETED, and an analysis with `error` set.
  See `saq/analysis/cache.py::put_cached_delta` and
  `saq/engine/executor.py::AnalysisExecutor._maybe_write_cache_delta`.
  [docs/ANALYSIS_CACHING.md §A4]
- **`cache_ttl` cannot be combined with `wide_diff` or `is_grouped_by_time`.** See
  `saq/modules/config.py::AnalysisModuleConfig`. [docs/ANALYSIS_CACHING.md §A6]
- **These modules are not cached on purpose:** yara (its output depends on file name and meta
  tags), the pcap modules (tls_keylog changes another node's analysis) and lure_url (it is
  never sealed). [docs/SVS.md, docs/PCAP_ANALYSIS.md, docs/LURE_URL.md]
- **A delayed module is cached only on its final COMPLETED cycle, with the earlier cycles'
  deltas merged in.** See `saq/engine/executor.py::AnalysisExecutor._maybe_write_cache_delta`.
  [docs/ANALYSIS_CACHING.md]
- **The cache table is append-only.** Reads take `expires_at > NOW()` ordered by `created_at
  DESC`. See `saq/analysis/cache.py::put_cached_delta` and
  `saq/analysis/cache.py::get_cached_delta`. [docs/ANALYSIS_CACHING.md §A8]
- **A snapshot, diff, key or write failure never blocks `root.save()`, and a replay failure
  falls through to a live run.** Replay stages every blob before it mutates the tree. See
  `saq/engine/executor.py::AnalysisExecutor._execute_module_analysis` and
  `saq/analysis/cache.py::apply_delta`. [docs/ANALYSIS_CACHING.md §5]
- **The `root.json` attribution copy of a delta is stripped of details, and its key is computed
  before the copy is made.** See `saq/engine/executor.py::AnalysisExecutor._apply_cached_delta`.
  [docs/ANALYSIS_CACHING.md]

## 15. Hunts and correlation

- **A hunt uuid is unique across all repositories, and dedup keys are prefixed with it.** See
  `saq/collectors/hunter/query_hunter.py::dedup_key_hunt_uuid`. [docs/HUNTS.md]
- **Files ending in `.include.yaml` are never loaded as hunts, and a non-schedulable hunt type
  never loads from disk.** See `saq/collectors/hunter/manager.py::HuntManager._list_hunt_yaml`
  and `saq/collectors/hunter/manager.py::HuntManager.load_hunts_from_config`. [docs/HUNTS.md]
- **The extra fields on the `completed hunt <name>` INFO record are a contract that SVS and
  operators query.** See `saq/collectors/hunter/base_hunter.py::Hunt.execute_with_lock`.
  [docs/HUNTS.md]
- **A correlate error or timeout never drops an event; the event falls through to alert.** See
  `saq/collectors/hunter/correlation/engine.py::CorrelationEngine.execute`.
  [docs/CORRELATION_HUNTS.md]
- **Hunt templates bind only `_event` and `_events`, and command output is sanitized against
  the credential store.** See
  `saq/collectors/hunter/correlation/validation.py::check_templates_for_removed_names` and
  `saq/collectors/hunter/correlation/engine.py::CorrelationEngine._execute_condition`.
  [docs/CORRELATION_HUNTS.md, docs/INTEGRATIONS.md]
- **An executable command always runs in the Landlock sandbox.** Its read allowlist is a code
  constant, its environment is a fixed allowlist, and TCP is allowed only to 443 and 53, never
  80. Staged sources are regular files inside a hunt repository. See
  `saq/sandbox/runner.py::SANDBOX_READ_DIRS` and
  `saq/collectors/hunter/correlation/sandbox.py::get_hunt_source_roots`.
  [AGENTS.md; docs/CORRELATION_HUNTS.md]
- **A submitted hunt names only files inside its own package.** See
  `aceapi_v2/hunt/service.py::_validate_and_execute` and
  `saq/collectors/hunter/loader.py::_load_and_merge_yaml`. [docs/HUNTS.md]
- **`query`, `executable` and `defined` are reserved command types, and each process shares one
  thread-safe instance per source or type.** See
  `saq/collectors/hunter/correlation/schema.py::BUILTIN_COMMAND_TYPES`. [docs/INTEGRATIONS.md]
- **After a stream reset, `CorrelationResult` origin indices point into the replaced stream.**
  See `saq/collectors/hunter/query_hunter.py::QueryHunt._original_events_by_submission`. [#1259]

## 16. Sandboxes

- **External programs that read alert files run through `run_sandboxed_tool()`, and a node
  without Landlock refuses rather than running unsandboxed.** See
  `saq/modules/file_analysis/pcap.py::_run_tool`. [AGENTS.md; docs/TOOL_SANDBOX.md]
- **Sandbox output is hostile.** Only a regular file with exactly one link is taken. See
  `saq/modules/base_module.py::_keep_tool_output` and `saq/sandbox/runner.py::_force_rmtree`.
  [docs/TOOL_SANDBOX.md]
- **A sandboxed command's memory limit is on the memory its processes use, measured by the
  launcher, never an rlimit on address space.** Runtimes reserve far more than they use, and the
  tools run with their default settings because of it. The launcher's last stderr line on a memory
  kill is what `run_sandboxed()` reads the memory used from, since a command can exit with
  `EXIT_MEMORY_LIMIT` itself. See `saq/sandbox/launcher.py::supervise` and
  `saq/sandbox/runner.py::_MEMORY_LIMIT_LINE`. [docs/TOOL_SANDBOX.md; #1161]
- **A sandboxed program located in a directory that holds `SAQ_HOME` or the data dir is
  refused.** See `saq/modules/base_module.py::_NEVER_TOOL_DIRS` and
  `saq/modules/base_module.py::_tool_dirs`. [docs/TOOL_SANDBOX.md]
- **Captures are recognized by magic number, never by name, and pcap output goes in
  `<capture>.pcap_objects/`, never `.extracted/`.** See
  `saq/modules/file_analysis/archive.py::ArchiveAnalyzer.execute_analysis` and
  `saq/modules/file_analysis/pcap.py::PcapAnalyzer.execute_analysis`. [docs/PCAP_ANALYSIS.md]
- **The SVS replay work dir has no `.` in its real path, because `extension` and `file_ext`
  read past the last `.` of the whole path.** See `saq/svs/yara/replay.py::_check_work_root`.
  [docs/SVS_VALIDATION.md]

## 17. YARA scanner and QA

- **The engine and the scanner see each file at the same absolute path, because only the path
  is sent.** See `saq/modules/file_analysis/yara.py::YaraScanner_v3_4.execute_analysis`.
  [AGENTS.md; docs/YARA_SCANNER.md]
- **A generation compiles the rules once and then forks. The old generation retires only after
  the new one is serving, and a failed compile never replaces a working ruleset.** See
  `saq/yara_scanning/server.py::_Manager._promote`. [AGENTS.md]
- **`scanner.sock` is a symlink that exists only while a generation is serving.** See
  `saq/yara_scanning/server.py::_Manager._publish`. [docs/YARA_SCANNER.md]
- **Every level is stopped through a control pipe, never a signal, and every child closes the
  pipe ends that belong to other processes.** See `saq/yara_scanning/server.py::_signal_stop`
  and `saq/yara_scanning/server.py::_fork`. [AGENTS.md]
- **The wire protocol is 4-byte big-endian length frames, an `A` byte on accept, `"v": 1`, and
  no pickling.** See `saq/yara_scanning/protocol.py::PROTOCOL_VERSION`. [docs/YARA_SCANNER.md]
- **Only `YaraServiceUnavailable` falls back to local scanning; a crashed scan is never
  rescanned locally.** See `saq/yara_scanning/client.py::_request`. [AGENTS.md]
- **Nothing on the scanning path touches the database.** QA files are hardlinked before the
  answer, and the job is committed by rename after it. A job still claimed at recorder start is
  dropped, never retried. See `saq/yara_scanning/qa.py::QASpooler.begin`,
  `saq/yara_scanning/qa.py::QARecorder.process_job` and
  `saq/yara_scanning/qa.py::QARecorder.drop_interrupted`. [AGENTS.md; docs/YARA_SCANNER.md]
- **The QA spool is on the same filesystem as engine storage.** See
  `saq/yara_scanning/qa.py::QASpooler.begin`. [docs/YARA_SCANNER.md]
- **`rule_content_hash` uses the same `content_hash()` as the signature inventory.** See
  `saq/signatures/loaders/yara.py::attach_rule_details` and
  `saq/signatures/loaders/yara.py::parse_rule_file`. [docs/YARA_QA.md]
- **The `enabled`, `qa`/`no_alert` and `whitelisted` meta fields are interpreted only in
  `saq/signatures/yara_meta.py`.** See `saq/signatures/yara_meta.py::detection_blocker`.
  [AGENTS.md; docs/YARA_RULES.md]
- **`qa` implies `no_alert`, and a rule without a `uuid` has nothing filed under it.** See
  `saq/yara_qa/store.py::record_qa_match_or_raise` and the docstring of `saq/svs/capture.py`.
  [docs/YARA_QA.md]
- **ACE owns `svs_marker/` and `observable_export/` under `signature_dir`.** See
  `saq/signatures/loaders/yara.py::GENERATED_RULE_DIR_NAMES`. [docs/YARA_RULES.md]
- **The marker rule is written before the scanner is built, only when its bytes change, and
  atomically.** Its regex matches `MARKER_REGEX`. See
  `saq/svs/marker_rule.py::install_marker_rule`, `saq/svs/marker_rule.py::MARKER_RULE` and
  `saq/svs/markers.py::MARKER_REGEX`. [docs/SVS_RUNS.md]
- **Only `saq/yara_qa` writes the QA tables, and only the recorder calls `record_qa_match()`.**
  A QA version is the rule's content hash, and slots are reserved by a conditional UPDATE,
  never a lock. Rollover deletes only from a superseded version, `FOR UPDATE SKIP LOCKED`. See
  `saq/yara_qa/store.py::qa_version`, `saq/yara_qa/store.py::SUPERSEDED_AFTER_SECONDS` and
  `saq/yara_qa/store.py::record_qa_match_or_raise`. [AGENTS.md; docs/YARA_QA.md]
- **The QA match row is written with `match_digest` NULL before the CAS puts, and purge, prune
  and download skip NULL rows.** See `saq/yara_qa/store.py::qa_hold` and
  `saq/yara_qa/store.py::record_qa_match_or_raise`. [docs/YARA_QA.md]

## 18. SVS: verdicts, samples, runs, coverage

- **Only explicit verdicts are stored.** The derivation rule exists exactly twice (SQL and
  `compute_effective()`), and a test holds them to agree. See
  `saq/detection_verdicts/effective.py::effective_verdict_expr` and
  `saq/detection_verdicts/effective.py::compute_effective`. [docs/SVS.md Part 1]
- **Verdicts are keyed on `(alert_id, content_hash)`, never on `detection_points.id`.** See
  `saq/database/model.py::DetectionPointVerdict.__table_args__`. [docs/SVS.md]
- **The detection identity formula is frozen, and literal hashes pin it.** A node's value hash
  is the `observables` table key. See `saq/analysis/detection_identity.py::node_identity` and
  `saq/analysis/detection_identity.py::detection_content_hash`. [docs/SVS.md]
- **SVS ignores a YARA detection without structured details.** That is how pre-SVS alerts are
  excluded. See `saq/svs/capture.py::candidates_from_root`. [docs/SVS.md]
- **An alert from a run that is not Reviewed has no verdicts and is never captured.** See
  `saq/detection_verdicts/effective.py::unreviewed_run_condition`. [docs/SVS.md]
- **Every verdict change writes history in the same transaction, and a no-op writes nothing.**
  See `saq/detection_verdicts/store.py::_write`. [docs/SVS.md Part 6]
- **A disposition is frozen by its `analyst_selectable: false` flag, never by the name
  `SIMULATED`.** A frozen alert is never reset, re-analyzed or re-dispositioned. SIMULATED
  alerts are archived, never deleted. See `saq/disposition.py::is_frozen_disposition` and
  `saq/svs/maintenance.py::open_window`. [docs/SVS_RUNS.md]
- **A sample label is never stored; `saq/svs/labels.py` derives it.** Capture is idempotent on
  `(alert_uuid, sha256, rule_uuid)`. `svs_yara_captures` has no foreign key to `alerts`, and
  deletions are checked before and after a store. See `saq/svs/capture.py::_claim_row`.
  [AGENTS.md; docs/SVS_SAMPLES.md]
- **The validation cache key includes `corpus_version()` and `engine_fingerprint()`, so a new
  input that changes results is added to one of them.** See
  `saq/svs/validations.py::corpus_version` and `saq/svs/validations.py::engine_fingerprint`.
  [docs/SVS_VALIDATION.md]
- **Validation leases: claims are conditional UPDATEs on the DB clock,
  `heartbeat * 3 <= lease`, and a worker that lost its lease drops its result.** See
  `saq/svs/validations.py::_expired`. [AGENTS.md]
- **SVS validates from its own bare mirror, copies samples with `open()` (never
  `materialize`), and compiles the way the service does.** See
  `saq/svs/yara/corpus.py::write_units` and `saq/svs/yara/child.py::run`.
  [docs/SVS_VALIDATION.md]
- **Run state changes are conditional UPDATEs, a test host belongs to one run at a time (host
  rows locked in id order), and windows are fixed at registration.** See
  `saq/svs/runs.py::_transition` and `saq/svs/runs.py::run_timers`. [docs/SVS_RUNS.md]
- **The marker cache holds only positive results.** The only cached negative is the "any run
  open?" gate. See `saq/svs/attribution.py::_Caches`. [docs/SVS.md Part 3]
- **Attribution rows are keyed on alert uuid, written in their own transaction, and never
  deleted.** An alert's SVS status is derived, never stored. See the docstring of
  `saq/svs/alert_status.py`. [docs/SVS_RUNS.md]
- **An alert router never changes the tree and never breaks `ALERT()`.** Routers run in
  priority order, with SVS at 100. A router moves only OPEN alerts with no owner, and the
  automation user counts as no owner. A `svs_manual` move holds the alert in place. See
  `saq/alert_routing/registry.py::route_alert` and `saq/svs/routing.py::MarkerRouter.route`.
  [docs/SVS.md, docs/INTEGRATIONS.md]
- **A catalog test's identity is its `auto_generated_guid`, and a vanished test keeps its row.**
  See `saq/svs/catalog.py::parse_atomic_file` and `saq/svs/catalog.py::_store`.
  [docs/SVS_RUNS.md]
- **A catalog test counts (coverage, the worklist, registration) only while it is in its repository
  and not excluded, and an exclusion deletes nothing.** Each reader of the tests that count applies
  both conditions. See `saq/svs/test_state.py::excluded_condition` and
  `saq/svs/coverage.py::refresh_coverage`. [docs/SVS_RUNS.md, *Excluded tests*]
- **A coverage refresh is one transaction under the `svs_coverage_state` lock, worklist first,
  changed columns only, and rows are retired, never deleted.** ATT&CK is never fetched in
  production. See `saq/svs/coverage.py::_write` and
  `saq/configuration/schema.py::SVSConfig.attack_release`. [AGENTS.md; docs/SVS_COVERAGE.md]
- **The public identifiers are stable:** alert uuid, signature uuid, `content_hash`, sample
  sha256, validation uuid, test GUID, run uuid and technique id. [docs/SVS_API.md]
- **SVS log records carry `svs_run`, `svs_test` and `svs_marker` in `extra`, and a test pins
  that contract.** See `tests/saq/svs/test_logging_contract.py`. [docs/SVS.md Part 5]
- **`signature_version` is the repository commit, not the rule text; use `content_hash` for the
  rule's identity.** [#1131]

## 19. Search

- **Qdrant point ids are `uuid5(alert uuid, kind:key:chunk)`, and re-indexing upserts before it
  deletes.** See `saq/search/index.py::point_id`. [docs/SEARCH.md]
- **The collection name embeds the model slug and `SCHEMA_VERSION`.** See
  `saq/search/index.py::collection_name`. [docs/SEARCH.md]
- **A query term or filter that cannot be honored is an error, never dropped.** See
  `saq/search/syntax.py::_parse_term` and `saq/gui/filter_url.py::decode_filter_query`.
  [docs/SEARCH.md, docs/ALERT_FILTER_URLS.md]
- **Only `download_model()` fetches the model.** See `saq/search/model.py::download_model` and
  `saq/search/model.py::load_model`. [docs/SEARCH.md]
- **Search and "similar alerts" leave out `svs.queue` unless queues are named, and prevalence
  (`/observables/lookup`) counts only `default` unless the request names queues.** See
  `saq/search/query.py::leave_out_test_alerts` and
  `aceapi_v2/observables/service.py::_alert_predicates`. [docs/SEARCH.md, docs/SVS_RUNS.md]

## 20. API, auth, GUI

- **Every v2 route has a permission gate, and a test enforces it.** See
  `tests/saq/test_permission_catalog.py::_fastapi_apps`. [docs/FLASK_API_MIGRATION.md]
- **A migrated route keeps its legacy (major, minor) permission pair.**
  [docs/FLASK_API_MIGRATION.md]
- **`ApiAuthResult` is falsy for the empty sentinel, and `system()` auth has an empty scope.**
  See `saq/auth.py::ApiAuthResult`. [docs/FLASK_API_MIGRATION.md]
- **Cookie-authenticated unsafe requests pass the `Sec-Fetch-Site`/`Origin` check, and proxies
  forward those headers.** See `aceapi_v2/dependencies.py::_reject_cross_site_cookie_write`.
  [docs/FLASK_API_MIGRATION.md]
- **The startup seed is the only thing that writes `auth_permission_catalog`, so a new permission
  is a `PERMISSION_CATALOG` entry and no migration.** The seed never prunes: a removed entry's row
  stays until `ace perm catalog sync`. See `saq/database/seed.py::seed` and
  `saq/permissions/catalog.py::sync_permission_catalog`; `tests/saq/database/test_seed.py` pins it.
  [AGENTS.md]
- **No API key holds `user:self`, and minting a key needs a GUI session.** See
  `saq/permissions/catalog.py::SESSION_ONLY_PAIRS`. [docs/USER_PREFERENCES.md]
- **An alert's file is never served inline.** It goes out with `nosniff` and a `CSP: sandbox`
  header. File bytes leave ACE only as `infected`-password zips. See
  `aceapi_v2/alerts/router.py::get_observable_image`. [docs/FLASK_API_MIGRATION.md, docs/SVS.md]
- **nginx routes `/api/v2/engine/*` to `http-api-engine`, and `create_app()` still mounts those
  routes.** See `etc/nginx/conf.d/default.conf` (`location /api/v2/engine/`).
  [AGENTS.md; docs/ENGINE_API.md]
- **Sync code in the FastAPI apps reaches a thread only through `run_db_in_thread`.**
  [AGENTS.md]
- **Integration routes live under `/api/v2/integrations/<name>`, with a per-route gate.** See
  `aceapi_v2/application.py::create_app`. [docs/INTEGRATIONS.md]
- **The GUI CLI sends only an execution id between nodes, and refuses global and
  secret-bearing options.** See `aceapi_v2/cli/service.py::claim_execution`. [docs/GUI_CLI.md]
- **Filter slugs are permanent, `LEGACY_FILTER_NAME_ALIASES` is append-only, and the encoding
  lives only in `filter_url.py`.** See `saq/gui/filter_names.py::FILTER_SLUGS` and
  `saq/gui/filter_names.py::LEGACY_FILTER_NAME_ALIASES`. [docs/ALERT_FILTER_URLS.md]
- **Polled Datastar endpoints never write the session and send `private, no-store`.** See
  `app/analysis/views/manage.py::manage_refresh`. [docs/GUI_DATASTAR.md]
- **Durable preferences go only through `PREFERENCE_SCHEMAS`; view state stays in the
  session.** [docs/USER_PREFERENCES.md]
- **Alert and observable comments are stored normalized: LF line breaks, no edge whitespace.**
  The models' validators normalize every ORM write, the raw inserts in `saq/database/util/alert.py`
  call it themselves, and an edit compares the normalized text with the stored one by plain
  equality. See `saq/database/model.py::normalize_comment`. [#1165]

## 21. Crash reports

- **Nothing in `saq/crash_report.py` raises.** [AGENTS.md]
- **`metadata.json` is written last and atomically, and it marks the report complete.**
  Replication uploads it last too. See `saq/crash_report.py::_write_atomic`.
  [docs/CRASH_REPORTS.md]
- **The timeout watchdog writes with `index=False`, and deferred indexing uses a spool outside
  every report directory.** See `saq/engine/executor.py::AnalysisModuleMonitor.run`.
  [docs/CRASH_REPORTS.md]
- **The filesystem is authoritative.** `analysis_module_crashes` is a derived, idempotent
  index. [AGENTS.md]
- **`crash_id` is validated as a uuid4 before any path is built.** See
  `saq/crash_report.py::CRASH_ID_PATTERN`. [docs/CRASH_REPORTS.md]
- **Prune deletes the remote copy first.** [docs/CRASH_REPORTS.md]

## 22. Deployment, multi-instance, cron

- **`ACE_STACK` is the compose project name, and `COMPOSE_PROJECT_NAME` is never set.** See
  `docker-compose.yml` (`name: ${ACE_STACK:-ace}`) and `docker/startup/initialize_volumes.sh`.
  [AGENTS.md; docs/MULTI_INSTANCE.md]
- **Only five host ports are fixed, and no code depends on an ephemeral port.** See
  `docker-compose.yml`. [AGENTS.md]
- **The phishkit manager reaps only containers with its own `phishkit.stack` label.** See
  `phishkit/phishkit.py::_list_phishkit_containers`. [docs/MULTI_INSTANCE.md]
- **Cron tasks are unordered and parallel, and a task's file name is its stable identity.** See
  `saq/cron_tasks.py::IGNORED_SUFFIXES` and `saq/cron_tasks.py::get_max_parallel_tasks`.
  [AGENTS.md; docs/CRON.md]

## 23. Integrations and tests

- **An integration's `python_module` is imported by every process, so it registers only light
  hooks.** Everything for an integration stays under `integrations/<name>/`. [AGENTS.md]
- **`create_root_analysis()` gives each root a fresh uuid, and so a storage directory of its
  own, because unit tests do not wipe the data directory between tests.** A test passes `uuid=`
  only to reopen a root it saved. See `tests/saq/helpers.py::create_root_analysis`. [#1130]
- **Module-level state is reset in `global_function_setup`, because the suite runs in random
  order.** [AGENTS.md]
