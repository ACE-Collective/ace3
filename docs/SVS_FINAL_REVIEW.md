# SVS: final pre-implementation review

> **Status: review, not design.** Written 2026-09-28 against `docs/SVS.md` (design of record) and
> `docs/SVS_REVIEW.md` (decision record, frozen after round 10), with every claim below checked
> against the checkout at `9d20ef7d` (`jd/svs`, which includes `origin/main` after the CAS merge).
> Nothing here reverses an agreed decision. It lists what the design still leaves undefined, what
> the code does differently from what the design assumes, and what has to land before each phase.
> Item IDs are `FR-n` so they can be cited the way `DP-2` and `ART-15` are.

## Summary

The design is coherent and the decisions hold up. Four things need a decision or a code change
before the phase they belong to can start, and none of them is large:

| ID | Concern | Blocks |
|---|---|---|
| FR-1 | The CAS has no shared backend, so the `svs_samples` pool cannot be `shared: true` | phase 2 on a multi-node site |
| FR-2 | The alert-router "explicit queue" and priority rules, as written, stop the SVS router from ever routing hunt alerts that carry a queue, or alerts whose YARA rule carries a `queue` meta | phase 4 |
| FR-3 | A `PRE_INSERT` router cannot persist a tag or detection, because the orchestrator saves the root *before* `ALERT()` | phase 4 |
| FR-4 | Closing a run sets `SIMULATED`, and `SIMULATED` is class tp, so a discarded run still feeds TP samples | phase 4 |

Two more are pre-existing core defects the design depends on not existing:

| ID | Concern |
|---|---|
| FR-5 | A `dispositioned` work item pulled by another node runs in correlation mode instead, so capture silently does not run |
| FR-6 | Correlation-mode submissions sent to a *remote* node never get an `alerts` row (review item F-24, now confirmed) |

Phase-0 status: **only the CAS has landed.** Every other phase-0 PR is still to do (§5).
§7 records what the v3.0.121 release changed under the design after this review was written.

---

## 1. Blocking: settle before the phase

### FR-1 — No shared CAS backend, so samples cannot be shared between nodes  *(phase 2)*

The design requires the sample pool to be shared: "SVS samples must be shared, because they are
captured on whichever node analyzed the alert and scanned by the SVS service" (CAS-6). The CAS as
merged rejects that configuration:

- `saq/configuration/schema.py:696-697`: `shared: true` with `backend: local` raises at config
  validation, and `backend:` accepts only `local | custom` (`:678`).
- `docs/CAS.md`, *Still open*: "the S3 backend, needed before any pool can be `shared: true`".
- `etc/saq.default.yaml:187-188` says the same in the commented `svs_samples` example.

On a single-node instance this is fine. On the site installation, capture happens in the engine of
whichever node owns the alert, and validation runs in `service_svs` on one node, so the pool has to
be reachable from every node.

**Options.** (a) Build the S3 backend as a phase-2 prerequisite. `docs/CAS.md` already specifies
it (`get_s3_client()`, conditional writes), the email archive already has S3 configuration on the
site, and it is the smaller of the two remaining CAS gaps. (b) A `custom` backend on a shared
filesystem that declares `node_local = False`. That works today with no CAS change, but every node
needs the mount, and it is a second storage mechanism to operate. **I recommend (a)**, and adding
it to the phase-0 table in `docs/SVS.md` as the last phase-0 PR. Either way, `docs/SVS.md` should
say which one the site deploys, because the capture module cannot be turned on until it exists.

### FR-2 — The router rules, as written, exclude the alerts that matter  *(phase 4)*

Two rules in Part 3 interact badly with how queues actually work.

**"An explicitly set `root.queue` is never overridden."** There is no flag that says a queue was
set explicitly. `RootAnalysis.queue` always has a value (`saq/analysis/root.py:75`, default
`QUEUE_DEFAULT`), and the existing router, `_apply_detection_queue`, implements "explicit" as
`root.queue != QUEUE_DEFAULT` (`saq/engine/analysis_orchestrator.py:402`). Every hunt has a
`queue:` field (`saq/collectors/hunter/base_hunter.py:79`) and submits with it
(`query_hunter.py:482`). So under this rule, **a hunt configured to a non-default queue produces
alerts the SVS router can never move**, whatever marker they carry. EDR hunts are exactly the
signatures test runs are meant to exercise.

**"Routers run in priority order, the first decision wins", with `_apply_detection_queue` as the
first built-in.** If a YARA rule with a `queue` meta matches a dropped test file, the
detection-queue router decides first and the SVS router never runs. The alert lands in the rule's
queue, unattributed, and the run reads *missing*.

**Recommendation.** Make three things explicit in Part 3:
1. Priority is a number on each router (built-in or config), and the SVS marker router runs
   **before** the detection-queue router.
2. A marker that agrees with its run is stronger evidence than a configured queue. The SVS router
   may route an alert whose queue was set by hunt config or detection meta. The only queue it
   never overrides is one the SVS queue primitive itself set earlier (so a manual *disassociate*
   is not undone by re-analysis), and `move_alert_to_queue` records that.
3. Every router runs inside a `try` in the registry, and a failing router is logged and skipped.
   `ALERT()` must never fail because a router did. ART-15 says this for *loading* a router; it has
   to hold at runtime too, since the registry sits inside every alert insert.

If instead the team wants "hunt queue wins", say so and accept that queue-specific hunts are
excluded from attribution. That is a worse outcome, but it should be a decision, not a side effect.

### FR-3 — A `PRE_INSERT` router cannot persist a tag or a detection  *(phase 4)*

Part 3 says a marker that does not agree with its run gives the alert the tag `svs:marker_mismatch`
and "a detection from a built-in signature". At `PRE_INSERT` that means mutating the root tree
inside `ALERT()`. The engine path saves the root *before* the call (`_convert_to_alert`,
`analysis_orchestrator.py:462` then `:471`), and `ALERT()` itself does not save
(`saq/database/util/alert.py:167-175`). A detection added there is indexed into `detection_points`
by the sync, but it is not in the JSON on disk. The next load and sync delete the row again, and
the mismatch is gone. The same holds for the other seven callers of `ALERT()`.

**Recommendation.** `PRE_INSERT` routers are pure: they return a `RouteDecision` and may write
their own rows (`svs_attributions`) in the caller's transaction, but never touch the tree. The
mismatch tag and detection are added at `POST_ANALYSIS`, which runs in the orchestrator and owns
the root, or by a small analysis module in correlation mode. Since hunt alerts get analyzed after
insert anyway and engine-converted alerts get a correlation pass, nothing is lost, and the mismatch
still surfaces before an analyst sees the alert. Write this rule into the `AlertRouter` contract in
`docs/INTEGRATIONS.md`, because integration routers will hit the same trap.

### FR-4 — "Nothing is learned from a Closed run" is not true for YARA samples  *(phase 4)*

*Close* (MGT-3) sets `SIMULATED` on the run's alerts, "and nothing is learned from it". But
`SIMULATED` is class tp (D-16), `set_dispositions()` requeues every non-IGNORE disposition into
`analysis_mode_dispositioned` (`saq/database/util/alert.py:284-300`), and the capture module
captures every YARA-matched file on a tp-class alert as a TP sample. A run closed because it hit
the wrong target or ran a broken image therefore adds TP samples to the corpus, and so does every
Canceled or Error run that the timer closes. Those are precisely the runs whose alerts are least
trustworthy.

**Recommendation.** The capture module skips alerts attributed to a run whose state is not
*Reviewed* (one join on `svs_attributions` → `svs_runs.state`). Alerts with no attribution (normal
alerts) are unaffected. State this under *Capture* in Part 2 and under *Test alerts downstream* in
Part 3.

---

## 2. Pre-existing defects the design depends on

### FR-5 — A `dispositioned` work item pulled by another node runs in the wrong mode

Capture rides on `analysis_mode_dispositioned`. The requeue targets the alert's own node
(`alerts.location`, `alert.py:285-297`), but any node of the same company may pull it when it has
no local work (`get_work_target(local=False)`, `saq/engine/workload_manager/database.py:413-416`).
`transfer_work_target` (`:123-230`) downloads the storage directory and returns
`RootAnalysis(uuid=…, storage_dir=…)` **without the work item's `analysis_mode`**. The orchestrator
then falls back to the mode saved in the JSON (`analysis_orchestrator.py:147`), which is
`correlation`, and `_check_disposition` skips the alert. The `dispositioned` workload row appears
to survive (the clear deletes by the original mode), so the item may run later on the new owner,
but that is inferred from the SQL, not tested.

Today this is invisible because dispositioned mode runs nothing
(`etc/saq.default.yaml:2700-2710`; its only module is `enabled: false`). Once capture depends on it,
a transferred item is a silently missed capture, and the bytes may be gone by the time anyone
notices (FP alerts are archived after `fp_days`).

**Recommendation.** Fix in the phase-2 PR, with a test: either `transfer_work_target` carries the
mode, or dispositioned work is never transferred (it needs no re-analysis, only the local bytes).
The second is simpler and matches what the mode is for.

### FR-6 — Correlation-mode submissions to a remote node never get an `alerts` row

Review item F-24 was marked unverified. It is real: `RemoteNode.submit_remote` uploads with
`is_alert=False` and never calls `ALERT()` (`saq/collectors/remote_node.py:118-141`); the receiving
endpoint only schedules the root (`aceapi/engine.py:77-192`); and the engine's later
`_sync_alert_to_database` finds no row and does nothing (`analysis_orchestrator.py:506-544`). Such
a submission is analyzed and then lost.

This does not break the choke-point argument of ART-15 (`ALERT()` is still the only insert), but it
means any hunt whose collector submits to a remote node produces no alert at all, test or not.
Check whether the site's collectors ever take the `submit_remote` path. If they do, this is a
phase-0 fix in its own right, before any run is measured.

---

## 3. Design gaps to settle (non-blocking, but decide before the phase)

### FR-7 — `SIMULATED` alerts are kept forever  *(phase 4)*

Maintenance archives only `FALSE_POSITIVE` alerts and deletes only `IGNORE` ones
(`saq/util/maintenance.py:72-125`). Every other disposition is kept with its full storage
directory. `SIMULATED` alerts will be the steadiest source of new alerts once the test program runs
(every test, every run, every target), and nothing ever frees them. Their bytes are already in the
CAS after capture, so keeping the directories buys nothing.

**Recommendation.** A retention rule for `SIMULATED`: archive like FP after `svs.simulated_days`
(default 30), or delete after the run's attribution window plus a grace period. Also add
`SIMULATED` to the engine's `stop_analysis_on_dispositions` (`etc/saq.default.yaml:2588`), since
nothing needs further analysis of a test alert.

### FR-8 — Marker resolution must never declare a mismatch from a stale cache  *(phase 4)*

Part 3 resolves markers "through a short-lived per-process cache". The router runs in every
process that calls `ALERT()`: engine workers, the hunter's collector, the API, the Flask GUI and the
CLI. A launcher registers a run, starts the test within seconds, and an EDR hunt fires within a
minute. A process whose cache predates the registration would resolve the marker as *unknown*,
route the alert to the default queue, tag it `MARKER MISMATCH`, and an analyst would investigate a
test. That is the loud signal, triggered by a cache TTL.

**Recommendation.** Cache only positive resolutions. A marker that misses the cache always goes to
the database before any decision. Separately, gate the whole scan (regex over every observable
value and `root.details`, on every alert insert, forever) behind one cheap check, "is any run
inside an open attribution window?", cached for a few seconds, so the router costs nothing when no
test is running. Say both in Part 3.

### FR-9 — Context-only attribution is undefined per detection and under concurrent runs  *(phase 4)*

- ART-7 makes attribution per detection, and `PARTIAL TEST` depends on it. Context attribution
  (no marker) has no per-detection signal. Which detections does a context match attribute? The
  simplest rule is *all of them*, so a context-only alert is always `TEST?`, never partial. Write
  it down.
- Two runs on the same target with overlapping windows and no marker: which run gets the alert?
  Recommend: context attribution requires exactly one candidate run; otherwise no attribution, and a
  WARNING record with both run UUIDs. Attributing to the wrong run teaches the wrong expectation.
- "The event falls inside the run's attribution window": which timestamp? `root.event_time` is the
  right one for hunts (the query's event time) and falls back to insert time for the rest. Specify.

### FR-10 — The first run of a test has the shortest window when it needs the longest  *(phase 4)*

The observation window is computed from the test's *expected* signatures. The first run has none,
so it gets the floor (60 minutes in the sketch). A daily hunt with a 24-hour range cannot arrive in
that window. Its alert lands in the attribution window as *late*, and only if the operator has
already reviewed does the run come back as *changed since review*. The first run is where
expectations are discovered, so this is the run that most needs the full window.

**Recommendation.** With no expectations, the window is the maximum worst-case latency over every
*enabled* hunt (or the ceiling), not the floor. One sentence in Part 3.

### FR-11 — Isolating PR rules: `include`, symlinks, duplicate uuids, warnings  *(phase 3)*

YR-9 puts compilation in a subprocess with limits. Three details are still open:

- **`include` and symlinks.** `git archive` preserves symlinks, and a YARA `include` resolves
  relative to the rule file or by absolute path. A PR can therefore read files on the SVS node
  through a rule. Compile with `includes=False`, or an include callback confined to the export
  tree. Better: run the compile-and-scan subprocess in the Landlock sandbox that shipped with
  correlation hunts. `build_sandbox_argv` / `run_sandboxed`
  (`saq/collectors/hunter/correlation/sandbox.py:243-397`) take any argv, the venv is readable
  inside, and a YARA caller passes its own `ExecutableSandboxConfig` with `allowed_tcp_ports=[]`.
  Only `stage_executable` and `get_sandbox_config()` are hunt-specific.
- **Duplicate `uuid` meta in the head tree** makes two rules share one label set. YR-7 covers a
  missing uuid; the report should list duplicates as *not regression-testable* too.
- **Compile diagnostics.** `yara_scanner.load_rules()` logs a failing file and returns `False`; it
  does not return which namespace failed or why, and it exposes no compiler warnings. The
  validation should compile with `yara.compile(sources=…)` directly, per namespace, which gives
  the error text and `Rules.warnings` (present in yara-python 4.5.4). That is a detail for the
  implementer, but it decides which library the validation is written against.

### FR-12 — The scanning node holds the whole corpus in plaintext  *(phase 3)*

The pool is encrypted, but `materialize` of an encrypted object goes through the node-local read
cache (`docs/CAS.md`, *Read cache*), and replay writes each sample at `<tmp>/files/<file_path>`.
Both are plaintext live malware and customer documents on the SVS node's disk. That is inherent in
scanning, so accept it, but say it in Part 2: the SVS node is a malware store (AV exclusions,
disk encryption, restricted shell access), the replay tree is deleted after every validation, and
`cas.read_cache.max_bytes` is sized to the corpus so a validation does not decrypt tens of
thousands of objects twice.

### FR-13 — `service_svs` topology and idempotent transitions  *(phases 3, 4)*

X-1 puts scans, run timers and the catalog refresh in `service_svs`, without saying how many of it
run. Two instances would fire every timer twice and scan every validation twice.

**Recommendation.** One instance (primary node, like the CAS cron tasks), and every timer transition
written as a conditional update (`UPDATE svs_runs SET state='ended' … WHERE id=? AND
state='started'`) so a duplicate is harmless anyway. Validations are a queue with a concurrency cap
of one scan at a time by default, and a result is cached per `(repository, base_sha, head_sha,
corpus version)` so a CI retry does not rescan.

### FR-14 — Where the ATT&CK catalog comes from  *(phase 5)*

`attack_release: "v17"` implies ACE has the technique list (ids, names, parents, revoked and
renamed techniques) for that release. Nothing in the repo has it, and production ACE should not
fetch it from the internet at startup. Decide: vendor a compact JSON extract in the repo per
supported release, or point a `git_repo_<name>` section at a MITRE CTI checkout and parse it the
way the ART catalog is parsed. The extract is smaller and needs no polling.

### FR-15 — Smaller items to decide

- **Test hosts in YAML** (ART-9) means every process that evaluates routers restarts to add a host.
  Acceptable for a lab, but say so; the alternative is a table under `svs:admin`.
- **Refused registrations create alerts** (ART-9). A misconfigured launcher retrying in a loop
  creates one alert per call. Collapse them: one alert per `(caller, host)` per hour, the rest
  logged at WARNING. Cap the size of the launcher's `extra`, which is stored and rendered.
- **"Has unlabeled detections"** (Part 1, manage page) is nearly empty under D-6: every detection
  on a classified alert inherits a verdict. The useful filter is *has unconfirmed
  (`inherited_multi`) detections*. Reword.
- **Verdict chips on `SIMULATED` alerts** should not be editable by analysts; the run review owns
  those verdicts (the ignore lists write FP overrides). Otherwise an analyst override and a run
  re-review fight over the same row.
- **The automation user.** `SIMULATED` is written by user id 1 (`ace`, seeded in
  `saq/database/seed.py:53`, `automation_user_id` in `saq/environment.py`). `set_dispositions()`
  also backfills `owner_id` with the dispositioning user (`alert.py:261-266`), so test alerts will
  be *owned by `ace`*. The "an owned alert is never moved" rule has to treat the automation user
  as nobody, or a re-review can never move an alert.
- **Verdict source is computed from the current signature count.** Re-analysis or `ace alerts
  reset` that adds or removes a detection flips `inherited_single` ↔ `inherited_multi`
  retroactively. Acceptable, but `svs_validation_results` should store the label *and its source*
  at scan time, so a report is reproducible after the alert changes.
- **A changed `disposition_classification` relabels the whole corpus at once**, since labels are
  derived at read time. Intended, but worth an INFO record at startup listing the map, and the
  existing rule that unknown keys fail validation.
- **`analysis` node identity** (DP-7) uses the module path. A refactor that moves a module
  changes every detection on its analysis nodes. Detections on analysis nodes are rare (most sit
  on observables or the root); measure with one query before pinning, and prefer the config
  module `name` if it is at least as stable.
- **`signature_version` is `"unknown"` unless `service_yara.git_repo_dirs` is set** (it defaults
  to `[]`, `etc/saq.default.yaml:1191`). The capture record's audit column is worthless without it;
  confirm the site sets it.

---

## 4. Implementation hazards: where the code differs from the design's text

These do not change any decision. They are places where `docs/SVS.md` describes the code
inaccurately, and an implementer who trusts the text will be surprised.

| ID | `docs/SVS.md` says | The code does | Consequence |
|---|---|---|---|
| FR-16 | "The `detection_points` rows themselves are deleted and reinserted as the tree changes" (Part 1) | `sync_detection_points` is a delta upsert keyed on `(alert_id, content_hash)`; unchanged rows keep their `id` (`saq/database/util/index.py:331-385`) | The conclusion (verdicts keyed on `content_hash`, not `id`) still holds. Fix the sentence. |
| FR-17 | "`alerts` gains `updated_at`, set wherever `alerts.version` rotates (`Alert.sync()`, `touch_alerts()`)" (Part 6) | `version` is rotated in seven places: `Alert.sync()`, `Alert.archive()`, `touch_alerts()`, and inline `version = %s` in `alert.py:227, 264, 382, 446` | Use a server-side `ON UPDATE CURRENT_TIMESTAMP` column rather than seven call sites. Keyset for `changed_since` is `(updated_at, id)`. |
| FR-18 | "`saved_filters` gains a `screen` column" (Part 5) | Also in the way: the unique key is `(user_id, name)`; the `working`/`temp` scratch rows are one per user; `FilterEntry` validates names against the alert `FILTER_NAMES`; `create_filter` and the correlated subqueries hard-code `Alert` (`saq/gui/filter_query.py:88-95, 185-190, 236-243, 324, 351`) | The phase-0 PR is "saved filters per screen", not "a column": unique `(user_id, screen, name)`, scratch rows per screen, a registry object per screen passed to the validator, and an `entity`-generic query builder. |
| FR-19 | The executor scans "each new analysis's `details` and new observables, by an executor hook right after the module returns" (Part 3) | There is no post-module hook. What exists right after `analyze()` returns is the `ModuleExecutionDelta` (`executor.py:1478-1485`), which already lists the new observables and added detections | Build the hook on the delta, which the cache path also produces; then cache replays get scanned too. |
| FR-20 | YARA `no_alert` rule "whose match strings land in `YaraScanResults.details`" (Part 3) | Confirmed: a `no_alert` match adds no detection but its `scan_results` entry, strings included, is recorded (`saq/modules/file_analysis/yara.py:341-396, 520-566`) | Works as designed. The rule must live in a namespace production loads, or be added by the module itself. |
| FR-21 | YARA module change (DP-4) | The YARA module is deliberately *not* cached (`docs/ANALYSIS_CACHING.md`, the *Yara: deferred* note: filtered output depends on file name and `meta_tags`, which are not in the cache key) | No cache-version bump is needed for DP-4. The same note is why replay (YR-4) has to rebuild path and `meta_tags`: the design already does. |
| FR-22 | "`GET /api/v2/alerts` shares its filter vocabulary and SQL path (`build_alert_query()`, `apply_sql_filters()`)" (Part 6) | `apply_sql_filters` is `saq/search/lexical.py:94`, a narrower path over `SearchFilters`; `build_alert_query` is `saq/gui/filter_query.py:314` | Both exist; the sentence should name the split (`build_alert_query` for the filter list, `apply_sql_filters` for the typed search filters). |
| FR-23 | "Attribution rows are written at the same time" as the `PRE_INSERT` decision | At `PRE_INSERT` the alert row has no id until the session flushes | Write attribution rows keyed on the alert *uuid*, or flush before the router returns. Small, but it decides the `svs_attributions` key. |
| FR-24 | `_apply_detection_queue` comment says `all_detection_points` omits root detections | It doesn't (`analysis_tree_query.py:36`); root detections are counted twice, harmlessly | Fix the comment when the function becomes the first router. |

---

## 5. Phase-0 status at `9d20ef7d`

| Phase-0 PR (from `docs/SVS.md`) | Status | Evidence |
|---|---|---|
| CAS with the `svs_samples` pool | **Landed** (pool not yet defined; the example is commented out) | `saq/cas/`, `etc/saq.default.yaml:185-194` |
| `saq/crypto` fixes (verify before release, v1 header) | **Landed** with the CAS | `docs/CAS.md`, *Encryption* |
| `archive()` fix (YR-11) | Not landed | `retained_files = set()` at `saq/analysis/root.py:759`; `hardcopies/` skipped at `local_file_manager.py:239-277` |
| Disposition clean-up (TP-2, TP-3, `analyst_selectable`, server-side validation) | Not landed | `benign_dispositions` still at `etc/saq.default.yaml:2845`; the four hidden constants at `saq/constants.py:335-338`; `/set_disposition` validates against constants (`app/analysis/views/edit/disposition.py:26`) |
| Prevalence counts only the default queue | Not landed (disposition history already does, PR #587) | `aceapi_v2/observables/service.py:236-247` has no queue predicate |
| `saq/storage` defects (F-13, F-18, F-19) | Not landed | `factory.py:166`, `s3.py:498-507`, `local.py:61,84` |
| `GET /api/v2/alerts` + `alerts.updated_at` | Not landed | `aceapi_v2/alerts/router.py` has no list; `Alert` has no `updated_at` |
| `saved_filters.screen` | Not landed (and larger than a column, FR-18) | `saq/database/model.py:2643-2725` |
| Structured hunt completion record | Not landed | `base_hunter.py:609-612` is a positional-format line without `extra` |
| Alert-router registry, `move_alert_to_queue` (phase 4, but core) | Not landed | no matches anywhere |
| Detection identity includes the node (DP-7, phase 1 gate) | Not landed | `content_hash` unchanged at `saq/analysis/detection_point.py:77-84` |

The disposition clean-up touches more than the six config blocks TP-2 counted. The constant list
is consumed in eight code sites and six templates (the review's F-3 undercounted): the event
roll-up (`Event.disposition`, `model.py:962-979`), the event bulk views, `filter_query.py:297`, the
session filters, the review view, and the templates that index `dispositions[...]['css']`. Budget
the PR accordingly.

**Recommended additions to phase 0**, all core and all independent of SVS:
- the S3 CAS backend (FR-1), before phase 2;
- the alert-router registry and `move_alert_to_queue` as their own PR (they are a core refactor of
  `_apply_detection_queue` and a new primitive; phase 4 is already the largest phase);
- the F-24 fix (FR-6) if the site's collectors can reach `submit_remote`;
- the dispositioned-mode transfer fix (FR-5), with the capture PR at the latest.

---

## 6. What was checked and holds

For confidence, the assumptions the design leans on hardest were verified and are correct:

- **`ALERT()` is the only insert into `alerts`** and all eight callers go through it
  (`saq/database/util/alert.py:167`; engine, `submit_local`, API submit, hunt validation, GUI
  upload, CLI import, `hunt` and `correlate`). `alerts.queue` is never written after insert, and
  `Alert.sync()` does not copy `root.queue` back. ART-15's premise stands.
- **Scoped API keys exist.** `AuthApiKey.inherit_user_scope=False` restricts a key to its own
  `(major, minor)` scope rows intersected with the owner's permissions (`model.py:2574-2630`,
  `saq/permissions/logic.py:67-83`; `ace user add-api-key <user> --scope "svs:validate"`). The CI
  key and the read-only reporting key are feasible exactly as YR-3 and RPT-5 describe.
- **Permissions** are per-user and per-group ALLOW/DENY rows with fnmatch patterns; the catalog is
  a read model seeded by a data migration per addition (`61b26390b94e` is the template). The guard
  test `tests/saq/test_permission_catalog.py` requires every enforced pair to be in the catalog.
- **Both disposition writers requeue into `analysis_mode_dispositioned`** on the alert's own node,
  for everything except IGNORE and CORRECT reviews (`alert.py:284-300, 399-416`). The workload
  row is unique on `(uuid, analysis_mode)`, so repeated dispositioning is idempotent. The engine
  locks and loads the root from disk for it, as capture needs.
- **Match evidence survives.** `YaraScanResults` keeps strings, offsets, namespace, commit and
  the rule's meta per match, so YR-4's "original match record" is available at capture time.
- **A private in-process `YaraScanner` is already how the module falls back** when the scanner
  socket fails (`yara.py:213-219, 310-318`), so YR-9's isolated scanner has a precedent.
- **Search has no default queue exclusion today**; `SearchFilters.queues` defaults to empty and
  the manage page's *Reset* narrows to the user's queue. RPT-7's one-place change in
  `saq/search/query.py` is the right place.
- **Hunt suppression** works as ART-8 describes: grouped submissions are dropped while
  `is_group_suppressed()` (`base_hunter.py:476-485`), manual and validation runs bypass it, and
  `dedup_key` is enforced in the collector for 24 hours. The hunter keeps no execution history
  (F-31 confirmed), which is why MGT-9's log record is the right answer.
- **The Landlock sandbox is reusable** for untrusted YARA (FR-11): generic argv, venv readable
  inside, memory and CPU limits, and no TCP when asked.
- **`git_repo_<name>` sections** have `ssh_key_path` and are polled by one thread each with no
  callback (F-12 confirmed), so the mirror clone in YR-3 and the HEAD comparison in ART-12 are both
  the right shape.
- **`alert_type` exists on `alerts`**, `faqueue` is still the only type-based exclusion, and
  disposition history already filters `queue = 'default'`, so D-16's queue-based exclusion is
  consistent with the precedent.

---

## 7. Changes in v3.0.121

> Added 2026-10-02 against `e6005308` (v3.0.121). Sections 1–6 were checked against `9d20ef7d`,
> which predates every PR in that release (#621–#635). This section records what the release
> changed under the design and the decisions taken on it. Nothing here reverses an agreed decision.

Nothing the design relies on was removed. The cleanup PRs deleted dead modules, the analysis-tree
facade, the Bro/Zeek subsystem, the mailbox collectors, and orphaned config and templates. Every
path, symbol and config block `docs/SVS.md` names still exists, and the behaviors sections 1–6
describe are unchanged: `sync_detection_points` (FR-16), the `content_hash` formula (DP-7), the
disposition constants against the config (Part 1), `_apply_detection_queue` and its comment
(FR-24), `transfer_work_target` (FR-5), `submit_remote` (FR-6), `analysis_mode_dispositioned`, the
hunt completion line (MGT-9) and the search queue handling (RPT-7). PR #621 (`ace alert rebuild
--all` at scale) walks alerts by `id` and never writes `alerts.version`, so FR-17 stands. PR #622
filters spurious DESC-index differences out of autogenerate, so an SVS migration will not drag two
unrelated index rebuilds along with it.

PR #631 (the yara scanner as an ACE service, QA matches in the CAS) is the one that matters.

### FR-25 — The marker rule cannot be added by the YARA module  *(phase 4)*

Part 3 says the built-in `no_alert` marker rule "must live in a namespace production loads, or be
added by the YARA module itself". The second option is gone. Scanning moved into the `yara` service
(`saq/yara_scanning/`, `docs/YARA_SCANNER.md`): a generation compiles `service_yara.signature_dir`
and `git_repo_dirs` once and forks its workers (`_Generation.run` in `server.py`), and
`ScannerSettings` has no field for extra rules. The module compiles rules only in its fallback
scanner, which runs only on `YaraServiceUnavailable`. A rule added there would reach the fallback and
nothing else.

**Decision.** The rule ships in the repo as its own namespace under the signature directory, loaded
through whatever lists rule locations (`saq/signatures/locations.py`), and a test asserts that both
the service and the fallback scanner load it. The mechanism belongs to phase 4.

### FR-26 — Compile failures are per file in production, not per namespace  *(phase 3)*

FR-11 and Part 2 describe a compile failure as "namespace X failed to compile: all N rules in it are
dropped". The production loader (`yara_scanner` 3.0.0, `compile_and_load_rules`) does two things. It
compiles each file on its own and drops only a file that fails. Then it compiles the survivors once
per namespace; if that combined compile fails (two files in one directory defining the same rule
name, for instance) the whole ruleset is dropped and the service keeps serving the previous
generation (`docs/YARA_SCANNER.md`, *Broken rules never replace working ones*). A validation that
compiles a namespace as one source would report every rule in it as regressed when one file is
broken. The library also calls `yara.set_config(max_strings_per_rule=30720)` when it is imported,
process-wide. `Rules.warnings` is still not surfaced anywhere, so the direct `yara.compile` call
FR-11 asked for remains the way to get it.

**Decision.** The validation mirrors the loader: each file alone first (a failure is the result
"file X does not compile: its N rules are dropped"), then the namespace from the files that passed
(a failure is the result "the ruleset would not load; production keeps the previous generation").
The subprocess applies the same `yara.set_config` as the library, so limits match production.

### FR-27 — The YARA QA store is the precedent for capture  *(phase 2)*

PR #631 built what Part 2 designs, for QA-mode rules (`docs/YARA_QA.md`). `saq/yara_qa/store.py`
puts the matched file and the full match record into the encrypted `yara_qa` CAS pool and indexes
them in `yara_qa_signatures` and `yara_qa_matches`, unique on `(signature uuid, signature version,
sha256)`, with holds that carry an expiry, caps reserved by one conditional UPDATE, a `wrong_node`
answer for bytes on another node's local pool, infected-password zips through
`aceapi_v2/common/archive.py`, and the rule "a multi-node site redefines the pool with a shared
backend", which is FR-1's resolution, documented and shipped. The match record also stays in the
tree (`YaraScanResults.details`, strings included), so YR-4 holds.

What keeps the two stores apart: QA records every match of a QA rule on any analysis, at scan time,
in the service; SVS captures at disposition time, in the engine, only on classified alerts. QA's
key has no alert and includes the rule version; SVS's is `(alert, sha256, rule uuid)`. QA caps and
expires; SVS holds for as long as the capture record exists. Two things to copy with care: QA
serializes the record with `_JSONEncoder` (`saq/json_encoding.py`), which decodes string bytes with
`unicode_escape` and is lossy, while the scanner protocol (`saq/yara_scanning/protocol.py`) encodes
the same strings as base64 and is byte-exact. And the namespace in a match is the absolute rule
directory, which is not the path a replay tree has.

The signature inventory (`saq/signatures/loaders/yara.py`) now reads `modifiers` and `enabled` with
the scanner's helpers (`saq/signatures/yara_meta.py`) and gives uuid, per-rule `content_hash` and
`mitre:` tags, but it skips rules without a uuid silently and keeps one of two rules sharing a uuid
(`saq/yara_qa/inventory.py`).

**Decision.** `svs_yara_captures` and the `svs_samples` pool stay as designed and reuse the
building blocks: the hold idiom and conditional-UPDATE reservation, the protocol's base64 encoding
for the stored record, `signature_version` taken exactly as QA takes it, the namespace stored
relative to the signature directory, `wrong_node` semantics, and the archive helper for downloads.
The validation's duplicate-uuid check (FR-11) parses the head tree itself, or extends the inventory
to report duplicates.

### FR-28 — The Signatures area and `signature:*` permissions exist  *(phases 2, 3, 5)*

The release added a **Signatures** navigation entry (`app/signatures/`, cards laid out like Admin
from `SIGNATURE_MODULES`, gated by `signature:read` in `views/access.py`), the permissions
`signature:read` and `signature:download` (`saq/permissions/catalog.py`, seeded by `a7c2e41d9b35`),
and the Yara QA Results page, a shell whose data all comes from `/api/v2/signatures/yara-qa`. That
is Part 6's rule (every screen reads through a public endpoint) already in practice. Part 5 designs
a separate SVS entry with six tabs and three permissions, `svs:validation_read`, `svs:sample_read`
and `svs:sample_download`, that would answer the question `signature:read` and `signature:download`
already answer: may this person see what YARA rules matched, and may they have the files. A
disabled `DetectOps` placeholder sits in the navigation bar (`app/templates/base.html`) next to
Signatures.

**Decision.** Validations and Samples are cards in the Signatures hub, gated by `signature:read`,
with sample bytes behind `signature:download`; `svs:validation_read`, `svs:sample_read` and
`svs:sample_download` are dropped. Runs, Tests, Coverage, Worklist and the Test hosts admin tab are
the SVS entry, in the placeholder's slot. API paths stay under `/api/v2/svs/`, so the CI contract
and the router package are unchanged.

### FR-29 — Phase-0 and CAS status

The CAS still ships only the `local` backend plus loadable `custom` classes. `svs_samples` is still
the commented example in `etc/saq.default.yaml`, and `yara_qa` is the one pool defined. The
consumer table in `docs/CAS.md` was changed in the release to say steps 1 and 2 are built; step 1
(`svs_samples`) is not, it is defined when phase 2 lands. `docs/CAS.md` is corrected with this
reconciliation. The phase-0 table in §5 is otherwise unchanged by the release.

### FR-30 — Wording in `docs/SVS.md`

Not caused by the release, found while checking it:
- `ace alerts reset` is `ace alert reset` (`saq/cli/commands/alerts.py`).
- `saq/logging.py` renders `extra={}` fields, but `crash_id` is not in that file; the sentence
  should name the mechanism, not `crash_id`.
- `alerts.version` is rotated by `new_alert_version()` at ten call sites, not seven; the point
  (a server-side `ON UPDATE` column) is unchanged.
- `build_alert_query` and `create_filter` already take `entity=`, defaulting to `Alert`; what is
  left for FR-18 is the correlated subqueries that still name `Alert`.
- `FilterEntry` is in `aceapi_v2/saved_filters/schemas.py` and `FILTER_NAMES` in
  `saq/gui/filter_names.py`.
- There is no bare `ace search`; `--include-tests` goes on `ace search query` and `ace search
  similar`.
