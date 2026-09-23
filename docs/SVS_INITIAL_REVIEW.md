# SVS Initial Review

A proofread of `docs/SVS_INITIAL.md` against the current codebase (branch `jd/svs`, 2026-09-08).
This is not a design. It is the list of things the design session needs to know before it starts:
what ACE already has that the proposal should build on, where the proposal's model is thinner than
the reality it has to cover, and the questions that have to be answered before the subsystem can
be shaped. File references are to this checkout so the design session can go read the code.

Sections:

1. What already exists (do not re-specify it)
2. Where the proposal's model is too simple
3. Gaps in the Signature Development requirements
4. Gaps in the Atomic Red Team requirements
5. Requirement 3 (technique coverage) is underspecified
6. Cross-cutting concerns
7. Small things found along the way that SVS will trip over
8. Questions to answer before design
9. Suggested reframing

---

## 1. What already exists (do not re-specify it)

The proposal reads as if signature identity and attribution still need to be invented. They do
not. Roughly a third of what the proposal implies is already merged and in production. The design
should start from this inventory.

### 1.1 Every detection point already knows which signature produced it, at which version

- `saq/analysis/detection_point.py:20-57` — `DetectionPoint` carries `signature_uuid` and
  `signature_version`, both non-null by construction. Legacy serialized detections load with the
  `LEGACY` sentinel; unattributed ones get `GENERIC`.
- `saq/database/model.py:1272-1309` — the `detection_points` table mirrors this, with
  `ix_detection_points_signature (signature_uuid, signature_version)`. **This index is the
  "find every alert that signature X fired on" query SVS needs.** `content_hash` gives a stable
  per-detection identity for diffing "before" vs "after" replay results.
- Producers: YARA uses the rule's `uuid` meta and the repo commit (`saq/modules/file_analysis/yara.py:66-78`);
  hunts use the hunt `uuid` and the `git_dir` commit (`saq/collectors/hunter/query_hunter.py:490-497`);
  observable modifier rules use the rule `uuid` (`saq/modules/util/observable_modifier.py:933,1019`);
  ACE-native detections use constants from `saq/signatures/builtin.py`.
- `saq/signatures/builtin.py` is a registry of 19 built-in signatures for detection logic that
  lives in Python. Their "version" is `ACE_VERSION`.
- `docs/DETECTION_DB_MIGRATION_NOTES.md` explains the `git_dir` convention that makes
  `signature_version` a real commit hash rather than `"unknown"`.

### 1.2 A signature inventory that can already diff signatures across commits

- `saq/signatures/model.py` — `SignatureType` (`yara`, `hunt`, `observable_modifier`, `builtin`)
  and a `Signature` dataclass with `uuid`, `version` (commit), `git_remote`, repo-relative
  `source_path`, a `content_hash` over the *individual signature's* text, and `tags`.
- `saq/signatures/loaders/` — one loader per type, each deliberately mirroring the traversal of
  the real detection path (so what the inventory reports is what the deployment loads).
- `saq/signatures/locations.py` — resolves where each family is loaded from, from config.
- `ace signatures list|locations` (`saq/cli/commands/signatures.py`).
- The docstring in `model.py` says it exists so signatures can be "counted, tagged, diffed across
  commits". **"Which signatures did this PR change?" is `content_hash` at base commit vs head
  commit.** The design should extend this package, not build a parallel one.

### 1.3 There is already a hunt validation toolchain, and it is called `signature_validator`

- `lib/signature_validator/` is a standalone pip package (`hunt_compiler`, script
  `validate-hunt`). It compiles a hunt YAML plus its includes and referenced files into one
  JSON payload and POSTs it to `POST /api/hunt/validate` (`aceapi/hunt.py:262`), which validates
  it and can **execute it ad hoc** with explicit time ranges, return the raw events, and
  optionally submit the results as alerts.
- This is the existing pattern for "validate a signature from a PR against a live ACE": the
  **repository's CI calls ACE**, ACE never reaches out to GitHub. It also means the name
  "Signature Validation System" collides with an existing package name. Either SVS absorbs and
  supersedes `lib/signature_validator`, or it needs a different name.
- `HuntTypeConfig.schedulable: false` (`saq/configuration/schema.py:405`) exists precisely so a
  hunt type can be validated and executed on demand without being scheduled. That is the shape a
  "replay this hunt" backend wants.

### 1.4 YARA QA mode is prior art for capturing telemetry

`saq/modules/file_analysis/yara.py:355-367`: a rule with `modifiers = "qa"` copies every file it
matches, plus the full match JSON, into `qa_dir/<rule_name>/` **outside the alert storage
directory**. This is exactly the "record what a signature matched" capture the proposal describes,
already running in production, and it already made the right call on storage location (see 3.4).

### 1.5 The dispositioned analysis mode is the TP hook

`analysis_mode_dispositioned` (`etc/saq.default.yaml:2574-2584`, `saq/constants.py:640`):
when an analyst dispositions an alert, `set_dispositions()` re-queues it into this mode so
modules can react to the disposition value with the full analysis tree loaded, asynchronously,
outside the analyst's HTTP request. `alert_added_to_event` already uses it. A telemetry-recording
module belongs here, not inline in `saq/database/util/alert.py:134-215`.

### 1.6 Detection lineage is already computed

`saq/analysis/detection_chain.py` — `build_detection_chains(root)` walks from each detection
point back to the root observable, recording which analysis produced each intermediate
observable. This is the answer to "what data did signature X match and how did ACE derive it",
which is what has to be captured for the dynamic-detection case (see 2.2).

### 1.7 An ATT&CK tag convention already exists

Hunts tag alerts `mitre:T1105`; the YARA loader turns a `mitre_attack` meta into the same
`mitre:` tags (`saq/signatures/loaders/yara.py:39-44`). Requirement 3 (technique coverage) can be
seeded from this rather than from a hand-built mapping. Coverage of the convention across the
real signature repos is unknown from this checkout and should be measured.

### 1.8 Patterns to copy for the remote-execution and scheduling pieces

- `saq/remediation/external/probe.py` and `saq/file_collection/` — core defines an abstract
  driver plus polling, locking, retry and persistence; the vendor-specific implementation lives in
  an out-of-tree integration. This is the only acceptable shape for "run a command on a remote
  host", given the integrations rule in `CLAUDE.md`.
- `saq/git.py` `GitManagerService` — one polling thread per configured repo, branch-aware. The
  natural place to add "also track these additional repos" for Atomic Red Team test collections.
- `saq/collectors/hunter/base_hunter.py:78-109` — the hunter already supports both `HH:MM:SS`
  frequencies and cron strings for per-item scheduling.
- `saq/permissions/catalog.py` — one `CatalogEntry` line plus a migration adds a permission
  (`ai:search` at line 43 is the precedent).
- `saq/phishkit.py` — the Celery-plus-shared-volume pattern for an isolated worker, if test
  execution is done from a dedicated container.
- `saq/modules/tool_version.py` — version probing for external CLI tools, built for cache
  invalidation. It is the mechanism for recording "which version of the PDF parser produced the
  telemetry" in the dynamic-detection case.

---

## 2. Where the proposal's model is too simple

### 2.1 "Signature" is at least six different things, and `d(X)` means something different for each

The proposal uses YARA as its worked example and treats everything else as a variation. In ACE
the families differ in what `X` is, where `X` lives, and whether ACE can evaluate `d` at all
without the outside world.

| Family | What `X` is | Where `X` lives | Can ACE replay `d(X)` locally? | Versioned today? |
|---|---|---|---|---|
| YARA rule | bytes of one file **plus** scan context (name, path, extension, mime type, `meta_tags`, blacklist, `enabled`) | alert storage dir (derived files deleted on archive) | Yes, cheaply | Yes (repo commit) |
| Hunt (Splunk/Logscale/Rapid7) | a SIEM index over a time window | the SIEM, not ACE; only the *returned rows* are in `root.details` | **No.** ACE cannot evaluate SPL against saved rows. Replay means re-querying the SIEM. | Yes |
| Correlation hunt (`correlate`, `commands`) | the above plus the results of external commands and secondary queries | external systems | No, and the commands may have side effects | Yes |
| Observable modifier rule | the **entire analysis tree** of an alert | the serialized `RootAnalysis` | Only by re-running the module against a preserved root | Yes |
| Built-in (Python) detection | whatever the module looks at | the `RootAnalysis` | Only by re-running the module | `ACE_VERSION` only |
| Observable detection (IOC) | one observable value | `observable_detections` table + redis | Trivially, but the value set changes daily and has expiry | Not really |
| Snort/Suricata rules | packets | never in ACE | No | No uuid, no `SignatureType`, outside attribution entirely |
| External EDR rules (`custom_ioa`, Splunk saved searches) | EDR telemetry | the vendor | No. ACE only sees the resulting alert via a hunt. | Named in `etc/saq.signatures.default.yaml` but nothing loads them |

Consequences the design has to absorb:

- **"Apply the modified signature to the recorded telemetry" is only literally possible for
  YARA.** For every other family, "replay" is either re-executing a query against a live external
  system (with cost, quota, and retention limits), or re-running part of the analysis engine
  against a preserved `RootAnalysis`. The design needs to decide whether SVS has two replay
  engines (a fast YARA path and a general re-analysis path) or one general one with YARA as an
  optimization.
- **Hunt regression needs its own definition.** Candidates: (a) re-run the modified hunt over the
  recorded time window and check that the recorded event identities still come back, which only
  works inside SIEM retention and costs a query per recorded sample; (b) keep a local corpus of
  events and require hunts to be expressible in something ACE can evaluate, which changes what a
  hunt is; (c) accept that hunts get only syntactic validation plus the ad hoc execution that
  `validate-hunt` already offers. Option (c) is what exists today.
- **Half the signature families are versioned by Python code.** A change to a built-in
  detection is a PR to this repo, not to a signature repo. Either SVS ignores built-ins, or the
  "PR to a signature repository" trigger is one of several triggers.
- **The external families cannot be validated statically at all**, only by the Atomic Red Team
  path. That is a strong argument that requirement 1 (static regression) and requirement 3
  (technique coverage via tests) serve *different* signature families and should not be forced
  into one abstraction.

### 2.2 "Telemetry" for a YARA match is more than the file

The proposal's static case treats `X` as "the PDF". In ACE the match result also depends on:

- external variables `filename`, `filepath`, `extension` (`docs/YARA_RULES.md:85-100`);
- filtering meta directives `file_ext`, `file_name`, `full_path`, `mime_type`, `meta_tags`,
  evaluated *after* the condition matches, where `meta_tags` come from directives that upstream
  **analysis modules** put on the observable;
- the rule's `enabled` meta, `no_alert`/`qa` modifiers, and the global `etc/yara.blacklist`;
- the scanner library version.

So a recorded YARA sample must capture the scan *context* (at minimum the original file name and
path, the `yara_meta_tags` on the observable, the mime type) or replay will produce false
regressions. The YARA scanner's own reasoning about why it was excluded from the analysis cache
(`docs/ANALYSIS_CACHING.md:47`) lists exactly these dependencies.

And the dynamic case is the common case, not the exception: most YARA hits in ACE are on
*derived* files (extracted attachments, `pdftotext` output, decoded macros, deobfuscated JS).
The recorded sample needs the derivation chain (1.6) and the versions of the tools in it (1.8,
`tool_version.py`). Otherwise a tool upgrade that changes output shows up as a signature
regression, and a signature regression can hide behind "the tool changed".

### 2.3 "True Positive" is not a thing ACE has

- There is no `DISPOSITION_TRUE_POSITIVE`. Dispositions are a kill-chain vocabulary
  (`saq/constants.py:294-334`); "malicious" is the config-driven `malicious_dispositions` map
  (`etc/saq.default.yaml:2723-2734`, read by `saq/disposition.py`, which is marked `XXX refactor
  this` and whose `get_malicious_dispositions()` currently has no callers). The design has to
  pick the set, and it probably wants `GRAYWARE`/`POLICY_VIOLATION` handled explicitly.
- **An alert's disposition is not a per-signature verdict.** One alert can carry several
  detection points from several signatures. A `DELIVERY` disposition confirms the *alert* was
  real, not that each signature that fired was right. If SVS records every detection on a TP
  alert as a positive sample, a noisy rule that co-fires with a good one gets its false positives
  enshrined as regression baselines. Options: record per-detection confirmation (a new analyst
  action), infer from `detection_chain` (the signature whose chain leads to the observable the
  analyst acted on), or accept the noise and let analysts prune samples.
- There are **two disposition writers**: `set_dispositions()` and `set_disposition_reviews()`
  (`saq/database/util/alert.py:134` and `:218`). The review path is also how a TP is later
  corrected to FP, which is the "removes these records" case in the proposal.
- `disposition_review` (`CORRECT`/`INCORRECT`) is a stronger signal than disposition alone and
  should probably gate recording.
- **The proposal only records positives.** A signature that is modified and *newly* matches
  known false positives is also a regression, and arguably the more common one (rules get
  loosened to catch a variant and start firing on the benign corpus). FP-dispositioned alerts are
  the negative corpus, and ACE already holds them. Recommend recording both.

---

## 3. Gaps in the Signature Development requirements

### 3.1 "When a PR is submitted" has no receiver and needs a trust model

- There is no webhook endpoint, no GitHub/GitLab client, and no HMAC verification anywhere in
  ACE. `GitManagerService` polls `main` of configured repos only.
- Signature repos are out of tree, there may be several, and the checkout ACE loads from is not
  necessarily a git checkout at all (`docs/DETECTION_DB_MIGRATION_NOTES.md:14-21`).
- Three realistic trigger designs: (1) the signature repo's CI calls an ACE API with the diff or
  the compiled signatures, which is what `validate-hunt` does today and needs no GitHub
  credentials in ACE; (2) ACE polls open PR branches through the forge API; (3) a webhook
  receiver in `aceapi_v2`. Option 1 fits the existing pattern and keeps recorded telemetry
  inside ACE. Whichever is chosen, the design has to say where the report goes (a PR check, an
  ACE page, both) and how it gets there.
- **PR content is untrusted input that SVS turns into executed code.** Correlation hunts have a
  `commands` block that runs subprocesses (`saq/collectors/hunter/correlation/commands.py:324`);
  the existing validate endpoint already has to guard against secret-marker leakage
  (`aceapi/hunt.py:120-128`). YARA rules are compiled, which is safer but not free (regex
  blowups, huge rulesets). Custom Atomic Red Team repos are arbitrary commands run on real
  hosts. The design needs an explicit answer for who may trigger validation, whether `commands`
  execute during validation, and resource limits per run.

### 3.2 "Determines which signatures have been modified" is harder than a file diff

- Hunt includes: the inventory hashes the **raw file**, not the merged result
  (`saq/signatures/loaders/hunt.py:56-60`), so a change to a shared `*.include.yaml` changes many
  hunts without changing any hunt's `content_hash`.
- YARA rule dependencies: a rule can reference other rules in the same namespace (private rules,
  rule-name conditions), so a change to one rule changes the effective behavior of dependents.
- Global state outside the signature: `etc/yara.blacklist`, `enabled` meta, the analysis mode a
  hunt submits into, `instance_types`. Is switching a rule to `enabled = "false"` or adding
  `no_alert` a "regression"? The proposal needs a definition of what counts.
- Renames, uuid changes, deletions, and rules with no `uuid` (which the inventory skips and the
  scanner attributes to the `YARA_RULE_MATCH` fallback). What is the regression semantics for a
  deleted signature that had recorded samples?
- The modified rules must be compiled **in isolation**, never dropped into the live
  `signature_dir`, or the PR is deployed to production by the act of validating it. That means
  an isolated scanner instance per validation run, and handling namespace and duplicate-uuid
  collisions between the PR version and the live version.

### 3.3 Replay must be deterministic, and ACE has several non-deterministic detections

- Time-relative detections (`new_sender`, observable detections with `expires_on`, correlated
  tag matches, anything keyed on "first seen") cannot be replayed to the same answer later. The
  design should scope replay to signature families that are pure functions of the recorded
  input, and say so.
- The analysis result cache would happily serve a stale result during a re-analysis replay.
  Replay runs must bypass it, and must not *write* to it either (the PR version of a rule must
  not poison the production cache).
- Replay runs must not create alerts, workload rows, search-index entries, remediations, or
  observable-detection hits. There is no "sandboxed engine run" primitive today; the closest is
  the `UNITTEST` instance type plus `WorkloadManager` memory mode. This is a substantial piece
  of work in its own right.

### 3.4 Recorded telemetry cannot live in, or point into, alert storage

- `RootAnalysis.archive()` (`saq/analysis/root.py:750-777`) resets every non-root analysis's
  details and deletes every file observable that did not arrive with the alert. That is exactly
  the YARA scan results and the derived files. `retained_files` there is always empty; it looks
  like an unfinished retention hook and may be the place to wire this.
- FP alerts are archived after `fp_days` (default 30); `IGNORE` alerts are **hard deleted after
  1 day** (`saq/util/maintenance.py:71-97`); `distribute_old_alerts` can move a storage dir to
  another node. Hunt root details survive archival; YARA match data does not.
- So SVS needs its own store, keyed by content hash and deduplicated, with its own retention,
  its own access control, and (because samples are live malware and customer email) a decision
  about encryption at rest and who can download. The YARA `qa_dir` layout is the working
  precedent. The analysis cache's blob store (`docs/ANALYSIS_CACHING.md`, "file observable bytes
  always blob-backed") is the other candidate and already solves dedup.
- Multi-node deployments: the recording module runs on whichever node analyzed the alert; the
  replay runs wherever SVS runs. The store has to be shared or replicated.

### 3.5 Root-level detections may be missing from the table SVS would query

`RootAnalysis.all_detection_points` (`saq/analysis/root.py:902-910`) omits the root's own
`detections`. The orchestrator compensates (`saq/engine/analysis_orchestrator.py:405-407`) but
`saq/database/util/index.py:150`, which builds the `detection_points` rows, does not. Hunt
detections and `tag.py:69` detections are root-level. If this is real, the "which alerts did hunt
X fire on" query returns nothing today. Verify with a hunt-originated alert before designing
around the table.

---

## 4. Gaps in the Atomic Red Team requirements

### 4.1 Execution is entirely greenfield, and it is the dangerous part

- Nothing in ACE executes anything on a remote host. No SSH, WinRM, EDR live-response, or agent
  client exists in this repo; vendor code must live in an integration. Core SVS should define a
  target driver interface in the shape of `saq/file_collection/file_collector.py` and
  `saq/remediation/external/probe.py`, with statuses like `HOST_OFFLINE`, retries, and a
  per-target lock, and leave "how" to integrations (Invoke-AtomicRedTeam over WinRM, Falcon RTR,
  a resident agent, and so on).
- Atomic tests are not just a command. The Atomic Red Team YAML has, per `atomic_tests[]` entry:
  `auto_generated_guid`, `supported_platforms`, `input_arguments` with defaults, `executor`
  (`command_prompt`, `powershell`, `sh`, `bash`, `manual`), `elevation_required`,
  `dependencies[]` with `prereq_command` and `get_prereq_command`, `cleanup_command`. The unit
  the proposal calls "a test" should be the atomic test GUID, not the technique (one technique
  has many atomics), and the executor has to handle prerequisites, elevation, cleanup, and
  platform matching, or explicitly refuse tests that need them.
- Safety controls the proposal does not mention: an allowlist of targets that are actually lab
  hosts, an approval step or at least a dedicated permission (`svs:execute` or similar via the
  catalog), an audit trail of who ran what where, one-test-at-a-time per host, a global kill
  switch, and a "dry run" that shows the resolved commands. Running attack techniques against a
  production host by accident is the single worst outcome of this subsystem.
- Custom test repositories are arbitrary command execution on real hosts, so repo trust and
  branch pinning matter more than they do for the signature repos.

### 4.2 "Automatically determine when an alert is generated from a test" needs a concrete attribution model

- There is no per-alert session or correlation id column. Grouping today is `Alert.queue`,
  tags, hunt `group_by`, and `Event.campaign_id`.
- Proposed inputs to attribution: a **test run** record (run id, target host, user account,
  start and end time, executor) plus a **marker** injected into the test's input arguments
  (a unique string in a command-line argument or file name) so any signature that sees the
  command line or file carries it. Then match alerts by marker where possible and by
  `hostname` + `user` + time window otherwise. Marker-less telemetry (network, authentication
  logs) will only ever match on host and window.
- Host-and-window matching **will misattribute a real incident on a lab host during a test**.
  The design has to state that a test-attributed alert is a hypothesis an analyst can reject, and
  that the "special dedicated queue" must never make a real alert invisible. This argues for
  routing by SVS *after* attribution (update `Alert.queue` and tag it) rather than at detection
  time.
- If routing is done at detection time, `_apply_detection_queue`
  (`saq/engine/analysis_orchestrator.py:397-421`) is all-or-nothing: an alert stays in `default`
  if **any** detection point has no queue. Most detections have none. Detection-time routing to a
  test queue will therefore not work without changing that rule.
- Test alerts should **not** be dispositioned `IGNORE` to get them out of the way. `IGNORE`
  alerts are deleted after one day (3.4), and test alerts are the highest-quality positive
  telemetry SVS will ever get. They also need to be excluded from analyst metrics; the `faqueue`
  alert type (`saq/constants.py:648`, filtered in `saq/database/database_observable.py`) is the
  precedent for "a class of alerts outside normal metrics".

### 4.3 "Built-in delay of detections" is more than a timeout

- Each expected signature has its own latency: hunt `frequency` + `time_range` + `offset`, plus
  `use_index_time`/`full_coverage` behavior, plus engine backlog. The settle window for a run is
  the maximum over its expected signatures, and it is computable from the hunt configs.
- Hunt **`suppression`** (`saq/collectors/hunter/base_hunter.py:80`) will swallow a test's alert
  entirely if the same hunt fired recently. Hunt **`dedup_key`** can do the same. A run that
  "missed" a detection because of suppression is a different outcome from a run whose signature
  did not match, and SVS should be able to tell them apart (the hunt's own log and the
  `KEY_TRANSACTION_ID` stamped on hunt roots help).
- Hunts only run in their declared `instance_types`. A test run against a lab host will only
  ever be detected by the ACE instance whose hunts run there. Which instance hosts SVS?
- The outcome vocabulary needs more than expected/unexpected/missing. At least:
  **prevented** (the EDR blocked the technique before telemetry existed; `Event.prevention_tool`
  is the existing concept), **no telemetry** (the log source is not there, which is
  requirement 2), **telemetry but no detection** (the signature did not match), **detected but
  no alert** (`no_alert`, `qa`, whitelisted, suppressed, deduped, disabled signature), and
  **alerted**. Requirement 2 cannot be answered at all without a way to check for telemetry
  independent of any signature, which suggests each test or technique carries an optional
  "telemetry probe" query that the ad hoc hunt executor runs.

### 4.4 The test-to-signature mapping should be derived first and hand-edited second

Signatures already declare techniques via `mitre:` tags (1.7). Atomic tests are keyed by
technique. So the default expectation for a test is "every enabled signature tagged with this
technique, or its parent technique", with per-test overrides (ignore, add, remap) layered on top,
which is what the proposal's review operations describe. Expectations must also be evaluated
against the signature's **enabled** state and version at run time: a disabled signature is
expected *not* to fire, and a signature edited since the last passing run is "stale" until re-run.

---

## 5. Requirement 3 (technique coverage) is underspecified

"Validate that a given technique is actually covered by one or more detection signatures" has at
least four different answers that should be distinct states:

1. **claimed** — some signature is tagged with the technique;
2. **tested** — a test for the technique has been run in this environment;
3. **validated** — the last run produced the expected detections, at the current signature
   versions;
4. **stale** — validated once, but a signature, the environment, or the test changed since.

Other things to settle: ATT&CK version drift (techniques are renamed and split), sub-technique
roll-up, techniques that Atomic Red Team does not cover (most of ACE's email and file-analysis
strength has no atomic), and whether coverage is reported per company/tenant (`Company` exists in
the model) since telemetry availability differs per environment.

---

## 6. Cross-cutting concerns

- **Placement.** SVS will need: DB tables on the main Alembic chain; a `service_svs` long-running
  service (`docs/SERVICES.md`) for replay and run tracking; `aceapi_v2/svs/` routers; GUI pages
  for run review and sample management; `ace svs ...` CLI; permission catalog entries. The
  proposal does not mention the GUI at all, and most of the ART requirements are GUI workflows.
- **Cost bounding.** Replay per PR is (changed signatures) × (recorded samples). Without a cap,
  sampling policy, or a per-signature sample limit, a popular rule's corpus grows without bound
  and every PR gets slower. SIEM re-execution has real money cost and quota (see
  `schedulable: false`).
- **Data sensitivity.** Recorded samples are customer email and live malware. Where the replay
  runs decides who can see them. Running replay in the signature repo's CI (GitHub-hosted
  runners) would move that data outside ACE; running it inside ACE means the repo CI gets only a
  verdict. This is a decision, not a detail.
- **Instance types.** Production has the telemetry; dev and QA do not. SVS on dev validating
  against production's corpus is a cross-instance data flow that does not exist today.
- **Naming.** `lib/signature_validator` and `saq/signatures/` both already exist; "signature
  validation" currently means "compile a hunt and try it". Pick a name that does not collide, or
  fold the existing package in.

---

## 7. Small things found along the way that SVS will trip over

- `etc/saq.signatures.default.yaml` declares `signature_types: [yara, splunk, custom_ioa]` and
  `signature_repos: []`. Nothing in Python reads either key, and the list contradicts the live
  `SignatureType` enum. Dead config; decide whether SVS revives it or it is removed.
- `ace hunt execute --query-result-file` sets an attribute nothing reads
  (`saq/cli/commands/hunt.py:51`). Its documented purpose, saving raw hunt results to a file, is
  the hunt-replay primitive SVS wants.
- `ace hunt list` is marked `# XXX broken`. `ace hunt verify` is a load check, not a behavior
  check; the proposal's language should not imply it does more.
- Snort/Suricata rules have no uuid and no `SignatureType`; they are outside attribution.
- About 20 of the roughly 53 `add_detection_point` call sites still pass no signature and land on
  `GENERIC`. Those detections cannot be regression-tested or coverage-mapped until they are
  attributed.
- `F_TEST` (`saq/constants.py:209`) is an existing observable type name; check its meaning before
  reusing "test" as a term.

---

## 8. Questions to answer before design

1. Which signature families are in scope for static regression in the first version? (Suggest:
   YARA only.) Which for test-driven validation?
2. What is the regression definition per family: for YARA, "recorded sample no longer matches";
   for hunts, is it re-execution against the SIEM, and inside what retention window?
3. What is the exact "record this" trigger: which dispositions, does `disposition_review` gate
   it, and is confirmation per alert or per detection point?
4. Are false positives recorded as a negative corpus?
5. Where does the sample store live, what is its retention, who can read it, and is it encrypted?
6. Where does replay run (inside ACE vs repo CI), and how does the verdict reach the PR?
7. Is a PR trigger a webhook, a poll, or a CI call into ACE? Who is allowed to trigger it?
8. Do correlation-hunt `commands` execute during validation?
9. What is the remote-execution driver interface, and which integration implements the first one?
10. What is the attribution model for test alerts (marker vs host-and-window), and what happens
    when attribution is wrong?
11. Which ACE instance owns SVS, and how do dev/QA/prod split the work?
12. What are the safety controls for launching tests: target allowlist, permission, approval,
    concurrency, kill switch, cleanup-on-failure?
13. What is the coverage state model, and is it per tenant?
14. Does SVS absorb `lib/signature_validator`, or coexist with it under another name?

---

## 9. Suggested reframing

- **Treat "replay" as one primitive: re-run a chosen set of analysis modules against a
  preserved `RootAnalysis` snapshot in an isolated engine context, with the cache bypassed and
  all side effects disabled, then diff detection points by `content_hash`.** The static YARA case
  is a fast path over that primitive, not a separate system. This also gives observable modifier
  rules and built-ins a replay story for free, and it is the piece with the most reuse value
  beyond SVS.
- **Separate the three requirements into three subsystems that share a data model.** Static
  regression (signature repo → sample store), test execution (targets → runs → attributed
  alerts), and coverage (techniques × signatures × runs) have different triggers, different risk
  profiles, and different signature families. Forcing them through one abstraction will make
  each worse.
- **Record negatives as well as positives.**
- **API first, forge second.** Expose "validate this signature set against recorded samples" as
  an ACE API in the shape of `/api/hunt/validate`, and let repository CI call it. Webhooks and
  forge-specific reporting can come later without changing the core.
- **Phase it.** A plausible order: (1) sample capture on disposition plus YARA static regression
  through an API; (2) the isolated re-analysis primitive, extending regression to observable
  modifier rules and built-ins; (3) hunt re-execution regression within SIEM retention; (4) test
  execution with a single integration-supplied driver and manual expectation mapping; (5) derived
  coverage and the GUI review workflow. Phase 1 is high value, low risk, and exercises the store,
  the trigger, and the reporting path that everything else depends on.
