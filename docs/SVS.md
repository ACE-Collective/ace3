# Signature Validation System (SVS)

> **Status: agreed design; phase 0 landed in v3.0.122, phase 1 landed (PRs #651–#656), phase 2 in
> progress (2026-10-05). Parts 5 and 6 were added in review rounds 8–10, the pre-implementation
> review folded in and the design reconciled with the v3.0.121 release on 2026-10-02.**
> This is the design of record.
> `docs/SVS_INITIAL.md` is the original brief. `docs/SVS_REVIEW.md` is the decision record: every
> bracketed ID in this document (`[DP-2]`, `[D-6]`) points at the item there that records the
> reasoning and the alternatives that were rejected. `docs/SVS_FINAL_REVIEW.md` is the
> pre-implementation review of this design against the code; `[FR-n]` IDs point there, and the
> decisions on its items are written into this document. Its §7 (`[FR-25]` to `[FR-30]`) records
> what the v3.0.121 release changed under the design. SVS stores its samples in the CAS
> (`docs/CAS.md`).

SVS answers two questions about ACE's detection signatures:

1. **Does a signature change break what it used to catch, or start catching what it shouldn't?**
   For YARA rules, SVS checks every pull request against a corpus of files that analysts have
   already graded.
2. **Which ATT&CK techniques do we actually detect?** SVS runs Atomic Red Team tests (the tests are
   launched outside ACE), attributes the resulting alerts to each test, and learns which signatures
   fire for which techniques.

It does not validate that telemetry exists in the environment. That goal was dropped [D-4], so a
*missing* detection in a test run doesn't say whether the log data never arrived or the signature
didn't match.

**Out of scope:**
- running tests or preparing test hosts (a separate, site-specific launcher does that);
- real incidents on test hosts;
- True Negative samples;
- regression testing for non-YARA signatures;
- the dynamic case of YARA regression, where the tool that produced the scanned file changes
  [D-5];
- every alert created before SVS is deployed [D-3].

## Concepts

| Term | Meaning |
|---|---|
| **Disposition class** | Every alert disposition classifies as **tp**, **fp** or **unclassified**, from config. [D-15] |
| **Verdict** | TP or FP for one *detection* (detection point), as opposed to the alert. Derived from the alert's disposition unless an analyst set it. [D-6] |
| **Verdict source** | Why a verdict is what it is: `explicit`, `inherited_single`, `inherited_multi`. [DP-2] |
| **Sample** | A YARA-matched file captured into the CAS with its scan context. |
| **Label** | The TP/FP grade of a sample for one rule, i.e. per `(sha256, rule uuid)`, aggregated from verdicts. [D-8] |
| **Base / head** | The rulesets of a YARA PR's base commit and head commit. |
| **Test** | An Atomic Red Team atomic test, identified by its `auto_generated_guid`. |
| **Run** | One registered execution of one test against one or more targets. It has its own lifecycle and marker. [D-10] |
| **Marker** | A random token the launcher injects into the test, so that ACE can recognize the resulting telemetry. |
| **Attribution** | Linking a detection (and, when complete, its alert) to a run. |
| **Expectation** | A signature that is expected to fire for a test. It is learned from reviewed runs. [D-9] |

**What TP and FP mean.** A detection is **TP** when it was part of detecting malicious activity and
**FP** when it was not. The label follows the analyst's answer to "did we detect malicious
activity?", not "did the rule match what its author intended". [D-1]

## Part 1 — Labels

### Disposition classification

A single config map classifies dispositions. Anything unlisted is unclassified. [D-2, D-15]

| Class | Dispositions |
|---|---|
| tp | `GRAYWARE`, `POLICY_VIOLATION`, `RECONNAISSANCE`, `WEAPONIZATION`, `DELIVERY`, `EXPLOITATION`, `INSTALLATION`, `COMMAND_AND_CONTROL`, `EXFIL`, `DAMAGE`, `SIMULATED` |
| fp | `FALSE_POSITIVE` |
| unclassified | `OPEN`, `IGNORE`, `UNKNOWN`, `REVIEWED` |

The config becomes the single list of dispositions. `AUTHORIZED` and `DATA_CONTROL` (configured but
never usable) and `INSIDER_DATA_CONTROL`, `INSIDER_DATA_EXFIL`, `APPROVED_BUSINESS` and
`APPROVED_PERSONAL` (constants never configured) are removed. The disposition views validate
against the config, not the constants. `benign_dispositions` / `malicious_dispositions` are
replaced by the map, and `saq/disposition.py` gains
`get_disposition_class(disposition) -> tp | fp | None`.

Each disposition can be flagged `analyst_selectable: false`. `SIMULATED` is the only one; see Part 3.

### Detection verdicts

Only what an analyst explicitly set is stored. Everything else is derived when read. [D-6]

```
effective(dp) =
    NULL                        if class(alert.disposition) is unclassified
    NULL                        if the alert is attributed to a run that is not Reviewed
    FP   (inherited_single)     if class(alert.disposition) == fp         # overrides are masked
    override (explicit)         if an override row exists                 # tp alerts only
    TP   (inherited_single)     if the alert has one signature
    TP   (inherited_multi)      otherwise
```

- **On an FP alert every verdict is FP.** If the alert itself was wrong, the fix is to correct its
  disposition (the review path), not to override a detection. [DP-3] Its source is
  `inherited_single`, whatever the number of signatures: the alert-level FP covers each detection
  directly, so an FP alert never has unconfirmed detections and its FP labels are not weakened in
  label precedence (Part 2).
- **An alert from a run that is not Reviewed has no verdicts.** *Close* sets `SIMULATED` on
  canceled, error and discarded runs too (Part 3), and `SIMULATED` is tp, so without this rule every
  detection on those alerts would count as TP in per-signature counts and in the detection-points
  API, although nothing was learned from the run. The check is one join from `svs_attributions` to
  `svs_runs.state`, the same one capture makes (Part 2). The FP overrides that review or close
  writes for ignored detections are stored either way and take effect only once the run is
  Reviewed. An alert with no attribution is unaffected.
- **Overrides survive disposition changes.** A TP→FP→TP correction restores them.
- **On a TP alert every detection inherits TP.** `inherited_multi` marks inheritance on an alert
  where several signatures fired: 37% of TP alerts with a YARA hit, in production data from
  September 2026. It is a weaker label, reported separately (Part 2). [DP-2]
- **Any detection of any signature family can be labeled.** Only YARA consumes labels for
  regression, but per-signature TP/FP counts are useful everywhere. [DP-6]

**Storage.** `detection_point_verdicts(alert_id, content_hash, signature_uuid, verdict, user_id,
set_at)`, unique on `(alert_id, content_hash)`. `set_at` is maintained by the server on every change
of the row, so it doubles as the table's `updated_at`. The rule above lives in one module,
`saq/detection_verdicts/effective.py`, as SQL expressions and as a Python function that the tests
hold to agree; analyst writes go through `saq/detection_verdicts/store.py`, which accepts them only on
a tp alert whose disposition analysts can set, and on a detection synced with its node identity. The
`detection_points` rows are synced as a delta
upsert keyed on `(alert_id, content_hash)`: a row whose detection disappears from the tree is
deleted, and one that reappears gets a new `id`. So the verdict is keyed on `content_hash`, never
on the row. [DP-1, FR-16]

**Detection identity** (prerequisite, before the first verdict is written). Before phase 1,
`content_hash = sha256(signature_uuid, description, details)` ignored the node the detection sat
on. Detections whose description doesn't name their object collapsed into one row, and would have
shared one verdict. The node's identity is folded into the hash (`saq/analysis/detection_identity.py`)
and stored in the `node_kind`, `node_type`, `node_value_sha256` and `node_module_path` columns:
- observable nodes: `('observable', type, value hash)`;
- the root: `('root')`;
- analysis nodes: `('analysis', module path, parent observable type, parent value hash)`.

The value hash is the observable's key in the `observables` table: `sha256(value)` for every type
except `file`, whose value already is the content sha256 and is used as it is. So
`(node_type, node_value_sha256)` joins to `observables(type, sha256)`, and a file detection's node
is its sample's sha256. Analysis nodes use `Analysis.module_path` (an `Analysis` doesn't carry its
config module name); in core only the clicker detection puts detections on them.

The formula is pinned by a unit test (`tests/saq/analysis/test_detection_identity.py`) and never
changes afterwards, because a changed formula orphans every override. Rows synced under the earlier
formula carry NULL node columns and are re-keyed on the alert's next sync, which is harmless while
no verdict exists. [DP-7]

**YARA detections sit on the file** that matched, not on the shared `yara_rule` observable. [D-20]
- They carry structured `details`: `{"sha256", "rule", "namespace", "rule_uuid"}`.
- A `YaraScanResults` analysis that produced a detection is always visible, so the pruned alert
  view keeps the rule and match evidence.
- Detection chains become exact per file.
- Alerts created before SVS carry detections without these details, and SVS ignores them. That is
  how D-3 is enforced, with no date cutoff.

### GUI

- **Disposition modal.** For a TP alert with several signatures there is a collapsed section:
  *"3 signatures inherit TP. Mark any that were noise."* Expanded, it lists each detection
  (per file for YARA), pre-set to TP. Flipping one writes an FP override. **Confirm** upgrades
  `inherited_multi` to `explicit` without changing the value. Bulk disposition from the manage page
  has no verdict step. [DP-5, DP-2]
- **Alert page.** Each detection shows a verdict chip, marked *inherited* or *explicit*, editable at
  any time. On an FP alert the chip reads *"FP (from alert). If the alert was wrong, correct its
  disposition"* and offers no TP option. [DP-3] On a `SIMULATED` alert the chips are read-only:
  the run review owns those verdicts (Part 3), so an analyst override and a run re-review never
  fight over the same row. [FR-15] The chips sit next to each detection in the analysis tree and
  in the Detection Chains card, which also lists the detections on the alert itself (hunts,
  alertable tags), since those have no place in the tree. A chip offers *mark as noise (FP)*,
  *confirm as TP* and *inherit from the alert*; it reads and writes through
  `/api/v2/alerts/{uuid}/detection-points` (`app/static/js/detection_verdicts.js`).
- **Manage page.** A filter for *has unconfirmed detections*, i.e. detections whose verdict source
  is `inherited_multi`. (Under D-6 nearly every detection on a classified alert has a verdict, so
  "unlabeled" would be an empty filter.) [FR-15] It is *Unconfirmed Detections*, slug
  `unconfirmed_detections`, and the same filter works in `GET /api/v2/alerts`.

## Part 2 — YARA static regression

### Capture

A module, `svs_yara_sample_capture`, runs in `analysis_mode_dispositioned`. Both disposition
writers already requeue into that mode, run review and close set `SIMULATED` through one of them
(Part 3), and today the mode runs nothing by default. The module reads `alerts.disposition` from
the database, because roots don't carry it. [YR-5]

- **What gets captured:** every YARA-matched file on an alert whose disposition classifies tp or
  fp, whatever the per-detection verdict. A verdict set later needs only a database write, never
  the bytes again.
- **Idempotent** on `(alert, sha256, rule uuid)`.
- **Missing data** is logged at ERROR and counted per rule, and the count is shown on the SVS page.
- **Capture is the only chance.** Since the phase-0 archive fix [YR-11], `archive()` removes an FP
  alert's derived files after `fp_days`. IGNORE alerts are deleted after a day.
- **Alerts from unreviewed runs are skipped.** An alert attributed to a run (one join from
  `svs_attributions` to `svs_runs.state`) is captured only when that run is *Reviewed*. Closed,
  Canceled and Error runs set `SIMULATED` too (Part 3), and their alerts are the least
  trustworthy, so they add nothing to the corpus. Alerts with no attribution are unaffected. [FR-4]
- **`signature_version` is checked.** It is `"unknown"` unless `service_yara.git_repo_dirs` is
  set, which makes the audit column worthless. The module logs ERROR for every capture whose
  version is unknown. [FR-15]
- **The work item keeps its mode.** The `dispositioned` requeue targets the alert's own node, but
  any node of the same company may pull it. `transfer_work_target` used to return the root without
  the item's `analysis_mode`, so the orchestrator fell back to the `correlation` mode saved on
  disk and capture did not run on that pass. The transfer moves every workload row of the alert
  to the new node and the clear deletes only the row of the mode that ran, so the `dispositioned`
  row ran on a later pass instead: capture was delayed, after a pointless correlation pass, not
  lost. `transfer_work_target` now carries the selected item's mode. [FR-5]

Each capture record stores: [YR-4]

| Field | Why |
|---|---|
| `sha256` → CAS pool `svs_samples` | The bytes, deduplicated, with a hold per capture record. |
| `file_path` (relative, as in the alert) | Rebuilds the `filename`/`filepath`/`extension` externals and the `file_name`/`full_path`/`file_ext` filters. |
| `yara_meta_tags` | Rebuilds `meta_tags`. |
| rule uuid, name, namespace | What the sample is labeled for. |
| `signature_version`, rule `content_hash` at capture | Audit. |
| original match record (strings, offsets) | Audit, and "why did this match" in reports. |
| alert uuid, file observable uuid | Provenance; label derivation. |
| yara-python and yara_scanner versions | Explains library-driven differences. |

Rules without a `uuid` fall back to the shared built-in signature, so they are not captured. [YR-7]
The signature inventory (`saq/signatures/loaders/yara.py`) lists only rules that have one, and
gives each rule's `content_hash`, `modifiers` and `enabled` with the same helpers the scanner uses.
It does not report two rules sharing a uuid: it keeps one. The validation's duplicate check (below)
parses the head tree itself, or extends the inventory to report duplicates. [FR-27]

**The YARA QA store is the precedent.** The yara service already keeps the files matched by rules
in QA mode, and their full match records, in the encrypted `yara_qa` CAS pool, indexed in
`yara_qa_matches` (`docs/YARA_QA.md`, `saq/yara_qa/store.py`). Capture is a second store of the
same shape, not a second consumer of that one: QA records every match of a QA rule at scan time,
in the service, keyed on `(rule uuid, rule version, sha256)`, capped and expiring; capture runs at
disposition time, in the engine, only on classified alerts, keyed on `(alert, sha256, rule uuid)`,
and holds for as long as the capture record exists. `svs_yara_captures` stays its own table and
reuses the building blocks: the hold idiom and the one-statement conditional UPDATE, the scanner
protocol's base64 encoding of match strings for the stored record (`saq/yara_scanning/protocol.py`;
the QA store's `_JSONEncoder` path decodes string bytes lossily, so it is not copied),
`signature_version` taken exactly as QA takes it, the namespace stored relative to the signature
directory (the match carries the absolute rule directory, which a replay tree does not have), the
`wrong_node` answer for bytes on another node's local pool, and the infected-password zips of
`aceapi_v2/common/archive.py` for downloads. [FR-27]

**Sample storage on a multi-node site.** Capture runs in the engine of whichever node owns the
alert and validation runs in `service_svs` on one node, so the `svs_samples` pool has to be
reachable from every node (`shared: true`). The CAS ships only the `local` backend, which is enough
for a single-node instance. **Providing a shared backend is the site integrator's job**: an S3
backend, whatever Azure offers, or any other `custom` class that declares `node_local = False`.
ACE does not build one as an SVS prerequisite, and the capture module stays disabled on a
multi-node site until the pool exists. The `yara_qa` pool already works this way (`docs/YARA_QA.md`,
*Nodes*): a site that has given it a shared backend gives `svs_samples` the same one. [FR-1, CAS-6]

The YARA module is deliberately not cached (`docs/ANALYSIS_CACHING.md`): its filtered output
depends on file name and `meta_tags`, which are not in the cache key. Moving its detections onto
the file [DP-4] therefore needs no cache-version bump, and it is the same fact that makes replay
rebuild path and `meta_tags`. [FR-21]

### Labels

A sample's label for a rule aggregates the verdicts of every contributing detection. The
precedence is `explicit` > `inherited_single` > `inherited_multi`. Votes of equal strength that
disagree make the pair **conflicted**: shown in reports, and excluded from results until someone
relabels it. The newest vote never silently wins. [YR-6, DP-2]

### Validation

**Trigger.** The signature repo's CI calls ACE. ACE never talks to the forge. [YR-3]

```
POST /api/v2/svs/yara/validations   {repository, base_sha, head_sha, branch, pr_url?}
GET  /api/v2/svs/yara/validations/{id}
```

- **`repository`** names an existing `git_repo_<name>` section, so ACE uses credentials it already
  has.
- **The CI key** belongs to a dedicated automation user with only `svs:validate`, so a leaked key
  can't read samples.
- **The response** carries counts, rule names and uuids only; sample content and file names never
  leave ACE. CI posts a **neutral** check and a comment with the counts and the link to the ACE
  report. **Validation warns and never blocks.**

**Fetching rules.** SVS keeps its own mirror clone per repository (same URL and SSH key), separate
from the `GitManagerService` checkout production loads rules from. It fetches `branch`, verifies
`head_sha`, and exports each commit's YARA tree with `git archive`.

**Scanning.** Each tree is compiled in a subprocess into a private `YaraScanner`, with a
wall-clock timeout, a memory limit and a size limit. It never touches the live scanner or
`signature_dir`. [YR-9] Production scanning lives in the `yara` service (`docs/YARA_SCANNER.md`),
and the `yara_scanner_v2` library (3.0.0) only compiles, tracks and filters rules, so the subprocess
uses it the way the module's fallback scanner does.
- **Validations are a queue.** `service_svs` runs one scan at a time by default
  (`svs.yara.max_concurrent_validations`), and a result is cached per `(repository, base_sha,
  head_sha, corpus version)`, so a CI retry does not rescan. [FR-13] The **corpus version** is the
  greatest `updated_at` over `svs_yara_captures`, `detection_point_verdicts`,
  `svs_sample_retirements`, the sample deletion audit and the `alerts` rows the captures reference
  (`alerts.updated_at`, Part 6). So a new capture, a relabel, a confirm, a retirement, a sample
  deletion or a disposition correction changes the version and the next request rescans, and
  nothing else does.
- **Compile the way production loads.** The production loader compiles each file on its own and
  drops only a file that fails; then it compiles the survivors once per namespace, and if that
  fails (two files defining the same rule name, for instance) the whole ruleset is dropped and the
  service keeps serving the previous generation. The validation does the same two steps, but
  through `yara.compile()` directly, because `yara_scanner.load_rules()` only logs a failing file
  and returns `False`, and the direct call gives the error text and the compiler warnings
  (`Rules.warnings`). The subprocess applies the same `yara.set_config()` limits the library sets
  when it is imported, so the two agree on what compiles. [FR-11, FR-26]
- **Compile errors are results.** "File X does not compile: its N rules are dropped", or "the
  ruleset would not load: production keeps the previous generation". A validation that compiled a
  namespace as one source would instead report every rule in it as regressed when one file is
  broken. [FR-26]
- **Duplicate `uuid` meta** in the head tree makes two rules share one label set. Both are listed
  as *not regression-testable*, next to the rules with no uuid [YR-7]. [FR-11]
- **The whole corpus is scanned with the whole base ruleset and the whole head ruleset**, and the
  results are diffed per `(sample, rule uuid)`. [YR-2] That is the only way to catch:
  - new rules, which have no samples of their own;
  - new false positives on *other* rules' samples;
  - effects that never change a rule's own text: private or referenced rules, includes, and a
    namespace that stops compiling.

  "Which rules changed" is a report heading, not a filter on what gets scanned.
- **Replay** materializes each sample at `<tmp>/files/<file_path>`, so the path-derived externals
  match. Rules filtering on `full_path` are flagged, because the original path contained the
  alert's storage directory.
- **The report also carries** base-vs-head scan time per namespace and the head's compiler
  warnings.

**The SVS node is a malware store.** The pool is encrypted, but `materialize` of an encrypted
object goes through the node-local CAS read cache, and replay writes every sample in plaintext under
`<tmp>/files/`. That is inherent in scanning, so it is accepted and operated accordingly: the node
gets AV exclusions, disk encryption and restricted shell access; the replay tree is deleted after
every validation; and `cas.read_cache.max_bytes` is sized to the corpus so a validation does not
decrypt tens of thousands of objects twice. [FR-12]

### Report and baseline

The **baseline is the set of labels**. Each sample is scanned under base and head, and a difference
exists only where they disagree. [YR-1]

| Label | base | head | Category |
|---|---|---|---|
| TP | match | **miss** | **Regression** |
| TP | miss | match | Recovered |
| TP | miss | miss | Already broken on base (shown separately) |
| FP | match | miss | Improvement |
| FP | miss | **match** | **New false positive** |
| FP | match | match | Known FP, still matching (counted) |
| none / conflicted | differs | differs | Unlabeled change (listed) |

A regression on an `inherited_multi` label goes in its own band: *"regression on an unconfirmed
label: check that the sample was ever a real hit for this rule"*. [DP-2]

**Analyst actions on a sample:**
- **Relabel.** This writes verdict overrides on the contributing detections, so it has the same
  source of truth as Part 1.
- **Confirm label.**
- **Retire** for one rule, with who and why. The sample is no longer expected to match that rule.
- **Download**, one sample or a selection, as a zip with the password `infected`, exactly as the
  Yara QA Results page does. It needs `signature:download`. [FR-28]
- **Delete sample.** A CAS purge plus rows, audited, for legal or privacy requests.

Nothing changes automatically when a PR merges. An accepted regression keeps showing as *already
broken on base* until it is retired or relabeled.

## Part 3 — Test execution (Atomic Red Team)

### Test hosts and registration

**Test hosts** are rows in `svs_test_hosts` (`hostname, fqdn?, usernames?, ips?`), managed on an
SVS admin tab and through `/api/v2/svs/test-hosts`, both under `svs:admin`. They are a table
rather than config because a site may build test VMs dynamically, and adding one must not need a
restart of every process that evaluates routers. Matching normalizes case, short name vs FQDN,
and `DOMAIN\user` / `user@domain` / `user`. [ART-9, FR-15]

The launcher (outside ACE) drives the run lifecycle through `aceapi_v2/svs/`. Every call requires
`svs:run_register`. [ART-2]

| Call | Transition | Notes |
|---|---|---|
| `POST /runs` `{test_guid, targets:[{hostname, username}], launcher, batch_id?, extra}` | → **Created** | Validates `test_guid` against the catalog and every target against the test hosts. Returns `run_id` and `marker`. |
| `POST /runs/{id}/start` | Created → **Started** | Records `started_at`; the windows start here. |
| `POST /runs/{id}/executed` `{exit_code, error?}` | Started → Started / **Error** | Optional; a launcher-reported failure moves the run to Error. |
| `POST /runs/{id}/cancel` | any non-terminal → **Canceled** | Launcher or analyst. |
| (timer) | Started → **Ended** | At `started_at + observation window`; the result is computed. |
| (timer) | Created → **Error** | `start` was never called within the configured time. |
| (analyst) | Ended → **Reviewed** | Sign-off; Coverage counts only Reviewed runs. See Part 5 for its preconditions. |
| (analyst) | Ended, Canceled, Error → **Closed** | Discards the run: its alerts are closed, nothing is learned from it. A reason is required on an Ended run. [MGT-3] |
| (timer) | Canceled, Error → **Closed** | When the attribution window ends. An Error run that never started has no window and is Closed in the same transition. Ended runs always wait for a person. |

**Cancel stops the run, not attribution.** The test may have run anyway, so a canceled run keeps
attributing inside its attribution window. Otherwise its markers would surface as
`MARKER MISMATCH`. An *Error* before `start` has no windows and no alerts, so it is Closed at the
transition, with the reason in its event log, and never waits in *Needs attention*. [MGT-3]

**Timers run in one place.** `service_svs` runs as a single instance on the primary node, like the
CAS cron tasks, and owns the run timers, the validation queue and the catalog refresh. Every timer
transition is a conditional update (`… SET state='ended' WHERE id=? AND state='started'`), so a
duplicate firing is harmless anyway. [FR-13]

**A reviewed run can change.** A late alert or a manual association after sign-off flags the run
*changed since review*, and it returns to the operator's *Needs attention* list. The result as
signed off is kept (Part 6). [MGT-2, RPT-4]

**Runs have an owner**, with the same model as alerts, including the confirmation for taking one
from another person. Reviewing a run takes it if nobody owns it. [MGT-3]

**Registration against a non-test host,** or an unlisted user on a host that lists `usernames`, is
**refused with 403**. It also creates an alert in the default queue through the normal submission
path, with a built-in signature and the caller's identity as observables. [ART-9] The alerts are
collapsed to one per `(caller, host)` per hour; further refusals in that hour are logged at
WARNING, so a misconfigured launcher retrying in a loop does not flood the queue. The launcher's
`extra` is stored and rendered, so its size is capped. [FR-15]

**Windows.** The *observation window* comes from the test's config if it sets one. Otherwise it is
computed as the maximum, over the test's expected signatures, of their worst-case latency (for
hunts, `frequency + time_range + offset`), plus slack, within a floor and a ceiling. A test with no
expectations yet (its first run, where expectations are discovered) gets the maximum worst-case
latency over every *enabled* hunt, capped at the ceiling, not the floor. [FR-10] The *attribution
window* is longer. Alerts that arrive after *Ended* but inside it are attributed, marked *late*,
and the result is recomputed. [ART-3, ART-2] "Inside the window" is judged on `root.event_time`
(for hunts, the query's event time), falling back to the alert's insert time when it is unset. [FR-9]

### Markers

- **Format:** `svs-` followed by 26 base32 characters (128 random bits), matchable by a regex.
- **Not secret.** Once a test runs, the marker is in telemetry. It is valid only in context.
- **A marker attributes only when it agrees with its run:** it matches a registered run, *and* the
  alert involves one of that run's targets, *and* the event falls inside the run's attribution
  window. [ART-4]
- **A marker that doesn't agree never routes the alert.** That covers unknown markers, well-formed
  markers not in the database, markers from another host, and markers outside the window. The
  alert stays in its normal queue, is tagged `svs:marker_mismatch`, and gets a detection from a
  built-in signature. Both are added at the `POST_ANALYSIS` stage, which owns the root (see
  *Attribution and routing*), never at `PRE_INSERT`. A marker on a production host is exactly what
  an analyst should see. [FR-3] **A disagreeing marker also ends attribution for that alert**: the
  context fallback below never runs on it, otherwise an alert carrying run A's marker outside A's
  window could be attributed by context to run B on the same target.
- **Without any marker**, attribution falls back to target plus window, recorded with confidence
  `context`. Context-only attribution also routes. [ART-5] An alert whose marker disagreed never
  reaches this fallback. It has no per-detection signal, so it
  attributes **every** detection on the alert: a context-only alert is always `TEST?`, never
  `PARTIAL TEST`. It also requires exactly one candidate run. When two runs on the same target
  have overlapping windows, nothing is attributed and a WARNING record names both run UUIDs,
  because attributing to the wrong run teaches the wrong expectation. [FR-9]

The launcher's contract is to put the marker where the technique's process telemetry will show it:
an input argument, a file name, or a trailing shell comment on the executor command.

**Injecting it without forking Atomic Red Team.** Both forms work against the unmodified upstream
repository.
- **Input arguments** go through `Invoke-AtomicTest -InputArgs`, which substitutes `#{name}` as
  plain text. Keys a test doesn't declare are silently dropped. About 58% of tests have a string,
  path or URL argument that reaches the command, but that is an upper bound: many of those name an
  input file, URL or registry key that must stay as it is. Only output names and free text are
  safe to change.
- **The trailing comment** has no hook in `Invoke-AtomicRedTeam`, which reads the test's YAML from
  `-PathToAtomicsFolder`. For each run, the launcher writes a copy of the test's YAML with the
  comment appended to `executor.command` into a temporary atomics folder, links `src/` and `bin/`
  back to upstream, and points `-PathToAtomicsFolder` at the copy. The copy is regenerated from
  upstream on every run, and `auto_generated_guid` is unchanged, so it still matches the catalog.

The runner turns a multi-line command into one process, so the comment goes at the end of the
whole command, in the form its executor needs:

| Executor | How the runner runs it | Trailing comment |
|---|---|---|
| `command_prompt` | `cmd.exe /c "line1 & line2 …"` | `& REM svs-…` |
| `sh`, `bash` | `sh -c "line1; line2 …"` | `# svs-…` |
| `powershell` | `powershell.exe "& {<script>}"` | `<# svs-… #>`. A `#` line comment would comment out the closing `}` and break the test. |
| `manual` | not executed | none |

**What a trailing comment reaches:**
- **The executor's own process** always carries it in its command line.
- **Its direct children** carry it only as `ParentCommandLine`, when the telemetry records that.
- **PowerShell** also carries it in script-block logging (event 4104).
- **Grandchildren, and file, registry, network and authentication events,** never carry it, and
  fall back to `context`.

### Attribution and routing

Attribution runs inside the engine, through a **core alert-router registry**. This is a change to
ACE itself, not only to SVS. [D-13, ART-15]

- **`AlertRouter.route(root, stage) -> RouteDecision | None`**, where a decision is
  `{queue, reason, router}`.
  - Every router, built-in or configured, has a numeric `priority`. Routers run in priority
    order, and the first decision wins. **The SVS marker router runs before the detection-queue
    router**, so a YARA rule with a `queue` meta that matches a dropped test file does not take the
    alert before SVS sees it. [FR-2]
  - **A configured queue may be overridden.** A marker that agrees with its run is stronger
    evidence than a queue set by hunt config, a `queue` detection meta or a submission, so the SVS
    router may route such an alert. (There is no "explicitly set" flag to honor: `root.queue`
    always has a value, and every hunt submits with one.) The only queue it never overrides is one
    that `move_alert_to_queue` itself set earlier and recorded as SVS-set, so a manual
    *disassociate* is not undone by re-analysis. When the SVS router makes no decision, the
    configured route applies as it does today. [FR-2]
  - **A router never breaks an insert.** The registry runs each router inside a `try`; a router
    that raises is logged with `report_exception()` and skipped, and `ALERT()` continues. ART-15
    says this for loading a router; it holds at runtime too, because the registry sits inside
    every alert insert. [FR-2]
  - Routers are registered as built-ins plus `alert_routers:` config entries
    (`python_module`/`python_class`/`priority`), in the same pattern as
    `hunter.correlation.command_types`.
  - The registry is **open to integrations from day one**. It is documented in
    `docs/INTEGRATIONS.md`, and the example integration ships a trivial router.
- **Stage `PRE_INSERT`**, inside `ALERT()`, the one function every alert insert goes through,
  before `Alert.create_from_root_analysis` copies `root.queue`.
  - Engine-converted alerts arrive here fully analyzed, so they never appear in the wrong queue.
  - **`PRE_INSERT` routers are pure.** They return a decision and may write their own rows (the
    SVS router writes `svs_attributions`) in the caller's transaction, but they never touch the
    tree. The tree belongs to the caller, and the routed queue is the only change `ALERT()`
    makes on a router's behalf (it saves the caller's root again when a router changed the
    queue). The mismatch
    tag and detection therefore belong to `POST_ANALYSIS`, below. This rule is part of the
    `AlertRouter` contract in `docs/INTEGRATIONS.md`, because integration routers hit the same
    trap. [FR-3]
  - The alert row has no `id` until the session flushes, so attribution rows are keyed on the
    alert **uuid**. [FR-23]
- **Stage `POST_ANALYSIS`**, in the orchestrator after each analysis pass, which owns the root.
  - It covers alerts inserted at submission time (hunts, API) whose marker appears only after
    analysis.
  - It is where the tree is changed: the `svs:marker_mismatch` tag and its detection, and the
    `svs_test` tag. Hunt alerts are analyzed after insert and engine-converted alerts get a
    correlation pass, so a mismatch still surfaces before an analyst sees the alert. [FR-3]
  - A decision there moves the existing alert through `move_alert_to_queue(alert, queue, reason,
    actor)`. That new core primitive updates the column and `root.queue`, touches the alert,
    refreshes the search payload, writes an audit line, and records the previous queue and that
    the move was SVS's.
- **An alert that is not `OPEN`, or that an analyst owns, is never moved.** It gets its SVS badge
  instead. The automation user (`ace`, `global.automation_user_id`) counts as nobody here: setting
  `SIMULATED` backfills `owner_id` with the dispositioning user, so without this exception a
  re-review could never move a test alert. [FR-15]
- **`_apply_detection_queue` becomes a built-in router**, with its all-or-nothing rule unchanged
  and a priority below the SVS router. (Its comment claims `all_detection_points` omits root
  detections; it does not, and they are counted twice, harmlessly. Fix the comment then. [FR-24])

**Where the SVS router looks:**

| Scan point | Covers |
|---|---|
| Observable values and file names, and `root.details` (at both stages) | Hunt raw events, API details, command lines, URLs |
| Each module's `ModuleExecutionDelta` (new observables and added detections, plus the new analysis's `details`), scanned in the executor right after the module returns. The cache path produces the same delta, so cache replays are scanned too. [FR-19] | Decoded or deobfuscated output |
| File contents, through a built-in `no_alert` YARA rule for the marker format, whose match strings land in `YaraScanResults.details`. Scanning happens in the `yara` service, which compiles only what is under `service_yara.signature_dir` and `git_repo_dirs`, so the rule ships in the repo as its own namespace there, listed with the other rule locations (`saq/signatures/locations.py`); a test asserts that both the service and the module's fallback scanner load it. [FR-20, FR-25] | Markers inside dropped scripts and documents |

**The scan is gated and the cache is one-sided.** [FR-8]
- The whole scan (a regex over every observable value and `root.details`, on every alert insert)
  runs only when one cheap check says a run is inside an open attribution window. That check is
  cached for a few seconds, so the router costs nothing when no test is running.
- Markers are resolved against runs through a short-lived per-process cache that holds **positive
  resolutions only**. A marker that misses the cache always goes to the database before any
  decision. The router runs in every process that calls `ALERT()` (engine workers, the hunter, the
  API, the GUI, the CLI), and a launcher registers a run seconds before the test fires; a stale
  negative would route a real test to the default queue as `MARKER MISMATCH`.

Attribution rows `(run, alert uuid, detection content_hash, confidence, late, source)` are written
at the same time as the decision.

**Mixed alerts.** Attribution is per detection. An alert is routed to the SVS queue only when
**every** detection is attributed. Otherwise it stays in its queue with the `PARTIAL TEST` status.
[ART-7]

### What analysts see

Every alert has at most one SVS status, and alerts SVS never touched show nothing. [ART-14]

| Status | Meaning | Queue | Action |
|---|---|---|---|
| `TEST` | Every detection attributed to run *R* by marker | SVS | None. Review happens in the run review. |
| `TEST?` | Attributed by context only | SVS | None, unless it looks wrong. One click: *not a test*. |
| `PARTIAL TEST` | Some detections are from run *R* | normal | Triage the rest as usual. Test detections are greyed out. |
| `MARKER MISMATCH` | A marker that doesn't fit its context | normal | Treat as suspicious and investigate. |

The status is one badge in the manage list and one banner on the alert page, and it always links
to the run. Confidence, per-detection attribution, suppression notes and late arrivals live in the
**run review**, which is the SVS operator's screen.

### Test alerts downstream

- **Disposition `SIMULATED`, class tp, ranked below `GRAYWARE` for event roll-up.** SVS sets it when
  a run is *Reviewed* or *Closed*, on the run's fully attributed alerts, through the same
  disposition writer analysts use. That writer requeues the alert into
  `analysis_mode_dispositioned`, so capture (Part 2) runs on a reviewed run's alerts the way it
  runs on any other. [D-16, MGT-3]
  - It is `analyst_selectable: false`: not in any modal, and rejected server-side.
  - A `SIMULATED` alert's disposition can't be changed by hand. The modals show *"Part of test run
    R. To treat this as a real alert, use Disassociate from run"*. Bulk actions skip such alerts
    and report them.
  - A `SIMULATED` alert is **never reset or re-analyzed** (`ace alert reset`, the GUI's
    re-analyze, bulk actions). Its detections, and so its verdict sources and the labels derived
    from them, are frozen at review time, so a report stays reproducible. [FR-15]
  - Verdict chips on a `SIMULATED` alert are read-only; the run review owns them (Part 1). [FR-15]
  - `SIMULATED` is added to the engine's `stop_analysis_on_dispositions`: nothing needs further
    analysis of a test alert. [FR-7]
- **Test alerts are archived after `svs.simulated_days`** (default 30), the way `FALSE_POSITIVE`
  alerts are archived after `fp_days`, and they are **never deleted**. Maintenance today archives
  only `FALSE_POSITIVE` alerts and deletes only `IGNORE` ones, and `SIMULATED` alerts would be the
  steadiest source of new alerts once the test program runs. `archive()` frees the analysis
  details and the derived files (the samples are already in the CAS) and keeps the row, its
  disposition and its detection points, which is what the verdicts (Part 1), the sample labels
  (Part 2) and the attributions derive from. Deleting the alert would orphan all three: every TP
  sample from the test program would lose its label source. A reset is no alternative, because
  `RootAnalysis.reset()` clears the disposition and the derived observables, which is the same
  loss. [FR-7]
- **Ignored detections are benign.** A run's ignored detections (launcher noise) get FP overrides
  when the run is reviewed or closed.
- **YARA TP samples come from Reviewed runs only.** Because `SIMULATED` is tp, YARA hits in a
  reviewed run become TP samples through the normal capture. Capture skips alerts attributed to a
  run in any other state (Part 2), and the verdict formula returns no verdict for them (Part 1),
  so nothing is learned from a Closed, Canceled or Error run, not even a per-signature TP count,
  which is what *Close* promises. [FR-4]
- **Test alerts stay out of observable history and prevalence.** Both count only the `default`
  queue. Disposition history already did (PR #587); prevalence is changed to match.
- **Routed alerts are tagged `svs_test`** (at `POST_ANALYSIS`).

### Expectations

Expectations are **learned from reviewed runs**, not derived from declared techniques. [D-9, ART-11]

1. **Discovery.** The first Reviewed run of a test proposes every attributed signature, minus the
   ignore lists, as a *candidate*. The analyst accepts (*expected*) or rejects each one. A rejected
   candidate is remembered and not proposed again.
2. **Steady state.** Later runs compare against the expected set:
   - an expected signature that doesn't fire is *missing*;
   - a signature that fires and isn't expected becomes a new candidate.
3. **No automatic demotion.** The run history shows flakiness, and only an analyst removes an
   expectation.

**Ignores come in two scopes:** global (launcher noise such as WinRM or remoting, ignored on test
targets during any run) and per test. [ART-13]

**Manual (re)association.** An analyst can associate any alert with any run, or disassociate one.
It uses `move_alert_to_queue`, records who, when and why, recomputes the run's result, and is
reversible. Disassociating restores the previous queue. [ART-13]

**Hunt suppression.** When an expected hunt signature is *missing* and that hunt alerted within its
`suppression` period before the run started, the result reads *missing, possibly suppressed*. It is
imprecise for `group_by` and `dedup_key`, and says so. Preventing suppression for test targets is
deferred. The revisit trigger is 50 Reviewed runs or 3 months: if more than about 10% of *missing*
results are *possibly suppressed*, reconsider. The SVS page shows that share. [D-19, ART-8]

### The Atomic Red Team catalog

ACE doesn't execute tests. It holds ART repositories only as a **catalog**: to validate
`test_guid`, to display names and descriptions, to check `supported_platforms`, and to know each
test's technique. [ART-12]
- Each repository is an ordinary `git_repo_<name>` section, polled by `GitManagerService`.
- SVS parses `atomics/T*/T*.yaml` into a catalog table when the commit changes.
- Custom repositories follow the ART schema and must carry `auto_generated_guid`. A test without
  one is skipped with a warning.
- A GUID that disappears from the catalog keeps its run history.

## Part 4 — Coverage

**Grain:** technique × environment, rolled up to parent techniques. Coverage is **global**, not per
company. [COV-1]

**Where technique facts come from:** [D-17, ART-11, ART-16]

| Fact | Source |
|---|---|
| test → technique | The atomic's own YAML |
| signature → technique, **measured** | Techniques of the tests where the signature is *expected* |
| signature → technique, **manual** | The existing `mitre_attack` YARA meta and `mitre:` hunt tags |

- **Manual mappings count until resolved.** A signature's techniques are the union of measured and
  manual. A manual mapping keeps counting until someone resolves it.
- **When a tagged signature is measured**, it goes on a single **declared-vs-measured worklist**
  (once per signature) with three resolutions:
  - *tag confirmed*: automatic when measured and declared agree;
  - *keep tag*: it covers something no test reaches;
  - *remove tag*: a PR to the signature repo, which ACE records as intent.
- **On day one every tagged signature is manual.** That is an honest starting picture: claimed,
  not measured.

**States per technique:**

| State | Meaning |
|---|---|
| **validated** | A test for it has expectations, and its latest Reviewed run hit all of them. |
| **failing** | The latest Reviewed run of a test for it had a *missing* expected signature. |
| **stale** | Validated, but an expected signature's per-rule `content_hash`, or the test, has changed since. |
| **untested** | Atomics exist, but none has a Reviewed run with accepted expectations. |
| **manual** | Covered only through manual mappings. |
| **none** | No atomics and no mappings. |

*Failing* means a test of the technique missed an expected signature. It does not mean the
technique is undetected; the drill-down shows which tests and signatures cover it. The ATT&CK
release used for names and roll-up is pinned in config. Revoked or renamed techniques are mapped on
upgrade.

**The ATT&CK catalog ships in the image.** [FR-14] Production ACE never fetches it from the
internet. A compact extract per supported release is vendored in this repo at
`etc/attack/<release>.json` (`etc/` is copied into the image) and holds only what SVS uses:
technique ids and names, sub-technique → parent, tactics, and the revoked and renamed maps.
`bin/update-attack-catalog <release>` builds it: it downloads the raw enterprise ATT&CK STIX bundle
for that release from MITRE's CTI repository, parses it and writes the extract. A developer runs it
when ACE adds support for a release, and commits the result. `attack_release` names one of the
vendored files, and startup fails validation when the file is missing.

## Part 5 — Operating SVS

Someone owns the test program: they launch runs (outside ACE), watch them, review results, cancel
what went wrong and debug what didn't fire. What to run next is the team's decision, made with
whatever logic it uses. ACE shows the facts, and neither recommends nor queues tests. [MGT-4]

### One SVS area

SVS has two homes, because its YARA half belongs with the other signature screens. [FR-28]

- One *SVS* navigation entry, in the slot of the disabled *DetectOps* placeholder, with tabs
  **Runs**, **Tests**, **Coverage** and **Worklist**, plus a **Test hosts** admin tab shown only
  with `svs:admin` [FR-15].
- **Validations** and **Samples** are cards in the existing **Signatures** hub (`app/signatures/`,
  next to *Yara QA Results*), so they are gated by `signature:read` like everything else there,
  and built the way that page is: a shell whose data all comes from the API.

Every tab and card follows the alert manage page's pattern [MGT-7]:
- a filtered, sortable, paged list, with its own filter registry in the manage page's
  `{name, inverted, values}` shape, saved filters and share URLs;
- export, which is the API (Part 6);
- a detail page per row.

Saved filters become **per screen** (`alerts`, `svs_runs`, `svs_tests`, `svs_validations`,
`svs_samples`, ...), so there is one saved-filter system for every screen. [MGT-1] That is more
than a column: the unique key becomes `(user_id, screen, name)`, the `working`/`temp` scratch rows
are one per user *per screen*, `FilterEntry` (`aceapi_v2/saved_filters/schemas.py`) validates names
against a registry object passed in per screen instead of the alert `FILTER_NAMES`, and the query
builder in `saq/gui/filter_query.py`, whose `entity=` parameter already exists, stops naming `Alert`
in its correlated subqueries. [FR-18, FR-30]

### Runs

`/ace/svs/runs` lists runs. [MGT-1]
- **Columns:** state; test name, GUID and technique; targets; launcher and batch; created, started
  and ended times; time left while *Started*; a result summary (expected hits *n*/*m*, missing,
  possibly suppressed, candidates, late); alert count by confidence; owner; reviewer.
- **Filters:** state; test; technique, including its parents; target; launcher; batch; date ranges;
  *has missing / possibly suppressed / candidates / late / context-only*; owner; reviewer; *has open
  alerts*.
- **Default view, *Needs attention*:** Ended and not reviewed, Error, reviewed runs *changed since
  review*, and terminal runs that still hold open alerts. A run Closed because `start` was never
  called is found through the *state* and *reason* filters, not here.
  Its count is shown on the navigation entry.
- **Bulk actions:** take ownership, cancel, close, export. Review is never a bulk action.
- **Batches.** `batch_id` is a label, not a table. It is a filter and a group-by, and a grouped
  batch shows one summary row (runs by state, expected hits, missing).

### The run page

`/ace/svs/runs/{run_uuid}` is the run review from Part 3, and the operator's screen (ART-14).
[MGT-2]
1. **Header:** test, technique, GUID and catalog commit; a timeline strip with the observation and
   attribution windows; marker; targets; launcher, batch, `extra`; owner.
2. **Result:** one row per signature (hit, missing, possibly suppressed, candidate, ignored), with
   that signature's recent history on this test.
3. **Attributed alerts:** SVS status, confidence, *late*, attributed detections, whether associated
   by hand.
4. **Candidates:** accept or reject each one; per-test and global ignores.
5. **Logs:** the run's search keys, or a link (below).
6. **Comments.**
7. **Event log.**

**Review has preconditions.** *Mark reviewed* is enabled only when every candidate is decided and
every context-only (`TEST?`) attribution has been kept or marked *not a test*, because review sets
`SIMULATED`. While a run is *Started*, the page refreshes and shows alerts as they are attributed.

### Tests

`/ace/svs/tests` is a **read-only** view of the ART catalog and its history, one row per test.
[MGT-4]
- **Columns:** technique; name; platforms; repository; test state; last run; last reviewed run;
  number of runs; expected signatures; missing in the last *n* runs.
- **Test state:** *never run*, *awaiting review*, *no expectations*, *validated*, *failing*, *stale*
  (with the same meanings as in Part 4).
- **Sort and filters:** the default sort is technique, then name. There is no suggested order.
- **The detail page:** the test's description, commands and input arguments from the catalog, its
  expectations and ignores, and its run history.

### Debugging a run

**Test failures are debugged from ACE's logs, in the site's own log tooling.** SVS doesn't build
debugging tools. Every site's logging is different, and ACE already works this way for everything
else. What SVS owes the operator is logs that are sufficient. [MGT-9]

**The run page's *Logs* section** shows the run's search keys, ready to copy: `svs_run`,
`svs_marker`, the targets and the window. If `svs.log_search_url` is set, for example
`https://splunk.example/…?q=svs_run={run_uuid}`, the section is also a link. ACE never queries it.

**Missing YARA signatures** link to the files captured from the run's alerts.

**The run event log** (`svs_run_events`) is the run's history, not a debugging tool. It has one
append-only row per:
- state transition;
- launcher call, with its payload;
- attribution (including *late* ones) and manual association or disassociation;
- candidate decision;
- review or close, with the reason.

Each row records its actor and time. The run page renders it as a timeline, it holds the reason
for a close, and it is the run's change feed (Part 6). [MGT-5]

### Logging contract

ACE's convention applies: the message text describes the event, and `extra={}` carries the fields.
`saq.log` renders them as `key=value`, and the fluent formatter makes them top-level Splunk fields
(`saq/logging.py`; crash reports log their `crash_id` this way). [FR-30] **Every SVS record
carries `svs_run`**, plus `svs_test` and `svs_marker` wherever they are known, so one search on
`svs_run=…` returns everything ACE did about a run, across services and nodes. [MGT-9]

| Event | Level | Fields beyond the run's own |
|---|---|---|
| Lifecycle transition, including timers | INFO | `from_state`, `to_state`, `actor` |
| Launcher call | INFO; a refused registration at WARNING | `launcher`, the call, its outcome (and the caller on refusal; after the first refusal per `(caller, host)` in an hour this record is all that is written, no alert) [FR-15] |
| Router decision on an alert, at both stages | INFO | `alert_uuid`, `stage`, `decision` (routed / partial / none / not moved because owned or closed), `queue`, `confidence` |
| Marker sighting, agreeing or not | INFO; a mismatch at WARNING | `alert_uuid`, `scan_point`, `result` (attributed / unknown / other host / outside window) |
| Context attribution refused: more than one candidate run | WARNING | `alert_uuid`, `candidate_runs` (every run UUID; no single `svs_run`) [FR-9] |
| Attribution written or removed | INFO | `alert_uuid`, `detection`, `confidence`, `late`, `source` |
| Result computed | INFO, plus DEBUG per signature | per-status counts |
| Missing expected signature | INFO | `signature_uuid`, `signature_family`, `possibly_suppressed` |

Two SVS records are not about a run and carry no `svs_run`: [FR-15]

| Event | Level | Fields |
|---|---|---|
| The `disposition_classification` map, once at startup | WARNING | the map. A changed map relabels the whole corpus at read time, so every start says what it is. Unknown keys still fail validation. |
| A capture whose `signature_version` is `"unknown"` | ERROR | `alert_uuid`, `sha256`, `rule_uuid` |

**The hunt completion record** (core). The hunter's per-execution line (`base_hunter.py`,
*completed hunt …*) is how an operator checks whether an expected hunt ran over a run's window. It
becomes a record with `extra={}`: `hunt_uuid`, `hunt_name`, `hunt_type`, `status`, `query_start`,
`query_end` (after the offset is applied), `result_count`, `submission_count`, `duration_ms`. The
hunter knows nothing of runs; the operator searches by `hunt_uuid` and the run's window.

A test asserts that each record in the table carries its fields. The table is a contract, and a
refactor can't silently drop them.

## Part 6 — Data access and reporting

ACE doesn't impose a reporting structure. Every test, detection and alert fact can be downloaded,
and reports are built outside ACE. [RPT-1]

### Rules

- **Every SVS screen reads through a public `aceapi_v2` endpoint.** Anything a screen shows can be
  fetched with the same filters, and a screen with no endpoint behind it is a bug.
- **A filter is the same object in the GUI and the API.** List endpoints take the screen's filter
  list and its share-URL encoding.
- **Export in the GUI is the API:** CSV, JSON or NDJSON of the current list, or *Copy API URL*.
- **SVS ships screens for operating, not reports.** A reporting need the API can't meet is fixed by
  adding data to the API.
- **Identifiers are stable and public:** run UUID, test GUID, signature UUID, technique ID, alert
  UUID, detection `content_hash`, sample `sha256`, validation UUID.

### Endpoints

**Core ACE.** These are changes to ACE itself, not only to SVS. [RPT-2, RPT-7]

| Endpoint | Returns |
|---|---|
| `GET /api/v2/alerts` | Full alert rows (uuid, times, queue, disposition and disposition user, owner, company, tags, `updated_at`, detection count, SVS status). It takes the manage page's filters and share-URL encoding, with the same node scoping. |
| `GET /api/v2/detection-points` | Detection points with effective verdict, verdict source, signature UUID and family, alert UUID and node identity. Filters: signature, family, alert date, queue, verdict, source, has override. |
| `GET /api/v2/alerts/{uuid}/detection-points` | The same, for one alert |

`GET /api/v2/alerts` shares its filter vocabulary and SQL path with the alert search listing, and
differs in pager and row shape. Those are two paths: `build_alert_query()`
(`saq/gui/filter_query.py`) for the manage page's filter list, and `apply_sql_filters()`
(`saq/search/lexical.py`) for the typed `SearchFilters` of the search API. [FR-22] It
returns test alerts like any other; filtering them out is the caller's choice. It is not added to
the AI API, which stays small and rate-limited for agents. `/api/v2/detection` is
observable-detection settings, a different thing, which is why this one is `detection-points`.

**Alert search leaves test alerts out by default.** `saq/search/query.py` excludes `svs.queue`
whenever a request doesn't filter on queues. That covers the search box, `POST /api/v2/search/*`,
`POST /ai/v1/search/*` and the `ace search` subcommands. Each response counts what it left out
(`excluded_test_alerts`); naming the SVS queue, the GUI toggle or `--include-tests` on `ace search
query` and `ace search similar` brings them back. This is the same split as prevalence (Part 3):
"have we seen this before?" means real alerts. [RPT-7]

**SVS** (`/api/v2/svs/…`, list and detail for each):
- `runs`, and for each run `results` (live and as reviewed), `attributions` and `events`;
- `tests`;
- `expectations` and `ignores`;
- `validations` and their results, read with `signature:read` [FR-28];
- `samples` and their labels (metadata only, `signature:read`; the bytes need `signature:download`)
  [FR-28];
- `coverage`, `coverage/history`;
- `worklist`;
- `test-hosts`, read with `svs:run_read`, written with `svs:admin` [FR-15].

### Mechanics

[RPT-3]
- **Keyset pagination** with an opaque cursor over a stable order, never OFFSET. NDJSON streams the
  whole result.
- **Formats:** JSON pages, NDJSON, and CSV for flat lists. Nested data is its own endpoint.
- **Incremental pulls with `changed_since`:**
  - every SVS table has `updated_at`;
  - `alerts` gains `updated_at`, because the version token is random and can't be ordered. It is a
    server-side `ON UPDATE CURRENT_TIMESTAMP` column rather than a write at each of the ten call
    sites that rotate `alerts.version`, and the keyset for `changed_since` is `(updated_at, id)`
    [FR-17, FR-30];
  - deletions and disassociations appear in the run event log and the sample deletion audit.
- **Schemas** are versioned through the OpenAPI document. Renaming or removing a field is a breaking
  change and goes in the changelog.

### History kept for reports

These can't be rebuilt later, so they are recorded from day one. [RPT-4]
1. **A run's result as signed off**, kept alongside the live result.
2. **Daily coverage snapshots.** `etc/cron/daily/svs-coverage-snapshot` writes one row per
   technique × state per day.
3. **Verdict history.** `detection_point_verdict_history` is append-only:
   `(alert_id, content_hash, signature_uuid, old_verdict, new_verdict, user_id, changed_at)`. It is
   written in the same transaction as each change, including *Confirm*. The verdicts are the stored
   override values, NULL meaning none: setting one is NULL → tp|fp, clearing it tp|fp → NULL, a
   *Confirm* NULL → tp; a write that changes nothing records nothing.

### Access

[RPT-5]
- **A reporting key is read-only:** an automation user with the `*_read` permissions,
  `alert:read` and `signature:read`.
- **File contents never come out of a reporting endpoint.** Sample, file and email bytes stay behind
  their download permissions.
- **Alert data is scoped as in the GUI.** SVS data is global.

### Documentation

`docs/SVS_API.md` is written with the endpoints. [RPT-6] It holds:
- a data dictionary, in particular the fields whose meaning comes from this design;
- the joins between resources;
- three worked examples, which also run as API tests:
  - per-signature FP rate over 90 days;
  - test pass rate per month;
  - technique coverage over time.

## Changes to ACE outside SVS

Several agreed changes are general-purpose and ship as their own PRs:

| Change | Why | Item |
|---|---|---|
| `archive()` frees derived hardcopies and keeps root-level files in subfolders, **landed** | Two defects: derived bytes were never freed; root files in `files/<dir>/` were deleted | YR-11 |
| Dispositions: config as the single list, classification map, `analyst_selectable`, server-side validation, **landed** | Part 1 | TP-2, TP-3 |
| Prevalence counts only the default queue, **landed** | Consistency with disposition history (PR #587) | ART-10 |
| Detection identity includes the node, **landed** | Part 1 | DP-7 |
| YARA detections on the file, **landed** | Part 1 | DP-4 |
| Alert-router registry, `move_alert_to_queue`, as their own PR (a refactor of `_apply_detection_queue` plus a new primitive), **landed** | Part 3 | ART-15, FR-2 |
| CAS (`saq/cas/`), **landed** | Sample storage, and later every byte store. The shared backend a multi-node site needs for `svs_samples` is the site's to provide | `docs/CAS.md`, FR-1 |
| Correlation-mode submissions to a remote node get an `alerts` row, **landed** | `submit_remote` never calls `ALERT()` and the receiving node only schedules the root, so such a submission is analyzed and lost. Any hunt whose collector submits remotely produces no alert, test or not. Phase 0 | FR-6 |
| `transfer_work_target` carries the work item's `analysis_mode`, **landed** | A `dispositioned` item pulled by another node ran in correlation mode first, which delayed capture. Phase 2 | FR-5 |
| `SIMULATED` alerts are archived after `svs.simulated_days`, never deleted; `SIMULATED` in `stop_analysis_on_dispositions` | Nothing else frees test alerts, and deleting them would orphan their verdicts, labels and attributions | FR-7 |
| Vendored ATT&CK extract (`etc/attack/`) and `bin/update-attack-catalog` | Part 4 | FR-14 |
| `saq/storage` fixes (TLS, 403 vs missing, atomic local writes) and `saq/crypto` fixes, **landed** | Prerequisites for the CAS | F-13, F-18 to F-20 |
| `GET /api/v2/alerts` and `alerts.updated_at` (server-side `ON UPDATE`), **landed** | No alert export API exists; the search listing pages by OFFSET | RPT-2, RPT-3, RPT-7, FR-17 |
| `GET /api/v2/detection-points` and verdict history, **landed** | No detection-point API exists | RPT-2, RPT-4 |
| Saved filters per screen, **landed** | Saved filters for screens other than the manage page; unique key, scratch rows, name registry and query builder all become per screen | MGT-1, FR-18 |
| Alert search excludes the SVS queue by default | Test alerts would dominate "similar alerts" | RPT-7 |
| The hunt completion log line carries structured fields, **landed** | Debugging a missing hunt detection from the site's logs | MGT-9 |

## Data model (sketch)

The final models are written in `saq/database/model.py` and the migration is autogenerated. All
tables are on the main chain.

| Table | Purpose |
|---|---|
| `detection_point_verdicts` | Explicit verdicts (Part 1) |
| `svs_yara_captures` | One row per `(alert, sha256, rule uuid)`, with scan context; each holds its CAS object |
| `svs_sample_retirements` | Retire actions: `(sha256, rule uuid, who, why, when)` |
| `svs_validations`, `svs_validation_results` | A validation request and its per-`(sample, rule)` outcome and category; a request is served from an earlier validation with the same `(repository, base_sha, head_sha, corpus version)` [FR-13] |
| `svs_test_hosts` | Test hosts: `hostname, fqdn, usernames, ips` (Part 3) [FR-15] |
| `svs_catalog_tests` | The ART catalog: guid, repository, technique, name, platforms, commit |
| `svs_runs`, `svs_run_targets` | Runs, their lifecycle timestamps, marker, windows, and targets |
| `svs_attributions` | `(run, alert uuid, detection content_hash, confidence, late, source, actor)`; keyed on the alert uuid because the row is written at `PRE_INSERT`, before the alert has an id [FR-23] |
| `svs_expectations` | `(test guid, signature uuid, state: candidate/expected/rejected, who, when)` |
| `svs_ignores` | `(scope: global/test, test guid?, signature uuid)` |
| `svs_run_results` | Per `(run, signature)`: hit / missing / possibly suppressed / unexpected / ignored |
| `svs_technique_worklist` | Declared-vs-measured flags and their resolution |
| `svs_run_events` | Append-only run event log (Part 5) |
| `svs_coverage_snapshots` | Daily technique × state rows (Part 6) |
| `detection_point_verdict_history` | Append-only verdict changes (Part 6; core) |

`svs_runs` also carries an owner and a reviewer, and `svs_run_results` carries the result as
reviewed next to the live one. Every SVS table has `updated_at`.

## Permissions

| Permission | Grants |
|---|---|
| `svs:run_register` | The launcher's run lifecycle calls |
| `svs:validate` | Requesting a YARA validation (the CI key) |
| `svs:run_read` | Runs and Tests screens, run pages, coverage, and their read APIs [MGT-6] |
| `svs:run_manage` | Ownership, cancel, close, review, candidates, ignores, manual association [MGT-6] |
| `signature:read` (existing) | The Validations and Samples cards, validation reports, sample metadata and their APIs [FR-28] |
| `signature:download` (existing) | Sample bytes [FR-28] |
| `svs:admin` | Retiring and deleting samples, global ignores, the test-host table, configuration |

Plus `cas:purge` and `cas:hold` from the CAS. Each new `svs:*` permission is added to
`saq/permissions/catalog.py` with a seeding migration; the `signature:*` pair already exists and
gates the Signatures area. A reporting key gets the `*_read` permissions, `alert:read` and
`signature:read`.

## Configuration (sketch)

```yaml
disposition_classification:         # logged at WARNING on every start [FR-15]
  FALSE_POSITIVE: fp
  GRAYWARE: tp
  # ... (Part 1 table)
  SIMULATED: tp

cas:
  pools:
    svs_samples:                    # the second pool next to yara_qa (docs/YARA_QA.md) [FR-27]
      backend: local                # enough for one node. A multi-node site redefines this pool
      shared: false                 # with the shared backend it gave yara_qa, and shared: true [FR-1]
      encryption: system
      retention: held

svs:
  queue: svs
  simulated_days: 30                # SIMULATED alerts are archived after this, like FP alerts after fp_days [FR-7]
  runs:
    start_timeout_minutes: 30
    observation_window: {slack_minutes: 30, floor_minutes: 60, ceiling_hours: 72}
    attribution_extra_hours: 24
  log_search_url: null              # e.g. "https://splunk.example/...?q=svs_run={run_uuid}"
  yara:
    repositories: [signatures]      # git_repo_<name> sections SVS may validate
    scan_timeout_seconds: 1800
    max_concurrent_validations: 1   # [FR-13]
  attack_release: "v17"             # names etc/attack/v17.json [FR-14]

service_svs:                        # one instance, on the primary node [FR-13]
  enabled: true

alert_routers:
  - name: svs_marker
    python_module: saq.svs.routing
    python_class: MarkerRouter
    priority: 100                   # ahead of the built-in detection-queue router [FR-2]
```

Every value here is illustrative. The schema rejects unknown keys. Test hosts are rows in
`svs_test_hosts`, not config (Part 3).

## Phases

| Phase | Contents |
|---|---|
| **0: prerequisites** (independent PRs, each useful without SVS). **Landed** in v3.0.122 (PRs #638–#648) | `archive()` fix; disposition clean-up; prevalence default-queue change; `saq/storage` and `saq/crypto` fixes; the CAS with the `svs_samples` pool (the pool itself is defined in phase 2 [FR-29]); `GET /api/v2/alerts` with `alerts.updated_at`; saved filters per screen; the structured hunt completion record; remote-node correlation submissions get an `alerts` row [FR-6]; the alert-router registry and `move_alert_to_queue` [FR-2] |
| **1: labels**. **Landed** (PRs #651–#656) | Detection identity (**must land before any verdict is written**); YARA detections on the file; verdict table, effective verdicts and sources, verdict history; the GUI; the detection-points API |
| **2: YARA capture** | The capture module, with the `transfer_work_target` mode fix [FR-5]; the Samples card in the Signatures hub and its API [FR-28]. A multi-node site provides its shared `svs_samples` backend before enabling capture [FR-1] |
| **3: YARA validation** | API, mirror clones, isolated scanning that compiles the way the production loader does [FR-26], the validation queue and result cache, the report and its actions; the Validations card in the Signatures hub [FR-28]; CI in one signature repo |
| **4: runs** | Registration, the test-host table and admin tab, markers, the SVS marker router, the built-in marker rule shipped as a namespace the yara service loads [FR-25], `SIMULATED` and its retention, SVS statuses, the ART catalog; the Runs and Tests tabs, the run page with learned expectations, ownership, *Close*, event log; the SVS logging contract; the run APIs and the reviewed-result snapshot |
| **5: coverage** | Coverage states, the declared-vs-measured worklist, the ATT&CK release pin with the vendored extract and `bin/update-attack-catalog` [FR-14]; the Coverage and Worklist tabs, daily snapshots and their APIs; `docs/SVS_API.md` complete |

Each phase's PR description quotes the entries below that it makes true, and they go in
`CHANGELOG.md`.

## What changes for analysts

This section is written for the analysts and detection engineers who use ACE. ★ marks a change to
the *meaning* of something people already do; those deserve a conversation, not just a release
note. [X-5]

**★ Your disposition now also grades the detections** (analysts, SOC leads; phase 1).
- Besides closing the alert, the disposition you pick records whether its detections found
  malicious activity. That record is used to test future signature changes.
  - `FALSE_POSITIVE`: none of them did.
  - `GRAYWARE`, `POLICY_VIOLATION` and every kill-chain disposition: all of them did, including on
    alerts where several signatures fired.
  - `IGNORE`, `REVIEWED`, `UNKNOWN`: nothing is recorded.
- Choose `FALSE_POSITIVE` only when there really was no malicious activity. Don't use `REVIEWED`
  or `IGNORE` to avoid the call.

**Six unused dispositions are removed** (SOC leads, admins; phase 0). `AUTHORIZED`, `DATA_CONTROL`,
`INSIDER_DATA_CONTROL`, `INSIDER_DATA_EXFIL`, `APPROVED_BUSINESS` and `APPROVED_PERSONAL` could never
be selected in the GUI. Update any report or script that names them.

**You can grade individual detections** (analysts; phase 1).
- On a real attack where one signature was noise (a generic rule on a harmless logo in a phishing
  email), mark that detection FP.
- *Confirm* marks inherited TPs as checked by a person, and confirmed labels weigh more when
  signature changes are tested.
- If the whole alert was dispositioned wrong, correct the alert's disposition instead. On a
  `FALSE_POSITIVE` alert every detection is FP.

**YARA hits appear on the file** (analysts; phase 1). The fire icon sits on the file that matched,
and the YARA results under it are always shown.

**★ Every YARA pull request gets a validation report** (detection engineers; phase 3).
- The PR is checked against every file analysts have graded. The report lists:
  - regressions (graded-real files that no longer match);
  - new false positives;
  - improvements;
  - scan-time changes;
  - regressions on files graded only by inheritance, listed separately as "check the label
    first".
- It warns and never blocks. CI posts a summary on the PR with a link to ACE.
- The reports and the graded files live under *Signatures*, next to *Yara QA Results*, for anyone
  who can see that area; downloading a file needs the same permission as downloading a QA match.
- Rules without a `uuid` can't be checked.
- An intended regression is retired or relabeled in ACE, so the report stops showing it.

**★ "Seen before" numbers count only the default queue** (analysts; phase 0). Disposition history
already does (ACE 3.0.116); prevalence will too. Observables seen mostly in other queues, including
test alerts, show smaller numbers.

**Alerts from red-team test runs get their own queue and badge** (analysts; phase 4).
- They go to the test queue with the disposition `SIMULATED`. Only ACE sets it, and it can't be
  changed by hand; bulk actions skip those alerts. They can't be reset or re-analyzed either. After
  about 30 days they are archived like false positives: the analysis details go, the alert stays.
- Badges: `TEST` (nothing to do), `TEST?` (nothing unless it looks wrong; one click marks it *not a
  test*), `PARTIAL TEST` (triage the non-test detections as usual), and `MARKER MISMATCH`
  (**treat as suspicious and investigate**).
- An alert you own is never moved. If something was wrongly treated as a test, use *Disassociate
  from run*.

**Test runs have their own screens** (detection engineers and whoever runs the test program;
phase 4).
- *SVS → Runs* lists every run, like the alert manage page, with a *Needs attention* view.
- Each run has a page with its result, alerts, candidates and an event log.
- A test that didn't fire is debugged from ACE's logs in your usual log tool. Every SVS log line
  carries `svs_run`, and the run page shows the search keys, or a link if your site configures one.
- *SVS → Tests* shows every catalog test and how it has fared. It doesn't suggest what to run; that
  stays the team's call.
- Runs have owners, as alerts do.

**Alerts from canceled, failed or discarded runs are closed as `SIMULATED` too** (analysts,
operators; phase 4). A canceled run still claims its alerts, so they don't reach the normal queue
as `MARKER MISMATCH`. Closing a run, by hand or when its attribution window ends, closes its
alerts without learning anything from it: its YARA hits don't become samples, its signatures
don't become expectations, and its detections carry no verdict.

**All alert, detection and test data can be pulled through the API** (anyone who builds reports;
phases 0–5).
- New read endpoints list alerts and detections with their verdicts, and every SVS screen has an
  endpoint behind it. Each takes the same filters as the screen, and *Export* on any list is that
  endpoint.
- ACE doesn't ship fixed reports. `docs/SVS_API.md` explains the data and has worked examples.
- Ask for a read-only reporting key rather than using a personal one.

**Search leaves test alerts out unless you ask for them** (analysts; phase 4). Alert search and
"similar alerts" skip alerts from test runs. The results say how many were skipped, and one toggle
brings them back. [RPT-7]

**Archived false-positive alerts really delete their extracted files** (admins; phase 0). Files
that came with the alert are kept. The GUI already couldn't open extracted files after archive.

**★ ATT&CK coverage is measured first, declared second** (detection engineers, SOC leads; phase 5).
- Coverage comes from test runs wherever a test exists.
- Existing `mitre_attack` / `mitre:` tags count as manual mappings until a test measures the
  signature. Then they go on a worklist: confirm, keep, or remove.
- For signatures no test can exercise, the tag *is* the mapping, so keep those accurate.

**SVS only knows about alerts created after it is deployed** (SOC leads, detection engineers).
Grading, samples and attribution start empty; older alerts are not graded retroactively.

**A "missing" detection in a test run doesn't say why** (detection engineers, SOC leads; phase 4).
SVS can't tell missing log data from a signature that didn't match. It does flag when a hunt was
probably suppressed.

## Related

- **Hunt validation.** `lib/signature_validator` (`validate-hunt` → `POST /api/hunt/validate`)
  compiles and ad-hoc-executes a hunt from a repository's CI. SVS's YARA validation follows the same
  direction (the repository's CI calls ACE), but the two are separate systems. [D-11]
- **Deployment.** SVS runs against production ACE, which holds the samples and sees the test
  hosts' telemetry. Signature repository CI therefore needs network reach to it. [D-12]

## Deferred

- The dynamic case of YARA regression: re-deriving a sample with the current tool before scanning.
  [YR-10]
- Preventing hunt suppression for test targets, with the revisit trigger above. [ART-8]
- Moving other byte stores onto the CAS (`docs/CAS.md`, Consumers). [CAS-8]
- Per-company coverage. [COV-1]
