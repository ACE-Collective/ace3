# Signature Validation System (SVS)

> **Status: agreed design, not implemented (2026-09-27).** This is the design of record.
> `docs/SVS_INITIAL.md` is the original brief. `docs/SVS_REVIEW.md` is the decision record: every
> bracketed ID in this document (`[DP-2]`, `[D-6]`) points at the item there that records the
> reasoning and the alternatives that were rejected. SVS stores its samples in the CAS
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
    FP   (inherited)            if class(alert.disposition) == fp         # overrides are masked
    override (explicit)         if an override row exists                 # tp alerts only
    TP   (inherited_single)     if the alert has one signature
    TP   (inherited_multi)      otherwise
```

- **On an FP alert every verdict is FP.** If the alert itself was wrong, the fix is to correct its
  disposition (the review path), not to override a detection. [DP-3]
- **Overrides survive disposition changes.** A TP→FP→TP correction restores them.
- **On a TP alert every detection inherits TP.** `inherited_multi` marks inheritance on an alert
  where several signatures fired: 37% of TP alerts with a YARA hit, in production data from
  September 2026. It is a weaker label, reported separately (Part 2). [DP-2]
- **Any detection of any signature family can be labeled.** Only YARA consumes labels for
  regression, but per-signature TP/FP counts are useful everywhere. [DP-6]

**Storage.** `detection_point_verdicts(alert_id, content_hash, signature_uuid, verdict, user_id,
set_at)`, unique on `(alert_id, content_hash)`. The `detection_points` rows themselves are deleted
and reinserted as the tree changes, so they can't hold the verdict. [DP-1]

**Detection identity** (prerequisite, before the first verdict is written). Today
`content_hash = sha256(signature_uuid, description, details)`, which ignores the node the detection
sits on. Detections whose description doesn't name their object therefore collapse into one row,
and would share one verdict. The node's identity is folded into the hash and stored as a column:
- observable nodes: `('observable', type, sha256(value))`;
- the root: `('root')`;
- analysis nodes: `('analysis', module path, parent observable type + value hash)`.

The formula is pinned by a unit test and never changes afterwards, because a changed formula
orphans every override. [DP-7]

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
  disposition"* and offers no TP option. [DP-3]
- **Manage page.** A filter for *has unlabeled detections*.

## Part 2 — YARA static regression

### Capture

A module, `svs_yara_sample_capture`, runs in `analysis_mode_dispositioned`. Both disposition
writers already requeue into that mode, and today it runs nothing. The module reads
`alerts.disposition` from the database, because roots don't carry it. [YR-5]

- **What gets captured:** every YARA-matched file on an alert whose disposition classifies tp or
  fp, whatever the per-detection verdict. A verdict set later needs only a database write, never
  the bytes again.
- **Idempotent** on `(alert, sha256, rule uuid)`.
- **Missing data** is logged at ERROR and counted per rule, and the count is shown on the SVS page.
- **Capture is the only chance.** Once the phase-0 archive fix lands [YR-11], `archive()` removes an
  FP alert's derived files after `fp_days`. IGNORE alerts are deleted after a day.

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
`signature_dir`. [YR-9]
- **Compile errors are results.** For example: "namespace X failed to compile: all N rules in it
  are dropped".
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
- **Delete sample.** A CAS purge plus rows, audited, for legal or privacy requests.

Nothing changes automatically when a PR merges. An accepted regression keeps showing as *already
broken on base* until it is retired or relabeled.

## Part 3 — Test execution (Atomic Red Team)

### Test hosts and registration

**Test hosts** are configured under `svs.test_hosts` as a list of `{hostname, fqdn?, usernames?, ips?}`.
Matching normalizes case, short name vs FQDN, and `DOMAIN\user` / `user@domain` / `user`. [ART-9]

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
| (analyst) | Ended → **Reviewed** | Sign-off; Coverage counts only Reviewed runs. |

**Registration against a non-test host,** or an unlisted user on a host that lists `usernames`, is
**refused with 403**. It also creates an alert in the default queue through the normal submission
path, with a built-in signature and the caller's identity as observables. [ART-9]

**Windows.** The *observation window* comes from the test's config if it sets one. Otherwise it is
computed as the maximum, over the test's expected signatures, of their worst-case latency (for
hunts, `frequency + time_range + offset`), plus slack, within a floor and a ceiling. The
*attribution window* is longer. Alerts that arrive after *Ended* but inside it are attributed, marked
*late*, and the result is recomputed. [ART-3, ART-2]

### Markers

- **Format:** `svs-` followed by 26 base32 characters (128 random bits), matchable by a regex.
- **Not secret.** Once a test runs, the marker is in telemetry. It is valid only in context.
- **A marker attributes only when it agrees with its run:** it matches a registered run, *and* the
  alert involves one of that run's targets, *and* the event falls inside the run's attribution
  window. [ART-4]
- **A marker that doesn't agree never routes the alert.** That covers unknown markers, well-formed
  markers not in the database, markers from another host, and markers outside the window. The
  alert stays in its normal queue, is tagged `svs:marker_mismatch`, and gets a detection from a
  built-in signature. A marker on a production host is exactly what an analyst should see.
- **Without a marker**, attribution falls back to target plus window, recorded with confidence
  `context`. Context-only attribution also routes. [ART-5]

The launcher's contract is to put the marker where the technique's process telemetry will show it:
an input argument, a file name, or a trailing shell comment on the executor command.

### Attribution and routing

Attribution runs inside the engine, through a **core alert-router registry**. This is a change to
ACE itself, not only to SVS. [D-13, ART-15]

- **`AlertRouter.route(root, stage) -> RouteDecision | None`**, where a decision is
  `{queue, reason, router}`.
  - Routers run in priority order, and the first decision wins.
  - An explicitly set `root.queue` (a submission or hunt override) is never overridden.
  - Routers are registered as built-ins plus `alert_routers:` config entries
    (`python_module`/`python_class`), in the same pattern as `hunter.correlation.command_types`.
  - The registry is **open to integrations from day one**. It is documented in
    `docs/INTEGRATIONS.md`, and the example integration ships a trivial router.
- **Stage `PRE_INSERT`**, inside `ALERT()`, the one function every alert insert goes through,
  before `Alert.create_from_root_analysis` copies `root.queue`.
  - Engine-converted alerts arrive here fully analyzed, so they never appear in the wrong queue.
- **Stage `POST_ANALYSIS`**, in the orchestrator after each analysis pass.
  - It covers alerts inserted at submission time (hunts, API) whose marker appears only after
    analysis.
  - A decision there moves the existing alert through `move_alert_to_queue(alert, queue, reason,
    actor)`. That new core primitive updates the column and `root.queue`, touches the alert,
    refreshes the search payload, writes an audit line, and records the previous queue.
- **An alert that is not `OPEN`, or that an analyst owns, is never moved.** It gets its SVS badge
  instead.
- **`_apply_detection_queue` becomes the first built-in router**, with its all-or-nothing rule
  unchanged.

**Where the SVS router looks:**

| Scan point | Covers |
|---|---|
| Observable values and file names, and `root.details` (at both stages) | Hunt raw events, API details, command lines, URLs |
| Each new analysis's `details` and new observables, scanned by an executor hook right after the module returns | Decoded or deobfuscated output |
| File contents, through a built-in `no_alert` YARA rule for the marker format, whose match strings land in `YaraScanResults.details` | Markers inside dropped scripts and documents |

Markers found are resolved against runs through a short-lived per-process cache. Attribution rows
`(run, alert, detection content_hash, confidence, late, source)` are written at the same time.

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
  a run is *Reviewed*, on the run's fully attributed alerts. [D-16]
  - It is `analyst_selectable: false`: not in any modal, and rejected server-side.
  - A `SIMULATED` alert's disposition can't be changed by hand. The modals show *"Part of test run
    R. To treat this as a real alert, use Disassociate from run"*. Bulk actions skip such alerts
    and report them.
- **Ignored detections are benign.** A run's ignored detections (launcher noise) get FP overrides
  when the run is dispositioned.
- **YARA TP samples come for free.** Because `SIMULATED` is tp, YARA hits in reviewed runs become
  TP samples through the normal capture.
- **Test alerts stay out of observable history and prevalence.** Both count only the `default`
  queue. Disposition history already did (PR #587); prevalence is changed to match.
- **Routed alerts are tagged `svs_test`.**

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

## Changes to ACE outside SVS

Several agreed changes are general-purpose and ship as their own PRs:

| Change | Why | Item |
|---|---|---|
| `archive()` frees derived hardcopies and keeps root-level files in subfolders | Two defects: derived bytes were never freed; root files in `files/<dir>/` were deleted | YR-11 |
| Dispositions: config as the single list, classification map, `analyst_selectable`, server-side validation | Part 1 | TP-2, TP-3 |
| Prevalence counts only the default queue | Consistency with disposition history (PR #587) | ART-10 |
| Detection identity includes the node | Part 1 | DP-7 |
| YARA detections on the file | Part 1 | DP-4 |
| Alert-router registry, `move_alert_to_queue` | Part 3 | ART-15 |
| CAS (`saq/cas/`) | Sample storage, and later every byte store | `docs/CAS.md` |
| `saq/storage` fixes (TLS, 403 vs missing, atomic local writes) and `saq/crypto` fixes | Prerequisites for the CAS | F-13, F-18 to F-20 |

## Data model (sketch)

The final models are written in `saq/database/model.py` and the migration is autogenerated. All
tables are on the main chain.

| Table | Purpose |
|---|---|
| `detection_point_verdicts` | Explicit verdicts (Part 1) |
| `svs_yara_captures` | One row per `(alert, sha256, rule uuid)`, with scan context; each holds its CAS object |
| `svs_sample_retirements` | Retire actions: `(sha256, rule uuid, who, why, when)` |
| `svs_validations`, `svs_validation_results` | A validation request and its per-`(sample, rule)` outcome and category |
| `svs_catalog_tests` | The ART catalog: guid, repository, technique, name, platforms, commit |
| `svs_runs`, `svs_run_targets` | Runs, their lifecycle timestamps, marker, windows, and targets |
| `svs_attributions` | `(run, alert, detection content_hash, confidence, late, source, actor)` |
| `svs_expectations` | `(test guid, signature uuid, state: candidate/expected/rejected, who, when)` |
| `svs_ignores` | `(scope: global/test, test guid?, signature uuid)` |
| `svs_run_results` | Per `(run, signature)`: hit / missing / possibly suppressed / unexpected / ignored |
| `svs_technique_worklist` | Declared-vs-measured flags and their resolution |

## Permissions

`svs:run_register`, `svs:validate`, `svs:sample_read`, `svs:sample_download`, `svs:admin`; plus
`cas:purge` and `cas:hold` from the CAS. Each is added to `saq/permissions/catalog.py` with a
seeding migration.

## Configuration (sketch)

```yaml
disposition_classification:
  FALSE_POSITIVE: fp
  GRAYWARE: tp
  # ... (Part 1 table)
  SIMULATED: tp

svs:
  queue: svs
  test_hosts:
    - hostname: lab-win10-01
      fqdn: lab-win10-01.lab.example
      usernames: ['LAB\svs-runner']
  runs:
    start_timeout_minutes: 30
    observation_window: {slack_minutes: 30, floor_minutes: 60, ceiling_hours: 72}
    attribution_extra_hours: 24
  yara:
    repositories: [signatures]      # git_repo_<name> sections SVS may validate
    scan_timeout_seconds: 1800
  attack_release: "v17"

alert_routers:
  - name: svs_marker
    python_module: saq.svs.routing
    python_class: MarkerRouter
```

Every value here is illustrative. The schema rejects unknown keys.

## Phases

| Phase | Contents |
|---|---|
| **0: prerequisites** (independent PRs, each useful without SVS) | `archive()` fix; disposition clean-up; prevalence default-queue change; `saq/storage` and `saq/crypto` fixes; the CAS with the `svs_samples` pool |
| **1: labels** | Detection identity (**must land before any verdict is written**); YARA detections on the file; verdict table, effective verdicts and sources; the GUI |
| **2: YARA capture** | The capture module and the sample browser |
| **3: YARA validation** | API, mirror clones, isolated scanning, the report and its actions; CI in one signature repo |
| **4: runs** | Registration, test hosts, markers, the alert-router registry and `move_alert_to_queue`, `SIMULATED`, SVS statuses, the run review with learned expectations, the ART catalog |
| **5: coverage** | Coverage states, the declared-vs-measured worklist, the ATT&CK release pin |

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
- Rules without a `uuid` can't be checked.
- An intended regression is retired or relabeled in ACE, so the report stops showing it.

**★ "Seen before" numbers count only the default queue** (analysts; phase 0). Disposition history
already does (ACE 3.0.116); prevalence will too. Observables seen mostly in other queues, including
test alerts, show smaller numbers.

**Alerts from red-team test runs get their own queue and badge** (analysts; phase 4).
- They go to the test queue with the disposition `SIMULATED`. Only ACE sets it, and it can't be
  changed by hand; bulk actions skip those alerts.
- Badges: `TEST` (nothing to do), `TEST?` (nothing unless it looks wrong; one click marks it *not a
  test*), `PARTIAL TEST` (triage the non-test detections as usual), and `MARKER MISMATCH`
  (**treat as suspicious and investigate**).
- An alert you own is never moved. If something was wrongly treated as a test, use *Disassociate
  from run*.

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
