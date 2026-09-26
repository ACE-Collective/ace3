# SVS Design Review

A working review of `docs/SVS_INITIAL.md`. We both edit this file, and each revision is committed so
`git diff` shows what changed between rounds.

## How to use this document

- Every discussion item has a **stable ID** (`DP-3`, `YR-2`, ...). IDs are never renumbered or
  reused. A withdrawn item stays in place and is marked `WITHDRAWN`.
- Each item ends with a **Discussion** block. Reply inline under the item's `> **Response:**`
  line. Later rounds add `> **Round N (reviewer/author):**` lines under it rather than
  rewriting earlier ones, so the history of the argument stays readable in the file itself.
- **Status** values:
  - `OPEN` means it needs an answer or a decision.
  - `PROPOSED` means a concrete recommendation is on the table and is waiting for accept or reject.
  - `AGREED` means it is settled. Copy the outcome into the *Design Decisions* list in `SVS_INITIAL.md`.
  - `DEFERRED` means it is real but not needed for the first version.
  - `WITHDRAWN` means it was wrong or overtaken by events.
- **Blocking** means the item has to be settled before implementation of that subsystem can
  start. Non-blocking items can be settled during implementation.
- Code references are to this checkout (`jd/svs` at `ec3cab18`, 2026-09-26). §8 collects the code
  facts that the items rely on.

---

## 1. Status board

| ID | Topic | Blocking | Status |
|---|---|---|---|
| **Foundations** | | | |
| TP-1 | What "True Positive" means for a signature | yes | OPEN |
| TP-2 | TP/FP classification is three-valued; reuse existing config | yes | PROPOSED |
| DP-1 | Store verdict overrides, derive effective verdicts | yes | PROPOSED |
| DP-2 | "Single detection point" should be "single signature" | yes | PROPOSED |
| DP-3 | Behavior when the alert disposition changes | yes | PROPOSED |
| DP-4 | YARA detection points don't say which file matched | yes | PROPOSED |
| DP-5 | GUI for detection-point verdicts | no | PROPOSED |
| DP-6 | Verdicts for all signature families, not only YARA | no | OPEN |
| **YARA static regression** | | | |
| YR-1 | Define "difference" and "baseline" | yes | PROPOSED |
| YR-2 | Scan the whole corpus with the whole ruleset | yes | PROPOSED |
| YR-3 | Trigger, transport and where the report goes | yes | PROPOSED |
| YR-4 | What a sample record must capture | yes | PROPOSED |
| YR-5 | When capture happens | yes | PROPOSED |
| YR-6 | Label conflicts across alerts | no | PROPOSED |
| YR-7 | Rules without a `uuid` | no | PROPOSED |
| YR-8 | Sample store: CAS layer, retention, access | yes | OPEN |
| YR-9 | Isolation of PR rule compilation | no | PROPOSED |
| YR-10 | The dynamic case (`d(t(Y))`) in regression | no | OPEN |
| **Test execution (Atomic Red Team)** | | | |
| ART-1 | Terminology: *test* vs *run* | no | PROPOSED |
| ART-2 | Registration API and lifecycle transitions | yes | PROPOSED |
| ART-3 | Observation window length | no | PROPOSED |
| ART-4 | Marker threat model | yes | PROPOSED |
| ART-5 | Where ACE looks for the marker | yes | OPEN |
| ART-6 | When attribution happens and how the queue moves | yes | PROPOSED |
| ART-7 | Alerts that mix test and non-test detections | yes | PROPOSED |
| ART-8 | Hunt suppression / dedup / group_by swallow test detections | no | OPEN |
| ART-9 | Test host definition and unregistered-host handling | no | PROPOSED |
| ART-10 | What happens to test alerts downstream | no | OPEN |
| ART-11 | Technique-derived expectations are too broad | yes | PROPOSED |
| ART-12 | Why ACE holds the ART repos, and what it parses | no | PROPOSED |
| ART-13 | Launcher noise vs per-test ignores; manual (re)association | no | PROPOSED |
| **Coverage** | | | |
| COV-1 | The Coverage subsystem has no section yet | yes | OPEN |
| COV-2 | Goal 2 (telemetry exists) has no mechanism | yes | OPEN |
| **Cross-cutting** | | | |
| X-1 | Placement in the codebase and permissions | no | PROPOSED |
| X-2 | Which ACE instance owns SVS | no | OPEN |
| X-3 | Name collision with `lib/signature_validator` | no | OPEN |
| X-4 | Phasing | no | PROPOSED |

---

## 2. My reading of the design (correct me if this is wrong)

1. SVS adds **per-detection-point dispositions**. They are inherited from the alert where that is
   unambiguous and set by the analyst (optionally) where it isn't. They exist to label training
   and regression data.
2. **Static regression is YARA-only.** Files that YARA rules matched are captured into a sample
   store. They are labeled TP or FP from detection-point dispositions and re-scanned when a YARA PR
   is opened. Analysts review differences and adjust a baseline.
3. **Test execution is launcher-driven.** An external, site-specific launcher runs Atomic Red Team
   tests. It registers each execution with ACE and receives a random marker, which it injects into
   the test. ACE attributes the resulting alerts to the registration, moves them to a test queue
   and compares what fired to what was expected.
4. **Coverage** combines techniques, signatures and test results. It is named as a subsystem but
   not yet described.
5. Explicitly out of scope:
   - running tests or preparing hosts;
   - real incidents on test hosts;
   - True Negative samples;
   - regression testing for non-YARA signatures.

---

## 3. Foundations: TP/FP and detection-point dispositions

### TP-1 — What "True Positive" means for a signature  `OPEN` · blocking

The design takes TP/FP from the alert disposition. An alert disposition answers *"was this
activity malicious?"*. Regression testing needs the answer to a different question: *"did this
signature match what it was written to match?"* The two diverge often:

| Situation | Alert disposition | Did the signature do its job? |
|---|---|---|
| Rule for "encoded PowerShell" fires on an admin's encoded script | `FALSE_POSITIVE` (or `AUTHORIZED`) | **Yes.** It matched exactly what it describes. |
| Rule for "Emotet maldoc" fires on a Qakbot maldoc | `DELIVERY` | **No.** It matched the wrong family, so the match was accidental. |
| Pentest activity | `AUTHORIZED` (in `benign_dispositions`) | **Yes.** |

The consequences for regression (with the diff model in YR-1) are uneven:
- **FP samples are low-harm.** A modified rule that stops matching one is an improvement. One that
  keeps matching is neutral.
- **TP samples are where mislabeling hurts.** A "TP" sample that the rule only matched by accident
  pins the rule's accident as required behavior.

**Question:** Which meaning does SVS use? I recommend stating it outright in `SVS_INITIAL.md`:
*"TP means the signature matched the thing it describes. FP means it matched something it should
not."* The disposition mapping (TP-2) and detection-point overrides (DP-1) are then the tools for
approximating that. The consequence is that `FALSE_POSITIVE` alerts usually are signature FPs, but
`AUTHORIZED` should map to TP.

> **Response:**

### TP-2 — Classification is three-valued; reuse the existing config  `PROPOSED` · blocking

The design says a config setting classifies each disposition as TP or FP. Some dispositions are
neither: `OPEN`, `IGNORE`, `UNKNOWN` and `REVIEWED` carry no verdict about the signature. The
classification therefore needs a third value, **unclassified**. Any disposition not listed is
unclassified and is ignored by SVS, exactly like a NULL detection-point verdict.

ACE already has half of this config, unused:
- `benign_dispositions` and `malicious_dispositions` are at `etc/saq.default.yaml` (the
  `benign_dispositions:` block) and in `saq/configuration/schema.py:708-713`.
- `saq/disposition.py:30-40` builds them.
- Nothing outside one test reads them.

**Proposal:** Replace both lists with one map, and give `saq/disposition.py` a single
`get_disposition_class(disposition) -> TP | FP | None`:

```yaml
disposition_classification:   # absent = unclassified
  FALSE_POSITIVE: fp
  AUTHORIZED: tp          # see TP-1
  GRAYWARE: tp
  POLICY_VIOLATION: tp
  RECONNAISSANCE: tp
  # ... remaining kill-chain dispositions: tp
```

This needs a fix first: config and constants disagree about which dispositions exist (§8, F-3).
`AUTHORIZED` and `DATA_CONTROL` are configured but **silently dropped** because they are not in
`saq/constants.py`. The set_disposition view also validates against the constants rather than the
config. A classification map keyed by disposition name has to be validated against the
*effective* disposition list at startup, or a typo becomes a silent "unclassified".

> **Response:**

### DP-1 — Store overrides, derive effective verdicts  `PROPOSED` · blocking

The design describes each detection point's disposition as a value that is *assigned* and then
*re-assigned* when the alert disposition changes. Storing the derived value means a disposition
change or a config change has to rewrite every row, and the rewrite is easy to get wrong
(DP-3). There is also a durability problem: **`detection_points` rows are not stable.**
- `sync_detection_points` (`saq/database/util/index.py:331-385`) DELETEs every row whose
  `content_hash` is no longer in the tree and reinserts it if it comes back. The row `id` changes
  whenever that happens.
- Re-analysis, clicker re-runs, `ace alerts reset` and "mark observable malicious" all rebuild the
  rows.
- A disposition column on `detection_points` would be lost the first time any of those runs.

**Proposal:**
- A separate table holds **only what an analyst explicitly said**:
  `detection_point_verdicts(alert_id, content_hash, signature_uuid, verdict ∈ {tp, fp}, user_id, set_at)`,
  unique on `(alert_id, content_hash)`. `(alert_id, content_hash)` is the one durable identity a
  detection has today (§8, F-1).
- The **effective verdict** is computed, not stored:

  ```
  effective(dp) =
      FP        if class(alert.disposition) == FP          # design rule: FP alert ⇒ all FP
      override  if an override row exists
      TP        if class(alert.disposition) == TP and the alert has one signature (DP-2)
      NULL      otherwise
  ```

- Because nothing derived is stored, a disposition change, a review correction or a
  classification-config edit needs no fan-out write, and the result is correct everywhere
  immediately.
- One side effect is still needed at disposition time: capturing sample bytes before they can be
  archived (YR-5). That is capture, not labeling.

> **Response:**

### DP-2 — "Single detection point" should be "single signature"  `PROPOSED` · blocking

The design inherits the alert verdict only when the alert has a **single detection point**. The
most common YARA case breaks that rule:
- One rule matching an email and its three attachments produces **four** detection points, one
  per file, all with the same `signature_uuid` (`saq/modules/file_analysis/yara.py:501-507`).
- Under the current wording that alert's detections all stay NULL unless an analyst takes the
  extra step.
- A second, independent source of NULLs: an alert where a hunt fired *and* a YARA rule matched an
  attachment. That alert has two detection points, so the YARA sample stays unlabeled.

**Proposal:** Inherit when every detection point on the alert shares **one `signature_uuid`**. The
analyst can still override a single file's detection (for example, one of the four files was a
benign logo).

**Measure before deciding.** How many alerts end up NULL under each rule decides whether the
optional step is a rare nicety or the main labeling path. Run against production:

```sql
SELECT n_sigs, n_dps_bucket, COUNT(*) AS alerts FROM (
  SELECT a.id,
         COUNT(DISTINCT dp.signature_uuid) AS n_sigs,
         LEAST(COUNT(*), 5)                AS n_dps_bucket
  FROM alerts a JOIN detection_points dp ON dp.alert_id = a.id
  WHERE a.disposition NOT IN ('OPEN', 'IGNORE', 'UNKNOWN')
  GROUP BY a.id) t
GROUP BY n_sigs, n_dps_bucket ORDER BY n_sigs, n_dps_bucket;
```

> **Response:**

### DP-3 — When the alert disposition changes  `PROPOSED` · blocking

"The same logic is applied again" needs three precise rules. Under DP-1 they are:

1. **An alert that moves to FP masks overrides but does not delete them.** A TP→FP→TP round-trip
   (a common correction) restores the analyst's per-detection work.
2. **An alert that moves to an unclassified disposition** (for example `IGNORE`) makes every
   effective verdict NULL. Overrides are kept but inert.
3. **Both disposition writers are covered automatically.** Verdicts are derived at read time, so
   this holds for `set_dispositions()` and for `set_disposition_reviews()` (the INCORRECT
   correction path, `saq/database/util/alert.py:211-341`). It also works even though
   `set_dispositions()` **does not requeue** an alert set to `IGNORE` (`alert.py:174-190`).

**Open question inside this item:** can an analyst mark a detection **TP on an FP alert**? The
design says no. TP-1 is the case for yes: the rule matched correctly and the activity was benign.
If TP-1 lands on the "signature did its job" meaning, I would allow it.

> **Response:**

### DP-4 — YARA detection points don't say which file matched  `PROPOSED` · blocking

Two facts get in the way of labeling YARA samples:
- A YARA detection point sits on the **`yara_rule` observable**, not on the file. That observable
  is one shared node per rule name, deduplicated across the whole root (`yara.py:440`, `:503`).
- The only link from the detection to the file is the description string
  `"{file_path} matched yara rule X"`. The detection has no `details`.

So "the sample this detection-point verdict labels" can only be recovered by parsing a description
or by walking every file's `YaraScanResults` analysis and matching rule names. Neither is
something to build a labeled corpus on.

**Proposal:** The YARA module sets structured `details` on the detection point:
`{"sha256", "file_observable_uuid", "file_path", "rule", "namespace"}`.
- This changes `content_hash` for **newly analyzed** alerts only. Existing alerts pick it up only
  if re-analyzed, and then their rows are replaced once.
- The benefit: a detection-point verdict row (DP-1) names exactly one (file sha256, rule uuid)
  pair, which is the unit a regression sample is labeled with (YR-6).

This also shows up in the GUI. Every surface that shows a detection reads the in-memory tree
(`alert.html:449-454`, the Detection Chains card). A chain that starts at a shared `yara_rule` node
is ambiguous whenever the rule matched more than one file.

> **Response:**

### DP-5 — GUI for detection-point verdicts  `PROPOSED`

This fills the "we need to decide how this is going to work in the GUI" note.

- **Disposition modal** (`app/templates/base.html:276-325`):
  - Show a collapsed **"Detection verdicts (optional)"** section, only when the chosen disposition
    classifies as TP and the alert has more than one signature.
  - List one row per signature, expandable to one row per file for YARA. Each row has
    `TP / FP / leave unset` and defaults to *unset*.
  - Submitting without opening the section changes nothing.
- **Bulk disposition from the manage page:** no verdict step. Verdicts can be set later on each
  alert.
- **Alert page:** the detection area gets a verdict chip per detection, editable at any time. The
  chip shows *inherited* vs *explicit* so an analyst can see why a verdict is what it is.
  - The Detection Chains card (`app/templates/analysis/detection_chains.html`) is the natural
    home. It already groups by detection.
- **Manage page:** a filter "has unlabeled detections". This is the backlog view for anyone
  curating the corpus.

> **Response:**

### DP-6 — Verdicts for all signature families, not only YARA  `OPEN`

Detection-point verdicts cost the same for any signature. Only YARA consumes them for regression,
but a per-signature TP/FP count over time (the FP rate of each hunt) is useful on its own, and
it needs nothing extra once DP-1 exists.

**Question:** Should the GUI offer verdicts on every detection, or only YARA ones? I recommend every
detection. It is simpler to explain ("every detection can be labeled"), and it gives Coverage
(COV-1) a quality signal.

> **Response:**

---

## 4. YARA static regression

### YR-1 — Define "difference" and "baseline"  `PROPOSED` · blocking

"Reports any differences" and "the analyst is then able to modify the baseline" need a definition
of what is compared with what. Comparing a PR's rule against the *historical* match (what fired
when the alert was created) is misleading, because the rule on `main` has usually changed since.
The PR would be blamed for older edits.

**Proposal:** Every sample has one **label** (from verdicts) and gets two **observations**: the
result of scanning it with the **base** ruleset and with the **head** ruleset. A difference exists
only when base ≠ head. The label then says whether the change is good or bad:

| Label | base | head | Report category |
|---|---|---|---|
| TP | match | **miss** | **Regression**: fails the check |
| TP | miss | match | Recovered |
| TP | miss | miss | **Already broken on base**: shown separately, doesn't fail the PR |
| FP | match | miss | Improvement |
| FP | miss | **match** | **New false positive**: fails the check |
| FP | match | match | Known FP, still matching: informational, counted |
| any | *same as head* | *same as base* | No change: not listed |
| none (NULL) | *differs from head* | *differs from base* | Unlabeled change: listed, never fails |

- Under this model, **"the baseline" is the set of labels.** The historical match is kept for
  audit only.
- "Modify the baseline" becomes a small set of explicit analyst actions on a sample:
  - **relabel** (TP↔FP). This writes a detection-point verdict override, so it has the same source
    of truth as DP-1.
  - **retire** for one rule. The sample is no longer expected to match this rule, for example
    because the rule's scope was deliberately narrowed. Retirement is recorded with who/why and
    shown in later reports.
  - **delete sample.** This removes bytes and rows, for legal or privacy requests.
- Nothing about the baseline changes automatically when a PR merges. A merged PR that was reported
  as a regression keeps showing the same samples as *already broken on base*. That nags until
  someone retires or relabels them, which I think is the right amount of friction.

> **Response:**

### YR-2 — Scan the whole corpus with the whole ruleset  `PROPOSED` · blocking

The design runs *modified* rules against *their own* recorded samples. That misses three things:

1. **New false positives on other rules' samples.** A loosened rule is most likely to start
   matching benign files that some *other* rule was labeled FP on, or TP files of a different
   family. Only a rule's own samples are checked today, so this is invisible.
2. **New rules.** They have no samples of their own, so they get no check at all, and they are the
   riskiest change.
3. **Indirect changes.** Several effects never show up in a rule's own `content_hash` (§8, F-8):
   - an edit to a `private` rule or another rule a condition references;
   - an `include`;
   - a duplicate rule name that makes the **whole namespace fail to compile** (`yara_scanner`
     compiles each namespace as one unit and drops all of it on error).

   Changed-rule detection by `(uuid, content_hash)` can't see any of these.

**Proposal:** Compile the complete base ruleset and the complete head ruleset. Scan every sample
with both, then diff per `(sample, rule uuid)`.
- "Which rules changed" becomes a **report filter and heading**, not the thing that decides what
  gets scanned.
- Samples are labeled per `(sha256, rule uuid)` (YR-6). A match by rule B on a sample labeled for
  rule A is reported as *new match on a labeled sample*, which is exactly case 1.
- Cost: yara-python scans tens of MB/s per core, so a corpus of tens of thousands of files is
  minutes on one worker, twice. A cap (YR-8) keeps that bounded. If cost ever bites, restrict the
  head scan to namespaces whose files changed. That is still correct for cases 2 and 3, because
  namespaces are the compile unit.

> **Response:**

### YR-3 — Trigger, transport and where the report goes  `PROPOSED` · blocking

**Proposal:** The signature repo's CI calls ACE; ACE never talks to the forge. This is the same
direction as `validate-hunt` → `POST /api/hunt/validate` today.

1. CI tars the **base** and **head** YARA trees from its own checkout and POSTs them to
   `POST /api/v2/svs/yara/validations` (new, `aceapi_v2/svs/`, permission `svs:validate`, via a
   user-owned scoped API key). The response is a validation id.
   - Uploading both trees means ACE needs no repo credentials, fork PRs work, and "base" is exactly
     the PR's base rather than whatever production happens to have pulled.
2. ACE runs the scan asynchronously in the SVS service (YR-9). CI polls
   `GET /api/v2/svs/yara/validations/{id}`.
3. The response carries **counts and rule names/uuids only**, which CI turns into a PR check and
   comment. It also carries a link to the full report in the ACE GUI.
   - **Sample content, file names and alert links never leave ACE.** They are customer data and
     live malware.
4. The analyst review and the baseline actions (YR-1) happen in the ACE GUI.

**Question:** Should a *regression* or *new FP* fail the PR check (blocking merge), or only warn?
I suggest failing, with an override path through the retire/relabel actions: re-running the check
after them makes it pass.

> **Response:**

### YR-4 — What a sample record must capture  `PROPOSED` · blocking

"All data that would be required to re-scan the file" is more than the bytes. The YARA result
depends on:
- the **file's path**: the `filename`, `filepath` and `extension` externals, plus the `file_name`,
  `full_path` and `file_ext` meta filters;
- the file's **`yara_meta:` directives**, which become `meta_tags` and are put there by upstream
  analysis modules;
- its **mime type** (`mime_type` meta filter, computed by `file -b --mime-type` on the bytes).

See §8, F-7. A re-scan of a bare blob will "regress" every rule that uses those filters.

**Proposal:** The sample record captures:

| Field | Why |
|---|---|
| `sha256` (blob key) | Content identity and dedup. |
| `file_path` (relative, as in the alert) | Rebuilds the path externals and filters on replay. |
| `yara_meta_tags` | Rebuilds `meta_tags`. |
| `rule uuid`, `rule name`, `namespace` | What it was labeled for. |
| `signature_version`, rule `content_hash` at capture | Audit only (YR-1). |
| the original match record (strings/offsets) | Audit, and "why did this match" in the report. |
| `alert uuid`, `file observable uuid` | Provenance; label derivation (DP-1). |
| yara-python / yara_scanner versions | Explains library-driven differences. |

Replay materializes the blob at `<tmp>/files/<file_path>` so the path externals match. One known
gap: during analysis `full_path` sees `<storage_dir>/files/<file_path>`, which contains the alert's
uuid. Any rule that filters on that prefix can't be replayed faithfully. That should be rare, but
the report should flag rules that use `full_path`.

> **Response:**

### YR-5 — When capture happens  `PROPOSED` · blocking

The file bytes and the match JSON have hard deadlines (§8, F-5):
- **FP alerts:** `archive()` after 30 days wipes the YARA `scan_results` and deletes derived files'
  `files/` entries. The bytes survive only by accident, in `hardcopies/`, without their names.
- **IGNORE alerts:** deleted entirely after **1 day**.
- **TP alerts:** never archived.

**Proposal:**
- **Trigger:** A new module, `svs_yara_sample_capture`, runs in `analysis_mode_dispositioned`.
  That mode is already requeued by both disposition writers and currently runs **nothing** (§8,
  F-4). The module reads `alerts.disposition` from the DB, because roots don't carry it.
- **What gets captured:** Capture **every YARA-matched file on any alert whose disposition
  classifies TP or FP**, regardless of the per-detection verdict. The design's "come back later
  and assign dispositions" then needs only a DB write, never the bytes again. By then the bytes may
  be gone.
- **Idempotence:** Capture is keyed on `(alert, sha256, rule uuid)`. Repeated dispositioning, or a
  review correction, re-runs the module harmlessly.
- **If data is missing:** Keep the design's ERROR log, and also count it (per rule, surfaced on the
  SVS page). An ERROR log line alone won't be noticed.

**Alternative considered:** capture at alert creation. That is simpler, with no race against
archive, but it stores every alert's matches, including the large majority that end up IGNORE.
I'd stay with disposition time.

> **Response:**

### YR-6 — Label conflicts across alerts  `PROPOSED`

The same file (sha256) can be matched by the same rule in many alerts, with different verdicts.
The design says "the sample becomes a TP sample", but a label is really per
`(sha256, rule uuid)`, and several alerts vote on it.

**Proposal:**
- Explicit overrides beat inherited verdicts.
- Among votes of the same kind, if they disagree, the pair is **conflicted**. It is shown in the
  report and excluded from pass/fail until someone relabels it (YR-1).
- The newest vote does not silently win, because a label flip decides pass/fail.

> **Response:**

### YR-7 — Rules without a `uuid`  `PROPOSED`

A rule without `uuid` meta is attributed to the built-in fallback `YARA_RULE_MATCH`
(`yara.py:73-76`). Every uuid-less rule therefore shares one signature uuid, and their samples
would be pooled under it.

**Proposal:**
- Exclude them from capture.
- List uuid-less rules in the PR report as *not regression-testable*. That also gives the repos
  a nudge toward adding uuids.

> **Response:**

### YR-8 — Sample store: CAS layer, retention, access  `OPEN` · blocking

The design says samples go through `saq/storage`, content-addressed by sha256. Some facts:
- **`saq/storage` is not content-addressed.** It is a bucket/path file API with local and S3
  backends, used today only by crash-report replication. SVS needs a thin CAS layer:
  - key `svs-yara/<sha[:2]>/<sha256>`;
  - `object_exists` before upload;
  - verify the hash on download.

  That's straightforward.
- **Don't reuse the analysis-cache blob store** (`saq/analysis/blob_store.py`). It is sha256-keyed,
  but its references expire after ~35 days by design.
- **The S3 factory hardcodes `secure=False`** (`saq/storage/factory.py:114`). Customer email and
  live malware would travel to S3 without TLS. Fix that before SVS uses it.

**Questions:**
1. **Retention.** Do samples live forever? I suggest yes for labeled pairs, plus a per-rule cap on
   *inherited-TP* samples (for example, the newest 200 distinct sha256). A prolific rule shouldn't
   dominate scan time. Explicit labels are never capped.
2. **Access.** Who may view a sample's metadata and who may download bytes? I suggest two
   permissions: `svs:sample_read` and `svs:sample_download`. Downloads are audited and served
   zipped with a password, like other malware downloads in the GUI.
3. **Encryption at rest.** Is S3 SSE or disk encryption enough, or does SVS encrypt blobs itself?
4. **Deletion.** A legal or privacy delete has to remove bytes and rows and be audited. Who can do
   it?

> **Response:**

### YR-9 — Isolation of PR rule compilation  `PROPOSED`

PR rules must never touch the live scanner or `signature_dir`, or validating a PR deploys it. They
are also untrusted input: regex blowups, huge rulesets, pathological conditions.

**Proposal:** The SVS service compiles each uploaded tree into a **private `YaraScanner` instance
in a subprocess**, with a wall-clock timeout, a memory limit, and an upload size limit. It never
goes through the scanner service socket. Compile errors are a first-class report result:
"namespace X failed to compile: all N rules in it are dropped". That is exactly the silent
production failure mode YR-2 point 3 describes.

> **Response:**

### YR-10 — The dynamic case (`d(t(Y))`) in regression  `OPEN`

The design's framing says SVS supports both static and dynamic detection. As specified, YARA
regression is **purely static**: it re-scans the file the rule matched. Often that file was itself
produced by a tool (pdftotext output, an extracted macro, deobfuscated JS). If the tool changes,
nothing in regression notices, because the recorded output is frozen.

**Question:** Is it acceptable that the dynamic case is covered only by test execution (ART) in the
first version? I think yes, but the doc should say so. A later extension would record the parent
file's sha256 and the producing module (the detection chain already knows it:
`saq/analysis/detection_chain.py`). It would then re-derive the child with the current tool before
scanning. `saq/modules/tool_version.py` would supply tool versions, but pdftotext, olevba and the
JS modules don't use it yet.

> **Response:**

---

## 5. Test execution (Atomic Red Team)

### ART-1 — Terminology: *test* vs *run*  `PROPOSED`

The design uses "test" for two things: the atomic test *definition* ("which test is being
executed") and a registered *execution* ("when a test is created", the lifecycle states).
Lifecycle, markers, windows and results all belong to the execution.

**Proposal:**
- A **test** is an atomic test definition, identified by its `auto_generated_guid`.
- A **run** is one registered execution of one test against one or more targets.
- The lifecycle is a run lifecycle.
- "Associate an alert to a test" means *to a run*.
- Several runs launched together (one launcher session) can share an optional `batch_id` for
  display.

> **Response:**

### ART-2 — Registration API and lifecycle transitions  `PROPOSED` · blocking

The states are listed, but not who moves a run between them. Without that, *Started* and *Error*
can't happen.

**Proposal** (`aceapi_v2/svs/`, permission `svs:run_register`):

| Call | Transition | Notes |
|---|---|---|
| `POST /runs` `{test_guid, targets:[{hostname, username}], launcher, extra}` | → **Created** | Validates `test_guid` against the ART catalog (ART-12) and every target against test hosts (ART-9). Returns `run_id` and `marker`. |
| `POST /runs/{id}/start` | Created → **Started** | Records the actual `started_at`. The observation window (ART-3) starts here, not at registration. |
| `POST /runs/{id}/executed` `{exit_code, error?}` | Started → Started / **Error** | Optional. Records that execution finished. A launcher-reported failure moves to Error. |
| `POST /runs/{id}/cancel` | any non-terminal → **Canceled** | Analyst or launcher. |
| (timer) | Started → **Ended** | When `started_at + window` passes. |
| (timer) | Created → **Error** | The launcher never called `start` within N minutes. |

The design has no state after *Ended*. I suggest the result (expected hit / missing / unexpected /
ignored, per signature) is computed at *Ended* and becomes **Reviewed** once an analyst signs it
off. This is the state Coverage (COV-1) counts as *validated*.

**Late alerts:** keep an **attribution window** that is longer than the observation window. Alerts
that arrive after *Ended* but inside the attribution window are still attributed, marked *late*,
and recompute the result. This matters because hunt latency and engine backlog are real
(ART-3).

> **Response:**

### ART-3 — Observation window length  `PROPOSED`

A fixed window is wrong at both ends. EDR-driven hunts can fire in minutes. A daily hunt with a
24h range needs a day or more.

**Proposal:** Take the window from the test's config when one is set. Otherwise compute it as the
maximum over the test's expected signatures of their worst-case latency. For hunts that is
`frequency + time_range + offset` from the hunt config. Add a configurable slack, and apply a
floor and a ceiling.

> **Response:**

### ART-4 — Marker threat model  `PROPOSED` · blocking

A marker's job is to **move alerts out of the analysts' normal view**. That gives an attacker an
incentive to forge or replay one: an intruder whose tooling carries a valid-looking marker would
be routed into the test queue, which is exactly the "hide real activity" outcome. The design's
"real TP on a test host is out of scope" decision covers intruders *on test hosts*. It does not
cover a marker showing up on a **production** host.

**Proposal (rules the design should state):**
1. **Attribution requires the marker and the context to agree.** A marker attributes an alert only
   if it matches a registered run *and* the alert involves one of that run's targets *and* the
   event falls inside the run's attribution window.
2. **A marker that doesn't agree never routes the alert.** Such a marker could be unknown,
   well-formed but not in the DB, from a different host, or outside the window. The alert stays
   in its normal queue, gets tagged `svs:marker_mismatch`, and gets a detection point from a
   new built-in signature. A marker on a non-test host is exactly what an analyst should see.
3. **Markers are 128-bit random**, in a distinctive, regex-matchable format, for example
   `svs-<26 base32 chars>`.
4. **Markers are not secrets** once the test runs: they sit in telemetry. They are only valid in
   context (rule 1).

> **Response:**

### ART-5 — Where ACE looks for the marker  `OPEN` · blocking

"Marker injection" is decided. What isn't decided is the contract between launcher and ACE: where
the marker has to end up for ACE to find it, and where ACE searches. Some facts:
- **No existing search finds a substring in an alert.** Observable lookup is an exact
  `(type, sha256)` match and semantic search is fuzzy (§8, F-10).
- **Hunt alerts only carry the observables their `observable_mapping` declares.** The raw events
  are always kept in `root.details["events"]`, and that is where a marker reliably appears.
- **Atomics vary a lot in whether a marker can be injected at all.**
  - Some take `input_arguments` that land in a command line or a file name.
  - For many others, the only generic trick is appending a shell comment (`# svs-…`, `REM svs-…`)
    to the executor command so it appears in process-creation telemetry.
  - Network-only and authentication-only telemetry will never carry one.

**Proposal:** ACE searches for the marker regex in three places:
1. every observable value;
2. `root.details` of the root. For hunts that means the raw events;
3. the details of `CommandLineAnalysis`.

The launcher's contract is "put the marker where the technique's process telemetry will show it".
When no marker is found, attribution falls back to target + window (the design's "best effort"),
recorded with **confidence** `marker` vs `context`, so the review screen can show it.

**Question:** Should context-only attribution also route the alert to the test queue, or only link
it to the run and leave it in the normal queue for an analyst to confirm? I lean toward routing,
given the design decision that real TPs on test hosts are out of scope, but that is your call.

> **Response:**

### ART-6 — When attribution happens and how the queue moves  `PROPOSED` · blocking

"As soon as ACE is able to make that determination" hits two facts (§8, F-9):
- **Hunt alerts are inserted into `alerts` before any analysis runs.** Hunts submit in correlation
  mode, and `remote_node.py:98-99` inserts first. An engine module that finds the marker runs
  *after* the alert is already visible in the default queue. `_apply_detection_queue` never runs
  for these alerts at all.
- **Nothing in ACE can change `alerts.queue` after creation.** There is no GUI action, no API, and
  `Alert.sync()` doesn't copy `root.queue` back.

**Proposal:** Attribute in two stages.
1. **Pre-insert (preferred).** The hunter, before submitting, and the submission path in general,
   run the cheap check: marker regex over the raw events, plus a target lookup. They set
   `root.queue` before the alert exists. This covers most test alerts, which come from EDR hunts.
2. **Post-analysis.** An engine module in correlation mode catches markers that appear only after
   analysis, such as a decoded command line or an extracted file. Moving the alert needs a new,
   generic core primitive: `move_alert_to_queue(alert, queue, reason, user)`. It updates the
   column and `root.queue`, touches the alert, refreshes the search payload
   (`submit_payload_task`), and writes an audit line. The manual associate/disassociate buttons
   (ART-13) use the same primitive.

**Collision to check:** modules with `valid_queues` / `invalid_queues` (`base_module.py:191-202`)
change behavior if an alert's queue changes mid-analysis.

> **Response:**

### ART-7 — Alerts that mix test and non-test detections  `PROPOSED` · blocking

A single alert can contain both kinds:
- A hunt with `group_by` can merge a test host's events with a production host's events into one
  alert (`query_hunter.py:1043,1076`).
- A test alert can also pick up an unrelated detection during analysis.

The design tracks attribution **per detection point** but routes **per alert**.

**Proposal:**
- Record attribution per detection point, as the design says.
- **Route the alert to the test queue only when every detection point is attributed.** Otherwise
  it stays in the normal queue, linked to the run, with an `svs:partial` tag.
- This mirrors the rule `_apply_detection_queue` already applies to YARA-meta queues ("if any
  plain detection exists the alert is real").

> **Response:**

### ART-8 — Hunt suppression / dedup / group_by swallow test detections  `OPEN`

A "missing" expected detection may have matched and then been dropped before it became an alert.
There are three ways this happens:
- **Hunt `suppression`.** After a hunt alerts, the whole hunt, or with `group_by` that group, is
  suppressed for a period. Grouped submissions during suppression are **dropped**
  (`query_hunter.py:1268-1289`).
- **`dedup_key`.** It drops repeat keys for 24h (`base_collector.py:451-460`).
- **`full_coverage: false`.** The window after suppression skips the suppressed period.

A test run right after a real (or earlier test) alert from the same hunt looks like a detection
failure.

**Options:**
- (a) Report only. The result distinguishes *missing* from *possibly suppressed*: the hunt
  alerted within its suppression period before the run.
- (b) The hunter bypasses suppression and dedup for events on registered test targets during
  an active run. There is a precedent: manual and validation runs already bypass group suppression
  (`query_hunter.py:1273`).
- (c) Both.

I'd do (c). (b) makes results trustworthy, and (a) explains the cases (b) can't reach.

> **Response:**

### ART-9 — Test host definition and unregistered-host handling  `PROPOSED`

- **Test hosts:** YAML under `svs.test_hosts` as a list of `{hostname, fqdn?, usernames?, ips?}`,
  validated by the schema.
  - Matching normalizes case and short name vs FQDN. The `hostname` observable is already caseless.
  - Usernames are normalized across `DOMAIN\user`, `user@domain` and `user`.
- **Registration against a non-test host:**
  - The call **fails** with 403. The design says it generates an alert but doesn't say it is
    refused, and it should be.
  - It **also** creates an alert in the *default* queue through the normal submission path
    (`Submission` → `RemoteNode.submit_local`), with a built-in signature and the caller's
    identity (API key owner) as observables.
- Should a registration with a *listed host* but an *unlisted username* also be refused and
  alerted? I'd say yes if `usernames` is set for that host.

> **Response:**

### ART-10 — What happens to test alerts downstream  `OPEN`

Once an alert is in the test queue, several things still have to be decided:

1. **Disposition.** Which one, and who sets it? It must **not be `IGNORE`**: IGNORE alerts are
   deleted after one day, and test alerts are the best-labeled data SVS will ever see. Options:
   - SVS auto-dispositions a run's alerts at *Reviewed*, with a new disposition such as
     `SVS_TEST` classified *unclassified* in TP-2;
   - or the analyst dispositions them normally.
2. **Keeping them out of history.** Test artifacts must not feed "seen before" logic: observable
   disposition history and prevalence. The only precedent is a hard-coded
   `alert_type != 'faqueue'` filter in three queries (§8, F-11). Should test alerts get their own
   `alert_type`, or should the filter become a generic "excluded from history" flag?
3. **Should an expected YARA hit in a Reviewed run become a TP sample automatically?** It is
   exactly the labeled data regression wants, and it gives YARA regression coverage of techniques.
   I lean yes.

> **Response:**

### ART-11 — Technique-derived expectations are too broad  `PROPOSED` · blocking

Deriving expectations from declared techniques (a design decision) is a good default. Applied
literally, though, "every signature tagged `mitre:T1059.001` is expected to fire for every atomic
under T1059.001" produces a wall of *missing* on the first run:
- T1059.001 alone has dozens of atomics;
- a signature for encoded commands won't fire on an atomic that downloads a script.

**Proposal (a refinement of the decision, not a reversal):**
- Derived mappings are **candidates**.
- A candidate becomes **expected** when an analyst confirms it, or when it fires in a Reviewed run
  and the analyst accepts it.
- A candidate that never fires is shown as *candidate, not observed*, not as *missing*.
- Hand-edited expectations are *expected* immediately.

Source data for derivation:
- It comes from the signature inventory (`saq/signatures/`): YARA `mitre_attack` meta and hunt
  tags.
- Neither this repo's hunts nor the YARA module's alert-time tags carry `mitre:` today, so the
  coverage of the convention in the real signature repos should be measured first.
- Expectations are checked against the signature's **enabled** state at run time: a disabled
  signature is not expected to fire.

> **Response:**

### ART-12 — Why ACE holds the ART repos, and what it parses  `PROPOSED`

Execution is out of scope, so ACE needs the ART repos only as a **catalog**, for four things:
- validating `test_guid` at registration;
- test names and descriptions for display;
- `supported_platforms`;
- techniques, for ART-11.

**Proposal:**
- Each repo is an ordinary `git_repo_<name>` section, so `GitManagerService` polls it (§8, F-12).
- SVS parses `atomics/T*/T*.yaml` into a catalog table on change. `GitManagerService` has no
  post-update hook, so SVS compares HEAD commits.
- Custom repos must follow the ART YAML schema and must carry `auto_generated_guid`. Tests without
  one are skipped with a warning.
- A GUID that disappears from the catalog keeps its historical runs.

> **Response:**

### ART-13 — Launcher noise vs per-test ignores; manual (re)association  `PROPOSED`

- **Two scopes of ignore.**
  - The launcher's own activity (WinRM, PowerShell remoting, Invoke-AtomicRedTeam module loads)
    will fire signatures on *every* run. Ignoring them test by test is tedious and error-prone.
  - **Proposal:** a *global* ignore list (signatures ignored on test targets during any run), next
    to the design's *per-test* ignores.
- **Manual (re)association.**
  - "Associate any alert to any test" and "remap" both mean *to a run*, and both go through the
    generic queue primitive in ART-6.
  - Both record who/when/why, recompute the run's result, and are reversible.
  - Disassociating moves the alert back to the queue it would otherwise have had.

> **Response:**

---

## 6. Coverage

### COV-1 — The Coverage subsystem has no section yet  `OPEN` · blocking

Coverage is one of the three subsystems in the Design Decisions, and goal 3 depends on it, but the
design doesn't describe it. A strawman, to react to:

- **Grain:** one row per (technique, environment), rolled up to parent technique.
- **States** per technique:
  - **claimed:** at least one enabled signature is tagged with it;
  - **tested:** a run of an atomic for it reached *Reviewed*;
  - **validated:** the latest Reviewed run had every *expected* signature fire, at the current
    signature versions;
  - **failing:** the latest Reviewed run had a *missing* expected signature;
  - **stale:** validated, but an expected signature, the test or the test host set changed since.
- **ATT&CK catalog:** none exists in the repo. Pin one ATT&CK release (STIX bundle) as a config
  input. Map revoked or renamed techniques on upgrade instead of silently dropping them.
- **Out of reach:** techniques with no atomic (much of ACE's email and file-analysis strength)
  can only be *claimed*. The report should show that honestly rather than as a gap in testing.

**Questions:**
- Is *stale* by signature version too noisy? Signature versions are repo HEAD commits, so every
  commit changes them (§8, F-6). A per-rule `content_hash` is the better staleness key.
- Is coverage per company/tenant? Alerts carry one `company_id`.

> **Response:**

### COV-2 — Goal 2 (the telemetry exists) has no mechanism  `OPEN` · blocking

Goal 2 is *"validate the telemetry that signatures are designed to match is actually generated in
the environment"*. Nothing in the design does this. A *missing* detection is ambiguous:
- the telemetry never arrived (logging gap), or
- it arrived and the signature didn't match (signature gap).

Those have different owners.

**Options:**
- (a) Each test can carry an optional **telemetry probe**: a signature-independent query (for
  example "any process event on `<target>` containing `<marker>` in the window"). SVS runs it
  through the existing ad hoc hunt execution path at *Ended*, which yields
  `no telemetry` / `telemetry, no detection` / `detected`.
- (b) Drop goal 2 from the first version and say so.

I'd do (a) once markers exist. The marker makes a generic probe possible, which is a strong
argument for markers beyond attribution.

> **Response:**

---

## 7. Cross-cutting

### X-1 — Placement in the codebase and permissions  `PROPOSED`

| Piece | Where |
|---|---|
| Tables (verdict overrides, samples, sample links, validations, runs, run↔alert/detection links, expectations, ART catalog) | Main Alembic chain, models in `saq/database/model.py` |
| Scans, run timers, catalog refresh | New `service_svs` (`docs/SERVICES.md`) |
| APIs | `aceapi_v2/svs/` (router / service / schemas) |
| Sample capture, marker attribution | Analysis modules (`analysis_module_svs_*`) plus the hunter pre-insert check |
| GUI | Detection-verdict UI (DP-5), sample review, validation reports, run review, coverage |
| CLI | `ace svs ...` |
| Permissions (catalog + migration) | `svs:run_register`, `svs:validate`, `svs:sample_read`, `svs:sample_download`, `svs:admin` |

> **Response:**

### X-2 — Which ACE instance owns SVS  `OPEN`

Production holds the samples and sees the test hosts' telemetry. Dev and QA don't. So validations
and runs point at production ACE, which means signature-repo CI needs network access and an API key
for production.

**Question:** Is that acceptable, or does a separate SVS instance get a replicated sample store?
Replication is harder, so I'd start with production.

> **Response:**

### X-3 — Name collision with `lib/signature_validator`  `OPEN`

`lib/signature_validator` (`validate-hunt` → `/api/hunt/validate`) already means "signature
validation" in ACE, and it is the hunt analogue of YR-3.

**Question:** Does SVS eventually absorb it (the same CI entry point, `validate` for hunts and YARA),
or do they stay separate? I'd keep them separate for now and note the relationship in both docs.

> **Response:**

### X-4 — Phasing  `PROPOSED`

1. **Labels.** TP-2 classification, DP-1 verdict table and effective verdicts, DP-4 YARA detection
   details, and the minimal DP-5 GUI (alert page chips). This is useful by itself as a per-signature
   FP rate.
2. **YARA capture.** The sample store (YR-8), the capture module (YR-5), and sample browsing.
3. **YARA validation.** The API, isolated scanning, reports and baseline actions
   (YR-1/2/3/9). CI integration in one signature repo.
4. **Runs.** Registration API, test hosts, markers, attribution (pre-insert first), the test
   queue, the queue primitive, and run review with hand-edited expectations.
5. **Expectations and coverage.** ART catalog, derived candidates, the coverage view, and the
   telemetry probe (COV-2).

Phases 1–3 carry no execution risk and exercise storage, the API trigger and reporting. Phase 4 is
where the security questions (ART-4/6/7) have to be settled.

> **Response:**

---

## 8. Code facts this review relies on

These are verified against the checkout. Items marked **(defect)** are worth fixing whether or not
SVS happens.

- **F-1 Detection identity.**
  - `detection_points` is unique on `(alert_id, content_hash)`, where
    `content_hash = sha256(signature_uuid, description, details)` (`saq/analysis/detection_point.py:78-84`).
  - Detections with the same hash on different observables collapse into one row. The table
    records no observable. Descriptions that don't name their object ("URL has matches on Google
    Safe Browsing List") collapse per alert.
  - Rows are deleted and reinserted as the tree changes, so `id` is not durable
    (`saq/database/util/index.py:331-385`).
- **F-2 Root-level detections.** Root-level detections *are* included in
  `all_detection_points` (the list of all analyses starts with the root). The earlier review's
  §3.5 claim was wrong.
  - **(defect)** The comment at `analysis_orchestrator.py:405-407` is stale, and
    `_apply_detection_queue` and `saq/search/documents.py:177` double-count root detections.
    That is harmless today.
- **F-3 (defect) Disposition config vs constants.**
  - `AUTHORIZED` and `DATA_CONTROL` are configured but not constants, so they are silently
    dropped.
  - `INSIDER_DATA_CONTROL`, `INSIDER_DATA_EXFIL`, `APPROVED_BUSINESS` and `APPROVED_PERSONAL` are
    constants but not configured.
  - `/set_disposition` validates against the constants (`app/analysis/views/edit/disposition.py:25`).
  - `benign_dispositions` and `malicious_dispositions` have no production reader.
- **F-4 Dispositioned mode runs nothing by default.** Its only module, `alert_added_to_event`, is
  `enabled: false`. Roots don't carry the disposition; a module must query `alerts`.
  - `set_dispositions()` requeues into it for every disposition except IGNORE, including alerts
    whose disposition didn't change.
  - Disposition history is only the audit log, comments and the single `incorrect_*` slot.
- **F-5 Retention.**
  - `archive()` (FP after 30d) resets all non-root analysis details, which loses YARA
    `scan_results`, and removes non-root `files/` entries. `hardcopies/<sha256>` survives, but that
    looks accidental.
  - `retained_files` is always empty (`root.py:759`).
  - IGNORE alerts are deleted after 1 day. TP alerts are never archived. Cleanup runs only on
    PRODUCTION instances.
- **F-6 YARA versioning.**
  - `signature_version` is the repo **HEAD** commit, and only for dirs in
    `service_yara.git_repo_dirs`. That defaults to `[]`, so everything is `"unknown"` by default.
  - The inventory's per-rule `content_hash` covers only the rule's own text.
- **F-7 YARA scan context.**
  - Externals `filename`, `filepath` and `extension` are derived from the scanned path.
  - Post-match filters `file_ext`, `file_name`, `full_path`, `mime_type` and `meta_tags` come from
    `yara_meta:` directives.
  - Also applied: `enabled` meta, and `modifiers` = `qa` / `no_alert` / `directive=`.
  - **(defect)** The rule blacklist (`service_yara.blacklist_path`) is dead config: never read, but
    still documented in `docs/YARA_RULES.md`.
- **F-8 YARA compile unit.** A namespace is one subdirectory of `signature_dir`, non-recursive.
  - The files are compiled together. One bad file or a duplicate rule name drops the **entire
    namespace** (`yara_scanner`).
  - The inventory parses with plyara, ignores `include`, and lists private rules like any other.
- **F-9 Queues.**
  - `alerts.queue` is set once at creation from `root.queue`. There is no post-creation change path.
  - `_apply_detection_queue` is all-or-nothing and runs only on the transition into correlation
    mode, so it never runs for hunt alerts, which are inserted before analysis.
- **F-10 No substring search over alert content.** Lexical search is an exact `(type, sha256)`
  match, and `observables.value` has only a prefix index.
- **F-11 Metric exclusion.** The only precedent is a hard-coded `alert_type != 'faqueue'` in
  `saq/database/database_observable.py:65,107` and `aceapi_v2/observables/service.py:243`.
- **F-12 Git repos.** `git_repo_<name>` sections are polled by `GitManagerService`, one thread per
  repo, with no post-update callback.
- **F-13 (defect) S3 without TLS.** `saq/storage/factory.py:114` hardcodes `secure=False` and
  ignores `s3.secure`.
- **F-14 (defect) YARA QA mode copy.** `yara.py:360` creates only `<qa_dir>/<rule>/`, so copies of
  files whose `file_path` has subdirectories fail. They are logged and nothing else happens.
  `var/qa` is never cleaned up.
- **F-15 (defect) Local YARA scanner fallback lifetime.** `yara.py:299` multiplies seconds by 60
  where it should divide, so the fallback scanner is recycled almost immediately.
- **F-16 No ATT&CK catalog, no `mitre:` tags in this repo's hunts.** The YARA module doesn't add
  `mitre:` tags at alert time; only the inventory loader derives them.
- **F-17 No API v2 alert submission.** Programmatic alert creation goes through `Submission` /
  `RemoteNode.submit_local` or v1 `POST /api/analysis/submit`.

---

## 9. Round log

| Round | Who | Summary |
|---|---|---|
| 1 | reviewer | Initial review of `SVS_INITIAL.md` @ `ec3cab18`. 37 items: 20 blocking (15 PROPOSED, 5 OPEN). |
