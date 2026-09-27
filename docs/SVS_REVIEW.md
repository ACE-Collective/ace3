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
  - `SUPERSEDED by X` means the discussion continues in item or section X. The old text stays for
    the record.
- **Blocking** means the item has to be settled before implementation of that subsystem can
  start. Non-blocking items can be settled during implementation.
- Code references are to this checkout: round 1 at `ec3cab18`, round 2 at `6967686c` (after the
  merge of `main`), both 2026-09-26. Round 3 (2026-09-27) is at `654df8dc`; no code changed since
  round 2. Round 4 is at `e68985eb`, also with no code changes. §9 collects the code facts that
  the items rely on.
- §10 holds decision text ready to paste into the *Design Decisions* list of `SVS_INITIAL.md`.
- §11 is the standing list of what the SOC needs to be told (X-5). Settling an item that changes
  anything analysts or detection engineers see includes updating it.

---

## 1. Status board

**Round 4 at a glance.** A correction first: round 3 listed DP-2, DP-4, YR-3 and ART-8 as
unanswered. You had answered all four in plain text, and my search only found quoted
`> **Response:**` lines. They are all handled now. Settled this round: DP-4, YR-3 (a), ART-8 (a),
ART-10, ART-16 (a) and CAS-7. Two of your answers reopen something:

1. **DP-2, which is now the most consequential open item.** Your data shows that **37% of TP
   alerts with a YARA hit have more than one signature**. Under the current rule, every YARA sample
   on those alerts stays unlabeled unless an analyst takes the optional step. I propose changing the
   default (options (a) and (b) in the item).
2. **DP-3.** Your answer ("the analyst made a mistake") means a TP verdict on an FP alert isn't a
   real case. It is a wrong alert disposition, and the fix belongs there. I propose reverting the
   round-2 amendment that let overrides beat an FP alert.

Also still open: X-5 and the §11 list (no response yet).

| ID | Topic | Blocking | Status |
|---|---|---|---|
| **Foundations** | | | |
| TP-1 | What "True Positive" means for a signature | yes | AGREED (r2) |
| TP-2 | TP/FP classification is three-valued; reuse existing config | yes | AGREED (r2) |
| TP-3 | Classify the borderline dispositions | yes | AGREED (r3) |
| DP-1 | Store verdict overrides, derive effective verdicts | yes | AGREED (r2); the DP-3 amendment may be reverted (r4) |
| DP-2 | Which detections inherit a TP alert's verdict | yes | PROPOSED (r4: data says change the default) |
| DP-3 | Behavior when the alert disposition changes | yes | PROPOSED (r4: revert TP-on-FP overrides) |
| DP-4 | YARA detection points: move to the file | yes | AGREED (r3) |
| DP-5 | GUI for detection-point verdicts | no | AGREED (r2) |
| DP-6 | Verdicts for all signature families, not only YARA | no | AGREED (r2) |
| DP-7 | Detection identity must include the node it sits on | yes | AGREED (r3) |
| **YARA static regression** | | | |
| YR-1 | Define "difference" and "baseline" | yes | AGREED (r2) |
| YR-2 | Scan the whole corpus with the whole ruleset | yes | AGREED (r2) |
| YR-3 | Trigger, transport and where the report goes | yes | AGREED (r3): (a), CI calls ACE |
| YR-4 | What a sample record must capture | yes | AGREED (r2) |
| YR-5 | When capture happens | yes | AGREED (r2) |
| YR-6 | Label conflicts across alerts | no | AGREED (r2) |
| YR-7 | Rules without a `uuid` | no | AGREED (r2) |
| YR-8 | Sample store: CAS layer, retention, access | yes | superseded by §7 (CAS-*) |
| YR-9 | Isolation of PR rule compilation | no | AGREED (r2) |
| YR-10 | The dynamic case (`d(t(Y))`) in regression | no | DEFERRED (r2) |
| YR-11 | `archive()` must actually free derived files | no | AGREED (r3); its own PR, before SVS |
| **Test execution (Atomic Red Team)** | | | |
| ART-1 | Terminology: *test* vs *run* | no | AGREED (r2) |
| ART-2 | Registration API and lifecycle transitions | yes | AGREED (r2) |
| ART-3 | Observation window length | no | AGREED (r2) |
| ART-4 | Marker threat model | yes | AGREED (r2) |
| ART-5 | Where ACE looks for the marker | yes | AGREED (r2); the "where" is in ART-15 |
| ART-6 | When attribution happens and how the queue moves | yes | superseded by ART-15 |
| ART-7 | Alerts that mix test and non-test detections | yes | AGREED (r2) |
| ART-8 | Hunt suppression / dedup / group_by swallow test detections | no | AGREED (r3): (a) now, (b) deferred |
| ART-9 | Test host definition and unregistered-host handling | no | AGREED (r2) |
| ART-10 | What happens to test alerts downstream | no | AGREED (r4): `SIMULATED`, not selectable; one small question |
| ART-11 | Expectations come from measurement, not declared techniques | yes | AGREED (r3); meta key moved to ART-16 |
| ART-12 | Why ACE holds the ART repos, and what it parses | no | AGREED (r2) |
| ART-13 | Launcher noise vs per-test ignores; manual (re)association | no | AGREED (r2) |
| ART-14 | Keep the analyst's view simple: one SVS status per alert | yes | AGREED (r3) |
| ART-15 | Engine-native marker detection through an alert-router registry | yes | AGREED (r3) |
| ART-16 | Which meta key carries a manual technique mapping | yes | AGREED (r4): (a), reuse existing keys |
| **Coverage** | | | |
| COV-1 | The Coverage subsystem | yes | AGREED (r3); tenant question defaulted |
| COV-2 | Goal 2 (telemetry exists) has no mechanism | yes | AGREED (r2): goal 2 dropped |
| **Content-addressed storage** | | | |
| CAS-1 | Scope and consumers | yes | AGREED (r3) |
| CAS-2 | Three candidate designs | yes | AGREED (r3): design C |
| CAS-3 | Data model and API (design C) | yes | AGREED (r3) |
| CAS-4 | Retention, holds, GC correctness | yes | AGREED (r3) |
| CAS-5 | Encryption and object naming | yes | AGREED (r3): plain names, one system key |
| CAS-6 | Backends and the relationship to `saq/storage` | yes | AGREED (r3): (b) |
| CAS-7 | Where the CAS index lives, and how it is pruned | no | AGREED (r4) |
| CAS-8 | Migrating the existing byte stores | no | DEFERRED (r3 confirmed): SVS first |
| **Cross-cutting** | | | |
| X-1 | Placement in the codebase and permissions | no | AGREED (r3) |
| X-2 | Which ACE instance owns SVS | no | AGREED (r2) |
| X-3 | Name collision with `lib/signature_validator` | no | AGREED (r2) |
| X-4 | Phasing | no | AGREED (r2), revised for CAS |
| X-5 | Keep a list of what the SOC must be told | no | PROPOSED, waiting; the list is §11 |

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
6. **Round 2 additions** to what is out of scope:
   - Goal 2, validating that the telemetry exists (COV-2).
   - All ACE data created before SVS is deployed (DP-4). SVS acts only on alerts created after it.
   - The dynamic case in YARA regression (YR-10). Test execution covers it.

---

## 3. Foundations: TP/FP and detection-point dispositions

### TP-1 — What "True Positive" means for a signature  `AGREED` · blocking

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

> **Response:** The only thing that matters to us is that we detect the attack. In ACE, the question we answer when dispositioning alerts is "Did we detect malicious activity?" So we would disposition a signature matching the encoded powershell as False Positive if we find that is what a system admin doing authorized work. Thus, the rule for Emotet maldoc hitting on Qakbot maldoc would be dispositioned as DELIVERY regardless. In regression testing, the idea is for the "detection telemetry signal generator" to take on the role of the attacker. 

> **Round 2 (reviewer):** Understood and adopted. The definition that goes into §10 (D-1):
> *a detection is TP when it was part of detecting malicious activity, and FP when it was not. The
> label follows the analyst's answer to "did we detect malicious activity?", not "did the rule match
> what its author intended".* Consequences, all acceptable:
> - An FP sample for a behavioral rule is usually the rule working as written on benign activity.
>   Under YR-1 that is harmless: a PR that stops matching it is reported as an *improvement*, and one
>   that keeps matching it is informational.
> - An accidental match on real malware (Emotet rule on Qakbot) is a TP sample, and a later PR that
>   narrows the rule away from it is reported as a *regression*. That is the intended behavior: the
>   narrowing loses a detection of malicious activity, and the analyst decides in review (retire
>   the sample, or keep the old coverage).
> - The ART side fits this directly. A run is simulated malicious activity, so every attributed
>   detection in a Reviewed run is a TP by definition (see ART-10 #3).
>
> One follow-on: `AUTHORIZED` goes away (TP-2), and several dispositions need a class under this
> definition. That is TP-3.
### TP-2 — Classification is three-valued; reuse the existing config  `AGREED` · blocking

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

This needs a fix first: config and constants disagree about which dispositions exist (§9, F-3).
`AUTHORIZED` and `DATA_CONTROL` are configured but **silently dropped** because they are not in
`saq/constants.py`. The set_disposition view also validates against the constants rather than the
config. A classification map keyed by disposition name has to be validated against the
*effective* disposition list at startup, or a typo becomes a silent "unclassified".

> **Response:** I agree with the proposal. Remove AUTHORIZED and DATA_CONTROL as dispositions.

> **Round 2 (reviewer):** Agreed. Removing them touches six config blocks in `etc/saq.default.yaml`:
> `valid_dispositions`, `disposition_rank`, `disposition_css`, `show_save_to_event`, and
> `benign_dispositions`/`malicious_dispositions`, which the new map replaces anyway.
> - No stored alert can carry either value, because `/set_disposition` validates against the
>   constants and neither is a constant. A check on production before the removal costs nothing:
>   `SELECT disposition, COUNT(*) FROM alerts GROUP BY disposition;`
> - The reverse mismatch is still open: four constants that are **not** in config
>   (`INSIDER_DATA_CONTROL`, `INSIDER_DATA_EXFIL`, `APPROVED_BUSINESS`, `APPROVED_PERSONAL`,
>   `saq/constants.py:335-338`) are hidden from the GUI. Should they also be removed, or added to
>   config? I'd remove them, and make the config the single source of the disposition list, with
>   the constants kept only for the names code refers to. That is folded into TP-3.

### TP-3 — Classify the borderline dispositions  `AGREED` · blocking  *(new, round 2)*

Under TP-1's definition, most dispositions classify themselves. A few need your call. Here is my
proposed default map for `disposition_classification`; anything absent is unclassified:

| Disposition | Proposed class | Reasoning |
|---|---|---|
| `FALSE_POSITIVE` | fp | By definition. |
| `RECONNAISSANCE` … `DAMAGE` (the kill-chain set) | tp | Malicious activity was detected. |
| `GRAYWARE` | **tp?** | Unwanted software, but is it "malicious activity"? If analysts use it for adware and PUPs that the SOC wants detected, it's tp. |
| `POLICY_VIOLATION` | **tp?** | Not an attack, but it is what policy signatures exist to find. If it is fp, every policy rule's corpus is all-FP, and a PR that breaks a policy rule reads as an *improvement*. I lean tp. |
| `INSIDER_DATA_CONTROL`, `INSIDER_DATA_EXFIL` | **tp?** / remove | These only matter if they come back into config (TP-2 follow-up). |
| `APPROVED_BUSINESS`, `APPROVED_PERSONAL` | **fp?** / remove | These are the same as the old `AUTHORIZED`. |
| `OPEN`, `IGNORE`, `UNKNOWN`, `REVIEWED` | unclassified | They carry no verdict. |

**Questions:** Classify `GRAYWARE` and `POLICY_VIOLATION`. Remove the four hidden constants, or
restore them?

> **Response:** Classify GRAYWARE and POLICY_VIOLATION as `tp`. Remove the four hidden ones. I'm making an important decision here on behalf of our whole SOC that needs to be sure to be communicated. So let's keep track of the most important decisions we're making to make sure everyone understands (what needs to be clearly communicated to the rest of the team that is using this system?)

> **Round 3 (reviewer):** Recorded:
> - `GRAYWARE` and `POLICY_VIOLATION` classify as **tp**.
> - The four hidden constants (`INSIDER_DATA_CONTROL`, `INSIDER_DATA_EXFIL`, `APPROVED_BUSINESS`,
>   `APPROVED_PERSONAL`) are removed.
> - Together with TP-2, that makes the config the only list of dispositions.
> - The custom test disposition from ART-10 joins the map as **tp**.
>
> The final map:
>
> | Class | Dispositions |
> |---|---|
> | tp | `GRAYWARE`, `POLICY_VIOLATION`, `RECONNAISSANCE`, `WEAPONIZATION`, `DELIVERY`, `EXPLOITATION`, `INSTALLATION`, `COMMAND_AND_CONTROL`, `EXFIL`, `DAMAGE`, and the ART-10 test disposition |
> | fp | `FALSE_POSITIVE` |
> | unclassified | `OPEN`, `IGNORE`, `UNKNOWN`, `REVIEWED` |
>
> On communicating this: agreed, and it applies beyond this item. §11 is now a standing list of
> what the SOC has to be told, written for analysts and detection engineers rather than for us.
> This classification is its first entry (S-1). X-5 proposes how we keep the list current.

### DP-1 — Store overrides, derive effective verdicts  `AGREED` · blocking

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
  detection has today (§9, F-1).
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

> **Response:** Agree with the proposal.

> **Round 2 (reviewer):** Two amendments from later answers.
> 1. **Override precedence** (DP-3: a detection can be TP on an FP alert). The formula becomes:
>
>    ```
>    effective(dp) =
>        override  if an override row exists                     # always wins
>        FP        if class(alert.disposition) == FP
>        TP        if class(alert.disposition) == TP and the alert has one signature (DP-2)
>        NULL      otherwise                                     # incl. unclassified alerts
>    ```
>
>    One exception: an **unclassified** alert (`OPEN`, `IGNORE`, …) still makes every verdict NULL,
>    overrides included. Otherwise a label could exist on an alert nobody has triaged.
> 2. **The key** `(alert_id, content_hash)` is only as good as `content_hash`. That hash currently
>    ignores which node the detection sits on (DP-7), which has to be fixed before the first
>    override is written.

### DP-2 — "Single detection point" should be "single signature"  `PROPOSED` · blocking

*(Round 4: widened to "which detections inherit a TP alert's verdict". See the round 4 reply.)*

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

> **Response:** See results below.

```txt
+--------+--------------+--------+
| n_sigs | n_dps_bucket | alerts |
+--------+--------------+--------+
|      1 |            1 |  11206 |
|      1 |            2 |     97 |
|      1 |            3 |     36 |
|      1 |            4 |      5 |
|      1 |            5 |     18 |
|      2 |            2 |    936 |
|      2 |            3 |     29 |
|      2 |            4 |     31 |
|      2 |            5 |     42 |
|      3 |            3 |    123 |
|      3 |            4 |    153 |
|      3 |            5 |    150 |
|      4 |            4 |     70 |
|      4 |            5 |    218 |
|      5 |            5 |     54 |
|      6 |            5 |     11 |
|      7 |            5 |      6 |
+--------+--------------+--------+
```

> **Round 2 (reviewer):** Thanks. Here is what the numbers say. The total is 13,185 dispositioned
> alerts (excluding OPEN/IGNORE/UNKNOWN):
>
> | Group | Alerts | Share |
> |---|---|---|
> | exactly one detection point | 11,206 | 85.0% |
> | one signature, 2+ detection points (what DP-2 adds) | 156 | 1.2% |
> | **two or more signatures** | **1,823** | **13.8%** |
>
> - **DP-2 changes little in volume.** It moves 1.2% of alerts from NULL to inherited. It is still
>   the correct rule and costs nothing, so I suggest accepting it. The large YARA case I worried
>   about (one rule, many attachments) is rare here.
> - **The real question is the 13.8%.** Their FP alerts label themselves (FP applies to all). Only
>   the TP ones fall to the optional step. If most of those are TP, the optional step is where most
>   YARA TP labels would come from, and DP-5's "collapsed, optional" GUI might be too quiet.
> - **One more query settles it.** It splits by class and by whether a YARA rule is involved (YARA
>   detection descriptions currently end in `matched yara rule <name>`):
>
>   ```sql
>   SELECT cls, n_sigs, has_yara, COUNT(*) AS alerts FROM (
>     SELECT a.id,
>            CASE WHEN a.disposition = 'FALSE_POSITIVE' THEN 'fp'
>                 WHEN a.disposition IN ('OPEN','IGNORE','UNKNOWN','REVIEWED') THEN 'none'
>                 ELSE 'tp' END                                   AS cls,
>            LEAST(COUNT(DISTINCT dp.signature_uuid), 3)          AS n_sigs,
>            MAX(dp.description LIKE '% matched yara rule %')     AS has_yara
>     FROM alerts a JOIN detection_points dp ON dp.alert_id = a.id
>     GROUP BY a.id) t
>   GROUP BY cls, n_sigs, has_yara ORDER BY cls, n_sigs, has_yara;
>   ```
>
>   If `tp / n_sigs ≥ 2 / has_yara = 1` is large compared with `tp / 1 / 1`, I'd make the verdict
>   step in the disposition modal *expanded by default* for TP alerts with a YARA detection. It
>   would still be skippable.

> **Response:** See results below.

```txt
+------+--------+----------+--------+
| cls  | n_sigs | has_yara | alerts |
+------+--------+----------+--------+
| fp   |      1 |        0 |   3855 |
| fp   |      1 |        1 |    641 |
| fp   |      2 |        0 |     78 |
| fp   |      2 |        1 |     39 |
| none |      1 |        0 |   3052 |
| none |      1 |        1 |    128 |
| none |      2 |        0 |     12 |
| none |      2 |        1 |     23 |
| none |      3 |        1 |      2 |
| tp   |      1 |        0 |   3060 |
| tp   |      1 |        1 |   2715 |
| tp   |      2 |        0 |     59 |
| tp   |      2 |        1 |    835 |
| tp   |      3 |        0 |     17 |
| tp   |      3 |        1 |    768 |
```

> **Round 4 (reviewer):** This is the number that matters, and it's larger than I expected.
> (`n_sigs = 3` means 3 or more, and `none` includes `OPEN`.)
>
> | TP alerts with a YARA hit | Alerts | Share |
> |---|---|---|
> | one signature (inherits TP today) | 2,715 | 63% |
> | **two or more signatures (NULL unless an analyst acts)** | **1,603** | **37%** |
>
> - **Under the current design, 37% of the YARA TP evidence depends on an optional step.** Optional
>   steps in a triage workflow mostly get skipped, so most of those labels would never exist. They
>   are also the richest alerts: real attacks where several signatures agreed.
> - **Co-firing on YARA alerts is overwhelmingly real.** Among YARA alerts with two or more
>   signatures, 1,603 are TP and 39 are FP (98% TP). Combined with TP-1's definition (a detection is
>   TP when it was *part of detecting malicious activity*), most co-firing detections on a TP alert
>   are TP by definition.
> - **The noisy case still exists**: a generic rule firing on a *benign* object in a malicious alert,
>   such as the logo image in a phishing email. It is the minority. It is also the case the per-file
>   detection placement (DP-4) makes visible, because the verdict is now per file.
>
> The DP-2 question is therefore bigger than "single detection point vs single signature". It is
> *what the default is for a TP alert with several signatures*.
>
> **Options:**
> - **(a) Keep NULL, and push the step.** The verdict section of the disposition modal opens
>   expanded, pre-filled *unset*, for TP alerts with a YARA hit and several signatures. It is still
>   skippable, and labels exist only where an analyst acted.
> - **(b) Inherit TP by default, and let the analyst mark the noise.** Every detection on a
>   TP-class alert inherits TP, whatever the number of signatures. The modal shows the same section
>   pre-filled *TP*, and the analyst flips the noisy ones to FP. The original design's "left NULL if
>   the analyst opts out" is replaced by "left inherited".
>   - To contain the risk, inherited-TP on a multi-signature alert is recorded as a **weaker source**
>     (`inherited_multi`), distinct from `inherited_single` and `explicit`.
>   - The YR-1 report shows regressions on `inherited_multi` samples in their own band: *"regression
>     on an unconfirmed label: check that the sample was ever a real hit for this rule"*. The report
>     is warn-only (YR-3), so a mislabeled sample costs one retire/relabel click when it first shows
>     up.
>
> **I recommend (b).** It turns 1,603 alerts' worth of TP evidence from "probably never labeled" into
> "labeled, with the weak ones marked". The cost of a wrong label is bounded, because the report
> surfaces it exactly when it matters, when a PR changes that rule. (a) keeps labels clean but
> small, and the gap falls exactly where the evidence is best.
>
> Under (b), DP-2's original single-signature rule is no longer needed: every TP-class alert
> inherits. FP alerts are unchanged: all FP.
>
> **Question:** (a) or (b)? If (b), D-6 and S-1/S-3 change as drafted in §10 and §11 (marked
> *pending DP-2*).

> **Response:** Agree with (b).

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

> **Response:** Yes, they can.

> **Round 2 (reviewer):** Adopted: an override now always wins (see DP-1, round 2). Rule 1 changes
> to *"an alert that moves to FP makes every **non-overridden** verdict FP"*.
>
> **Question (non-blocking, for the GUI copy and the docs):** Under TP-1, an FP alert means "no
> malicious activity was detected". So what does a TP detection on an FP alert look like in
> practice? My guess is something like this: the alert as a whole was a false alarm, but one of its
> detections hit genuinely malicious content, such as a real but stale sample. An example would let
> DP-5 explain the case in one sentence instead of making it look like a contradiction.

> **Response:** It just means the analyst made a mistake. They set an alert to FP and then later realized they were wrong. Let me know if I'm not understanding your question.

> **Round 4 (reviewer):** You understood it, and your answer settles it the other way from the
> round-2 amendment. If the case only arises when the analyst was wrong about the *alert*, then the
> fix is to correct the **alert's** disposition, not to override one detection. The disposition
> review path (`set_disposition_reviews()`, `INCORRECT`) exists for exactly this. Correcting the
> alert re-derives every verdict automatically (DP-1), and it fixes the alert's own record too:
> metrics, disposition history, the event roll-up. A TP override on an alert that stays FP would
> leave the alert wrong and only the label right.
>
> **Proposal: revert the round-2 amendment.**
> - **On an FP alert every verdict is FP, and the GUI offers no TP override there.** The chip on an
>   FP alert says *"FP (from alert). If the alert was wrong, change its disposition."*
> - **Overrides are FP-on-TP only** (marking noise), plus TP-on-TP where the default would be weaker
>   (DP-2 (b)'s `inherited_multi`, or NULL under (a)).
> - **Rule 1 as originally written stands:** moving to FP masks overrides without deleting them, so
>   a TP→FP→TP correction restores them.
> - The DP-1 formula goes back to its round-1 order (FP alert first, then override). This also
>   removes a hard-to-explain case from the SOC list (S-3).
>
> **Question:** Revert as proposed?

> **Response:** I misunderstood this one. Agree with the revert.

### DP-4 — YARA detection points: move to the file  `AGREED` · blocking

*(Round 1 title: "YARA detection points don't say which file matched".)*

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

> **Response:** Consider moving the detection point to the file instead. Let's also assume that existing ACE data prior to the introduction of SVS is out of scope. Only alerts created after SVS is deployed are considered by SVS.

> **Round 2 (reviewer):** Both accepted. "Pre-SVS data is out of scope" is recorded as D-3. I
> checked what moving the detection point from the `yara_rule` observable to the file observable
> (`yara.py:500-507`) would touch.
>
> **What it fixes:**
> - **Detection chains.** `yara_rule` is one observable per rule name, shared across the root. A
>   rule that matched N files therefore has N parents, and the chain walk picks one by sorted uuid
>   (`detection_chain.py:48`). Today every detection renders under an arbitrary file's lineage.
>   With the detection point on the file, each chain is exact.
> - **The link from detection to sample.** The detection sits on the sample.
> - **`docs/YARA_RULES.md:39-40`** already says "the file becomes a detection point", so the code
>   would finally match the docs.
>
> **What it changes (and what to do about each):**
> 1. **GUI pruning hides the evidence.** The pruned alert view (`app/analysis/views/index.py:349-386`)
>    shows each path only down to the deepest node that has a detection point. With the detection on
>    the file, the `YaraScanResults` analysis and the `yara_rule` node below it drop out of the
>    default view, and those are the "which rule, which strings" evidence.
>    **Fix:** a `YaraScanResults` analysis that produced a detection sets `always_visible`
>    (`analysis.py:422`).
> 2. **The detection path grows.** `is_on_detection_path` would now be true for the file and for
>    everything extracted from it. That feeds `requires_detection_path` in `accepts()`
>    (`base_module.py:382`). No config sets it today, so this is latent, but worth one line in the
>    PR description.
> 3. **Tests.** Five assertions on `yara_rule.detections` need updating
>    (`tests/saq/modules/test_file_analysis_full.py:432, 463, 495, 530, 629`).
> 4. **Same-path collision.** Two different files with the same `file_path` string (same name,
>    different content) produce two detections with **one** `content_hash`, so one DB row.
>    DP-7 fixes this generically.
>
> **Revised proposal:**
> - Move the detection point to the file.
> - Keep the structured `details` from round 1: `{"sha256", "rule", "namespace", "rule_uuid"}`.
>   `file_observable_uuid` and `file_path` are no longer needed, because the node now says which
>   file. `sha256` stays so that DB-level joins from a verdict to a sample need no tree load.
> - Make `YaraScanResults` always visible when it produced a detection.
>
> **Pre-SVS scope gets enforcement for free.** Old alerts carry YARA detections without these
> `details`. The capture module (YR-5) acts only on detections that have them, so no date cutoff
> or flag is needed.

> **Response:** Revised proposal accepted.

> **Round 4 (reviewer):** Recorded (round 3 missed this answer). The work: move the detection point
> to the file, add structured `details`, make `YaraScanResults` always visible when it produced a
> detection, and update the five tests. S-4 is no longer pending.

### DP-5 — GUI for detection-point verdicts  `AGREED`

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

> **Response:** Agree with the proposal.

### DP-6 — Verdicts for all signature families, not only YARA  `AGREED`

Detection-point verdicts cost the same for any signature. Only YARA consumes them for regression,
but a per-signature TP/FP count over time (the FP rate of each hunt) is useful on its own, and
it needs nothing extra once DP-1 exists.

**Question:** Should the GUI offer verdicts on every detection, or only YARA ones? I recommend every
detection. It is simpler to explain ("every detection can be labeled"), and it gives Coverage
(COV-1) a quality signal.

> **Response:** Yes.

> **Round 2 (reviewer):** Recorded. Labeling every family makes the row-collapsing problem in F-1
> matter for all detections, not only YARA ones. That is DP-7.

### DP-7 — Detection identity must include the node it sits on  `AGREED` · blocking  *(new, round 2)*

`content_hash = sha256(signature_uuid, description, details)`. It does not include the node the
detection sits on (F-1). With verdicts on every detection (DP-6), that means one verdict silently
covers several things:
- `"URL has matches on Google Safe Browsing List"` on three URLs is **one row, one verdict**.
- The same holds for the other descriptions that don't name their object: `new sender`, `decrypted
  archive`, `RTF`, `XLM` and others.
- The YARA same-path collision (DP-4 item 4) is the same bug.

**Proposal:** Fold the node's identity into `content_hash`, and store it as a column, so the table
can finally say what a detection is *on*:
- For observable nodes use `(node_kind='observable', type, sha256(value))`. That is stable across
  re-analysis, unlike observable uuids, which derived observables regain afresh after `ace alerts
  reset`.
- For the root use `('root')`. For analysis nodes use `('analysis', module path, parent observable
  type+value hash)`.
- Changing the hash re-keys every existing row the next time each alert is synced. D-3 (pre-SVS
  data out of scope) makes that acceptable, **but it has to ship before the first verdict override
  is written, and never change again after**. A changed formula orphans every override. A unit test
  that pins the formula makes that explicit.

> **Response:** Agree with the proposal.

---

## 4. YARA static regression

### YR-1 — Define "difference" and "baseline"  `AGREED` · blocking

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

> **Response:** Agree with the proposal.

### YR-2 — Scan the whole corpus with the whole ruleset  `AGREED` · blocking

The design runs *modified* rules against *their own* recorded samples. That misses three things:

1. **New false positives on other rules' samples.** A loosened rule is most likely to start
   matching benign files that some *other* rule was labeled FP on, or TP files of a different
   family. Only a rule's own samples are checked today, so this is invisible.
2. **New rules.** They have no samples of their own, so they get no check at all, and they are the
   riskiest change.
3. **Indirect changes.** Several effects never show up in a rule's own `content_hash` (§9, F-8):
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

> **Response:** Agree with the proposal.

### YR-3 — Trigger, transport and where the report goes  `AGREED` · blocking

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

> **Response:** Disagree with 1. ACE already has credentials, and there are no forks, all works is done in the same repo. To answer the question, we should only warn. We may have a reason to push it though anyways (such as performance impact.)

> **Round 2 (reviewer):** Both accepted: ACE fetches the rules itself, and the result only warns.
> Revised flow:
>
> 1. **What gets sent.** The request names a configured repository and two commits:
>    `POST /api/v2/svs/yara/validations {repository, base_sha, head_sha, branch, pr_url?}`.
>    `repository` is the name of an existing `git_repo_<name>` section, so ACE uses credentials it
>    already has. `branch` is what ACE fetches; `head_sha` is verified after the fetch.
> 2. **SVS never touches the live checkout.** `GitManagerService`'s `local_path` is what production
>    loads rules from, and fetching PR branches into it races with its pull loop. SVS keeps **its own
>    mirror clone** per repository (same URL and `ssh_key_path`, under the SVS work dir). It exports
>    each commit's YARA tree with `git archive <sha>` into a throwaway directory for YR-9. The
>    base is exactly the PR's base commit, not whatever production last pulled.
> 3. **Warn only.** The CI check always passes. It carries the counts as a neutral annotation or
>    PR comment, with the ACE report link.
> 4. **Your "performance impact" point deserves a place in the report.** Scanning the whole corpus
>    twice (YR-2) gives base-vs-head **scan time per namespace** for free, plus the yara compiler's
>    warnings for the head rules. Per-*rule* timing isn't available from yara-python without
>    compiling each rule on its own, so that could only be an opt-in "profile this PR" mode.
>
> **Question — who starts a validation?**
> - **(a) Signature repo CI calls ACE** (above). It knows the PR lifecycle and can post back to it.
>   It needs an ACE API key in CI and network reach to production (X-2).
> - **(b) ACE polls the repo itself.** It runs `git ls-remote` on the mirror and validates every
>   branch whose head moved, against its merge-base with `main`. This needs no CI changes and no
>   inbound calls. Results are visible only in ACE unless something posts them to the PR, and ACE
>   has git credentials, not a forge API token.
>
> I'd do (a) if the signature repos already run CI, and (b) if they don't. Which is it?

> **Response:** Let's go with (a) here.

> **Round 4 (reviewer):** Recorded (round 3 missed this answer). The signature repo's CI calls
> `POST /api/v2/svs/yara/validations` with a user-owned, scoped API key (`svs:validate`), polls, and
> posts a neutral check plus a comment with the counts and the ACE link. Consequences:
> - CI needs network reach to production ACE (X-2 accepted this).
> - The API key is stored as a CI secret. It should be a dedicated automation user's key with only
>   `svs:validate`, so a leak can't read samples.
> - The validation endpoint returns only counts, rule names and uuids (round 1 point 3), so what CI
>   can see is bounded by design.

### YR-4 — What a sample record must capture  `AGREED` · blocking

"All data that would be required to re-scan the file" is more than the bytes. The YARA result
depends on:
- the **file's path**: the `filename`, `filepath` and `extension` externals, plus the `file_name`,
  `full_path` and `file_ext` meta filters;
- the file's **`yara_meta:` directives**, which become `meta_tags` and are put there by upstream
  analysis modules;
- its **mime type** (`mime_type` meta filter, computed by `file -b --mime-type` on the bytes).

See §9, F-7. A re-scan of a bare blob will "regress" every rule that uses those filters.

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

> **Response:** Agree with the proposal.

### YR-5 — When capture happens  `AGREED` · blocking

The file bytes and the match JSON have hard deadlines (§9, F-5):
- **FP alerts:** `archive()` after 30 days wipes the YARA `scan_results` and deletes derived files'
  `files/` entries. The bytes survive only by accident, in `hardcopies/`, without their names.
- **IGNORE alerts:** deleted entirely after **1 day**.
- **TP alerts:** never archived.

**Proposal:**
- **Trigger:** A new module, `svs_yara_sample_capture`, runs in `analysis_mode_dispositioned`.
  That mode is already requeued by both disposition writers and currently runs **nothing** (§9,
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

> **Response:** The "survive only be accident" is a bug that needs to be addressed! `archive()` is supposed to clean up everything. Agree with the proposal.

> **Round 2 (reviewer):** Agreed. The fix is YR-11. Once it lands, an FP alert's derived bytes are
> truly gone after `fp_days`, so capture at disposition time is not just the preferred option, it
> is the only one.

### YR-6 — Label conflicts across alerts  `AGREED`

The same file (sha256) can be matched by the same rule in many alerts, with different verdicts.
The design says "the sample becomes a TP sample", but a label is really per
`(sha256, rule uuid)`, and several alerts vote on it.

**Proposal:**
- Explicit overrides beat inherited verdicts.
- Among votes of the same kind, if they disagree, the pair is **conflicted**. It is shown in the
  report and excluded from pass/fail until someone relabels it (YR-1).
- The newest vote does not silently win, because a label flip decides pass/fail.

> **Response:** Agree with the proposal.

### YR-7 — Rules without a `uuid`  `AGREED`

A rule without `uuid` meta is attributed to the built-in fallback `YARA_RULE_MATCH`
(`yara.py:73-76`). Every uuid-less rule therefore shares one signature uuid, and their samples
would be pooled under it.

**Proposal:**
- Exclude them from capture.
- List uuid-less rules in the PR report as *not regression-testable*. That also gives the repos
  a nudge toward adding uuids.

> **Response:** Agree with the proposal.

### YR-8 — Sample store: CAS layer, retention, access  `SUPERSEDED by §7` · blocking

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

> **Response:** First, let's go ahead and built a full blown abstract CAS layer for ACE. Propose designs for this idea before we continue.

> **Round 2 (reviewer):** Done. See §7 (CAS-1 to CAS-8). This item's four questions (retention,
> access, encryption at rest, deletion) move there as CAS-4 and CAS-5 in general form. SVS's own
> answers become pool settings once the CAS shape is agreed.

### YR-9 — Isolation of PR rule compilation  `AGREED`

PR rules must never touch the live scanner or `signature_dir`, or validating a PR deploys it. They
are also untrusted input: regex blowups, huge rulesets, pathological conditions.

**Proposal:** The SVS service compiles each uploaded tree into a **private `YaraScanner` instance
in a subprocess**, with a wall-clock timeout, a memory limit, and an upload size limit. It never
goes through the scanner service socket. Compile errors are a first-class report result:
"namespace X failed to compile: all N rules in it are dropped". That is exactly the silent
production failure mode YR-2 point 3 describes.

> **Response:** Agree with proposal.

### YR-10 — The dynamic case (`d(t(Y))`) in regression  `DEFERRED`

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

> **Response:** Yes, I agree.

> **Round 2 (reviewer):** Recorded as D-5: the first version's YARA regression is static only, and
> the dynamic case is covered by test execution.

### YR-11 — `archive()` must actually free derived files  `AGREED`  *(new, round 2)*

This is your YR-5 bug, analyzed. Two defects are in the same code path (`RootAnalysis.archive`,
`saq/analysis/root.py:750-777`; `archive_files`, `local_file_manager.py:239-277`):

1. **Derived bytes are never freed.** Every `files/<path>` is a hardlink to
   `hardcopies/<sha256>`. `archive()` removes the `files/` link of each derived file, but
   `archive_files` skips the `hardcopies/` directory, so the inode keeps its other link and no byte
   is ever reclaimed. Nothing documents or tests keeping them. The code dates from the v1 port.
2. **Files that came with the alert can be deleted.** `retained_files` is always the empty set
   (`root.py:759`). `archive_files` deletes every file in any *subdirectory* of `files/`. A
   root-level file observable whose path has a folder component (`files/attachments/x.pdf`) is
   therefore deleted, even though archive is supposed to keep it.

**Proposal:**
- Build `retained_files` from the root-level file observables (fixes 2).
- After unlinking derived `files/` entries, delete each `hardcopies/<sha>` whose sha is no
  longer referenced by any remaining `files/` entry. Hardcopies of root-level files stay (fixes 1).
  - Bytes are freed only when the inode's last link goes. A cache-replayed file also has an
    analysis-cache blob link, so its bytes live until blob GC. That is correct, since the blob
    belongs to the cache.
- Delete the unused `AnalysisTreePersistence.archive_analysis_details`
  (`analysis_tree_persistence.py:264-290`). It encodes the opposite policy, and it is dead code
  that someone will eventually call.
- Tests: one for each defect. The current tests only check the `untracked/` directory.

This stands on its own. It could ship as its own PR before SVS.

> **Response:** Agree with proposal, and agree with it standing along as it's own PR before SVS.

> **Round 3 (reviewer):** Recorded. It has one visible effect, which goes on the SOC list (S-8):
> after the fix, an archived FP alert's derived files are really gone from disk. Analysts couldn't
> open them through the GUI after archive anyway, because the `files/` link was already removed.
> But anyone who pulled bytes from `hardcopies/` on disk will find them gone.

---

## 5. Test execution (Atomic Red Team)

### ART-1 — Terminology: *test* vs *run*  `AGREED`

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

> **Response:** Agree with proposal.

### ART-2 — Registration API and lifecycle transitions  `AGREED` · blocking

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

> **Response:** Agree with proposal.

### ART-3 — Observation window length  `AGREED`

A fixed window is wrong at both ends. EDR-driven hunts can fire in minutes. A daily hunt with a
24h range needs a day or more.

**Proposal:** Take the window from the test's config when one is set. Otherwise compute it as the
maximum over the test's expected signatures of their worst-case latency. For hunts that is
`frequency + time_range + offset` from the hunt config. Add a configurable slack, and apply a
floor and a ceiling.

> **Response:** Agree with proposal.

### ART-4 — Marker threat model  `AGREED` · blocking

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

> **Response:** Agree with proposal.

### ART-5 — Where ACE looks for the marker  `AGREED` · blocking

"Marker injection" is decided. What isn't decided is the contract between launcher and ACE: where
the marker has to end up for ACE to find it, and where ACE searches. Some facts:
- **No existing search finds a substring in an alert.** Observable lookup is an exact
  `(type, sha256)` match and semantic search is fuzzy (§9, F-10).
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

> **Response:** Yes, I agree with your lean towards routing.

> **Round 2 (reviewer):** Recorded. Context-only attribution routes too, recorded with confidence
> `context`, and shows as the `TEST?` status in ART-14. The question of *where* ACE looks is now
> answered by the engine design in ART-15. The three places listed here become that design's scan
> points, plus a fourth one for file contents.

### ART-6 — When attribution happens and how the queue moves  `SUPERSEDED by ART-15` · blocking

"As soon as ACE is able to make that determination" hits two facts (§9, F-9):
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

> **Response:** Let's investigate a deeper change to ACE here. Investigate building the marker detection directly into the engine, so that the engine can detect the markers as early as possible.

> **Round 2 (reviewer):** Investigated; the result is ART-15, which replaces this item. The short
> version: there *is* a single choke point for every alert insert (`ALERT()`), the event bus is
> unsuitable, and the right shape is a core "alert router" registry. The existing
> `_apply_detection_queue` becomes that registry's first router.

### ART-7 — Alerts that mix test and non-test detections  `AGREED` · blocking

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

> **Response:** Agree with the proposal. Let's start to keep the awareness of the analyst in mind as we start to add indicators that suggest these complex scenarios are in play. Need to keep it simple for the analyst to understand what is happening and what should be done.

> **Round 2 (reviewer):** Agreed, and I've made the "keep it simple" principle an item of its own
> (ART-14) so each later proposal can be checked against it.

### ART-8 — Hunt suppression / dedup / group_by swallow test detections  `AGREED: (a); (b) DEFERRED`

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

> **Response:** Agree with the proposal, but concerned with how complex that is going to be. Let's see how this one goes.

> **Round 2 (reviewer):** A fair concern. The two halves differ a lot in cost, so I suggest staging
> them.
> - **(a) Explain: first version, cheap.** When a run ends with an expected hunt signature
>   *missing*, SVS checks one thing: did that hunt produce an alert (any queue) in the
>   `suppression` period before the run's start? If yes, the result says *missing, possibly
>   suppressed*, not *missing*. That needs only a query on `alerts` by the hunt's signature uuid
>   (`detection_points.signature_uuid` is indexed). It needs no hunter changes. It is imprecise for
>   `group_by` hunts (it can't tell whether *this* group was suppressed) and for `dedup_key`, and it
>   says so rather than guessing.
> - **(b) Prevent: deferred.** Teaching the hunter to bypass suppression and dedup for registered
>   targets touches the grouped suppression path, the duplicate filter and the time-window logic.
>   It also needs the hunter to know active runs at query time. Revisit only if (a) shows that
>   suppression is actually hiding results.
>
> Status: PROPOSED as (a) now, (b) DEFERRED.

> **Response:** Understood. Let's with with (a) for now, with notes to later revisit (b) once we've got this running and have data to review.

> **Round 4 (reviewer):** Recorded (round 3 missed this answer). To make "revisit once we have data"
> concrete, the run review counts the outcomes. The revisit trigger for (b) is: **after the first
> 50 Reviewed runs, or 3 months of runs, whichever comes first**, check what share of *missing*
> results were *possibly suppressed*. If it is material (say over 10%), (b) is worth its
> complexity. If not, it stays deferred. The count lives on the SVS page, so nobody has to remember
> to query for it.

### ART-9 — Test host definition and unregistered-host handling  `AGREED`

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

> **Response:** Yes, I agree.

### ART-10 — What happens to test alerts downstream  `AGREED`

Once an alert is in the test queue, several things still have to be decided:

1. **Disposition.** Which one, and who sets it? It must **not be `IGNORE`**: IGNORE alerts are
   deleted after one day, and test alerts are the best-labeled data SVS will ever see. Options:
   - SVS auto-dispositions a run's alerts at *Reviewed*, with a new disposition such as
     `SVS_TEST` classified *unclassified* in TP-2;
   - or the analyst dispositions them normally.
2. **Keeping them out of history.** Test artifacts must not feed "seen before" logic: observable
   disposition history and prevalence. The only precedent is a hard-coded
   `alert_type != 'faqueue'` filter in three queries (§9, F-11). Should test alerts get their own
   `alert_type`, or should the filter become a generic "excluded from history" flag?
3. **Should an expected YARA hit in a Reviewed run become a TP sample automatically?** It is
   exactly the labeled data regression wants, and it gives YARA regression coverage of techniques.
   I lean yes.

> **Response:** I've merged in main, which has some of this addressed (#2 in particular.) Review again.

> **Round 2 (reviewer):** Reviewed at `6967686c`.
>
> **#2: mostly solved by the merge, if the test queue is not `default`.** PR #587 limits observable
> disposition history to `alerts.queue = 'default'`
> (`saq/database/database_observable.py:53-71, :111-115`). Test alerts land in an SVS queue, so they
> no longer feed "seen before" dispositions, and no new flag or `alert_type` is needed.
> What remains:
> - **Prevalence** (`aceapi_v2/observables/service.py:236-250`) still counts every queue except
>   `faqueue`. Test artifacts (the atomic's dropped file hashes, the test host name) will inflate
>   prevalence. Should prevalence get the same default-queue rule? I'd say yes, for the same reason
>   PR #587 gives. It changes what the endpoint reports for other non-default queues too, so it's a
>   deliberate choice rather than a side effect.
> - **Mixed alerts stay in `default`** (ART-7) and so still count. That is correct: they contain
>   non-test detections.
> - The hunt-validation precedent from the same merge (`TAG_HUNT_VALIDATION`, `aceapi/hunt.py:238`)
>   suggests SVS also tags routed alerts (`svs_test`), so they stay identifiable in search if
>   someone moves them.
>
> **#1 and #3 are still open.** Restated compactly:
> 1. **Disposition of test alerts.** TP-1 answers this one: a run is simulated malicious activity,
>    so its attributed detections are TP. Proposal: when a run is *Reviewed*, SVS dispositions its
>    fully attributed alerts with the kill-chain disposition the analyst picks once per run
>    (default `EXPLOITATION`). A new `SVS_TEST` disposition is not needed. Never `IGNORE`: those
>    alerts are deleted after a day.
> 3. **Expected YARA hits in a Reviewed run become TP samples automatically.** This follows from #1.
>    Once they carry a TP disposition, YR-5 captures them like any other TP alert. The one
>    subtlety: a run's *ignored* detections (launcher noise, ART-13) are benign activity. SVS
>    writes FP overrides (DP-1) for them when it dispositions the run, so they don't inherit TP.

> **Response:** Prevalence should get the same default-queue rule. Disagree with proposal. The disposition doesn't matter here. In a normal alert, the disposition serves two purposes: it defines FP vs TP vs ignored, and in the case of TP, it *also* defines how far into the kill chain the attack was successful. We don't really need to measure that here, so a custom disposition for this is fine.

> **Round 3 (reviewer):** Both accepted.
>
> **Prevalence gets the default-queue rule.** It is a small standalone change in the style of
> PR #587: `_alert_predicates` in `aceapi_v2/observables/service.py:236-250` gains
> `Alert.queue == QUEUE_DEFAULT`. It changes the numbers analysts see for *every* non-default queue,
> not only SVS's, so it goes on the SOC list (S-6).
>
> **A custom disposition for test alerts.** Your reasoning is right: the kill-chain stage is
> meaningless for a simulation, and a dedicated value makes test alerts identifiable forever, even
> after a queue move. For concreteness:
> - **Name.** I suggest `SIMULATED`. It says what happened, not which subsystem did it, and still
>   reads correctly if a test alert is found months later. `SVS_TEST` is the alternative.
> - **Class:** tp (TP-3). This is what makes ART-10 #3 work: YR-5 captures a Reviewed run's YARA
>   hits as TP samples without special-casing.
> - **Set by:** SVS, when a run is *Reviewed*, on the run's fully attributed alerts. Ignored
>   detections get FP overrides as before.
> - **Rank and CSS:** it needs a `disposition_rank` entry for event roll-up. I'd rank it below
>   `GRAYWARE`, so that a test alert never raises an event's disposition above a real one.
>
> **Question:** Should `SIMULATED` be selectable in the normal disposition modal, or set only by
> SVS? I'd hide it from the modal. An analyst who thinks an alert is a test uses ART-13's
> *associate with run*, which sets it through the run review. Otherwise the disposition could
> appear on alerts that no run accounts for.

> **Response:** Agree with proposal, and agree that it should not be selectable in the GUI.

> **Round 4 (reviewer):** Recorded: the name is `SIMULATED`, class tp, ranked below `GRAYWARE`, and
> it is set only by SVS. "Not selectable" needs two things, because hiding it isn't enough:
> - **Config.** A per-disposition flag, for example `analyst_selectable: false`, in the disposition
>   config. The modals (`app/templates/base.html`) list only selectable ones. The disposition list
>   is config-driven after TP-2/TP-3, so this is a schema field, not a special case in a template.
> - **Server side.** `/set_disposition` and `/review_disposition` reject a non-selectable
>   disposition from a user. Today `/set_disposition` validates against the constants
>   (`app/analysis/views/edit/disposition.py`), and it will validate against the config instead.
>   Without this, a hand-crafted POST could set it. SVS sets it through `set_dispositions()`
>   directly, as the automation user.
>
> One consequence for analysts goes on the SOC list (S-7): analysts can't set `SIMULATED` by hand.
> They *can* change a `SIMULATED` alert to another disposition, but the alert then stays attached to
> the run, in the test queue. The right way out is *Disassociate from run* (ART-13), which moves the
> alert back to its previous queue and clears the disposition for normal triage.
>
> **Question (small):** Should the modal block changing a `SIMULATED` alert's disposition, and point
> to *Disassociate* instead? I'd block it. Otherwise a real alert can end up dispositioned in the test
> queue, where no analyst looks.

> **Response:** Agree with your suggestion.

### ART-11 — Expectations come from measurement, not declared techniques  `AGREED` · blocking

*(Round 1 title: "Technique-derived expectations are too broad". Rewritten in round 2 after your
answer. The round 1 text stays below for the record.)*

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

> **Response:** In my opinion, the mapping should come from actual test results. The mitre attack technique framework is too large for a human to fully comprehend and correctly categorize. So I feel as though the existing mappings in the signatures should actually just be ignored. We could surface when they differ from real test results as an option, but I feel like with a system like SVS in place, it should just be measured. If a signature cannot be measued with SVS, *then* manual application of technique makes sense I guess.

> **Round 2 (reviewer):** Agreed. This is a stronger position than the design's current decision
> ("derived first from declared techniques, then hand-edited"), so §10 D-9 replaces that line. The
> model, rewritten:
>
> **Where each fact comes from:**
>
> | Fact | Source | Trusted? |
> |---|---|---|
> | test → technique | the atomic's own YAML (`atomics/T1059.001/...`) | Yes. The test is defined by the technique it exercises. |
> | test → expected signatures | **learned from Reviewed runs**, confirmed by an analyst | Yes, once confirmed. |
> | signature → technique (measured) | derived: techniques of the tests where the signature is *expected* | Yes. |
> | signature → technique (declared) | `mitre_attack` meta / `mitre:` tags in the signature repos | **Ignored**, and shown only as a diff |
> | signature → technique (manual) | an analyst, in ACE, for signatures SVS cannot measure | Yes, but labeled *manual* |
>
> **How expectations are learned:**
> 1. **Discovery.** The first Reviewed run of a test proposes every attributed signature (minus the
>    ignore lists, ART-13) as a *candidate* expectation. The analyst accepts or rejects each one in
>    the run review. Accepted means *expected*.
> 2. **Steady state.** Each later run compares against the expected set:
>    - an expected signature that didn't fire is *missing* (see ART-8 for the suppression caveat);
>    - a signature that fired and isn't expected is a new *candidate*;
>    - a rejected candidate is remembered, so it isn't proposed again for that test.
> 3. **No automatic demotion.** A signature that goes missing is a finding, not a reason to lower
>    the expectation. The run history shows flakiness (for example, missing in 2 of the last 5
>    runs), and only an analyst removes an expectation.
>
> **Declared techniques become an optional diff:** *declared but never measured* and *measured but
> not declared*. That diff is useful as a clean-up list for the signature repos, and it influences
> nothing.
>
> **Questions:**
> 1. **Where do manual mappings live?** You said declared tags are ignored. For *unmeasurable*
>    signatures (most email and file-content rules: no atomic produces their telemetry), the
>    options are:
>    - **(a)** a mapping table in ACE, edited in the SVS GUI;
>    - **(b)** the signature's own `mitre_attack` meta, trusted only when the signature has no
>      measurement.
>
>    (b) keeps the knowledge with the signature and needs no new GUI. (a) keeps "the signature repos'
>    tags are ignored" absolute. I lean (b). The rule "declared counts only when unmeasurable" is
>    simple to state, and it avoids a second place to maintain the same data.
> 2. **How does ACE know a signature is unmeasurable, as opposed to not yet measured?** I suggest
>    an explicit flag rather than inference. An analyst marks it, or a signature family is marked
>    unmeasurable as a whole (for example, all email-content YARA namespaces). Inference ("never
>    fired in any run") can't tell *untested* from *untestable*.

> **Response:** The manual mappings should live in the signature's meta (b). The manual mapping becomes the explicit flag, so if it ends up actually getting measured later, it should be brought to the analysts attention that a signature was manually marked but showed up in a test.

> **Round 3 (reviewer):** Accepted: manual mappings live in signature meta, and a manual mapping *is*
> the "unmeasurable" flag. That removes question 2, since there is no separate flag to maintain.
>
> **Surfacing "manually mapped, but measured".** A signature with a manual mapping that fires in a
> Reviewed run is flagged in that **run review**, not on the alert (ART-14 keeps SVS off the alert
> page). The flag reads: *"Signature S carries a manual mapping to T1234 but was measured in test
> X (T5678). Remove the manual mapping, or keep it if it covers a technique no test reaches."* The
> same list appears in the coverage hygiene report until it is resolved.
>
> Once a signature is measured, its manual mapping could be ignored, as "measurement wins" suggests,
> or unioned with the measured techniques. I suggest **union, flagged**: the manual mapping keeps
> counting until someone removes it. A measurement proves the signature detects T5678. It doesn't
> prove the manual claim about T1234 wrong, since no test may reach T1234.
>
> One thing needs settling first: *which* meta key. That is ART-16, because it interacts with your
> round-1 answer.

### ART-16 — Which meta key carries a manual technique mapping  `AGREED: (a)` · blocking  *(new, round 3)*

Two of your answers pull in different directions, depending on the key:
- **ART-11, round 1:** *"the existing mappings in the signatures should actually just be ignored."*
- **ART-11, round 2:** *"manual mappings should live in the signature's meta … The manual mapping
  becomes the explicit flag."*

If the manual mapping reuses the **existing** key (`mitre_attack` in YARA meta; `mitre:` tags in
hunts), every signature that has one today becomes "manually mapped, unmeasurable" on day one. So
the mappings you wanted ignored would count after all, and every one of them would also be flagged
the first time it is measured.

**Options:**
- **(a) Reuse the existing keys.** Accept that today's tags become manual mappings, and clean them
  up through the "manually mapped but measured" flag as tests arrive. No repo changes.
- **(b) A new, SVS-specific key** that means "a person asserts this technique and SVS can't measure
  it". For example `svs_technique = "T1566.001"` in YARA meta, and `svs_techniques: [...]` in hunt
  YAML.
  - Existing `mitre_attack` / `mitre:` stay what they are today: descriptive tags that SVS ignores,
    and that feed only the declared-vs-measured hygiene diff.
  - Adding the new key is a deliberate act, so it really is the explicit flag you described.

**I recommend (b).** It is the only option that honors both answers, and "this signature is
unmeasurable" is a stronger claim than "this is about T1566", so it deserves its own word. The
inventory loaders (`saq/signatures/loaders/yara.py`, `hunt.py`) read the new key next to the
existing ones. `HuntConfig` rejects unknown keys (`saq/collectors/hunter/base_hunter.py:66-67`), so the new hunt
field has to be added there before any hunt can use it.

> **Response:** I was going back and forth on that. Let's go with (a).

> **Round 4 (reviewer):** Recorded. What (a) means in practice:
> - **No loader or schema changes.** The YARA inventory loader already turns `mitre_attack` meta into
>   `mitre:` tags (`saq/signatures/loaders/yara.py:39-71`), and hunts carry `mitre:` tags in their
>   existing `tags`. The phase-1 note about reading a new key is dropped (X-4).
> - **Day one: every tagged signature is "manual".** Coverage (COV-1) starts with those techniques
>   in the *manual* state, which is an honest picture of today (claimed, not measured). It fills in
>   with *validated* / *failing* as runs are reviewed.
> - **The "manually mapped but measured" flag is the clean-up mechanism, so it will be busy early.**
>   Nearly every signature that fires in a run already carries a tag. To keep the run review usable:
>   - flag once per *signature*, not per run;
>   - group the flags into a single "declared vs measured" worklist on the coverage page rather than
>     in each run review;
>   - resolving a flag is one of: *tag confirmed* (the measured technique equals the tag), *keep
>     tag* (it covers something no test reaches), or *remove tag* (a PR to the signature repo; ACE
>     only records the intent).
>
>   *Tag confirmed* resolves automatically when measured and declared agree, which should be the
>   common case.
> - **Union rule (ART-11 round 3) still applies.** A tag counts until someone resolves it as
>   *remove*. So your round-1 wish, measurement wins, is reached through the worklist rather than by
>   discarding tags up front.

### ART-12 — Why ACE holds the ART repos, and what it parses  `AGREED`

Execution is out of scope, so ACE needs the ART repos only as a **catalog**, for four things:
- validating `test_guid` at registration;
- test names and descriptions for display;
- `supported_platforms`;
- techniques, for ART-11.

**Proposal:**
- Each repo is an ordinary `git_repo_<name>` section, so `GitManagerService` polls it (§9, F-12).
- SVS parses `atomics/T*/T*.yaml` into a catalog table on change. `GitManagerService` has no
  post-update hook, so SVS compares HEAD commits.
- Custom repos must follow the ART YAML schema and must carry `auto_generated_guid`. Tests without
  one are skipped with a warning.
- A GUID that disappears from the catalog keeps its historical runs.

> **Response:** Agree with proposal.

### ART-13 — Launcher noise vs per-test ignores; manual (re)association  `AGREED`

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

> **Response:** Agree with proposal.

### ART-14 — Keep the analyst's view simple: one SVS status per alert  `AGREED` · blocking  *(new, round 2)*

Your ART-7 point, made concrete. SVS adds several situations an analyst could meet (routed,
partially attributed, context-only, marker mismatch, suppressed). Each one shown as its own
indicator adds up to noise. Proposal: **every alert has at most one SVS status**, from a closed
list. Each status has a one-line meaning and one action, and alerts that SVS never touched show
nothing at all.

| Status | Meaning | Queue | What the analyst does |
|---|---|---|---|
| `TEST` | Every detection is attributed to run *R* by marker. | SVS | Nothing. Review happens in the run review, not the alert. |
| `TEST?` | Attributed to run *R* by context only (no marker). | SVS | Nothing, unless it looks wrong. One click: *not a test*. |
| `PARTIAL TEST` | Some detections are from run *R*, others are not. | normal | Triage as usual. Test detections are greyed out and labeled, so only the rest need attention. |
| `MARKER MISMATCH` | A marker is present that doesn't fit its context (ART-4 rule 2). | normal | Treat as suspicious and investigate. This one is meant to be loud. |

Rules that keep it simple:
- The status appears as one badge in the manage list and one banner on the alert page. It always
  links to the run.
- Wording states the action, not the mechanism. For example "Part of test run *R*: no action
  needed", not "attribution confidence: marker".
- Everything else (confidence, per-detection attribution, suppression notes, late arrivals) lives
  in the **run review**. The run review is the SVS operator's screen; the alert page is the
  analyst's.
- Any new SVS indicator proposed later has to fit one of these four statuses or justify a fifth.

> **Response:** Agree with proposal.

### ART-15 — Engine-native marker detection through an alert-router registry  `AGREED` · blocking  *(new, round 2)*

This replaces ART-6. It is the investigation you asked for there.

**What the code allows** (verified at `6967686c`):
1. **`ALERT()` is a true choke point.** `saq/database/util/alert.py:167` is the only code that
   inserts into `alerts`. All seven callers go through it: engine conversion, `submit_local` for
   collectors, API submit, hunt validation, CLI hunt/correlate/import, and GUI upload. Every
   caller's root has its observables and `root.details` loaded at that moment. `ALERT()` copies
   `root.queue` into the row, so a queue decided here is in place **before any analyst can see the
   alert**.
2. **The analysis event bus is the wrong tool.**
   - `TAG_ADDED`, `DETAILS_UPDATED` and `DETECTION_ADDED` are declared but never fired.
   - Nothing fires when a tree is loaded from JSON, and the engine always loads from disk.
   - Listeners don't survive the hunter's stage-to-disk and `duplicate()` steps.

   Making the bus reliable is a larger project than SVS needs.
3. **The engine has no hook list.** Per-root logic (`_check_disposition`, `_apply_detection_queue`,
   the whitelisting checks) is hard-coded in the orchestrator. The closest registry precedent is
   `hunter.correlation.command_types` (`saq/collectors/hunter/correlation/command_types.py`): config
   entries with `python_module`/`python_class`, one failing entry isolated from the others, and
   loaded once at startup.
4. **The `valid_queues` collision from ART-6 is not a problem.** Only the unit-test config sets
   `valid_queues`/`invalid_queues`, so moving a queue changes no production module's behavior.
5. **`alerts.queue` is never updated after insert** (F-9).

**Proposal — a core alert-router registry with two stages:**
- **Interface.** `AlertRouter.route(root, stage) -> RouteDecision | None`. A decision is
  `{queue, reason, router}`. Routers are registered like correlation command types: built-ins plus
  `alert_routers:` config entries. They run in priority order, the first decision wins, and an
  explicitly set `root.queue` (submission or hunt override) is never overridden.
- **Stage `PRE_INSERT`**, inside `ALERT()` before `create_from_root_analysis`. It covers every
  insert path.
  - For alerts the engine converts after analysis (email, file submissions), the root at this
    point is the **fully analyzed tree**, so every marker the analysis surfaced is already visible.
    That is the "as early as possible" you asked for: those alerts never appear in the wrong queue.
- **Stage `POST_ANALYSIS`**, in the orchestrator after each analysis pass. It exists for the one case
  `PRE_INSERT` can't see: alerts inserted at submission time (hunts, API) where the marker appears
  only after analysis (a decoded command line, an extracted file). A decision here moves the
  existing alert through a new primitive.
- **`move_alert_to_queue(alert, queue, reason, actor)`** updates the column and `root.queue`,
  touches the alert, refreshes the search payload, writes an audit line, and records the previous
  queue so that "disassociate" (ART-13) can move the alert back.
- **`_apply_detection_queue` becomes the first built-in router**, with the same all-or-nothing rule.
  Running it at `PRE_INSERT` also closes its current blind spot: it never runs for hunt alerts
  (F-9). Its output shouldn't change in practice, since a hunt's own detection has no queue meta.

**The SVS marker router, and where it looks** (ART-5's list, made concrete):

| Scan point | Covers | Mechanism |
|---|---|---|
| Observable values and file names, `root.details` | Hunt raw events, API details, command lines, URLs | Regex at `PRE_INSERT` and `POST_ANALYSIS` |
| Each new analysis's `details`, as it is produced | Decoded or deobfuscated output from modules | An executor hook right after a module returns (`executor._execute_module_analysis`). It scans only the new analysis and the observables it added, and records the markers found in root state. The event bus is not needed. |
| File **contents** | A marker inside a dropped script or document | No engine file reads. A built-in YARA rule matches the marker format (`no_alert`); its match strings land in `YaraScanResults.details`, which the previous row already scans. |

Found markers are resolved against registered runs with a short-TTL per-process cache. The ART-4
context rules are then applied, and the router returns the SVS queue, nothing, or the mismatch
handling. Attribution rows (run ↔ alert ↔ detection `content_hash`, confidence) are written at the
same time.

**Move policy for alerts already being worked** (analyst awareness, ART-14): a `POST_ANALYSIS` move
happens only while the alert is `OPEN` **and unowned**. If an analyst has already taken it, the
alert stays put and gets the `TEST`/`TEST?` badge instead. Pulling an alert out from under someone
is worse than leaving it.

**Questions:**
1. Accept the registry (core, generic) with SVS as one router, rather than SVS-specific code in
   the orchestrator?
2. Accept the move policy for owned alerts?
3. Should the registry be open to integrations from day one (`alert_routers:` config), or
   core-only until a second consumer appears? I'd open it. The pattern already exists, and "route
   alerts from vendor X to queue Y" is a recurring ask.

> **Response:** Agree with proposal. Answers to questions: 1) Yes. 2) Yes. 3) Yes, open from day one.

> **Round 3 (reviewer):** Recorded as D-13. Opening it from day one means the `alert_routers:`
> config schema and the `AlertRouter` interface are public API. They get a section in
> `docs/INTEGRATIONS.md` next to "Extending correlation hunts", and the example integration gets a
> trivial router, so the contract is tested from outside core.

---

## 6. Coverage

### COV-1 — The Coverage subsystem  `AGREED` · blocking

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
  commit changes them (§9, F-6). A per-rule `content_hash` is the better staleness key.
- Is coverage per company/tenant? Alerts carry one `company_id`.

> **Response:**

> **Round 2 (reviewer):** No response yet. ART-11's rewrite changes the strawman, because "claimed"
> was built on the declared tags that are now ignored. Revised strawman:
>
> - **Grain:** technique × environment, rolled up to the parent technique. Coverage *of a
>   technique* is computed from tests; coverage *by a signature* is its measured techniques.
> - **States per technique:**
>
>   | State | Meaning |
>   |---|---|
>   | **validated** | At least one test for the technique has expectations, and its latest Reviewed run hit all of them. |
>   | **failing** | The latest Reviewed run of a test for it had a *missing* expected signature. |
>   | **stale** | Validated, but since that run an expected signature's per-rule `content_hash` changed, or the test changed. |
>   | **untested** | Atomics exist for it, but none has a Reviewed run with accepted expectations. |
>   | **manual** | No measurement is possible; a signature is mapped manually (ART-11 Q1). |
>   | **none** | No atomics and no manual mapping. |
>
> - **What *failing* means.** An expected signature was missing *in a test of this technique*. It
>   does not mean the technique is undetected, because other tests or signatures may cover it. The
>   drill-down shows which.
> - **ATT&CK catalog.** Pin one ATT&CK release as a config input, and map revoked or renamed
>   techniques on upgrade. Only needed for names and roll-up. ART supplies the technique ids.
> - **Removed.** *Claimed* is gone. The declared-vs-measured diff from ART-11 is a signature-repo
>   hygiene report, not a coverage state.
>
> The two questions above remain. The first is answered: use the per-rule `content_hash`, not the
> repo commit, which is how *stale* is now defined.

> **Response:** Agree with proposal.

> **Round 3 (reviewer):** Recorded. Two follow-ups:
> - **Tenant question.** It went unanswered, so I'm recording a default: **coverage is global, not
>   per company**. Test hosts are one lab, and splitting results by `company_id` would need test
>   hosts per company. Say so if that's wrong.
> - **ART-11 round 3 changes one state.** Manual mappings now union with measured ones and are
>   flagged. A technique covered *only* by a manual mapping stays **manual**, even if the signature
>   was measured for other techniques. That matches the table as written.

### COV-2 — Goal 2 (the telemetry exists) has no mechanism  `AGREED: goal 2 dropped` · blocking

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

> **Response:** Let's drop goal 2.

> **Round 2 (reviewer):** Recorded as D-4. The goals list at the top of `SVS_INITIAL.md` should drop
> its second bullet, and ART-8 (a)'s *possibly suppressed* is the only diagnosis of a *missing*
> result that SVS will offer. A *missing* detection then stays deliberately ambiguous between "no
> telemetry" and "no match". The run review should say that in one line, so nobody reads *missing*
> as "the signature is broken".

---

## 7. Content-addressed storage (CAS)  *(new, round 2)*

In YR-8 you asked for a full abstract CAS layer for ACE, designed before we continue. This section
proposes one. SVS samples are its first consumer, but nothing here is SVS-specific. Once we agree,
it should move to its own `docs/CAS.md`, and SVS will refer to it.

**What ACE does with bytes today** (verified at `6967686c`):

| Store | Key | Encrypted | Retention | Backend | Known problems |
|---|---|---|---|---|---|
| Alert `hardcopies/` | `<storage_dir>/hardcopies/<sha256>`, hardlinked from `files/` | no | life of the alert; never freed on archive | local, per node | YR-11; no dedup across alerts |
| Analysis-cache blobs (`saq/analysis/blob_store.py`) | `<root>/<sha[:3]>/<sha>` + `blob_refs` | no | references expire with their ~35-day partition | local only (pluggable, no S3 implementation) | GC race; duplicate reference rows (F-21) |
| Email archive (`saq/email_archive/`) | `<sha[:2]>/<sha>.gz.e`, S3 key = sha | AES-GCM, system key | 30 days (DB, files); **S3 objects never deleted** | local + S3, own factory | F-23 |
| Crash report bytes | `crash_reports/…/<crash_id>/file/<name>` | no | 30 days | local; optional replication via `saq/storage` | — |
| YARA `qa_dir` | `var/qa/<rule>/<file>-<sha>` | **no, live malware in plaintext** | **never cleaned** | local | F-14 |
| phishkit / js_deobfuscator volumes | per job | no | 3 days / **never** | Docker volume | F-22 |
| `saq/storage` (general) | bucket + path | no | caller's job | local, S3, custom | F-13, F-18, F-19 |

There are four independent sha256-keyed stores, three retention mechanisms and one encryption
scheme, and nothing in ACE can keep a byte "until I say so".

### CAS-1 — Scope and consumers  `AGREED` · blocking

- **Goal:** one subsystem that all ACE code uses to store **immutable bytes by content**. Policy is
  set per use: retention, encryption, backend, and sharing between nodes. Lifecycle is correct: no
  byte is deleted while something holds it, and nothing lingers once nothing does.
- **First consumer:** SVS YARA samples.
- **Designed to absorb later** (CAS-8): analysis-cache blobs, the YARA QA copies, crash report
  bytes, the email archive, and alert hardcopies (dedup across alerts).
- **Non-goals:**
  - mutable objects;
  - alert storage directories as a whole (the JSON trees stay as files);
  - a user-facing browser;
  - dedup across pools with different encryption (CAS-5).

> **Response:** Agree with proposal.

### CAS-2 — Three candidate designs  `AGREED: C` · blocking

| | **A. Thin library on `saq/storage`** | **B. Promote the analysis-cache `BlobStore`** | **C. New `saq/cas/`: pools + holds** |
|---|---|---|---|
| Shape | Key `<prefix>/<sha[:2]>/<sha>` on the existing bucket API. No DB. Each consumer keeps its own references; GC is mark-and-sweep, asking every consumer which digests it still needs. | Move `blob_store.py` to core, add an S3 backend, keep `reference(sha, kind, id)`. | Pools (named policies) + holds (explicit references) + an index table that is authoritative for existence. Backends are dumb byte stores. Keeps B's API shape. |
| For | Smallest. No new tables. Reuses the backend crash replication uses. | The API is already the right shape (put/get/materialize/reference). The analysis cache moves over trivially. | Per-use policy. Correct GC. Permanent and legal holds. Encryption per pool. GC never has to list S3. The analysis cache can move later as a TTL pool. |
| Against | `saq/storage` needs fixing and extending anyway: file paths only, no put-if-absent, `object_exists` reports False on a 403, non-atomic local writes. Mark-and-sweep over S3 means listing the bucket, and every consumer has to implement enumeration. There is nowhere to keep per-object facts (size, key id, last verified). | Inherits the model. References live in the partitioned cache DB and **expire at 35 days by design**, which is wrong for permanent samples. It also inherits the exists-then-reference GC race and the duplicate reference rows. No pools means one policy for everything. No encryption. | The most work: new tables, a backend protocol, GC, CLI and cron. Migrating existing stores is separate (and deferred). |

**Recommendation: C.** A and B each end up rebuilding most of C once a second consumer with a
different policy arrives. The analysis cache (TTL, high volume, plaintext, hardlinks) and SVS
(permanent, low volume, encrypted, shared) are opposite ends of that range already.

**Question:** C?

> **Response:** Agree with C.

> **Round 3 (reviewer):** Recorded as D-14. With CAS-1 to CAS-6 agreed, the CAS is designed well
> enough to move out of this review. I suggest writing `docs/CAS.md` as part of the CAS PR (phase 0),
> with this section as its source, and leaving a pointer here.

### CAS-3 — Data model and API (design C)  `AGREED` · blocking

**Tables** (main DB; CAS-7):
- `cas_objects(pool, digest CHAR(64), size, stored_size, key_id NULL, created_at, last_held_at,
  verified_at NULL, state ENUM('present','deleting'))`, primary key `(pool, digest)`.
- `cas_holds(pool, digest, holder_kind VARCHAR(32), holder_id VARCHAR(128), created_at,
  expires_at NULL, created_by NULL)`, primary key `(pool, digest, holder_kind, holder_id)`.
  - There is **no timestamp in the key**, which fixes `blob_refs`' duplicate rows.
- `cas_purges(pool, digest, reason, actor, purged_at)`: audit of forced deletions.

**API sketch:**

```python
pool = get_cas().pool("svs_samples")

digest = pool.put(src, hold=Hold("svs_sample", sample_id))  # src: path | bytes | BinaryIO
                                                            # atomic, idempotent, hashed while writing
pool.hold(digest, Hold("svs_sample", other_id))
pool.release(digest, Hold("svs_sample", sample_id))

with pool.open(digest) as stream: ...        # verified (sha / GCM tag) before any byte is released
pool.materialize(digest, dest_path)          # hardlink if local + plaintext, else decrypt / download
pool.exists(digest); pool.stat(digest)
pool.purge(digest, reason="…", actor=user)   # forced delete across holds, audited in cas_purges
```

- The **digest is the sha256 of the plaintext**. If the caller passes the digest it expects, a
  mismatch fails the `put`. This is the check the analysis cache does today by hand.
- `put(..., hold=…)` is atomic with respect to GC (CAS-4). There is no window between "exists" and
  "reference".
- CLI: `ace cas pools | stat | get | verify | gc | purge | orphans`. Cron: `gc` hourly and a
  sampled `verify` weekly, as `etc/cron/{hourly,weekly}/` tasks.

**Config sketch:**

```yaml
cas:
  pools:
    svs_samples:
      backend: s3            # or local | custom {python_module, python_class, config}
      bucket: ace-svs-samples
      encryption: system     # none | system  (CAS-5)
      retention: held        # held | ttl | permanent  (CAS-4)
      grace_seconds: 86400
      shared: true           # refuse a node-local backend (CAS-6)
```

> **Response:** Agree with proposal.

### CAS-4 — Retention, holds, GC correctness  `AGREED` · blocking

**Retention modes** (per pool):

| Mode | An object lives while… | Intended for |
|---|---|---|
| `held` | it has at least one unexpired hold, plus `grace` | SVS samples |
| `ttl` | `last_held_at + ttl` has not passed; any use *touches* it; holds optional | caches (the analysis cache later), without a row per reference at cache volume |
| `permanent` | always; only `purge` deletes | reference sets, if ever needed |

A **legal hold** is a hold with `holder_kind='legal_hold'` and no expiry, set by `ace cas hold` /
the API with its own permission.

**GC without races:**
1. A candidate is a `present` object with no live holds and `last_held_at < now - grace`.
2. One conditional statement flips it: `UPDATE cas_objects SET state='deleting' WHERE … AND
   state='present' AND NOT EXISTS (live hold)`. If zero rows change, skip it: someone took a hold
   in the meantime.
3. Delete the bytes, then the row.
4. `put` and `hold` lock the object row (`SELECT … FOR UPDATE`). A `put` that finds `deleting`
   waits for the row to go and re-uploads. Hold creation and the GC flip therefore serialize on
   one row. This closes the analysis cache's "exists → GC → reference" window.

**Order of writes on `put`:** bytes first, then the row and the hold. A crash in between leaves
orphan bytes, which `ace cas orphans` sweeps by listing the backend occasionally. It never leaves a
row pointing at nothing. GC itself never lists the bucket.

**Questions:**
1. **Purge vs legal hold.** Should `purge` refuse while a legal hold exists? I'd say yes, and
   require the legal hold to be released first by someone with that permission.
2. **Who can purge?** I suggest a permission `cas:purge`, separate from any pool's read
   permissions.

> **Response:** Agree with proposal. 1) Yes, require hold to be released. 2) Agree with permission.

### CAS-5 — Encryption and object naming  `AGREED` · blocking

- **Per pool:** `none`, or `system`, which reuses `saq/crypto.py`'s AES-256-GCM with the system
  data key.
- **`saq/crypto` needs two changes before long-lived blobs rely on it:**
  1. A header with a format version and a **key id**, bound as authenticated data (AAD). Today the
     header isn't authenticated, and there is no key id, so the data key can never be rotated.
  2. **Verify before release.** Today `decrypt()` streams plaintext into the destination before
     the GCM tag is checked (`saq/crypto.py:199-231`). The CAS decrypts to a temp file and renames
     it only after the tag verifies.
- **Dedup still works.** Identity is the plaintext sha256. The ciphertext differs per write
  (random nonce), but a pool writes each digest only once.
- **SSE on S3 is complementary, not a substitute.** It protects the disks, not the bucket
  credentials.
- **Object naming.** Plain `<sha[:2]>/<sha>` names tell anyone who can *list* the bucket exactly
  which hashes ACE holds. That is harmless for malware, but it confirms the presence of a known
  customer document. The alternative is `name = HMAC(pool key, digest)`. Since the index is
  authoritative anyway, the only cost is that operators can't map a bucket key to a hash by eye.

**Questions:**
1. Plain or HMAC object names for encrypted pools? I lean HMAC for encrypted pools and plain for
   the rest.
2. Is one system key per ACE acceptable for all encrypted pools, or do you want a key per pool,
   derived from the system key with HKDF and the pool name? Per-pool derivation is cheap and limits
   what one leaked derived key exposes. I'd do it.

> **Response:** Plain is fine, and one system key is also fine.

> **Round 3 (reviewer):** Recorded: plain object names and the single system key. The two
> `saq/crypto` fixes weren't questioned and stay in scope:
> - **Verify before release** is a correctness fix that stands on its own.
> - **The key-id header** is still worth having with one key, because it is what makes rotating
>   that key possible later without re-encrypting everything in one go. It costs a few bytes per
>   object.
>
> Both are backwards-compatible if the header carries a version and old-format files keep
> decrypting. The email archive's existing `.gz.e` files depend on that.

### CAS-6 — Backends and the relationship to `saq/storage`  `AGREED: (b)` · blocking

**Options:**
- **(a) Build CAS backends on `saq/storage`.** Extend `StorageInterface` with stream put/get,
  put-if-absent, and an `exists` that tells 403 from 404.
  - For: one S3 configuration; custom backend loading already exists; crash replication gets the
    fixes.
  - Against: it widens a general file API around CAS-specific guarantees.
- **(b) A small CAS backend protocol of its own:** `write(key, stream)` (atomic, if-absent),
  `open(key)`, `delete(key)`, `iter_keys(prefix)`, and an optional `link(key, dest)`
  capability. Local and S3 implementations share `get_s3_client()`, which already honors
  `s3.secure`, `cert_check` and `region`, unlike the `saq/storage` factory.

**I lean (b).** The CAS's needs are narrower and stricter than a general file API. `saq/storage`'s
defects (F-13, F-18, F-19) should be fixed regardless, since crash replication uses it.

**Backend facts that hold either way:**
- **Local.** Temp file, `fsync`, then `rename` in the same directory, under
  `<root>/<pool>/<sha[:2]>/<sha[2:4]>/<name>`. Supports `link` for plaintext pools, which keeps the
  analysis cache's hardlink trick available.
- **S3.** Conditional writes (`If-None-Match: *`) avoid redundant uploads. If the object store in
  use doesn't support them (check your S3/MinIO version), a redundant upload of identical content
  is harmless, because the index decides existence.
- **Multi-node.** A local backend is node-local. A pool declared `shared: true` refuses one at
  config validation. SVS samples must be shared, because they are captured on whichever node
  analyzed the alert and scanned by the SVS service.
- **Read cache.** `materialize` from S3 goes through a bounded node-local LRU directory, because
  YARA and most analysis tools need a file path.

**Question:** (a) or (b)?

> **Response:** Agree with (b).

### CAS-7 — Where the CAS index lives, and how it is pruned  `AGREED`

**Proposal:** the main ACE DB (`Base` chain) for the first version.
- SVS rows (samples, verdicts) live there, and joins from a sample to its `cas_objects` row are
  useful.
- The analysis cache's volume argues for keeping *its* index in the cache DB when it migrates.
  So the tables are designed so that a pool's index can live on another chain (the pool config
  names it). The decision about which chain is deferred until that migration.

> **Response:** Agree with proposal, however, take a note to measure performance on large CAS stores with regards to pruning. In the past we stored email archive reference data in the database, and when we went to prune it, the operation would take forever and block inserts. We switched to a more complicated pruning which solved that issue. Review that before you decide to agree with my agreement of your proposal.

> **Round 3 (reviewer):** Reviewed. Your instinct is right, and it changes the proposal, though not
> for SVS's own pool.
>
> **What the email archive does now** (`bin/manage-email-archive-partitions.sh`, fixed in
> PR #601). `archive`, `archive_index` and `email_history` are `PARTITION BY RANGE COLUMNS(insert_date)`
> with one partition per ISO week plus a `p_catchall`. A weekly cron drops whole partitions older
> than 30 days (`ALTER TABLE … DROP PARTITION`) and creates the next weeks ahead. The analysis cache
> does the same with daily partitions for `blob_refs`
> (`bin/manage-analysis-result-cache-partitions.sh`).
>
> **Why that works:** dropping a partition is a metadata operation. It takes no row locks, writes
> no undo log, and doesn't block inserts. The `DELETE … WHERE insert_date < cutoff` it replaced
> locked and logged every row it touched, for as long as it ran, which is what blocked inserts.
>
> **What that means for the CAS:**
> 1. **Partition dropping only fits time-based expiry.** It works when everything older than X goes.
>    A `held` pool expires by *reference*: an object goes when its last hold is released, whenever
>    that is. So `held` pools can't prune by dropping partitions. They need row deletes, which is the
>    pattern that hurt before.
> 2. **The difference is churn.** SVS samples are low volume (thousands to tens of thousands) and
>    nearly permanent, so a GC pass deletes a handful of rows. The email archive deleted millions of
>    rows a week. The analysis cache, the likely second CAS consumer (CAS-8), is closer to the
>    email archive than to SVS.
>
> **Revised proposal:**
> - **No unbounded `DELETE`, ever.** CAS GC deletes in primary-key order, in batches of at most N
>   rows (say 500), one short transaction per batch, with a pause between batches. The "flip to
>   `deleting`" step in CAS-4 already works one object at a time, so this is a rule for the sweep
>   loop, not a redesign. A code-review rule for the CAS module says the same.
> - **Pools declare a churn class**, and the class decides the index layout:
>   - **`held` pools (low churn), such as SVS:** tables in the main DB as proposed. Batched row
>     deletes.
>   - **`ttl` pools (high churn), such as the analysis cache:** an **append-only, day-partitioned
>     touch table** (`INSERT IGNORE (day, digest)`) instead of updating `last_held_at` on every use.
>     Expiry drops old partitions, exactly like the email archive and `blob_refs`. GC then removes
>     `cas_objects` rows that have no touch left, in batches. These tables live in the pool's own
>     chain (the cache DB for the analysis cache), never the main DB, so any lock contention stays
>     away from alert inserts.
>   - This also avoids a hot-row problem: a `ttl` pool that updated `last_held_at` on every cache
>     hit would turn each read into a write on a shared row.
> - **MariaDB constraints to design around.** A partitioned table must include the partition column
>   in every unique key, and it can't have foreign keys. So `cas_touches` has no FK to
>   `cas_objects`, and its key is `(day, pool, digest)`.
> - **Measure before migrating** (your note, made a gate). Before the analysis cache moves to the CAS
>   (CAS-8 step 3), run a load test: a synthetic pool at production cache volume (millions of objects,
>   a day of churn), with GC running while a writer inserts at peak rate. Record insert latency with
>   and without GC. Nothing migrates until insert latency is flat under GC. I've added this to the
>   CAS-8 plan.
>
> For the SVS pool this changes nothing except the batched-delete rule. The partitioned design
> matters from the first high-churn pool on, and it is recorded now so that the SVS-first
> implementation doesn't bake in a layout that has to be undone.

> **Response:** Agree with your revised proposal.

> **Round 4 (reviewer):** Recorded as D-18. When `docs/CAS.md` is written, the batched-delete rule
> and the churn classes go in its "operating constraints" section, with a pointer to the
> email-archive history as the reason. That history is the kind of thing that gets forgotten and
> relearned.

### CAS-8 — Migrating the existing byte stores  `DEFERRED`

This is not needed for SVS, but it is the payoff of CAS-1. Suggested order, from least to most
risk:
1. **SVS samples** (new, nothing to migrate).
2. **YARA `qa_dir` → pool `yara_qa`.** This fixes the plaintext live malware, the missing cleanup
   and the copy bug (F-14) at once.
3. **Analysis-cache blobs → a `ttl` pool.** This fixes the GC race. It keeps hardlinks through the
   local backend's `link`.
4. **Crash report bytes.**
5. **Email archive.** It has its own DB and retention semantics, so moderate work.
6. **Alert hardcopies → cross-alert dedup.** This is the largest disk win and the largest blast
   radius: node-transfer tarballs, archive and hardlinks all change. It goes last.

> **Response:** Agree with proposal, but, let's keep our effort focused on SVS right now.

> **Round 3 (reviewer):** Agreed. Only the SVS pool is built now. Two things from this round are
> recorded so they aren't lost when the migration starts:
> - **The analysis-cache migration (step 3) is gated on the GC load test** in CAS-7.
> - **Step 2 (YARA `qa_dir`) is the cheapest follow-on.** It is the only existing store that holds
>   live malware in plaintext with no cleanup. That's a reason to do it right after SVS, not a
>   reason to do it now.

---

## 8. Cross-cutting

### X-1 — Placement in the codebase and permissions  `AGREED`

| Piece | Where |
|---|---|
| Tables (verdict overrides, samples, sample links, validations, runs, run↔alert/detection links, expectations, ART catalog) | Main Alembic chain, models in `saq/database/model.py` |
| Scans, run timers, catalog refresh | New `service_svs` (`docs/SERVICES.md`) |
| APIs | `aceapi_v2/svs/` (router / service / schemas) |
| Sample capture, marker attribution | Analysis modules (`analysis_module_svs_*`) plus the hunter pre-insert check |
| GUI | Detection-verdict UI (DP-5), sample review, validation reports, run review, coverage |
| CLI | `ace svs ...` |
| Permissions (catalog + migration) | `svs:run_register`, `svs:validate`, `svs:sample_read`, `svs:sample_download`, `svs:admin` |

> **Response:** Let's hold off on this until we've got the CAS layer design worked out.

> **Round 2 (reviewer):** Deferred. Round 2 adds three pieces to place later: the alert-router
> registry (ART-15, core, `saq/engine/`), `move_alert_to_queue` (core, next to `ALERT()`), and the
> SVS mirror clones (YR-3, SVS work dir). The CAS adds permission `cas:purge`, plus possibly a
> legal-hold permission (CAS-4).

> **Response:** I now agree with the proposal.

> **Round 3 (reviewer):** Recorded. The placement table plus the round-2 additions give the full
> list:
> - **Core:** the alert-router registry, `move_alert_to_queue`, `saq/cas/`.
> - **SVS:** tables, `service_svs`, `aceapi_v2/svs/`, modules, GUI, `ace svs`.
> - **Permissions:** `svs:run_register`, `svs:validate`, `svs:sample_read`, `svs:sample_download`,
>   `svs:admin`, `cas:purge`, and a legal-hold permission (`cas:hold`).

### X-2 — Which ACE instance owns SVS  `AGREED`

Production holds the samples and sees the test hosts' telemetry. Dev and QA don't. So validations
and runs point at production ACE, which means signature-repo CI needs network access and an API key
for production.

**Question:** Is that acceptable, or does a separate SVS instance get a replicated sample store?
Replication is harder, so I'd start with production.

> **Response:** That is acceptable.

### X-3 — Name collision with `lib/signature_validator`  `AGREED`

`lib/signature_validator` (`validate-hunt` → `/api/hunt/validate`) already means "signature
validation" in ACE, and it is the hunt analogue of YR-3.

**Question:** Does SVS eventually absorb it (the same CI entry point, `validate` for hunts and YARA),
or do they stay separate? I'd keep them separate for now and note the relationship in both docs.

> **Response:** Let's keep them separate for now and note the relationship.

> **Round 2 (reviewer):** Recorded as D-11. When YR-3 is implemented, a one-paragraph "see also"
> goes in both `docs/HUNTS.md` (validate-hunt) and the SVS doc.

### X-4 — Phasing  `AGREED`

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

> **Response:** Agree with proprosal.

> **Round 2 (reviewer):** Round 2 changes the plan in two ways. It adds a phase 0 of
> prerequisites that stand on their own, and it replaces "derived expectations" with measured
> ones. Revised:
>
> 0. **Prerequisites.** Each is its own PR, each is useful without SVS, and they can run in
>    parallel:
>    - the CAS core with its first pool (CAS-*), plus the crypto fixes (CAS-5);
>    - the `archive()` fix (YR-11);
>    - disposition clean-up and classification (TP-2, TP-3);
>    - `saq/storage` defects (F-13, F-18, F-19).
> 1. **Labels.** The detection identity change (DP-7), which **must precede** any override. The
>    YARA detection point moves to the file (DP-4). Verdict table, effective verdicts, and the GUI
>    (DP-1, DP-5).
> 2. **YARA capture** (YR-4, YR-5).
> 3. **YARA validation** (YR-1/2/3/9) against one signature repo.
> 4. **Runs.** Registration, test hosts, markers, the alert-router registry and
>    `move_alert_to_queue` (ART-15), the SVS status (ART-14), and run review with
>    discovery-based expectations (ART-11).
> 5. **Coverage** (COV-1) and the declared-vs-measured diff.
>
> The hard ordering constraint is DP-7 before the first verdict write. Everything else is
> preference.

> **Round 3 (reviewer):** Small additions from this round:
> - **Phase 0** gains the prevalence default-queue change (ART-10), a PR the size of #587. The
>   disposition clean-up now also removes the four hidden constants (TP-3).
> - **Phase 1** now also reads the ART-16 meta key in the signature loaders, if (b) is chosen. That
>   is cheap, and it lets detection engineers start marking unmeasurable signatures before runs
>   exist.
> - **Phase 4** adds the `SIMULATED` disposition (ART-10) and the public `alert_routers:` contract
>   (ART-15, D-13).
> - **Each phase's PR description carries its §11 entries**, so the SOC hears about a change in
>   the release that makes it (X-5).

> **Round 4 (reviewer):** Two corrections to the round-3 additions:
> - **Phase 1:** drop "reads the ART-16 meta key". Under ART-16 (a) the loaders already read the
>   existing tags. Phase 1 still carries DP-4 (now agreed) and, depending on DP-2, the
>   `inherited_multi` verdict source.
> - **Phase 0:** the disposition clean-up gains the `analyst_selectable` flag and server-side
>   validation against the config (ART-10). It fits naturally there, because TP-2/TP-3 already move
>   the disposition list into config.

### X-5 — Keep a list of what the SOC must be told  `PROPOSED`  *(new, round 3)*

This is your TP-3 request, turned into a process. Many decisions here change what an analyst sees
or what their choices *mean*: a disposition now labels training data, counts come only from the
default queue, and some alerts move to a test queue. Those need to reach the team in plain
language, at the moment they take effect, not as a design doc.

**Proposal:**
- **§11 is the standing list.** One entry per change the SOC will notice, written for the reader
  who didn't take part in the design. Each entry says who is affected, what changes, what they
  should do differently, and when (the phase). Design IDs are in brackets for us, not for them.
- **An entry is added in the same edit that settles the decision.** Whoever marks an item AGREED
  adds or updates its §11 entry if it changes anything visible.
- **An entry is delivered with the PR that makes it true.** Each phase's PR description quotes its
  entries, and they go in the release notes (`CHANGELOG.md`). When SVS ships, the list becomes the
  SVS section of the analyst docs.
- **Entries marked ★ change the meaning of something analysts already do.** Those deserve a
  conversation, not just a release note.

> **Response:** Agree with proposal.

---

## 9. Code facts this review relies on

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
  - *Round 2:* since PR #587, observable disposition history also requires `queue = 'default'`
    (`database_observable.py:53-71, :111-115`). Prevalence does not (ART-10).
  - The same merge added `TAG_HUNT_VALIDATION` (`saq/constants.py:781`, `aceapi/hunt.py:238`), the
    precedent for tagging a class of alerts.
- **F-12 Git repos.** `git_repo_<name>` sections are polled by `GitManagerService`, one thread per
  repo, with no post-update callback.
- **F-13 (defect) S3 without TLS.** `saq/storage/factory.py:166` (round 1 said `:114`; the file
  was reworked in the merge) hardcodes `secure=False`, and ignores `s3.secure`, `s3.cert_check` and
  `s3.region`. `get_s3_client()` (`saq/storage/s3.py:108`) honors all three, but the storage factory
  doesn't use it.
- **F-14 (defect) YARA QA mode copy.** `yara.py:360` creates only `<qa_dir>/<rule>/`, so copies of
  files whose `file_path` has subdirectories fail. They are logged and nothing else happens.
  `var/qa` is never cleaned up.
- **F-15 (defect) Local YARA scanner fallback lifetime.** `yara.py:299` multiplies seconds by 60
  where it should divide, so the fallback scanner is recycled almost immediately.
- **F-16 No ATT&CK catalog, no `mitre:` tags in this repo's hunts.** The YARA module doesn't add
  `mitre:` tags at alert time; only the inventory loader derives them.
- **F-17 No API v2 alert submission.** Programmatic alert creation goes through `Submission` /
  `RemoteNode.submit_local` or v1 `POST /api/analysis/submit`.

*Round 2 additions:*

- **F-18 (defect) `S3Storage.object_exists` reports False on any error.** A 403 or a timeout looks
  like "missing" (`saq/storage/s3.py:498-506`). Only a 404 means that.
- **F-19 (defect) The local storage backend is neither atomic nor confined.** Upload and download
  are plain `shutil.copy2` with no temp-plus-rename (`saq/storage/local.py:61,84`). `remote_path`
  has no path-traversal guard (`:43`). Metadata kwargs are silently dropped.
- **F-20 (defect) `saq/crypto.decrypt` releases plaintext before authenticating it.** Chunks are
  written to the target before `finalize()` checks the GCM tag (`saq/crypto.py:199-233`). The
  header is not bound as AAD, and there is no key id, so the data key can't be rotated.
- **F-21 (defect) Analysis-cache blob store.**
  - GC race: an existing blob's mtime isn't refreshed by `put()`, and the cache does `exists()`
    then `reference()` (`saq/analysis/cache.py:318-336`). GC can delete between the two calls.
  - `reference()` is `INSERT IGNORE`, but `created_at` is part of the key, so repeated calls add
    rows.
  - References expire with their ~35-day partition, whatever still uses the blob.
- **F-22 (defect) The js_deobfuscator shared volume is never cleaned.** Phishkit's is cleaned after
  3 days (`phishkit.max_file_age_days`).
- **F-23 (defect) Email archive S3 objects are never deleted.** The DB index and local files expire
  after 30 days. The S3 copies stay, and can no longer be found by message-id.
- **F-24 (unverified) Correlation-mode submissions to a remote node may never get an alert row.**
  `RemoteNode.submit_remote` uploads with `is_alert=False` (`saq/collectors/remote_node.py:119-130`),
  and the receiving side (`aceapi/engine.py:157-176`) never calls `ALERT()`. The engine's later
  `_sync_alert_to_database` finds no row and does nothing. Worth a test. It also matters for
  ART-15's `PRE_INSERT` stage.
- **F-25 Event bus.** `TAG_ADDED`, `DETAILS_UPDATED`, `DETECTION_ADDED` and `CONTEXT_RECORD_ADDED`
  are declared (`saq/constants.py:525-566`) and never fired. Nothing fires when a tree is loaded from
  JSON. `CONTEXT_RECORD_ADDED` isn't in `VALID_EVENTS`.
- **F-26 `ALERT()` is the only alert insert** (`saq/database/util/alert.py:167`). It has seven
  callers, and all of them go through it (ART-15).
- **F-27 `valid_queues` / `invalid_queues`** are set only in `etc/saq.unittest.default.yaml`, on
  disabled test modules.

---

## 10. Decisions ready for `SVS_INITIAL.md`

This is text for the *Design Decisions* list, one line per settled outcome. Paste, reword or reject
as you like; the source item is in brackets.

- **D-1** A detection is **TP** when it was part of detecting malicious activity and **FP** when it
  was not. The label follows the analyst's answer to "did we detect malicious activity?". [TP-1]
- **D-2** A single config map classifies each disposition as TP, FP or unclassified; unlisted
  means unclassified. `AUTHORIZED` and `DATA_CONTROL` are removed as dispositions. [TP-2]
- **D-3** ACE data created before SVS is deployed is out of scope. SVS acts only on alerts created
  after it. [DP-4]
- **D-4** Goal 2 (validating that the telemetry exists) is dropped. [COV-2]
- **D-5** YARA regression is static only. The dynamic case (`d(t(Y))`) is covered by test
  execution. [YR-10]
- **D-6** Only analyst-set detection-point verdicts are stored. Effective verdicts are derived when
  read. Any detection of any signature family can be labeled. *(Pending DP-3, round 4: on an FP
  alert every verdict is FP, and a wrong FP is fixed by correcting the alert's disposition. Pending
  DP-2, round 4: under (b), every detection on a TP-class alert inherits TP, and multi-signature
  inheritance is recorded as a weaker source.)* [DP-1, DP-2, DP-3, DP-6]
- **D-7** A YARA validation compares each sample's label with its scan result under the PR's base
  and head rulesets. The whole corpus is scanned with the whole ruleset. Results warn and never
  block. The signature repo's CI starts a validation through the API; ACE fetches the rules itself
  with its existing git credentials. [YR-1, YR-2, YR-3]
- **D-8** Samples are captured at disposition time, for every YARA-matched file on a TP- or
  FP-class alert, with their scan context. Labels are per (sha256, rule uuid). Conflicting labels
  are excluded from results. Rules without a uuid are not regression-testable. [YR-4 to YR-7]
- **D-9** *(replaces "Test-to-signature mapping is derived first from declared techniques, and then
  hand-edited mappings")* Test-to-signature expectations are **learned from reviewed test runs**
  and confirmed by an analyst. For how technique mappings work, see D-17. [ART-11]
- **D-10** A *test* is an atomic definition; a *run* is one registered execution with its own
  lifecycle and marker. A marker only counts when it agrees with the run's targets and window.
  Context-only attribution also routes. An alert with any non-test detection stays in the normal
  queue. [ART-1 to ART-5, ART-7, ART-9]
- **D-11** SVS and `lib/signature_validator` stay separate, and each doc notes the relationship.
  [X-3]
- **D-12** SVS runs against production ACE. [X-2]
- **D-13** Alert queue routing becomes a core, pluggable alert-router registry. Routers run
  before insert (inside `ALERT()`) and after each analysis pass. The registry is open to
  integrations from day one. SVS's marker detection is one router. An alert that an analyst already
  owns is never moved. [ART-15]
- **D-14** ACE gets a general content-addressed store (`saq/cas/`) built on pools and holds. SVS
  samples are its first pool; the other byte stores migrate later. [CAS-1 to CAS-6]
- **D-15** Dispositions classify as follows. **tp:** `GRAYWARE`, `POLICY_VIOLATION`, the
  kill-chain set, and the test disposition. **fp:** `FALSE_POSITIVE`. **Unclassified:**
  `OPEN`, `IGNORE`, `UNKNOWN`, `REVIEWED`. The four hidden constants are removed. [TP-3]
- **D-16** Alerts from test runs get a dedicated disposition, `SIMULATED`, set only by SVS and
  never selectable by analysts (enforced server-side). They count as TP. They are excluded from observable disposition history and from prevalence, which both
  count only the default queue. [ART-10]
- **D-17** Technique mappings are measured from test runs. The existing signature tags
  (`mitre_attack` meta, `mitre:` tags) count as manual mappings. They keep counting until a
  measurement confirms them or someone removes them, through one "declared vs measured" worklist.
  [ART-11, ART-16]
- **D-18** The CAS never runs an unbounded `DELETE`. Low-churn pools delete in small batches;
  high-churn pools expire through time partitions in their own database. A GC load test gates the
  analysis-cache migration. [CAS-7]
- **D-19** Hunt suppression is explained, not prevented: a missing result says *possibly
  suppressed* when it applies. Prevention is revisited after 50 Reviewed runs or 3 months. [ART-8]
- **D-20** YARA detections sit on the file that matched, carry structured details, and keep their
  scan results visible. [DP-4]

**Other lines in `SVS_INITIAL.md` that the agreed items contradict:**
- The **goals** list: remove the second bullet (D-4).
- *"If an ACE alert is dispositioned as False Positive, then all detection points are also
  dispositioned as False Positive"*: add "unless an analyst set that detection explicitly" (D-6).
- *"If an ACE alert has a single detection point…"*: becomes "a single signature" if DP-2 is
  accepted.
- *"ACE will have the ability to assign a disposition to a detection point"*: it is a TP/FP
  *verdict*, not one of the alert dispositions (D-6). The wording matters, because the GUI will
  use it.

---

## 11. What the SOC needs to be told  *(new, round 3)*

This is the standing list from X-5, written for the analysts and detection engineers who use ACE,
not for us. Each entry says who is affected, what changes, what to do differently, and when it
takes effect. ★ marks a change to the *meaning* of something people already do. Those deserve a
conversation, not just a release note. Entries marked *(pending)* depend on an item that isn't
settled yet.

**S-1 ★ Your disposition now also grades the detections.**
- **Who:** analysts, SOC leads.
- **What changes:** besides closing the alert, the disposition you pick now tells ACE whether its
  detections were good or bad, and that record is used to test future signature changes.
  - `FALSE_POSITIVE` means none of the detections found malicious activity.
  - `GRAYWARE`, `POLICY_VIOLATION` and every kill-chain disposition mean they did.
  - `IGNORE`, `REVIEWED` and `UNKNOWN` record nothing either way.
- **What to do:** choose `FALSE_POSITIVE` only when there really was no malicious activity. Don't
  use `REVIEWED` or `IGNORE` to avoid making the call, because then the detections teach nothing.
- *(Pending DP-2.)* If (b) is chosen, a real-attack disposition grades **every** detection on the
  alert as good, including alerts where several signatures fired. Marking the noisy ones (S-3)
  becomes the one extra habit to learn.
- **When:** phase 1. [TP-1, TP-2, TP-3, D-1, D-15]

**S-2 Six unused dispositions are removed.**
- **Who:** SOC leads, ACE admins, anyone with reports or scripts that name dispositions.
- **What changes:** `AUTHORIZED`, `DATA_CONTROL`, `INSIDER_DATA_CONTROL`, `INSIDER_DATA_EXFIL`,
  `APPROVED_BUSINESS` and `APPROVED_PERSONAL` go away. None of them could actually be selected in
  the GUI, so no triage workflow changes.
- **What to do:** update any report, dashboard or script that refers to them.
- **When:** phase 0. [TP-2, TP-3]

**S-3 You can grade individual detections.**
- **Who:** analysts.
- **What changes:** each detection on an alert can be marked TP or FP. This is optional: by
  default a detection follows the alert's disposition. The alert page shows whether a verdict is
  inherited or set explicitly.
- **When to use it:** a real attack where one of the signatures that fired was noise, such as a
  generic rule on a harmless logo in a phishing email. Mark that one FP.
- **When not to use it** *(pending DP-3)*: if the whole alert was dispositioned wrong, correct the
  alert's disposition; don't grade detections to compensate. On a `FALSE_POSITIVE` alert, every
  detection is FP.
- **When:** phase 1. [DP-1, DP-3, DP-5, DP-6]

**S-4 YARA hits appear on the file.**
- **Who:** analysts.
- **What changes:** in the alert tree, a YARA detection (the fire icon) sits on the file that
  matched, rather than on a separate `yara_rule` node, and the YARA results under the file are
  always shown. With several matched files, each file's detection chain is now exact.
- **When:** phase 1. [DP-4]

**S-5 ★ Every YARA pull request gets a validation report.**
- **Who:** detection engineers.
- **What changes:** a YARA PR is checked against every file analysts have graded (S-1, S-3). The
  report lists:
  - **regressions:** files graded as real detections that no longer match;
  - **new false positives:** files graded FP that newly match;
  - improvements;
  - scan-time changes.

  It only warns and never blocks a merge. Rules without a `uuid` can't be checked.
- **What to do:** read the report in ACE before merging. If a regression is intended, retire or
  relabel the sample there so the report stops showing it.
- **How it arrives:** the repo's CI requests the validation from ACE and posts a summary comment
  on the PR with a link to the full report in ACE. The PR check never fails.
- **When:** phase 3. [YR-1 to YR-7, D-7]

**S-6 ★ "Seen before" numbers count only the default queue.**
- **Who:** analysts.
- **What changes:**
  - An observable's disposition history already counts only alerts in the `default` queue (ACE
    3.0.116, PR #587).
  - Its prevalence (how often it was seen) will do the same.
  - The numbers for observables seen mostly in other queues get smaller. That includes test
    alerts, which then stop inflating them.
- **When:** phase 0. [ART-10, D-16]

**S-7 Alerts from red-team test runs get their own queue and badge.**
- **Who:** analysts.
- **What changes:** alerts caused by a registered test go to a test queue with the disposition
  `SIMULATED`. Only ACE sets that disposition; it isn't in the disposition menu. If an alert was
  wrongly treated as a test, use *Disassociate from run*, which sends it back for normal triage.
  An alert shows at most one of four badges:
  - `TEST`: nothing to do.
  - `TEST?`: nothing to do unless it looks wrong. One click marks it *not a test*.
  - `PARTIAL TEST`: triage the non-test detections as usual; the test ones are greyed out.
  - `MARKER MISMATCH`: **treat as suspicious and investigate.**

  An alert you already own is never moved out from under you.
- **When:** phase 4. [ART-7, ART-14, ART-15, D-13, D-16]

**S-8 Archived false-positive alerts really delete their extracted files.**
- **Who:** ACE admins, and anyone who retrieves files from the storage directory on disk.
- **What changes:** when an FP alert is archived (after `fp_days`, default 30), files extracted
  during analysis are now removed from disk. The files that came with the alert are kept. The GUI
  already couldn't open them after archive, so analysts see no difference.
- **When:** phase 0. [YR-11]

**S-9 ★ ATT&CK coverage is measured first, declared second.**
- **Who:** detection engineers, SOC leads.
- **What changes:**
  - Which techniques a signature covers now comes from test runs wherever a test exists.
  - The existing `mitre_attack` meta and `mitre:` tags stay, and count as *manual* (unmeasured)
    mappings. When a test measures a tagged signature, ACE puts it on a "declared vs measured"
    worklist: confirm the tag, keep it (it covers something tests can't reach), or remove it.
  - For a signature no test can exercise, the tag *is* the mapping. Keep tagging those carefully.
- **When:** phase 5. [ART-11, ART-16, D-17]

**S-10 SVS only knows about alerts created after it is deployed.**
- **Who:** SOC leads, detection engineers.
- **What changes:** grading, samples and test attribution start empty on deployment day. Older
  alerts are not graded retroactively.
- **When:** phase 1. [D-3]

**S-11 A "missing" detection in a test run doesn't say why.**
- **Who:** detection engineers, SOC leads.
- **What changes:** when an expected signature doesn't fire, SVS can't tell whether the log data
  never arrived or the signature failed to match. It does flag when the hunt was probably
  suppressed. Investigate both possibilities.
- **When:** phase 4. [COV-2, ART-8, D-4]

---

## 12. Round log

| Round | Who | Summary |
|---|---|---|
| 1 | reviewer | Initial review of `SVS_INITIAL.md` @ `ec3cab18`. 37 items: 20 blocking (15 PROPOSED, 5 OPEN). |
| 1 | author | Responses to all items except COV-1 (commit `6967686c`). |
| 2 | reviewer | Replies to every response. 26 items AGREED, YR-10 DEFERRED, X-1 DEFERRED until CAS. Revised DP-4 (move to file), YR-3 (ACE fetches, warn only), ART-8 (staged), ART-10 (narrowed after the #587 merge), ART-11 (measured expectations), COV-1 (strawman without declared tags). New: TP-3, DP-7, YR-11, ART-14, ART-15 (replaces ART-6), §7 CAS-1 to CAS-8 (replaces YR-8), §10 decision text, F-18 to F-27. |
| 2 | author | Responses to all round-2 items except DP-2, DP-4, YR-3 (a)/(b), ART-8 and the DP-3 example (commit `654df8dc`). Asked for a record of decisions that must be communicated to the SOC. |
| 3 | reviewer | 15 more items AGREED: TP-3, DP-7, YR-11, ART-10, ART-11, ART-14, ART-15, COV-1, CAS-1 to CAS-6, X-1, and the CAS-8 deferral confirmed. CAS-7 revised after reviewing email-archive pruning (no unbounded DELETE; partitioned touch tables for high-churn pools; a GC load test gates the analysis-cache migration). New: ART-16 (manual-mapping meta key), X-5 and §11 (SOC communication list, S-1 to S-11), decisions D-13 to D-17. |
| 3 | author | Answers to TP-3's follow-ups, DP-2 (follow-up query results), the DP-3 example, ART-10, ART-16 (a) and CAS-7. Earlier plain-text answers to DP-2, DP-4, YR-3 and ART-8 reformatted as quoted responses (commit `e68985eb`). X-5 and §11 not yet answered. |
| 4 | reviewer | **Correction:** round 3 wrongly reported DP-2, DP-4, YR-3 and ART-8 as unanswered, because its search matched only quoted responses. AGREED: DP-4, YR-3 (a), ART-8 (a) with a revisit trigger, ART-10 (`SIMULATED`, server-side enforced), ART-16 (a), CAS-7. Reopened: DP-2, where the data shows 37% of TP YARA alerts are multi-signature, so it proposes inherit-TP-by-default (b); and DP-3, which proposes reverting TP-on-FP overrides. D-6, D-7, D-16 and D-17 updated; D-18 to D-20 added; S-1, S-3, S-4, S-5, S-7 and S-9 updated. |
