# SVS data API

ACE doesn't ship fixed reports (`docs/SVS.md`, Part 6). Every fact SVS keeps can be pulled through
`aceapi_v2`, with the same filters the screens use, and reports are built outside ACE. This document
is the data dictionary for those endpoints, the joins between them, and worked examples. It covers
alerts and detections (phases 0 and 1), the YARA samples (phase 2), the YARA validations (phase 3),
the test hosts, the Atomic Red Team test catalog and the runs with their event logs (phase 4), and
ATT&CK coverage with its daily snapshots and the declared-vs-measured worklist (phase 5).

## Conventions

- **Authentication.** An API key in the `x-ace-auth` header. For reporting, use a read-only key: an
  automation user with the `*_read` permissions, `alert:read` and `signature:read` (RPT-5).
- **Filters** are the share-link encoding of `docs/ALERT_FILTER_URLS.md`, one `f=` parameter per
  filter: `f=[!]slug:value[,value…]`. Separate filters are ANDed, the values of one are ORed, and
  repeats of a filter with the same polarity are merged. `:`, `,` and `%` inside a value are
  percent-encoded. Each screen has its own slugs; an unknown slug or a bad value is a 422.
- **Pages** are keyset pages: `{"data": […], "next_cursor": "…"}`. Pass `cursor=` with the same
  filters for the next page, until `next_cursor` is null. Nothing is skipped or repeated while new
  rows arrive. `limit` is at most 1000.
- **Exports** stream the whole result in one response, with the same filters and order:
  `…/export/ndjson` (one row per line; a failure part-way ends the stream with an `{"error": …}`
  line) and `…/export/csv` (a header line; a failure part-way truncates it).
- **Incremental pulls** take `changed_since` (ISO 8601, UTC if no offset). Delivery is
  at-least-once: a row can come again, never be missed.
- **Timestamps** are UTC. Relative date filters (`-7d`, `@d`) resolve in the `tz` parameter's zone.
- **Scope.** Alert data is scoped to the alerts this node shows, as the GUI is. SVS data (samples,
  validations, tests, runs) is global.
- **Stable identifiers:** alert UUID, signature UUID, detection `content_hash`, sample `sha256`,
  validation UUID, test GUID, run UUID, ATT&CK technique id.

### Conflicting writes

A write that two people can make from the same page may say what it was made from, as an HTTP
precondition, so that the second of two writes from one read is refused instead of silently
replacing the first (`saq/svs/preconditions.py`):

- `If-Match: <updated_at>`: the row's `updated_at` exactly as it was read. The write applies only
  while the row is unchanged since.
- `If-None-Match: *`: the client saw no row. The write applies only while there still is none.

A precondition that no longer holds answers **412** with `{"detail": {"message", "current"}}`, where
`current` is the row as it is now (null when it was removed), and changes nothing. A malformed one,
or both headers at once, is a 400. Without either header a write applies as before, which is what a
script that owns its data wants. The GUI always sends one.

| Write | Precondition the GUI sends |
|---|---|
| `PUT /api/v2/svs/worklist/{signature_uuid}/{technique}/resolution`, and its `DELETE` | `If-Match` of the row on the page |
| `PUT /api/v2/svs/tests/{guid}/expectations/{platform}/{signature_uuid}` | `If-None-Match: *` (a candidate has no decision) |
| `PUT /api/v2/svs/tests/{guid}/ignores/{signature_uuid}`, `PUT /api/v2/svs/ignores/global/{signature_uuid}` | `If-None-Match: *` |
| `PUT /api/v2/svs/test-hosts/{host_id}` | `If-Match` of the host the form loaded |

The bulk worklist resolution takes no precondition: it resolves the rows as they are.

## Alerts

`GET /api/v2/alerts` (and `/export/ndjson`, `/export/csv`) lists alerts as flat rows with the alert
manage page's filters (`docs/ALERT_FILTER_URLS.md`). `detection_count` is the number of
`detection_points` rows of the alert: one per detection *per node it sits on*, so a description
that fired on three URLs counts three.

`svs_status` is the alert's SVS status (`docs/SVS_RUNS.md`, *What happens to the alert*), and null
for an alert no test run touched:

| `svs_status` | Meaning |
|---|---|
| `test` | Every detection is attributed to a run, at least one by a marker |
| `test?` | Every detection is attributed, by context only |
| `partial` | Some detections are attributed |
| `mismatch` | A marker in the alert doesn't agree with its run (the alert carries the `svs:marker_mismatch` tag) |

`svs_runs` lists the uuids of the runs the alert is attributed to (`GET /api/v2/svs/runs/{run_id}`),
empty for a mismatch. Both are derived from the attributions when the row is read, so an alert
disassociated from its run loses them, and in CSV `svs_runs` is joined with `,` as `tags` is. Test
alerts are listed like any other; `f=!queue:<svs.queue>` leaves out the ones routed to the test queue.

### An alert's SVS status

One alert's side of SVS, as its page shows it (`docs/SVS_RUNS.md`, *Test alerts in the alert list
and on the alert page*):

| Endpoint | Permission | Does |
|---|---|---|
| `GET /api/v2/alerts/{uuid}/svs` | `alert:read` | `{"alert_uuid", "svs_status", "runs", "detections", "mismatches"}`; 404 for an unknown alert, and a null status with empty lists for one no run touched |
| `POST /api/v2/alerts/{uuid}/svs/disassociate` `{"reason"?}` | `alert:write` | Disassociate the alert from every run that holds it (409 when none does) |
| `POST /api/v2/alerts/{uuid}/svs/not-a-test` `{"reason"?}` | `alert:write` | The same for a `TEST?` alert, recorded as *not a test* (409 unless it is `TEST?`) |

- `runs` are the runs whose attributions hold, oldest first, each `{"run_id", "state", "test_guid",
  "test_name"}`.
- `detections` are the attributed detections, `{"content_hash", "run_ids"}`, keyed like `GET
  /api/v2/alerts/{uuid}/detection-points`.
- `mismatches` are the markers that disagree with their run, `{"marker", "result", "run"}`; `run` is
  null when no run has the marker.
- The two actions need a user's key (a config key gets 422). Each answers `{"alert_uuid", "run_ids",
  "svs_status", "queue", "moved", "reopened"}`: the runs it was disassociated from, and the alert's
  status and queue afterwards.
- They are the run-scoped `disassociate` and `not-a-test` (*Attributions*, below), applied to each
  run in turn. They need `alert:write` rather than `svs:run_manage`: they are an analyst's correction
  of an alert they triage.

## Detections

A **detection** (detection point) is one signature firing on one node of an alert's analysis tree.
Each has an effective TP/FP **verdict**, derived from the alert's disposition unless an analyst set
it (`docs/SVS.md`, Part 1).

| Endpoint | Permission | Returns |
|---|---|---|
| `GET /api/v2/detection-points` | `alert:read` | Detections of every alert, filtered and paged |
| `GET /api/v2/detection-points/export/ndjson`, `/export/csv` | `alert:read` | The same, streamed |
| `GET /api/v2/alerts/{uuid}/detection-points` | `alert:read` | One alert's detections |
| `PUT /api/v2/alerts/{uuid}/detection-points/{content_hash}/verdict` `{"verdict": "tp"\|"fp"}` | `alert:write` | Stores an explicit verdict; the updated row |
| `DELETE /api/v2/alerts/{uuid}/detection-points/{content_hash}/verdict` | `alert:write` | Removes it; the updated row |
| `POST /api/v2/alerts/{uuid}/detection-points/confirm` | `alert:write` | Confirms every unconfirmed TP: `{"confirmed": n}` |

A verdict write is refused with 409 on an FP alert (correct the alert's disposition instead), on an
alert whose disposition is unclassified or only set by ACE, and on a detection synced before node
identity existed. It needs a user's key: a config key belongs to nobody, and gets 422.

### Fields

| Field | Meaning |
|---|---|
| `alert_uuid` | The alert. Join to `GET /api/v2/alerts` on `uuid`. |
| `content_hash` | The detection's identity within its alert: a hash of the node it sits on, its signature, description and details. Stable across re-analysis; verdicts are keyed on it. |
| `description`, `details` | What the detection says. A YARA detection's `details` are `{"sha256", "rule", "namespace", "rule_uuid"}` (`docs/YARA_RULES.md`). |
| `queue` | The queue the detection asked its alert to be routed to, not the alert's queue. |
| `signature_uuid`, `signature_version` | The signature and its version (for repository rules, the commit). |
| `signature_family` | `yara`, `hunt`, `observable_modifier` or `builtin`; null when the producer didn't say. |
| `node_kind` | `root`, `observable` or `analysis`; null on a row synced before node identity. |
| `node_type`, `node_value_sha256` | The observable's type and its `observables.sha256` key in hex: the sha256 of the value, except for a `file`, whose value is the content sha256. For an analysis node, those of the observable it analyzed. |
| `node_module_path` | The analysis module, for an analysis node. |
| `insert_date` | When the row was written. A detection that leaves the tree and comes back gets a new row. |
| `verdict` | The effective verdict, `tp` or `fp`; null when the alert's disposition is unclassified (`OPEN`, `IGNORE`, `UNKNOWN`, `REVIEWED`). |
| `verdict_source` | Why the verdict is what it is (below); null with no verdict. |
| `override`, `override_user`, `override_set_at` | The verdict an analyst stored, who and when. It is masked (but kept) while the alert is FP. |

### Verdicts and their sources

| Alert disposition class | Stored override | Signatures on the alert | `verdict` | `verdict_source` |
|---|---|---|---|---|
| unclassified | any | any | null | null |
| fp | any (masked) | any | `fp` | `inherited_single` |
| tp | `tp` or `fp` | any | the override | `explicit` |
| tp | none | one | `tp` | `inherited_single` |
| tp | none | several | `tp` | `inherited_multi` |

- **`explicit`**: an analyst set it, or confirmed an inherited TP.
- **`inherited_single`**: the alert's disposition covered this detection directly. That is an FP
  alert (every detection on it is FP), or a TP alert whose detections all come from one signature.
- **`inherited_multi`**: an inherited TP on an alert where several signatures fired, which nobody
  has confirmed. It is the weakest source, and SVS reports regressions on such labels separately.

The classification of dispositions comes from `disposition_classification` in the configuration
and is applied when the data is read, so a changed map relabels everything at once.

Each change of a stored verdict is kept in `detection_point_verdict_history` (old and new stored
value, who, when); it has no endpoint yet.

### Filters

| Slug | Filter | Values |
|---|---|---|
| `signature` | Signature | `<signature uuid>[%3A<version>]` |
| `family` | Family | `yara`, `hunt`, `observable_modifier`, `builtin` |
| `alert_date` | Alert Date | a date range, as for alerts (`-90d`, `@d - now`, an absolute range) |
| `queue` | Queue | the alert's queue |
| `verdict` | Verdict | `tp`, `fp`, `none` (no verdict) |
| `source` | Source | `explicit`, `inherited_single`, `inherited_multi` |
| `has_override` | Has Override | `true`, `false` |

`!` inverts a filter, including rows whose value is null: `!verdict:tp` returns FP detections and
those with no verdict.

### Incremental pulls

With `changed_since`, a detection is returned when anything its row shows may have changed since
then: its alert's row changed (a disposition change re-derives every verdict), the detection was
synced again, or its verdict was set or cleared. Pass the time the previous pull *started*. The
alert's row changes on every analysis pass, so a pull returns more than strictly changed, never less.

### Joins

- **Detection → alert:** `alert_uuid` = alert `uuid`.
- **Detection → observable:** `(node_type, node_value_sha256)` is the `observables` table's key.
- **YARA detection → sample:** `details.sha256` and `details.rule_uuid` are the sample's `sha256`
  and `rule_uuid` (below).

## Samples

A **sample** is a file a YARA rule matched on an alert an analyst graded TP or FP, kept so that rule
changes can be tested against it (`docs/SVS.md`, Part 2; `docs/SVS_SAMPLES.md`). It is one
`(sha256, rule_uuid)` pair. Each alert it was captured from is one **capture** of it, and its TP/FP
**label** is derived from the verdicts on those alerts' detections when it is read.

| Endpoint | Permission | Returns |
|---|---|---|
| `GET /api/v2/svs/samples` | `signature:read` | Samples, filtered and paged |
| `GET /api/v2/svs/samples/export/ndjson`, `/export/csv` | `signature:read` | The same, streamed (the CSV flattens `votes` into one column each) |
| `GET /api/v2/svs/samples/{sha256}/{rule_uuid}` | `signature:read` | One sample, with its captures and the verdicts of their detections |
| `GET /api/v2/svs/samples/captures/{id}/record` | `signature:read` | A capture's full match record (JSON) |
| `GET /api/v2/svs/samples/missing` | `signature:read` | How many captures of each rule lack something, by reason |
| `GET /api/v2/svs/samples/{sha256}/{rule_uuid}/download` | `signature:download` | The file and its match records, in a zip |
| `GET /api/v2/svs/samples/download?f=…` | `signature:download` | The files of every sample the filters match, in one zip |
| `GET /api/v2/svs/samples/deletions` | `signature:read` | The audit of deleted sample files (*Sample deletions*) |
| `PUT`, `DELETE /api/v2/svs/samples/{sha256}/{rule_uuid}/label` | `signature:read` + `alert:write` | Relabel, or reset to inherited (*Sample actions*) |
| `POST /api/v2/svs/samples/{sha256}/{rule_uuid}/confirm` | `signature:read` + `alert:write` | Confirm its unconfirmed TPs |
| `PUT`, `DELETE /api/v2/svs/samples/{sha256}/{rule_uuid}/retirement` | `svs:admin` | Retire, or unretire |
| `DELETE /api/v2/svs/samples/{sha256}` | `svs:admin` | Delete the file from SVS, for every rule |

The listing takes `sort` (`last_captured`, the default, `first_captured`, `capture_count`, `rule`,
`label` or `sha256`) and `desc` (default `true`). A cursor belongs to its sort and direction; using
it with another is a 400. A listing, and an export, count the captures that existed when its first
page was read: the cursor carries the newest one, so a sample captured again mid-walk keeps its place
(and its count as of then) instead of moving past the cursor and being skipped; a new listing counts
the new captures. A `label` sort can still move a sample relabeled mid-walk.

**Downloads** are zips encrypted with the password `infected`, as for YARA QA results. Each file is
in a zip once, under `<sha256>/`, next to a `match-<capture id>.json` per capture; `manifest.json`
lists the samples in it and what was skipped (`wrong_node`, `no_longer_stored`). A bulk download is
limited to `svs.samples.max_bulk_download_files` files and `max_bulk_download_bytes` bytes (413
past either). With the default node-local pool, bytes are only on the node that stored them: a
request for them on another node answers 409 `{"error": "wrong_node", "node": …}`, and a bulk
download lists them as skipped.

### Fields

| Field | Meaning |
|---|---|
| `sha256`, `rule_uuid` | The sample: the file, and the rule's `uuid` meta (the `signature_uuid` of its detections). |
| `rule_name`, `namespace`, `file_path`, `file_size` | As the latest capture has them. The namespace is relative to the signature directory; the path is relative to the alert's `files/` directory. |
| `capture_count` | How many alerts it was captured from. |
| `stored`, `missing` | How many captures hold the file, and how many could not keep it. |
| `missing_data` | How many captures lack something: the file, or the match record. |
| `unknown_version` | How many captures recorded signature version `unknown` (the rule's repository is not in `service_yara.git_repo_dirs`). |
| `first_captured`, `last_captured`, `updated_at` | Over its captures. |
| `label` | `tp`, `fp`, `conflicted`, or null (below). |
| `label_source` | The strength that decided the label: `explicit`, `inherited_single` or `inherited_multi`. |
| `votes` | How many contributing detections vote TP or FP at each strength: `tp_explicit`, `fp_explicit`, `tp_inherited_single`, … |
| `retired` | Whether the sample is retired for its rule: a YARA validation only counts it. |
| `retired_by`, `retired_at`, `retired_reason` | Who retired it, when and why, while it is retired. |
| `local` | Whether this node can serve the file. Always true with a shared pool. |

A capture (in a sample's detail) carries its `alert_uuid`, `observable_uuid`, `signature_version`,
`rule_content_hash`, `yara_meta_tags`, `state` (`pending`, `stored`, `missing`), `missing_reason`
(`file`, `storage`, `match_record`; `docs/SVS_SAMPLES.md`, *States*), `has_record`, a
`match_summary`, the node and library versions, and its `detections`: the contributing detections
with their verdict, source and override. Nothing else about the alert is exposed.

### Labels

A sample's **contributing detections** are, on each alert it was captured from, the detections of
its rule on a file node with its sha256. Each one with a verdict casts a vote of its verdict source's
strength, and the strongest strength present decides:

| Votes at the strongest strength present | `label` | `label_source` |
|---|---|---|
| none at all | null | null |
| TP only | `tp` | that strength |
| FP only | `fp` | that strength |
| both | `conflicted` | that strength |

The strengths are `explicit` > `inherited_single` > `inherited_multi`. So an analyst's override
outweighs any number of inherited votes, and an FP alert (whose detections are `inherited_single`)
outweighs an unconfirmed TP from an alert where several signatures fired. The newest vote never
silently wins: YARA validation (phase 3) leaves a conflicted sample out until someone relabels it.

A detection without a verdict casts no vote: an alert whose disposition is unclassified, or one
from a test run that is not Reviewed. Nor does an alert that was deleted: its captures remain, with
no votes.

### Filters

| Slug | Filter | Values |
|---|---|---|
| `signature` | Signature | the rule uuid |
| `rule` | Rule | text the rule name contains (in any capture) |
| `sha256` | SHA256 | the file's sha256 |
| `alert` | Alert | an alert uuid it was captured from |
| `file_name` | File Name | text the file path contains (in any capture) |
| `label` | Label | `tp`, `fp`, `conflicted`, `none` (no label) |
| `label_source` | Label Source | `explicit`, `inherited_single`, `inherited_multi` |
| `last_captured` | Last Captured | a date range (`-30d`, an absolute range) |
| `stored` | Stored | `true`, `false`: whether any capture holds the file |
| `missing_data` | Missing Data | `true`, `false`: whether any capture lacks its file or match record |
| `unknown_version` | Unknown Version | `true`, `false` |
| `retired` | Retired | `true`, `false` |

`!` inverts a filter, including rows whose value is null: `!label:tp` returns FP, conflicted and
unlabeled samples.

### Incremental pulls

With `changed_since`, a sample is returned when a capture of it was added or changed, it was retired
or unretired, a contributing alert's row changed (a disposition change relabels it), or a
contributing detection's verdict was set or cleared. Deleting an alert removes its votes without
changing anything a pull can see; a report that must notice that pulls everything again. A deleted
sample is gone from the listing; `GET /api/v2/svs/samples/deletions?changed_since=…` says which.

### Sample actions

What each action means is in `docs/SVS_SAMPLES.md`, *Actions*. Every action records who took it,
so it needs a user's API key or session; a config key gets 422.

- **`PUT …/label`** `{"verdict": "tp" | "fp"}`, **`DELETE …/label`** and **`POST …/confirm`**
  answer what they did:
  - `changed` and `unchanged` count the contributing detections (for a reset, only those with an
    explicit verdict);
  - `skipped` lists the ones that cannot take an analyst's verdict, each with its `alert_uuid`,
    `content_hash` and `reason`;
  - `label` and `label_source` are the sample's label afterwards.

  They answer 409 when no contributing detection can take the verdict, and 404 for an unknown
  sample. A sample's detail (`GET …/{sha256}/{rule_uuid}`) carries `relabel_refusal`: the reason a
  relabel would answer 409 (every contributing detection is on an FP or `SIMULATED` alert, say), or
  null when it would write a verdict. The Samples page offers *Relabel* only when it is null, and
  shows the reason otherwise.
- **`PUT …/retirement`** `{"reason": …}` and **`DELETE …/retirement`** answer the retirement:
  `retired`, `reason`, `retired_by`, `retired_at`, `unretired_by`, `unretired_at`. Retiring a
  retired sample changes nothing. Unretiring one that is not retired is a 404.
- **`DELETE /api/v2/svs/samples/{sha256}`** `{"reason": …}` answers the deletion's audit row
  (below). A 409 carries `{"error": "wrong_node", "node": …}` when the bytes are on another node's
  local pool, and `{"error": "legal_hold"}` when the file is under legal hold. Deleting a deleted
  file retries an unfinished purge and answers the same row.

### Sample deletions

`GET /api/v2/svs/samples/deletions` lists the audit of deleted sample files, oldest change first,
in keyset pages (`limit`, `cursor`, `changed_since`). A row is:

| Field | Meaning |
|---|---|
| `sha256` | The deleted file. |
| `rule_uuids`, `capture_count` | The rules it had samples for, and how many captures were removed. |
| `deleted_by`, `reason`, `deleted_at` | Who deleted it, why and when. |
| `node` | The node its bytes were on. |
| `purged_at` | When its bytes were purged; null while they are not (deleting again retries). |
| `updated_at` | The row's last change: its creation, then its purge. |

### Joins

- **Sample → detections:** each capture's `alert_uuid`, plus `signature_uuid = rule_uuid`,
  `node_type = file` and `node_value_sha256 = sha256` in `GET /api/v2/detection-points`.
- **Sample → alerts:** the captures' `alert_uuid`.

## Validations

A validation replays every stored sample under two commits of a YARA rule repository and reports
what the change does (`docs/SVS_VALIDATION.md`). The signature repository's CI requests it with an
`svs:validate` key, which reads counts and rule names only; the reports, which name the samples,
are read with `signature:read`.

| Endpoint | Permission | Returns |
|---|---|---|
| `POST /api/v2/svs/yara/validations` `{repository, base_sha, head_sha, branch, pr_url?}` | `svs:validate` | 202 and a new queued validation, or 200 and the one that already answers the request: its status |
| `GET /api/v2/svs/yara/validations/{uuid}/status` | `svs:validate` | The status: state, counts, rules per category, compile errors. Names no sample |
| `GET /api/v2/svs/yara/validations` | `signature:read` | Validations, newest first, filtered and paged |
| `GET /api/v2/svs/yara/validations/export/ndjson`, `/export/csv` | `signature:read` | The same, streamed (the CSV leaves out `counts`) |
| `GET /api/v2/svs/yara/validations/{uuid}` | `signature:read` | One validation with its report |
| `GET /api/v2/svs/yara/validations/{uuid}/results` `?category=…&rule_uuid=…` | `signature:read` | The pairs its report lists, in a stable order, paged |
| `GET /api/v2/svs/yara/validations/{uuid}/results/export/ndjson`, `/export/csv` | `signature:read` | The same, streamed |
| `GET /api/v2/svs/yara/validations/{uuid}/download` `?category=…&rule_uuid=…` | `signature:download` | The files of the selected pairs and their samples' match records, in an `infected` zip |

**Requests.** `repository` is the `name` of a `git_repo_*` section, listed in `svs.yara.repositories`;
`base_sha` and `head_sha` are full commit ids (40 or 64 hex characters), because an abbreviation
would not be recognized as the same commit by the next request. A request with the same repository
and commits gets the validation that is queued or running, or a completed one while the corpus
version and engine fingerprint are unchanged (`docs/SVS_VALIDATION.md`, *The svs service*); a
failed one is never reused. A config key (no user) gets 422.

### Fields

| Field | Meaning |
|---|---|
| `uuid` | The validation. |
| `state` | `queued`, `running`, `completed`, or `failed` with `error` saying why. |
| `repository`, `base_sha`, `head_sha`, `branch`, `pr_url` | What was requested. |
| `requested_by` | The user whose key requested it. |
| `created_at`, `started_at`, `finished_at` | When it was requested, last claimed by a worker, and finished. |
| `diffed` | False when either commit's rules would not load, so nothing was compared. |
| `counts` | `{category: pairs}`, every category included; null until completed. |
| `regressions`, `new_fps`, `compile_errors` | `regression` + `regression_unconfirmed`; `new_fp` + `new_fp_other_rule`; the head's rule files that do not compile, plus one if its rules would not load together. Null until completed. |
| `updated_at` | The row's last change. |

`GET …/{uuid}` adds `attempts`, `claimed_by`, `corpus_version`, `engine_fingerprint` and the
`report`: `ReplayResult.to_dict()` (`saq/svs/yara/replay.py`) without its rows. It holds, per commit
(`base`, `head`), the namespaces, the files that do not compile and the rules they drop, whether
the ruleset would load (`loads`, `ruleset_error`), the include problems, the files the yara service
would not load, the archive members refused, the compiler warnings and the timings per namespace;
and the rules added, removed and changed, the rules that cannot be tested, the rules that filter on
`full_path`, the samples skipped (with why), and the corpus size.

`GET …/{uuid}/status` carries the request, the state, `diffed`, `counts`, `rules` (per listed
category, the rules with samples in it, most samples first: `{rule_uuid, rule_name, count}`), the
head's `compile_errors` (`{file, error}`, the file relative to the repository root) and
`ruleset_error`, and `report_path`, the report's page in the ACE GUI relative to its host.

A result row is one (sample, rule uuid) pair the report lists:

| Field | Meaning |
|---|---|
| `id` | The row; results page by it. |
| `sha256`, `rule_uuid`, `rule_name`, `namespace` | The file, and the rule with its name and namespace. |
| `label`, `label_source` | The sample's label when the validation ran (null for another rule's sample). |
| `base`, `head` | The outcome under each commit: `match` (the rule would make a detection), `miss` or `error`. |
| `raw_base`, `raw_head` | Whether the rule matched at all, before `enabled` and the `qa`/`no_alert` modifiers. |
| `category` | Below. |
| `note` | Why a raw match makes no detection, when it does not. |

The listed categories, most urgent first: `regression`, `regression_unconfirmed`, `new_fp`,
`new_fp_other_rule`, `rule_removed`, `scan_error`, `recovered`, `improvement`, `already_broken`,
`new_match_real_hit`, `unlabeled_change`. `known_fp`, `retired`, `not_testable` and `unchanged` are
only counted. What each means is in `docs/SVS_VALIDATION.md`, *The report*.

### Filters

| Slug | Filter | Values |
|---|---|---|
| `repository` | Repository | text the repository name contains |
| `branch` | Branch | text the branch contains |
| `head` | Head | the start of the head commit id (at least 4 hex characters) |
| `state` | State | `queued`, `running`, `completed`, `failed` |
| `has_regressions` | Has Regressions | `true`, `false` |
| `has_new_fp` | Has New FP | `true`, `false` |
| `compile_errors` | Compile Errors | `true`, `false` |
| `created` | Created | a date range (`-30d`, an absolute range) |

The count filters are false for a validation that has not completed, and `!` keeps those rows.

### Incremental pulls

With `changed_since`, a validation is returned when it was requested, claimed, completed or failed
at or after that time. A validation removed by retention (`svs.yara.retention_days`) just
disappears; deleting a sample removes its rows from every report.

### Joins

- **Result → sample:** `sha256` and `rule_uuid` in `GET /api/v2/svs/samples/{sha256}/{rule_uuid}`
  (a `new_fp_other_rule` or `new_match_real_hit` row has no sample of its own rule: use `sha256` with
  `f=sha256:…`).
- **Result → detections:** as for a sample.

## Test hosts

The hosts SVS test runs may target (`docs/SVS_RUNS.md`, *Test hosts*). Read with `svs:run_read`;
added, changed and removed with `svs:admin`, each change an AUDIT line.

| Endpoint | Permission | Returns |
|---|---|---|
| `GET /api/v2/svs/test-hosts` | `svs:run_read` | Test hosts by host name, paged |
| `GET /api/v2/svs/test-hosts/export/ndjson`, `/export/csv` | `svs:run_read` | The same, streamed (the CSV joins `usernames` and `ips` with `,`) |
| `GET /api/v2/svs/test-hosts/{id}` | `svs:run_read` | One test host |
| `POST /api/v2/svs/test-hosts` `{hostname, fqdn?, usernames?, ips?, platform?, notes?}` | `svs:admin` | 201 and the new host; 409 when its short name is already a test host, 422 for a field that can't be used |
| `PUT /api/v2/svs/test-hosts/{id}` (the same body) | `svs:admin` | The host with its fields replaced |
| `DELETE /api/v2/svs/test-hosts/{id}` | `svs:admin` | 204. Runs already registered keep their targets; its open maintenance window is ended |

### Fields

| Field | Meaning |
|---|---|
| `id` | The host. |
| `hostname` | The short name, lower case. It is unique: one test host per short name. |
| `fqdn` | The fully qualified name, lower case, or null. A target named by a fully qualified name matches only this one; with no `fqdn`, a target in any domain matches. |
| `usernames` | The bare user names runs may use, lower case (`CORP\Alice` and `alice@corp.example` are stored as `alice`); empty means any user. |
| `ips` | The host's addresses. |
| `platform` | `windows`, `linux` or `macos` when known: a test whose `supported_platforms` doesn't include it can't target the host. Null isn't checked. |
| `notes`, `created_by`, `created_at` | Free text, and who added it when. |
| `updated_at` | The row's last change. |

### Incremental pulls

With `changed_since`, a host is returned when it was added or changed at or after that time. A
removed host just disappears; its removal is an AUDIT line in ACE's log.

### Maintenance windows

A test host's maintenance windows (`docs/SVS_RUNS.md`, *Maintenance windows*). `{host}` is the
test host's id, or its short or fully qualified name.

| Endpoint | Permission | Returns |
|---|---|---|
| `POST /api/v2/svs/test-hosts/{host}/maintenance` `{minutes, reason}` | `svs:run_register` | 201 and the window. 403 for a host that is not a test host (it also alerts), 404 for an unknown id, 409 while a run or another window holds the host (`{"detail": {"message", "holders"}}`, as for runs), 422 for `minutes` over `svs.runs.max_maintenance_minutes` |
| `DELETE /api/v2/svs/test-hosts/{host}/maintenance` | `svs:run_register` | The window, ended now; 404 when the host has no open window |
| `GET /api/v2/svs/test-hosts/{host}/maintenance` | `svs:run_read` | The host's windows, latest first, paged with `cursor` |

| Field | Meaning |
|---|---|
| `id` | The window's uuid; `svs_maintenance` in ACE's logs and in the comment of every alert closed for it. |
| `host`, `fqdn` | The test host's names when the window opened. |
| `reason`, `opened_by`, `opened_at` | Why, who (the key's or user's name) and when. |
| `ends_at` | When it was opened to end. |
| `ended_at`, `ended_by`, `end_reason` | When it ended and who ended it: `ended` early by a call (ending the window, or removing its test host), or `expired` at `ends_at` (`ended_by` `svs`). |
| `open` | It hasn't ended. |

## Tests

The Atomic Red Team tests runs may be registered for, as `service_svs` reads them from the
repositories in `svs.catalog.repositories` (`docs/SVS_RUNS.md`, *The Atomic Red Team catalog*).
Read with `svs:run_read`, each with its state and run history. What is decided about a test's
signatures, and its settings, are changed under it with `svs:run_manage` (*Expectations*,
*Ignores* and *Test settings*, below).

| Endpoint | Permission | Returns |
|---|---|---|
| `GET /api/v2/svs/tests` | `svs:run_read` | Tests by technique, then name, filtered and paged |
| `GET /api/v2/svs/tests/export/ndjson`, `/export/csv` | `svs:run_read` | The same, streamed (the CSV joins `platforms` with `,`) |
| `GET /api/v2/svs/tests/{guid}` | `svs:run_read` | One test with its description and its atomic entry |
| `GET /api/v2/svs/catalog/repositories` | `svs:run_read` | Each catalog repository and the commit the catalog reflects (*Catalog repositories*, below) |
| `PUT`, `DELETE /api/v2/svs/tests/{guid}/expectations/{platform}/{signature_uuid}` | `svs:run_manage` | Decide a signature for the test's runs on the platform, or remove the decision |
| `PUT`, `DELETE /api/v2/svs/tests/{guid}/ignores/{signature_uuid}` | `svs:run_manage` | Ignore a signature during the test's runs on every platform, or stop |
| `GET /api/v2/svs/tests/{guid}/settings` | `svs:run_read` | The test's settings (404 when it has none) |
| `PUT`, `DELETE /api/v2/svs/tests/{guid}/settings` | `svs:run_manage` | Set them, or go back to the computed window |

### Fields

| Field | Meaning |
|---|---|
| `guid` | The test's `auto_generated_guid`, lower case: the stable identifier runs are registered with. |
| `repository` | The name of the `git_repo_*` section it is read from. |
| `technique`, `technique_name` | The ATT&CK technique of its atomic file (`attack_technique`, `display_name`). |
| `name`, `platforms`, `executor` | The test's `name`, `supported_platforms` (lower case) and `executor.name`. |
| `path` | Its atomic file, relative to the repository. |
| `commit` | The repository commit this version of the test was first read from: a new commit that doesn't change the test doesn't change it. |
| `content_hash` | sha256 of the test's entry; it changes exactly when the test does. |
| `first_seen_at` | When the catalog first read it. |
| `removed_at` | When it disappeared from its repository, or null. A removed test keeps its row and its runs. |
| `updated_at` | The row's last change. A change to the test's runs, results or state doesn't change it. |
| `test_state` | Below: `never_run`, or the worst of its platforms' states. |
| `run_count` | Every run registered for it, in any state. |
| `last_run_id`, `last_run_at` | Its latest run and when it was registered. |
| `last_reviewed_run_id`, `last_reviewed_at` | Its latest reviewed run, on any platform, and when it was reviewed. |
| `expected_signatures` | The signatures expected of it on any platform that no ignore applies to (one expected on two platforms counts once). |
| `recent_runs`, `recent_runs_missing` | Its latest ended or reviewed runs, at most 5, and how many of them missed an expected signature (missing or possibly suppressed in their live result). |

**Test state.** A test is judged on each platform on its own, on its latest *reviewed* run there,
as signed off, against what is expected of it there (*Expectations*, below):

| State on a platform | Meaning |
|---|---|
| `never_run` | It has no run and no decision there (only in `platform_states`). |
| `awaiting_review` | None of its runs there is reviewed, or something was expected of it there only after its latest reviewed run there, so no review has judged it. |
| `no_expectations` | It has a reviewed run there, and nothing is expected of it there. |
| `failing` | Its latest reviewed run there missed an expected signature (possibly suppressed counts). |
| `stale` | It would be validated, but the test (its `content_hash`) or the rule of an expected signature changed since that run was reviewed. A rule ACE can't read now doesn't count as changed. |
| `validated` | Its latest reviewed run there hit every expected signature. |

`test_state` is `never_run` when no run was ever registered for the test, else the worst state of
the platforms it has a run or a decision on: `failing`, `stale`, `awaiting_review`, `validated`,
`no_expectations`, in that order.

The state and history are derived when read, so they aren't filters: the rule hashes behind
`stale` come from the rule inventory, not the database. Its run history is
`GET /api/v2/svs/runs?f=test:{guid}`, its decisions `GET /api/v2/svs/expectations?test={guid}` and
`GET /api/v2/svs/ignores?test={guid}`.

`GET …/{guid}` adds `description` and `test`, the test's whole entry in its atomic file: `executor`
(`command`, `cleanup_command`, `elevation_required`), `input_arguments`, `dependencies`. It also adds
`platform_states`, one entry per platform the test supports or has a run or a decision on, by
platform: `{"platform", "test_state", "last_reviewed_run_id", "last_reviewed_at",
"expected_signatures"}`.

### Filters

| Slug | Filter | Values |
|---|---|---|
| `technique` | Technique | an ATT&CK id; `T1059` also finds `T1059.001` |
| `name` | Name | text the test name contains |
| `platform` | Platform | a platform in `supported_platforms` |
| `executor` | Executor | `command_prompt`, `powershell`, `sh`, `bash`, `manual` |
| `repository` | Repository | text the repository name contains |
| `removed` | Removed | `true`, `false` |

### Incremental pulls

With `changed_since`, a test is returned when it was added, changed, removed or came back at or
after that time.

### Catalog repositories

`GET /api/v2/svs/catalog/repositories` lists every repository in `svs.catalog.repositories`, and
any other that still has a row, by name: what `ace svs catalog status` prints. A launcher checks out
`commit` to run the tests, `src/` files included, as the catalog has them.

| Field | Meaning |
|---|---|
| `name` | The `name` of its `git_repo_*` section. |
| `configured` | It is in `svs.catalog.repositories`. |
| `git_url`, `branch` | From its `git_repo_*` section, `null` without one. `git_url` never carries a user or password. |
| `commit` | The commit the catalog's tests were last read from; `null` until the first read succeeds. |
| `refreshed_at` | When that commit was read. |
| `test_count`, `skipped_count` | The tests read from that commit, and the tests and files that read couldn't use. |
| `removed_count` | Its tests removed from the catalog. |
| `error` | Why the last refresh failed, `null` when it succeeded. The catalog keeps the tests of the commit it last read, so a launcher should treat `commit` as behind. |
| `retired` | Taken out of `svs.catalog.repositories`, so its tests were removed. |

## Runs

A run is one Atomic Red Team test a launcher outside ACE runs against test hosts, from
registration through review or close (`docs/SVS_RUNS.md`). The launcher drives it with the
lifecycle calls, which need `svs:run_register`. Everything else reads it with `svs:run_read`. A
launcher that also reads its runs needs both.

| Endpoint | Permission | Returns |
|---|---|---|
| `POST /api/v2/svs/runs` `{test_guid, targets: [{hostname, username?}], launcher, batch_id?, extra?}` | `svs:run_register` | 201 and the run in state `created`, with its `marker` |
| `POST /api/v2/svs/runs/validate`, same body | `svs:run_register` | What registering it would decide, without registering it: `decision` (`accepted`, `refused`, `invalid`, `host_busy`), the `status_code` registering would answer, `message`, each target's `accepted`, `reason`, `test_host`, `platform` and `held_by` (the runs holding its host), and when accepted the run's `platform`, `observation_seconds`, `observation_source`, `attribution_seconds` and `holds_host`. Creates no run, refusal or alert (`docs/SVS_RUNS.md`, *Validating a registration*) |
| `POST /api/v2/svs/runs/{run_id}/start` | `svs:run_register` | The run in state `started`, with its window ends |
| `POST /api/v2/svs/runs/{run_id}/executed` `{exit_code, error?, output?}` | `svs:run_register` | The run; a non-zero `exit_code` or an `error` moves it to `error`. `output` (what the test printed) is kept as the run's `launcher_output`, at most 64 KiB (`docs/SVS_RUNS.md`, *The test's output*) |
| `POST /api/v2/svs/runs/{run_id}/cleanup` | `svs:run_register` | The run, with `cleanup_at`: the test's cleanup begins now (a started run, once) |
| `POST /api/v2/svs/runs/{run_id}/cancel` | `svs:run_register` | The run in state `canceled`, or `closed` when it was never started |
| `GET /api/v2/svs/runs` | `svs:run_read` | Runs, newest first, filtered and paged |
| `GET /api/v2/svs/runs/export/ndjson`, `/export/csv` | `svs:run_read` | The same, streamed. The CSV joins `targets` with `,`, each as `hostname` or `hostname/username` |
| `GET /api/v2/svs/runs/count` | `svs:run_read` | `{"count"}`: how many runs the filters match |
| `GET /api/v2/svs/runs/suppression-share` | `svs:run_read` | How many missing expected signatures were possibly suppressed, over the reviewed runs (*Suppression share*, below) |
| `GET /api/v2/svs/runs/batches` (and `/export/ndjson`, `/export/csv`) | `svs:run_read` | One row per batch over the runs the filters match (*Batches*, below) |
| `GET /api/v2/svs/runs/{run_id}` | `svs:run_read` | One run, with what the launcher sent, what stands in the way of its review and its log search link |
| `GET /api/v2/svs/runs/{run_id}/alerts` (and `/export/ndjson`) | `svs:run_read` | The alerts the run holds or held (*Run alerts*, below) |
| `GET /api/v2/svs/runs/{run_id}/history?runs=` | `svs:run_read` | How the signatures of its result did in the test's earlier runs (*Run history*, below) |
| `GET /api/v2/svs/runs/{run_id}/events` (and `/export/ndjson`, `/export/csv`) | `svs:run_read` | The run's event log, oldest first |
| `GET /api/v2/svs/runs/events` (and `/export/ndjson`, `/export/csv`) | `svs:run_read` | The event feed: the events of every run the filters match, in `(updated_at, id)` order |

The lifecycle calls return the run's lifecycle fields: `run_id`, `marker`, `state`, `test_guid`,
`platform`, `targets`, the window lengths and ends, `holds_host`, `created_at`, `started_at`, `cleanup_at`, `error_reason` and
`close_reason`. Their errors:

| Status | When |
|---|---|
| 403 | A target is not a test host, or names a user the host doesn't list: `{"detail": {"message", "reasons": […]}}`, one reason per refused target. It also alerts (`docs/SVS_RUNS.md`, *Refused registrations*). Also a key without the call's permission. |
| 404 | No run has that `run_id`. |
| 409 | The call doesn't apply to the run's state: `{"detail": {"message", "state"}}`. |
| 409 | Registering, or starting, a run on a test host another run or a maintenance window holds: `{"detail": {"message", "holders": [{"host", "run_id", "maintenance_id", "state", "until"}]}}`. A run holder has `run_id` and its state, with `until` null while it hasn't started (`docs/SVS_RUNS.md`, *One run per test host*); a window holder has `maintenance_id`, `run_id` null and the state `maintenance`, with `until` when it ends (*Maintenance windows*). No alert. |
| 422 | The test is not in the catalog or was removed, a target's platform isn't one the test supports, the run's platform can't be decided (the targets' hosts disagree, or none has a platform and the test supports more than one), a host or user name can't be used, too many targets, or `extra` is too large. |

The reads answer 400 for a `run_id` that is not a UUID and 404 for an unknown one.

### Fields

| Field | Meaning |
|---|---|
| `run_id` | The run's UUID: the stable identifier of a run, and the `svs_run` field of every log record about it. |
| `state` | `created`, `started`, `ended`, `reviewed`, `canceled`, `error` or `closed` (`docs/SVS_RUNS.md`, *Run states and timers*). |
| `test_guid` | The catalog test (`GET /api/v2/svs/tests/{guid}`). |
| `test_name`, `technique`, `technique_name` | From the catalog, as it is now. |
| `platform` | The platform the run is on, an ATT&CK platform slug (`windows`, `linux`, `macos`, `iaas`, …), decided at registration: its targets' test hosts' platform, else the test's only supported platform (`docs/SVS_RUNS.md`, *Registering a run*). |
| `holds_host` | Lifecycle calls and the run's detail: the run holds its test hosts until its attribution window ends rather than its observation window, from its test's settings at registration (`docs/SVS_RUNS.md`, *One run per test host*). |
| `marker` | `svs-` and 26 base32 characters. Put it where the test's process telemetry shows it. It is `svs_marker` in ACE's log. |
| `targets` | As registered (`hostname`, `username`) and normalized (`host`, the short name; `fqdn`; `user`, the bare user name), all lower case when normalized. |
| `launcher`, `batch_id` | As registered. A batch is a label shared by the runs a launcher registered together, not a resource. |
| `created_at`, `started_at` | When it was registered and started. |
| `executed_at`, `exit_code` | What the launcher reported through `executed`. |
| `ended_at`, `canceled_at`, `closed_at` | When it moved to those states. |
| `observation_ends_at`, `attribution_ends_at` | When its windows end, set at `start`. *Time left* on a started run is `observation_ends_at` minus now. |
| `error_reason` | Why it is in `error`: the launcher's failure, or the start timeout. |
| `close_reason` | Why it was closed: `start timeout`, `canceled before start`, `attribution window ended`. |
| `owner`, `reviewer`, `reviewed_at` | Usernames, and when it was last reviewed (*Run actions*, below). |
| `changed_since_review` | An attribution of an alert to it was added or removed after its review: a late alert, a later analysis pass, or a manual association. |
| `needs_attention` | Whether it is in the *Needs attention* view (below). |
| `result_hit`, `result_expected` | Its result's hits out of the expected signatures it judged (*expected hits n/m*): `result_expected` counts hit, missing and possibly suppressed (*Results*, below). |
| `result_missing`, `result_possibly_suppressed` | Expected signatures it missed (possibly suppressed ones included), and of those the possibly suppressed. |
| `result_candidate`, `result_rejected`, `result_ignored` | Signatures that fired and nobody decided, were rejected, or are ignored. |
| `result_cleanup` | Signatures that fired only during the test's cleanup (`docs/SVS_RUNS.md`, *Cleanup*). |
| `result_stale` | Its result is about to be recomputed. |
| `reviewed_hit`, `reviewed_expected`, `reviewed_missing`, `reviewed_possibly_suppressed` | The same counts of the result as signed off at its latest review (`reviewed_status`); 0 until it is reviewed. |
| `alerts`, `marker_alerts`, `context_alerts`, `late_alerts` | The alerts attributed to it; of those, by a marker, by context alone (`TEST?`), and late. |
| `updated_at` | The row's last change; the `changed_since` key. A change to its result or its alerts doesn't change it: pull the result feed for those. |

`GET …/{run_id}` adds:
- `extra`, the object the launcher sent;
- `launcher_error`, the error `executed` reported;
- `launcher_output`, what the test printed, as `executed` reported it (at most 64 KiB, longer output
  truncated around a marker);
- `test_content_hash` and `catalog_commit`, the test as it was registered (a later catalog change
  doesn't change them);
- `observation_seconds` and `attribution_seconds`, the window lengths fixed at registration
  (`docs/SVS_RUNS.md`, *Windows*);
- `registered_by`, the username of the key that registered it (null for a config key);
- `review_blockers`, for an `ended` or `reviewed` run (null otherwise): `{"stale", "candidates",
  "context_alerts"}`, what a review would answer 409 with right now (*Run actions*, below), empty
  lists and `false` when nothing is in the way;
- `log_search_url`, the run's search in the site's log tooling, built from `svs.log_search_url`
  (`docs/SVS_RUNS.md`, *Logs*); null when that isn't set.

### Filters

The runs, the event feed and the GUI's Runs screen share these filters (screen `svs_runs`).

| Slug | Filter | Values |
|---|---|---|
| `needs_attention` | Needs Attention | `true`, `false` |
| `state` | State | the states above |
| `test` | Test | a test GUID |
| `test_name` | Test Name | text the catalog name contains |
| `technique` | Technique | an ATT&CK id; `T1059` also finds `T1059.001` |
| `target` | Target | a host, by its short or fully qualified name |
| `platform` | Platform | a platform slug; Atomic Red Team's names find the platform they count as (`iaas:aws` finds `iaas`) |
| `launcher` | Launcher | text the launcher's name contains |
| `batch` | Batch | a `batch_id` |
| `created`, `started`, `ended`, `reviewed` | Created, Started, Ended, Reviewed | date ranges; `reviewed` is the latest review |
| `owner`, `reviewer` | Owner, Reviewer | usernames |
| `reason` | Reason | text the close or error reason contains; `reason:start timeout` finds the runs closed because `start` was never called |
| `changed_since_review` | Changed Since Review | `true`, `false` |
| `has_open_alerts` | Has Open Alerts | `true`, `false`: an alert attributed to the run is still `OPEN` |
| `has_missing` | Has Missing | `true`, `false`: its result misses an expected signature (possibly suppressed included) |
| `has_possibly_suppressed` | Has Possibly Suppressed | `true`, `false` |
| `has_candidates` | Has Candidates | `true`, `false`: a signature fired that nobody has decided about |
| `has_late` | Has Late | `true`, `false`: an alert was attributed to it late |
| `has_context_only` | Has Context Only | `true`, `false`: an alert was attributed to it by context alone (`TEST?`) |

**Needs attention** is the Runs screen's default view and the count on its navigation entry. It
matches runs that:
- ended and wait for review;
- are in `error`;
- were reviewed and have changed since;
- are `reviewed` or `closed` and still hold an open alert (`has_open_alerts`): one an analyst
  took before the run closed, a `partial` alert whose other detections wait for triage, or one
  closing couldn't reach yet.

It is one filter, not a combination of the others, because it is an OR. A saved filter on it
follows any change to that definition.

### Incremental pulls

With `changed_since`, a run is returned when it was registered or its row changed at or after that
time. The pages are then in `(updated_at, id)` order instead of newest first, and a cursor only
works with the order it came from (otherwise 400). A row shows up a few seconds after it is
written, once no open transaction can still write an older `updated_at`. Resume from the last
row's `updated_at` and you never miss a run.

### Suppression share

Suppression a run doesn't key by itself (`docs/SVS_RUNS.md`, *Hunt suppression during runs*) is
judged by a revisit trigger (`docs/SVS.md`, Part 3, *Hunt suppression*). `GET /api/v2/svs/runs/suppression-share` reads it from every run's
result as signed off, and the Runs tab shows it above the list:

| Field | Meaning |
|---|---|
| `missing` | The expected signatures missing from the signed-off results, possibly suppressed ones included. |
| `possibly_suppressed` | Of those, the possibly suppressed. |
| `share` | `possibly_suppressed / missing`; null while nothing is missing. |
| `reviewed_runs` | The runs with a signed-off result. |
| `first_reviewed_at` | When the first run was reviewed (the event log's first `reviewed` event). |
| `trigger_reached` | 50 runs are reviewed, or 90 days passed since the first review. |
| `reconsider` | The trigger is reached and the share is above 10%. |

It takes no filters: the trigger is about the test program as a whole.

### Batches

A run's `batch_id` is a label the launcher gives it, not a table. `GET /api/v2/svs/runs/batches`
groups the runs by it, one row per batch:

| Field | Meaning |
|---|---|
| `batch_id` | The batch. Batch ids compare without case, as the `batch` filter does; runs without one are left out. |
| `runs`, `states` | How many runs, and how many in each state (every state is named, with 0 when there are none). |
| `needs_attention` | How many are in the *Needs attention* view. |
| `first_created_at`, `last_created_at` | When its first and its latest run were registered. |
| `result_hit`, `result_expected`, `result_missing`, `result_candidate` | The runs' result counts (*Fields*, above), summed. |

**The `f=` filters pick the runs, and a row counts only those.** A batch with no matching run has
no row, and `f=batch:<id>` on `GET /api/v2/svs/runs` lists exactly the runs a row counted. The
batch with the latest run comes first, ties by batch id; a batch moves up when a run joins it. There
is no `changed_since`: a batch is a summary, not a change feed. The CSV has a `state_<state>`
column per state in place of `states`.

`GET /api/v2/svs/runs/count` takes the same filters. `f=needs_attention:true` is the count the
GUI shows on its *SVS* entry.

### Run events

Each run has an append-only event log (`docs/SVS_RUNS.md`, *Following runs*). Each event has:
- `id` (a run's events are in `id` order) and `run_id`;
- `kind`, `from_state` and `to_state`;
- `actor` (the caller's name, or `svs` for a timer) and `actor_user` (its username, when it is a
  user);
- `details`, whose shape depends on `kind`;
- `created_at` and `updated_at`.

| `kind` | States | `details` |
|---|---|---|
| `registered` | `to_state: created` | The registration: `test_guid`, `targets`, `launcher`, `batch_id`, `extra`, the `platform` it decided, and `observation_source` (`override`, `expected` or `all_hunts`: where its observation window came from, `docs/SVS_RUNS.md`, *Windows*) |
| `transition` | both | `{"reason"}` when the move has one (an error, a close), else null |
| `launcher_call` | none | `{"call", "outcome", "payload"}`. `call` is `start`, `executed` or `cancel`. `outcome` is `started`, `recorded`, `error`, `canceled` or `conflict` (a call the state didn't allow). `payload` is `{exit_code, error}` for `executed` |
| `attributed` | none | `{"alert_uuid", "detections"}`: detections of one alert attributed to the run, each `{"detection", "confidence", "late", "scan_point"}` (`detection` is its `content_hash`; `scan_point` is null for context). Written when an attribution is added or comes back, not on every analysis pass. `actor` is `svs` |
| `attribution_removed` | none | `{"alert_uuid", "detections", "reason"}`: the `content_hash`es of the alert's detections whose attribution no longer holds (a later analysis pass found the marker disagrees, say) |
| `alerts_closed` | none | `{"alerts", "disposition", "late"}`: the alerts given `SIMULATED` when the run closed, or (`late: true`) by the timers afterwards (`docs/SVS_RUNS.md`, *Test alerts and `SIMULATED`*) |
| `result_computed` | none | `{"counts", "previous"}`: the run's result changed; the number of signatures per status, now and before. `actor` is `svs` |
| `candidate_decision` | none | `{"signature_uuid", "state", "reason"}`: a signature decided for the run's test from this run's result |
| `associated` | none | `{"alert_uuid", "detections", "late", "reason"}`: a person associated the alert with the run (`detections` are `content_hash`es) |
| `disassociated` | none | `{"alert_uuid", "detections", "reason", "not_a_test"}`: a person disassociated it, or marked it not a test |
| `context_kept` | none | `{"alert_uuid"}`: a person kept the alert's context attributions |
| `ownership_taken` | none | `{"from"}`: a person took the run, from that owner's username (null when nobody owned it) |
| `reviewed` | `from_state: ended` or `reviewed`, `to_state: reviewed` | `{"counts", "re_review"}`: a person signed the result off; the counts are per status, as signed off |

`alerts_closed` also carries `"reviewed": true` when a review closed them. A reader skips kinds it
doesn't know. In CSV, `details` is a JSON string.

### The event feed

`GET /api/v2/svs/runs/events` is the runs' change feed: every event of every run the `f=` filters
match, in `(updated_at, id)` order, with `changed_since`. As with the run list, an event shows up a
few seconds after it is written, so a pull resumed from the last event's `updated_at` never misses
one. It may repeat one. This is where a report sees what happened to a run between two pulls, and
later in phase 4 what was disassociated from it.

### Run actions

A person's actions on runs, all `svs:run_manage` and from a user's key (a config key gets 422);
`docs/SVS_RUNS.md`, *Reviewing runs*:

| Endpoint | Does |
|---|---|
| `POST /api/v2/svs/runs/bulk/take-ownership` | Take the runs |
| `POST /api/v2/svs/runs/bulk/cancel` | Cancel them (created or started) |
| `POST /api/v2/svs/runs/bulk/close` | Close them (ended, canceled or error); an ended run needs `reason` |
| `POST /api/v2/svs/runs/{run_id}/review` `{"confirmed_take_from"?}` | Review the run (ended, or reviewed again) |
| `GET`, `POST /api/v2/svs/runs/{run_id}/comments`; `PATCH`, `DELETE …/comments/{comment_id}` | Its comments (reading needs only `svs:run_read`; only the author changes or deletes one) |

- **The bulk actions** take `{"run_ids", "confirmed_takes"?, "reason"?}`. `confirmed_takes` maps a
  run id to the username of the person the caller agreed to take it from. They answer
  `{"done", "left_alone", "conflicts", "unknown"}`: the runs acted on; the ones someone else owns
  (run id → their username, which can be sent back as `confirmed_takes` as it is); the ones the
  action doesn't apply to (run id → why); and the ids that don't exist.
- **A review** answers `{"run", "re_review", "counts", "alerts_closed", "fp_verdicts"}`, or 409
  whose `detail` says what stands in the way, any of:
  - `owner`: the username of whoever else owns it, when `confirmed_take_from` didn't name them;
  - `state`;
  - `stale`: the result is being recomputed;
  - `candidates`: the undecided signature uuids;
  - `context_alerts`: the context-only alerts neither kept nor marked not a test.

### Results

A run's result is one row per signature (`docs/SVS_RUNS.md`, *Results*), read with `svs:run_read`:

| Endpoint | Returns |
|---|---|
| `GET /api/v2/svs/runs/{run_id}/results` (and `/export/ndjson`, `/export/csv`) | One run's rows in id order, with `stale` and `computed_at` |
| `GET /api/v2/svs/runs/results` (and `/export/ndjson`, `/export/csv`) | The rows of every run the `f=` filters match, in `(updated_at, id)` order, with `changed_since`; a row shows up a few seconds after it is written, as in the event feed |

| Field | Meaning |
|---|---|
| `run_id`, `signature_uuid` | The run and the signature; together they are unique. |
| `signature_family`, `signature_name` | `yara`, `hunt`, `builtin`, ...; and its name, from the rule inventory, or as last known when the rule is gone. |
| `status` | `hit`, `missing`, `possibly_suppressed`, `candidate`, `rejected`, `ignored` or `cleanup` (it fired only during the test's cleanup and isn't expected); null once the signature left the live result and the row holds only the reviewed one. |
| `alert_count` | The run's attributed alerts that carry the signature (0 when missing). A signature the test fired outside its cleanup counts only those alerts. |
| `late_only`, `context_only` | Every attribution of it was *late*, or by context alone. |
| `fallback_time` | Some attribution of it was judged by a fallback event time (`docs/SVS_RUNS.md`, *Fallback event times*). |
| `content_hash` | The rule's own content hash when the result was computed (the YARA rule's text, the hunt's file, a built-in's declaration). |
| `suppressing_alert_uuid` | For `possibly_suppressed`: the hunt's latest alert within its suppression period. Empty when the hunter recorded that it dropped the run's match, for a hunt with `group_by` or as a duplicate of its `dedup_key` (`docs/SVS_RUNS.md`, *Results*). |
| `reviewed_status`, `reviewed_alert_count`, `reviewed_late_only`, `reviewed_content_hash` | The result as signed off; null until the run is reviewed. A re-review replaces them. |
| `updated_at` | The row's last change; the feed's `changed_since` key. |

`stale` (one run only) is true while something changed since the result was computed: the timers
recompute it within `svs.runs.timer_interval_seconds`. A run that hasn't ended has no result.

### Attributions

Which detections of which alerts a run holds (`docs/SVS_RUNS.md`, *Attribution* and *Associating
alerts by hand*), one row per (alert, detection), removed ones included, read with `svs:run_read`:

| Endpoint | Returns |
|---|---|
| `GET /api/v2/svs/runs/{run_id}/attributions` (and `/export/ndjson`, `/export/csv`) | One run's rows in id order |
| `GET /api/v2/svs/runs/attributions` (and exports) | The rows of every run the `f=` filters match, in `(updated_at, id)` order, with `changed_since`; a row shows up a few seconds after it is written. A disassociation is a row whose `removed_at` changed, so this is where reports see one |

| Field | Meaning |
|---|---|
| `run_id`, `alert_uuid`, `detection` | The run, the alert, and the detection's `content_hash`; together they are unique. |
| `signature_uuid`, `signature_family` | The detection's signature. |
| `confidence`, `late` | `marker` or `context` (a person's association is `marker`), and whether the alert's event came after the observation window. |
| `event_time`, `cleanup` | The alert's event time the attribution was judged by (null for attributions written before it was kept), and whether it is at or after the run's `cleanup_at`: the test's cleanup caused it (`docs/SVS_RUNS.md`, *Cleanup*). |
| `event_time_source`, `fallback_time` | Where `event_time` came from: `event` (the event's own), `query_time` (a hunt couldn't extract it), `now` (nothing gave the alert a time, so its producer used the time it created it) or `insert_time` (the alert has none); null for attributions written before it was kept. `fallback_time` is true for all but `event` (`docs/SVS_RUNS.md`, *Fallback event times*). |
| `source` | `router` (the `svs_marker` router) or `manual` (a person associated the alert). |
| `scan_point` | Where the agreeing marker was found; null for context and for a person's association. |
| `actor`, `actor_user`, `created_at` | Who attributed it (`svs` for the router) and when. |
| `removed_at`, `removed_by`, `removed_by_user`, `removal_reason` | Set once it no longer holds: by the router (`svs`, it no longer applies) or by a person (disassociated, or *not a test*). |
| `kept_at`, `kept_by_user` | A person kept this context attribution. |
| `updated_at` | The row's last change; the feed's `changed_since` key. |

A person changes them with `svs:run_manage`, from a user's key (a config key gets 422):

| Endpoint | Does |
|---|---|
| `POST /api/v2/svs/runs/{run_id}/alerts/{alert_uuid}/associate` `{"reason"?}` | Associate the alert with the run (409 for a run that never started, 422 for an alert without detections) |
| `POST …/disassociate` `{"reason"?}` | Disassociate it (409 when the run doesn't hold it) |
| `POST …/not-a-test` `{"reason"?}` | Disassociate a `TEST?` alert (409 unless the run holds it by context alone) |
| `POST …/keep` | Keep its context attributions (409 when it has none) |

Each answers `{"alert_uuid", "svs_status", "queue", "moved", "reopened"}`: the alert's SVS status
and queue afterwards, whether it moved, and whether it went from `SIMULATED` back to `OPEN`.

### Run alerts

`GET /api/v2/svs/runs/{run_id}/alerts` is what the run page shows of the run's alerts: one row per
alert with an attribution to the run, held or removed, in the order they were first attributed,
paged with `cursor`. Its NDJSON export streams every row. The rows nest, so there is no CSV:
`…/attributions/export/csv` is the flat form.

| Field | Meaning |
|---|---|
| `alert_uuid` | The alert. |
| `alert` | Its row as `GET /api/v2/alerts` lists it, `svs_status` included; null when the alert is gone. |
| `holds` | An attribution of it to this run holds. A row whose attributions were all removed (disassociated, *not a test*, or the router found they no longer apply) has `false`. |
| `confidence` | Of the attributions that hold: `marker` when any is (a person's association counts as one), else `context`; null when none holds. |
| `late`, `manual` | An attribution that holds is late, or was made by a person. |
| `cleanup` | Every attribution that holds is the test's cleanup's. |
| `fallback_time` | An attribution that holds was judged by a fallback event time. |
| `kept` | A person kept its context attributions. |
| `undecided_context` | It has a context attribution that holds and that nobody kept: a review waits for *keep* or *not a test* (`review_blockers.context_alerts`). |
| `detections` | Every detection of the alert, then any attributed one it no longer has: `{"detection", "description", "signature_uuid", "signature_family", "attribution"}`, where `detection` is the `content_hash`, `description` is null for one it no longer has, and `attribution` is its attribution to this run (as in *Attributions*), or null when it never had one. |

### Run history

`GET /api/v2/svs/runs/{run_id}/history?runs=10` (1 to 50) answers how each signature of the run's
result did before: `{"runs", "signatures"}`.
- `runs` are the test's `ended` and `reviewed` runs on this run's platform (the only runs it is
  compared with) registered before this one, latest first, each
  `{"run_id", "state", "created_at", "reviewed_at"}`.
- `signatures` has one entry per signature of this run's result, in its order, `{"signature_uuid",
  "statuses"}`. `statuses` lines up with `runs`: the signature's status in that run, as signed off
  for a reviewed run and live for an ended one, or null when it isn't in that run's result (it
  didn't fire, and nothing expected it then).

### Joins

- **Run → test:** `test_guid` = the test's `guid` in `GET /api/v2/svs/tests`.
- **Event → run:** `run_id` = the run's `run_id`.
- **Attribution → alert, detection:** `alert_uuid` = an alert's `uuid` in `GET /api/v2/alerts`,
  `detection` = a detection's `content_hash` in `GET /api/v2/alerts/{uuid}/detection-points`.
- **Result → run:** `run_id` = the run's `run_id`; **result → signature:** `signature_uuid` = a
  detection's `signature_uuid` in `GET /api/v2/detection-points`, and a sample's `rule_uuid`.
- **Run → logs:** `run_id` and `marker` are the `svs_run` and `svs_marker` fields in ACE's log.

## Expectations

What is decided about each test's signatures on each platform (`docs/SVS_RUNS.md`, *Expectations
and ignores*). `GET /api/v2/svs/expectations` (and `/export/ndjson`, `/export/csv`), `svs:run_read`,
filtered by `test`, `platform`, `signature` and `state`. A decision is made with
`PUT /api/v2/svs/tests/{guid}/expectations/{platform}/{signature_uuid}` `{"state":
"expected"|"rejected", "reason"?, "run_id"?}` and removed with `DELETE`, both `svs:run_manage` and
from a user's key (a config key gets 422: a decision records who made it). The platform has to be
one the test supports, and a `run_id` a run of the test on that platform; otherwise the answer is
422.

| Field | Meaning |
|---|---|
| `test_guid`, `platform`, `signature_uuid` | The test, the platform its runs are judged on with it, and the signature; together they are unique. |
| `state` | `expected` or `rejected`. A candidate is a status in a run's result, never a row here. |
| `signature_family`, `signature_name` | As last known when the decision was made. |
| `reason` | Why, as the person wrote it. |
| `decided_from_run_id` | The run whose result it was decided from, when it was. |
| `decided_by`, `decided_at` | Who (username) and when. |
| `updated_at` | The row's last change; with `changed_since` the rows come in `(updated_at, id)` order. A removed decision is gone; the run results it changes show the difference. |

## Ignores

Signatures whose detections during runs are noise. `GET /api/v2/svs/ignores` (and exports),
`svs:run_read`, filtered by `scope` (`global`, `test`), `test` (that test's own and the global ones,
which apply to it) and `signature`. A test's ignore is set with `PUT /api/v2/svs/tests/{guid}/
ignores/{signature_uuid}` (`svs:run_manage`); a global one with `PUT /api/v2/svs/ignores/global/
{signature_uuid}` (`svs:admin`). Both take `{"reason"?}` and are removed with `DELETE`.

| Field | Meaning |
|---|---|
| `scope`, `test_guid` | `global`, or `test` with its guid. |
| `signature_uuid`, `signature_family`, `signature_name` | The signature, as last known when it was ignored. |
| `reason`, `created_by`, `created_at` | Why, who (username), when. |
| `updated_at` | The row's last change (a new reason); the `changed_since` key. |

## Test settings

`GET`, `PUT`, `DELETE /api/v2/svs/tests/{guid}/settings`: `{"observation_minutes", "holds_host"}`, for
the test's runs registered from then on. `observation_minutes` is their observation window, used as
it is (no slack, no floor) from 1 minute up to `svs.runs.observation_window.ceiling_hours`, or null
for the computed one (`docs/SVS_RUNS.md`, *Windows*). `holds_host` (default false) makes each run
hold its hosts until its attribution window ends rather than its observation window
(`docs/SVS_RUNS.md`, *One run per test host*). A `PUT` replaces both; `DELETE` goes back to the
defaults. The response adds `set_by` (username) and `updated_at`. Reading needs `svs:run_read`,
changing `svs:run_manage`.

## Coverage

ATT&CK coverage per technique and platform, as `service_svs` last refreshed it
(`docs/SVS_COVERAGE.md`): at most `svs.coverage.refresh_interval_seconds` (default 120) behind a
review. Read with `svs:run_read`; nothing here writes.

| Endpoint | Returns |
|---|---|
| `GET /api/v2/svs/coverage` | Rows by technique, then platform, filtered and paged |
| `GET /api/v2/svs/coverage/export/ndjson`, `/export/csv` | The same, streamed (the CSV joins `tactics` with `,`) |
| `GET /api/v2/svs/coverage/summary` | The rows the filters match, counted, and the last refresh |
| `GET /api/v2/svs/coverage/{technique}` | One technique's drill-down |

### Fields

| Field | Meaning |
|---|---|
| `technique`, `platform` | The ATT&CK technique id and a platform slug (`windows`, `linux`, `macos`, `esxi`, `iaas`, `containers`, `saas`, `office-suite`, `identity-provider`, `network-devices`, `pre`, or one only a test names); together they are unique. |
| `parent`, `is_subtechnique` | The parent of a sub-technique, and whether the row is one. |
| `technique_name`, `tactics` | From the pinned release (`tactics` are ids, `TA0002`); for a technique it doesn't have, the name a test gives it and no tactics. |
| `catalog_status` | `active`, `deprecated`, or `unknown` (not in the pinned release; only a test names it). A revoked id never has a row: it counts as its successor. |
| `attack_platform` | ATT&CK lists the platform for the technique; `false` when only a test brought the row. |
| `state` | `failing`, `stale`, `validated`, `manual`, `untested` or `none`: the worst of what counts toward the technique and its sub-techniques on the platform (`docs/SVS_COVERAGE.md`, *States*). |
| `own_state` | The same, leaving the sub-techniques out. |
| `tests_total`, `tests_validated`, `tests_failing`, `tests_stale` | The tests counted toward `state`, the sub-techniques' included. A test whose expectations no reviewed run judged yet is `stale`. |
| `manual_signatures` | Signatures whose `mitre:` tag counts toward `state`. |
| `measured_signatures` | Signatures expected of the counted tests on the platform, ignores applied. |
| `last_reviewed_at` | The latest review of a run that counts. |
| `state_changed_at`, `first_seen_at` | When `state` last changed, and when the row appeared. |
| `retired_at` | When the computation stopped producing the row (its test was removed, an ATT&CK upgrade revoked it), or null. Rows are never deleted, and a row that comes back is live again. |
| `updated_at` | The row's last change: a refresh writes only what changed. The `changed_since` key. |

### Filters

| Slug | Filter | Values |
|---|---|---|
| `technique` | Technique | an ATT&CK id; `T1059` also finds `T1059.001` |
| `name` | Name | text the technique name contains |
| `tactic` | Tactic | a tactic id (`TA0002`) or shortname (`execution`) of the pinned release |
| `platform` | Platform | a platform slug; Atomic Red Team's names find the slug they count as (`iaas:aws` finds `iaas`) |
| `state`, `own_state` | State, Own State | `failing`, `stale`, `validated`, `manual`, `untested`, `none` |
| `level` | Level | `technique`, `sub-technique` |
| `attack_platform` | ATT&CK Platform | `true`, `false` |
| `catalog_status` | Catalog Status | `active`, `deprecated`, `unknown` |
| `has_manual` | Has Manual | `true`, `false` |
| `state_changed` | State Changed | a date range |
| `retired` | Retired | `true`, `false` |

The GUI's default saved filters are *Endpoint platforms* (`platform:windows,linux,macos` and
`retired:false`), *Gaps and failures* (the same, plus `state:failing,stale,untested,none`) and *All*
(`retired:false`).

### Incremental pulls

With `changed_since`, a row is returned when it was added, changed, retired or came back at or
after that time, in `(updated_at, id)` order. A cursor from one order doesn't page the other: 400.

### Summary

`GET …/summary` takes the same filters and counts the rows they match: `rows`, `states` and
`own_states` (every state named, zeros included), and the same per platform in `platforms`, in the
release's platform order. It also carries the last refresh from `svs_coverage_state`:
`attack_release`, `refreshed_at` (null before the first), `duration_ms`, `unknown_tags` and
`ignored_tags` (`mitre:` tags naming an id the release doesn't have, and ones that aren't technique
ids), and `error`, why the latest refresh failed, null once one completes.

### Drill-down

`GET …/{technique}` answers what a technique's coverage rests on. A revoked id answers for its
successor (`requested` is the id asked for, `technique` the one answered for); something that isn't
a technique id is a 400, and a technique without rows that the release doesn't have a 404.

| Field | Meaning |
|---|---|
| `name`, `parent`, `is_subtechnique`, `catalog_status`, `tactics`, `attack_release` | The technique in the pinned release. |
| `refreshed_at` | When `rows` were refreshed. Everything below them is read now, so the two can disagree for up to one refresh interval. |
| `rows`, `sub_technique_rows` | Its rows and its sub-techniques' rows, retired ones included, as in the list. |
| `tests` | One entry per (test, platform) counting toward the technique or a sub-technique: `guid`, `name`, `test_technique` (as its atomic file names it), `technique` (what it counts toward), `platform`, `test_state` (as on the Tests screen; `never_run` when it has no run or decision there), `contribution` (what it counts as), `last_reviewed_run_id`, `last_reviewed_at` and `expected_signatures`. |
| `measured_signatures` | Each signature expected of those tests: `signature_uuid`, its `name` and `family` when ACE knows the signature, and the `tests` (`guid`, `platform`) expecting it. |
| `manual_signatures` | Each `mitre:` tag naming the technique or a sub-technique: `signature_uuid`, `name`, `family` (`hunt`, `yara`), `declared` (the id in the tag), `technique`, `counts`, and `reason` when it doesn't count: `not_counting` (the signature is disabled, or a YARA rule in QA mode), `unknown_technique`, or `removed` (resolved *remove* on the worklist). |
| `manual_signatures_error` | Why the tags couldn't be read (a YARA rule location that can't be loaded); `manual_signatures` is then empty and the rest is unaffected. |
| `removed_tests` | The technique's tests removed from their repository (`guid`, `name`, `technique`, `removed_at`); they don't count. |

### Joins

- **Coverage → tests:** `GET /api/v2/svs/tests?f=technique:{technique}&f=platform:{platform}`; the
  drill-down's `guid` is a test's `guid`.
- **Coverage → runs:** the drill-down's `last_reviewed_run_id` is a run's `run_id`;
  `GET /api/v2/svs/runs?f=technique:{technique}&f=platform:{platform}` lists them all.
- **Coverage → signatures:** `signature_uuid` is a detection's `signature_uuid` in
  `GET /api/v2/detection-points`, and `GET /api/v2/svs/expectations?signature={uuid}` lists where it
  is expected. `GET /api/v2/svs/worklist?f=technique:{technique}` lists the tags on the technique
  and what was decided about them.

## Coverage history

One row per technique × platform per day, filed by the daily snapshot (`docs/SVS_COVERAGE.md`,
*Snapshots*): the live coverage rows of that UTC day. Read with `svs:run_read`.

| Endpoint | Returns |
|---|---|
| `GET /api/v2/svs/coverage/history` | Snapshot rows by day, then technique and platform, oldest first |
| `GET /api/v2/svs/coverage/history/export/ndjson`, `/export/csv` | The same, streamed |
| `GET /api/v2/svs/coverage/history/counts?group=day\|month` | Rows per state and own state, per period |

Fields: `snapshot_date` (the UTC day), `technique`, `platform`, `attack_release`, `parent`,
`is_subtechnique`, `state`, `own_state`, `tests_total`, `tests_validated`, `tests_failing`,
`tests_stale`, `manual_signatures`, `measured_signatures`, all as in *Coverage* on that day, and
`updated_at`, when the row was written (a second snapshot the same day rewrites what changed). With
`changed_since` the rows come in `(updated_at, id)` order.

Filters: `date` (a date range; a snapshot counts when its day is in it), `technique` (with its
sub-techniques), `platform`, `state`, `own_state`, `level`, with the values of *Coverage*.

`…/counts` takes the same filters and answers `{"group", "data": [{"period", "snapshot_date",
"rows", "states", "own_states"}]}`, oldest first. A day's period is the day (`2026-10-16`); a month's
(`2026-10`) counts that month's **last** snapshot, which `snapshot_date` names, because adding up
daily snapshots would count each row once a day. The days come from the `date` filter alone, so a
day the other filters leave empty is still there, with zeros.

## Worklist

The declared-vs-measured worklist (`docs/SVS_COVERAGE.md`, *The worklist*): one row per (signature,
ATT&CK technique) for each signature that is expected of a catalog test, comparing the techniques
its `mitre:` tags claim with the ones its tests measure. Everything but the resolution is derived on
each coverage refresh; read with `svs:run_read`, resolved with `svs:run_manage`.

| Endpoint | Returns |
|---|---|
| `GET /api/v2/svs/worklist` | Rows by signature, then technique, filtered and paged |
| `GET /api/v2/svs/worklist/export/ndjson`, `/export/csv` | The same, streamed (the CSV joins `declared_as` and `measured_techniques` with `,`) |
| `GET /api/v2/svs/worklist/{signature_uuid}` | A signature's rows, retired ones included, and what it is measured on now; 404 when it has none |
| `PUT /api/v2/svs/worklist/{signature_uuid}/{technique}/resolution` | Resolve a row (below); answers the row |
| `DELETE /api/v2/svs/worklist/{signature_uuid}/{technique}/resolution` | Clear a row's resolution; 404 when it has none |
| `POST /api/v2/svs/worklist/bulk/resolve` | Resolve many rows alike |

### Fields

| Field | Meaning |
|---|---|
| `signature_uuid`, `technique` | The signature and the ATT&CK technique, as the pinned release has it (a revoked tag id counts as its successor); together they are unique. |
| `technique_name` | From the pinned release; null for an id it doesn't have. |
| `kind` | `declared` (a tag of the signature), `undeclared` (a technique it is measured on that no tag names) or `unknown` (a tag naming an id the release doesn't have). |
| `status` | `confirmed`, `open`, `kept`, `remove_pending`, `removed`, `undeclared`, `unknown` or `retired` (`docs/SVS_COVERAGE.md`, *The worklist*). |
| `declared_as` | The tag ids, as the signature writes them, that count as `technique`: usually one; two when a revoked id and its successor are both tagged. |
| `tag_present` | The signature has a tag that counts as `technique` now. |
| `signature_counts` | The signature is enabled, and isn't a YARA rule in QA mode. |
| `counts` | The tag counts toward coverage as a manual mapping. After a resolution this is already the new value; coverage follows at the next refresh. |
| `measured`, `measured_techniques` | The signature is expected of a catalog test, and the techniques it is measured on. |
| `signature_family`, `signature_name` | `hunt`, `yara`, ... and the name, as of the last refresh. |
| `resolution`, `reason`, `reference` | `keep` or `remove`, why, and a link (the pull request removing the tag); null when nobody resolved the row. A resolution is kept whatever the status becomes. |
| `resolved_by`, `resolved_at` | Who (username) and when. |
| `first_seen_at`, `status_changed_at` | When the row appeared, and when `status` last changed. |
| `updated_at` | The row's last change: a refresh writes only what changed. The `changed_since` key. |

### Filters

| Slug | Filter | Values |
|---|---|---|
| `signature` | Signature | a signature uuid, or text in its name |
| `family` | Family | `hunt`, `yara`, `builtin`, `observable_modifier` |
| `technique` | Technique | an ATT&CK id; `T1059` also finds `T1059.001` |
| `status` | Status | the statuses above |
| `kind` | Kind | `declared`, `undeclared`, `unknown` |
| `resolution` | Resolution | `keep`, `remove`, `none` (nobody resolved it) |
| `resolved_by` | Resolved By | a username |
| `resolved` | Resolved | a date range |

The GUI's default saved filters are *Needs decision* (`status:open`), *Remove pending*
(`status:remove_pending`) and *Undeclared* (`status:undeclared`).

### Incremental pulls

With `changed_since`, a row is returned when it was added, its status or anything derived changed,
or someone resolved it, at or after that time, in `(updated_at, id)` order. A cursor from one order
doesn't page the other: 400.

### A signature

`GET …/{signature_uuid}` answers `signature_family`, `signature_name`, `rows` (every row of the
signature, as in the list) and `measured`: each technique it is measured on now, with
`technique_name` and the `tests` (`guid`, `name`, `platform`) that expect it, ignores applied and
removed tests left out. `measured` is computed at the request, `rows` at the last refresh.

### Resolving

`PUT …/{signature_uuid}/{technique}/resolution` takes `{"resolution": "keep"|"remove", "reason",
"reference"?}`:
- `keep`: the tag covers something no test reaches; it keeps counting.
- `remove`: the signature repository will drop the tag; `reference` is the pull request. The tag
  stops counting from the next coverage refresh, while it is still there.

A reason is required, and `reference` must be an http(s) URL. Only `open`, `kept` and
`remove_pending` rows can be resolved; resolving again replaces the resolution. A `confirmed`,
`undeclared`, `unknown`, `retired` or `removed` row answers 409, an unknown row 404, and a bad body
or a config key (a resolution records who made it) 422. `DELETE` clears the resolution of any row
that has one: the tag counts again from the next refresh.

`POST …/bulk/resolve` takes the same body plus `rows: [{"signature_uuid", "technique"}]` (1 to 500)
and resolves them in one transaction. It answers `{"done": [...], "conflicts": [{"signature_uuid",
"technique", "status"}], "unknown": [...]}`; conflicting and unknown rows are left alone.

### Joins

- **Worklist → coverage:** `GET /api/v2/svs/coverage?f=technique:{technique}`; the drill-down
  `GET /api/v2/svs/coverage/{technique}` shows each tag with `counts` and its `reason`.
- **Worklist → expectations:** `GET /api/v2/svs/expectations?signature={signature_uuid}` lists the
  tests and platforms the signature is expected on, which is what *measured* means.
- **Worklist → detections:** `signature_uuid` is a detection's `signature_uuid` in
  `GET /api/v2/detection-points`.

## Worked examples

### Per-signature FP rate over 90 days

Pull every detection with a verdict from alerts of the last 90 days and count verdicts per
signature. `tests/aceapi_v2/detection_points/test_list.py::test_worked_example_fp_rate` runs the
same code against the API.

```python
import collections
import requests

ACE = "https://ace.example.com/api/v2"
HEADERS = {"x-ace-auth": "<api key>"}

counts = collections.defaultdict(collections.Counter)
params = {"f": ["alert_date:-90d", "verdict:tp,fp"], "limit": 1000}
while True:
    page = requests.get(f"{ACE}/detection-points/", params=params, headers=HEADERS).json()
    for row in page["data"]:
        counts[row["signature_uuid"]][row["verdict"]] += 1
    if page["next_cursor"] is None:
        break
    params["cursor"] = page["next_cursor"]

for signature_uuid, verdicts in sorted(counts.items()):
    print(signature_uuid, round(verdicts["fp"] / (verdicts["tp"] + verdicts["fp"]), 3))
```

Add `f=!source:inherited_multi` to count only labels a person stated or confirmed.

### Conflicted samples per rule

Count, per rule, the samples whose votes disagree: the ones someone has to relabel before a
validation can use them. `tests/aceapi_v2/svs/test_samples.py::test_worked_example_conflicted_samples_per_rule`
runs the same code against the API.

```python
import collections
import requests

ACE = "https://ace.example.com/api/v2"
HEADERS = {"x-ace-auth": "<api key>"}

conflicted = collections.Counter()
params = {"f": ["label:conflicted"], "limit": 1000}
while True:
    page = requests.get(f"{ACE}/svs/samples/", params=params, headers=HEADERS).json()
    for row in page["data"]:
        conflicted[row["rule_name"]] += 1
    if page["next_cursor"] is None:
        break
    params["cursor"] = page["next_cursor"]

for rule_name, count in conflicted.most_common():
    print(rule_name, count)
```

### Test pass rate per month

Of the runs reviewed in the last year, count per month how many hit every expected signature. A run
with nothing expected (`reviewed_expected` is 0) isn't judged. Missing includes possibly suppressed.
`tests/aceapi_v2/svs/test_run_reads.py::test_worked_example_pass_rate_per_month` runs the same code
against the API.

```python
import collections
import requests

ACE = "https://ace.example.com/api/v2"
HEADERS = {"x-ace-auth": "<api key>"}

months = collections.defaultdict(lambda: [0, 0])    # month -> [judged, passed]
params = {"f": ["state:reviewed", "reviewed:-365d"], "limit": 1000}
while True:
    page = requests.get(f"{ACE}/svs/runs/", params=params, headers=HEADERS).json()
    for run in page["data"]:
        if run["reviewed_expected"]:
            month = run["reviewed_at"][:7]
            months[month][0] += 1
            months[month][1] += run["reviewed_missing"] == 0
    if page["next_cursor"] is None:
        break
    params["cursor"] = page["next_cursor"]

for month, (judged, passed) in sorted(months.items()):
    print(month, f"{passed}/{judged}", round(passed / judged, 3))
```

`reviewed_at` is a run's latest review, so a run reviewed again counts in the month of that review.
Add `f=platform:linux` or `f=technique:T1059` to narrow it.

### Technique coverage over time

The share of techniques (sub-techniques left out) on the endpoint platforms that are validated, and
failing, at the end of each month, from the daily snapshots.
`tests/aceapi_v2/svs/test_coverage.py::test_worked_example_coverage_over_time` runs the same code
against the API.

```python
import requests

ACE = "https://ace.example.com/api/v2"
HEADERS = {"x-ace-auth": "<api key>"}

params = {"group": "month", "f": ["platform:windows,linux,macos", "level:technique"]}
counts = requests.get(f"{ACE}/svs/coverage/history/counts", params=params, headers=HEADERS).json()
for period in counts["data"]:
    if period["rows"]:
        states = period["states"]
        print(period["period"], f"{states['validated'] / period['rows']:.0%} validated",
              f"{states['failing'] / period['rows']:.0%} failing")
```

A month counts its last snapshot (*Coverage history*). Use `group=day` for a finer line, and add
`f=date:-365d` to limit it to the last year.
