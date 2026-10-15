# SVS data API

ACE doesn't ship fixed reports (`docs/SVS.md`, Part 6). Every fact SVS keeps can be pulled through
`aceapi_v2`, with the same filters the screens use, and reports are built outside ACE. This document
is the data dictionary for those endpoints, the joins between them, and worked examples. It grows
with each SVS phase; today it covers alerts and detections (phases 0 and 1), the YARA samples
(phase 2), the YARA validations (phase 3), and the test hosts, the Atomic Red Team test catalog and
the runs with their event logs (phase 4, so far).

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
  validation UUID, test GUID, run UUID.

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
it with another is a 400.

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
  sample.
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
| `DELETE /api/v2/svs/test-hosts/{id}` | `svs:admin` | 204. Runs already registered keep their targets |

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

## Tests

The Atomic Red Team tests runs may be registered for, as `service_svs` reads them from the
repositories in `svs.catalog.repositories` (`docs/SVS_RUNS.md`, *The Atomic Red Team catalog*).
Read with `svs:run_read`. The test state, last run and expectations columns of the Tests screen
come later in phase 4. What is decided about a test's signatures, and its settings, are changed
under it with `svs:run_manage` (*Expectations*, *Ignores* and *Test settings*, below).

| Endpoint | Permission | Returns |
|---|---|---|
| `GET /api/v2/svs/tests` | `svs:run_read` | Tests by technique, then name, filtered and paged |
| `GET /api/v2/svs/tests/export/ndjson`, `/export/csv` | `svs:run_read` | The same, streamed (the CSV joins `platforms` with `,`) |
| `GET /api/v2/svs/tests/{guid}` | `svs:run_read` | One test with its description and its atomic entry |
| `PUT`, `DELETE /api/v2/svs/tests/{guid}/expectations/{signature_uuid}` | `svs:run_manage` | Decide a signature for the test, or remove the decision |
| `PUT`, `DELETE /api/v2/svs/tests/{guid}/ignores/{signature_uuid}` | `svs:run_manage` | Ignore a signature during the test's runs, or stop |
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
| `updated_at` | The row's last change. |

`GET …/{guid}` adds `description` and `test`, the test's whole entry in its atomic file: `executor`
(`command`, `cleanup_command`, `elevation_required`), `input_arguments`, `dependencies`.

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

## Runs

A run is one Atomic Red Team test a launcher outside ACE runs against test hosts, from
registration through review or close (`docs/SVS_RUNS.md`). The launcher drives it with the
lifecycle calls, which need `svs:run_register`. Everything else reads it with `svs:run_read`. A
launcher that also reads its runs needs both.

| Endpoint | Permission | Returns |
|---|---|---|
| `POST /api/v2/svs/runs` `{test_guid, targets: [{hostname, username?}], launcher, batch_id?, extra?}` | `svs:run_register` | 201 and the run in state `created`, with its `marker` |
| `POST /api/v2/svs/runs/{run_id}/start` | `svs:run_register` | The run in state `started`, with its window ends |
| `POST /api/v2/svs/runs/{run_id}/executed` `{exit_code, error?}` | `svs:run_register` | The run; a non-zero `exit_code` or an `error` moves it to `error` |
| `POST /api/v2/svs/runs/{run_id}/cancel` | `svs:run_register` | The run in state `canceled`, or `closed` when it was never started |
| `GET /api/v2/svs/runs` | `svs:run_read` | Runs, newest first, filtered and paged |
| `GET /api/v2/svs/runs/export/ndjson`, `/export/csv` | `svs:run_read` | The same, streamed. The CSV joins `targets` with `,`, each as `hostname` or `hostname/username` |
| `GET /api/v2/svs/runs/{run_id}` | `svs:run_read` | One run, with what the launcher sent |
| `GET /api/v2/svs/runs/{run_id}/events` (and `/export/ndjson`, `/export/csv`) | `svs:run_read` | The run's event log, oldest first |
| `GET /api/v2/svs/runs/events` (and `/export/ndjson`, `/export/csv`) | `svs:run_read` | The event feed: the events of every run the filters match, in `(updated_at, id)` order |

The lifecycle calls return the run's lifecycle fields: `run_id`, `marker`, `state`, `test_guid`,
`targets`, the window lengths and ends, `created_at`, `started_at`, `error_reason` and
`close_reason`. Their errors:

| Status | When |
|---|---|
| 403 | A target is not a test host, or names a user the host doesn't list: `{"detail": {"message", "reasons": […]}}`, one reason per refused target. It also alerts (`docs/SVS_RUNS.md`, *Refused registrations*). Also a key without the call's permission. |
| 404 | No run has that `run_id`. |
| 409 | The call doesn't apply to the run's state: `{"detail": {"message", "state"}}`. |
| 422 | The test is not in the catalog or was removed, a target's platform isn't one the test supports, a host or user name can't be used, too many targets, or `extra` is too large. |

The reads answer 400 for a `run_id` that is not a UUID and 404 for an unknown one.

### Fields

| Field | Meaning |
|---|---|
| `run_id` | The run's UUID: the stable identifier of a run, and the `svs_run` field of every log record about it. |
| `state` | `created`, `started`, `ended`, `reviewed`, `canceled`, `error` or `closed` (`docs/SVS_RUNS.md`, *Run states and timers*). |
| `test_guid` | The catalog test (`GET /api/v2/svs/tests/{guid}`). |
| `test_name`, `technique`, `technique_name` | From the catalog, as it is now. |
| `marker` | `svs-` and 26 base32 characters. Put it where the test's process telemetry shows it. It is `svs_marker` in ACE's log. |
| `targets` | As registered (`hostname`, `username`) and normalized (`host`, the short name; `fqdn`; `user`, the bare user name), all lower case when normalized. |
| `launcher`, `batch_id` | As registered. A batch is a label shared by the runs a launcher registered together, not a resource. |
| `created_at`, `started_at` | When it was registered and started. |
| `executed_at`, `exit_code` | What the launcher reported through `executed`. |
| `ended_at`, `canceled_at`, `closed_at` | When it moved to those states. |
| `observation_ends_at`, `attribution_ends_at` | When its windows end, set at `start`. *Time left* on a started run is `observation_ends_at` minus now. |
| `error_reason` | Why it is in `error`: the launcher's failure, or the start timeout. |
| `close_reason` | Why it was closed: `start timeout`, `canceled before start`, `attribution window ended`. |
| `owner`, `reviewer`, `reviewed_at` | Usernames, and when it was reviewed. Review and ownership come later in phase 4, so these are null until then. |
| `changed_since_review` | An attribution of an alert to it was added or removed after its review: a late alert, a later analysis pass, or a manual association. |
| `needs_attention` | Whether it is in the *Needs attention* view (below). |
| `updated_at` | The row's last change; the `changed_since` key. |

`GET …/{run_id}` adds:
- `extra`, the object the launcher sent;
- `launcher_error`, the error `executed` reported;
- `test_content_hash` and `catalog_commit`, the test as it was registered (a later catalog change
  doesn't change them);
- `observation_seconds` and `attribution_seconds`, the window lengths fixed at registration
  (`docs/SVS_RUNS.md`, *Windows*);
- `registered_by`, the username of the key that registered it (null for a config key).

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
| `launcher` | Launcher | text the launcher's name contains |
| `batch` | Batch | a `batch_id` |
| `created`, `started`, `ended` | Created, Started, Ended | date ranges |
| `owner`, `reviewer` | Owner, Reviewer | usernames |
| `reason` | Reason | text the close or error reason contains; `reason:start timeout` finds the runs closed because `start` was never called |
| `changed_since_review` | Changed Since Review | `true`, `false` |
| `has_open_alerts` | Has Open Alerts | `true`, `false`: an alert attributed to the run is still `OPEN` |

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
| `registered` | `to_state: created` | The registration: `test_guid`, `targets`, `launcher`, `batch_id`, `extra`, and `observation_source` (`override`, `expected` or `all_hunts`: where its observation window came from, `docs/SVS_RUNS.md`, *Windows*) |
| `transition` | both | `{"reason"}` when the move has one (an error, a close), else null |
| `launcher_call` | none | `{"call", "outcome", "payload"}`. `call` is `start`, `executed` or `cancel`. `outcome` is `started`, `recorded`, `error`, `canceled` or `conflict` (a call the state didn't allow). `payload` is `{exit_code, error}` for `executed` |
| `attributed` | none | `{"alert_uuid", "detections"}`: detections of one alert attributed to the run, each `{"detection", "confidence", "late", "scan_point"}` (`detection` is its `content_hash`; `scan_point` is null for context). Written when an attribution is added or comes back, not on every analysis pass. `actor` is `svs` |
| `attribution_removed` | none | `{"alert_uuid", "detections", "reason"}`: the `content_hash`es of the alert's detections whose attribution no longer holds (a later analysis pass found the marker disagrees, say) |
| `alerts_closed` | none | `{"alerts", "disposition", "late"}`: the alerts given `SIMULATED` when the run closed, or (`late: true`) by the timers afterwards (`docs/SVS_RUNS.md`, *Test alerts and `SIMULATED`*) |
| `result_computed` | none | `{"counts", "previous"}`: the run's result changed; the number of signatures per status, now and before. `actor` is `svs` |
| `candidate_decision` | none | `{"signature_uuid", "state", "reason"}`: a signature decided for the run's test from this run's result |

Later phase-4 work adds kinds for manual association and disassociation and review. A reader skips
kinds it doesn't know. In CSV, `details` is a JSON string.

### The event feed

`GET /api/v2/svs/runs/events` is the runs' change feed: every event of every run the `f=` filters
match, in `(updated_at, id)` order, with `changed_since`. As with the run list, an event shows up a
few seconds after it is written, so a pull resumed from the last event's `updated_at` never misses
one. It may repeat one. This is where a report sees what happened to a run between two pulls, and
later in phase 4 what was disassociated from it.

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
| `status` | `hit`, `missing`, `possibly_suppressed`, `candidate`, `rejected` or `ignored`; null once the signature left the live result and the row holds only the reviewed one. |
| `alert_count` | The run's attributed alerts that carry the signature (0 when missing). |
| `late_only`, `context_only` | Every attribution of it was *late*, or by context alone. |
| `content_hash` | The rule's own content hash when the result was computed (the YARA rule's text, the hunt's file, a built-in's declaration). |
| `suppressing_alert_uuid`, `suppression_imprecise` | For `possibly_suppressed`: the hunt's latest alert within its suppression period, and whether the hunt groups or deduplicates its alerts, so it may not have suppressed the run's. |
| `reviewed_status`, `reviewed_alert_count`, `reviewed_late_only`, `reviewed_content_hash` | The result as signed off; null until the run is reviewed (later in phase 4). |
| `updated_at` | The row's last change; the feed's `changed_since` key. |

`stale` (one run only) is true while something changed since the result was computed: the timers
recompute it within `svs.runs.timer_interval_seconds`. A run that hasn't ended has no result.

### Joins

- **Run → test:** `test_guid` = the test's `guid` in `GET /api/v2/svs/tests`.
- **Event → run:** `run_id` = the run's `run_id`.
- **Result → run:** `run_id` = the run's `run_id`; **result → signature:** `signature_uuid` = a
  detection's `signature_uuid` in `GET /api/v2/detection-points`, and a sample's `rule_uuid`.
- **Run → logs:** `run_id` and `marker` are the `svs_run` and `svs_marker` fields in ACE's log.

## Expectations

What is decided about each test's signatures (`docs/SVS_RUNS.md`, *Expectations and ignores*).
`GET /api/v2/svs/expectations` (and `/export/ndjson`, `/export/csv`), `svs:run_read`, filtered by
`test`, `signature` and `state`. A decision is made with `PUT /api/v2/svs/tests/{guid}/expectations/
{signature_uuid}` `{"state": "expected"|"rejected", "reason"?, "run_id"?}` and removed with `DELETE`,
both `svs:run_manage` and from a user's key (a config key gets 422: a decision records who made it).

| Field | Meaning |
|---|---|
| `test_guid`, `signature_uuid` | The test and the signature; together they are unique. |
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

`GET`, `PUT`, `DELETE /api/v2/svs/tests/{guid}/settings`: `{"observation_minutes"}`, the observation
window of the test's runs registered from then on, used as it is (no slack, no floor) from 1 minute
up to `svs.runs.observation_window.ceiling_hours` (`docs/SVS_RUNS.md`, *Windows*). The response adds
`set_by` (username) and `updated_at`. Reading needs `svs:run_read`, changing `svs:run_manage`.

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
