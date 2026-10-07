# SVS data API

ACE doesn't ship fixed reports (`docs/SVS.md`, Part 6). Every fact SVS keeps can be pulled through
`aceapi_v2`, with the same filters the screens use, and reports are built outside ACE. This document
is the data dictionary for those endpoints, the joins between them, and worked examples. It grows
with each SVS phase; today it covers alerts and detections (phases 0 and 1) and the YARA samples
(phase 2).

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
- **Scope.** Alert data is scoped to the alerts this node shows, as the GUI is. SVS data (samples)
  is global.
- **Stable identifiers:** alert UUID, signature UUID, detection `content_hash`, sample `sha256`.

## Alerts

`GET /api/v2/alerts` (and `/export/ndjson`, `/export/csv`) lists alerts as flat rows with the alert
manage page's filters (`docs/ALERT_FILTER_URLS.md`). `detection_count` is the number of
`detection_points` rows of the alert: one per detection *per node it sits on*, so a description
that fired on three URLs counts three.

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

`!` inverts a filter, including rows whose value is null: `!label:tp` returns FP, conflicted and
unlabeled samples.

### Incremental pulls

With `changed_since`, a sample is returned when a capture of it was added or changed, a
contributing alert's row changed (a disposition change relabels it), or a contributing detection's
verdict was set or cleared. Deleting an alert removes its votes without changing anything a pull can
see; a report that must notice that pulls everything again.

### Joins

- **Sample → detections:** each capture's `alert_uuid`, plus `signature_uuid = rule_uuid`,
  `node_type = file` and `node_value_sha256 = sha256` in `GET /api/v2/detection-points`.
- **Sample → alerts:** the captures' `alert_uuid`.

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
