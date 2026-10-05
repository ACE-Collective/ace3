# SVS data API

ACE doesn't ship fixed reports (`docs/SVS.md`, Part 6). Every fact SVS keeps can be pulled through
`aceapi_v2`, with the same filters the screens use, and reports are built outside ACE. This document
is the data dictionary for those endpoints, the joins between them, and worked examples. It grows
with each SVS phase; today it covers alerts and detections (phases 0 and 1).

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
- **Scope.** Alert data is scoped to the alerts this node shows, as the GUI is.
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
- **YARA detection → sample:** `details.sha256` and `details.rule_uuid` are the sample and rule a
  phase-2 capture is keyed on.

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
