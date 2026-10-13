# SVS YARA samples

When an analyst grades an alert, ACE keeps every file a YARA rule matched on it, with the match.
These **samples** are the corpus SVS checks YARA rule changes against (`docs/SVS.md`, Part 2): a
file graded as a real hit should keep matching, and a file graded as a false positive should stop.
A sample's grade, its **label**, is not stored with it. It is derived from the verdicts on the
alert's detections whenever it is read, so a later disposition change or verdict override relabels
the sample without touching its bytes.

This document covers how samples are captured, stored, labeled, read and acted on. The design and its
reasoning are in `docs/SVS.md`; the API's data dictionary is in `docs/SVS_API.md`, *Samples*.

## What is captured, and when

The `svs_yara_sample_capture` analysis module (`saq/modules/svs.py`) runs in the `dispositioned`
analysis mode. Both disposition writers requeue an alert into that mode whenever its disposition is
set (except `IGNORE`), so the module sees every graded alert.

It captures when the alert's disposition classifies **tp** or **fp** (`disposition_classification`,
`docs/SVS.md` Part 1). An alert that is `OPEN`, `REVIEWED`, `UNKNOWN` or `IGNORE` is not captured;
if it is graded later, the next dispositioned pass captures it.

On such an alert it captures one sample per **(file sha256, rule uuid)** pair named by a YARA
detection, whatever the verdict on that detection:

- The detection must be one the YARA module puts **on the file** with structured details (`sha256`,
  `rule`, `namespace`, `rule_uuid`; `docs/SVS.md` Part 1). Alerts created before that change carry
  older detections and contribute nothing.
- The rule must have a `uuid` meta. A rule without one is attributed to a shared built-in signature,
  so its matches are not captured.
- Rules in `no_alert` or `qa` mode make no detection and are not captured. QA matches have their own
  store (`docs/YARA_QA.md`).
- The same bytes under two names in one alert are one sample; the first file observable wins.

The module works in post-analysis. It analyzes no observable and does not change the alert's
analysis tree. Post-analysis runs at the end of every pass, so it runs again on every later
dispositioned pass, and capturing is idempotent. Post-analysis waits for any delayed analysis of the alert, so an alert
dispositioned while a sandbox is still running is captured when the sandbox finishes.

**Capture is the only chance.** `archive()` removes a false positive's extracted files after
`fp_days`, and `IGNORE` alerts are deleted after a day. A sample captured before that keeps its
bytes for as long as its capture record exists.

## Storage

The bytes live in the content-addressed store (`docs/CAS.md`), in the pool named by
`svs.samples.pool` (default `svs_samples`), encrypted with the system key. Each capture stores two
objects:

- **The file.** Its digest is the file's sha256.
- **The match record.** This is the alert's `scan_results` entry for the rule, as the alert saved
  it, serialized and summarized by `saq/yara_scanning/match_record.py`. Its match strings went through the alert's JSON encoder, which decodes bytes lossily, so the
  record is for audit and for "why did this match". When SVS rescans a sample it gets exact strings.

`svs_yara_captures` (`saq/database/model.py`) has one row per (alert uuid, sha256, rule uuid). Only
`saq/svs` writes to it. The row holds both objects with `Hold("svs_capture", <row id>)`, with no
expiry. The same file captured from two alerts, or for two rules, is stored once and held once per
capture.

Each row records what a rescan needs to scan the file the way it was scanned:

| Column | Why |
|---|---|
| `file_path` | The path relative to the alert's `files/` directory. Rebuilds the `filename`, `filepath` and `extension` externals and the `file_name`, `full_path` and `file_ext` filters. |
| `yara_meta_tags` | The file's `yara_meta:` directives as `name=value` strings. Rebuilds `meta_tags`. |
| `rule_uuid`, `rule_name`, `namespace` | What the sample is labeled for. The namespace is relative to the signature directory. |
| `signature_version` | The commit of the rule's repository when it matched, or `unknown`. |
| `rule_content_hash` | The rule's content hash in the YARA rule inventory (`saq/signatures/yara_inventory.py`) at capture time. The inventory is cached per engine process for up to `svs.samples.inventory_refresh_seconds`. |
| `yara_python_version`, `yara_scanner_version` | The libraries of the node that captured it. |
| `alert_uuid`, `observable_uuid` | Where it came from. |
| `node` | The node that stored the bytes. |

**There is no foreign key to `alerts`.** An alert can be deleted (`ace alert delete`, or an alert
re-dispositioned `IGNORE`), and its captures outlive it, or their holds would never be released. A
capture whose alert is gone has no label.

## States

A capture row is `pending` while it is being stored, `stored` once the bytes are held, and `missing`
when they could not be. `missing_reason` says why:

| `state` | `missing_reason` | Meaning |
|---|---|---|
| `stored` | none | The file and the match record are held. |
| `stored` | `match_record` | The file is held, but the alert's YARA analysis was gone (the alert was archived). A later pass that has the record adds it. |
| `missing` | `file` | The file was gone, or no longer hashed to the capture's `sha256`, and the pool did not have the same bytes from another alert. |
| `missing` | `storage` | The CAS refused the bytes. Retried on the alert's next dispositioned pass. |

Missing captures are counted per rule, so a rule whose samples keep going missing is visible.

## Logs

Each record carries `alert_uuid`, `sha256` and `rule_uuid` as `extra={}` fields (`missing_reason`
too where it applies), so the site's log tooling can search on them.

| Event | Level |
|---|---|
| A sample was captured | INFO |
| A capture is missing for the first time (`file`) | ERROR, saying whether the file was gone or hashed to something else |
| A capture is still missing on a later pass | INFO |
| The CAS refused a capture (`storage`) | ERROR, with an error report |
| A capture was stored without its match record | ERROR |
| A capture was stored with signature version `unknown` | ERROR |

A signature version of `unknown` means the rule's repository is not listed in
`service_yara.git_repo_dirs`. The capture is still kept, but which version of the rule it was
graded under is lost. A site that wants SVS to work lists its signature repositories there.

## Labels

A sample is one (file sha256, rule uuid) pair, over every alert it was captured from. Its label is
derived when it is read (`saq/svs/labels.py`), from the verdicts (`docs/SVS.md`, Part 1) of its
**contributing detections**: on each of those alerts, the detections of its rule on a file with its
sha256. Each detection with a verdict votes, with the strength of its verdict source, and the
strongest strength present decides: `explicit` beats `inherited_single`, which beats
`inherited_multi`. Votes of that strength that disagree make the sample **conflicted**.

| Contributing detections | Label |
|---|---|
| On an alert dispositioned `FALSE_POSITIVE` | `fp` (`inherited_single`) |
| On a TP alert where only this rule fired | `tp` (`inherited_single`) |
| On a TP alert where several signatures fired | `tp` (`inherited_multi`), unless an analyst set or confirmed a verdict |
| One FP alert and one unconfirmed multi-signature TP alert | `fp`: the FP alert is the stronger vote |
| An FP alert and a single-signature TP alert | `conflicted` |
| Only on alerts that are unclassified, deleted, or from an unreviewed test run | no label |

So a disposition change or a verdict override relabels a sample at once, and nothing about the
sample itself is written. The label is reported with its votes, so a reader can tell a sample ten
analysts graded from one inherited once.

## Reading samples

Samples are read through `/api/v2/svs/samples` (`docs/SVS_API.md`, *Samples*). Reading samples, their labels and match records needs
`signature:read`; the files need `signature:download` and come only in zips encrypted with the
password `infected`, with their match records and a manifest. Every download is logged at INFO as
an `AUDIT:` line naming the user and the files.

The API filters with the `svs_samples` filter screen (label, label source, missing data, unknown
version, …), whose saved filters are per user like the alert manage page's. Its defaults are
*Conflicted* (samples someone has to relabel) and *Missing data* (captures that lost their file or
match record). `GET /api/v2/svs/samples/missing`
counts the missing captures per rule and reason.

## Actions

Five actions change what SVS makes of a sample (`saq/svs/actions.py`). Each is a call to the API
(`docs/SVS_API.md`, *Sample actions*), records who took it, and is logged at INFO as an `AUDIT:`
line. A config API key has no user, so it cannot take any of them (422).

| Action | Permission | What it does |
|---|---|---|
| **Relabel TP / FP** | `signature:read` + `alert:write` | Stores an explicit verdict on every contributing detection that can take one |
| **Reset to inherited** | `signature:read` + `alert:write` | Clears the explicit verdicts on its contributing detections |
| **Confirm** | `signature:read` + `alert:write` | Stores an explicit TP on each unconfirmed (`inherited_multi`) TP detection |
| **Retire / Unretire** | `svs:admin` | Marks the sample as no longer expected to match its rule, or expected again |
| **Delete sample** | `svs:admin` | Removes the file from SVS, for every rule |

**Relabel, reset and confirm write verdicts, never a label.** A label is always derived from the
verdicts of the sample's contributing detections (*Labels*), so these change those verdicts through
the same store the alert page uses (`saq/detection_verdicts/store.py`, `docs/SVS.md` Part 1), all
in one transaction. Each change is in the verdict history, like a change made on the alert page.
- A relabel writes explicit verdicts, which outweigh every inherited vote, so it is how a
  conflicted sample is resolved.
- Detections that cannot take an analyst's verdict are skipped and listed with why: those on a
  `FALSE_POSITIVE` alert (correct the alert's disposition instead), on an unclassified alert, on an
  alert whose disposition only ACE sets (`SIMULATED`), and rows synced before detection identity.
  When nothing can take the verdict, the action is refused (409).
- So relabelling TP a sample that is also on an FP alert writes TP on its TP alerts only. The
  label becomes TP, because an explicit vote outweighs the FP alert's inherited one, and the FP
  alert itself stays FP.
- A reset only touches the detections that have an explicit verdict, so the detections of an FP
  alert, whose verdict is inherited, are never listed as skipped.
- Confirm leaves detections someone has set alone. Confirming or resetting nothing is not an
  error.

**Retire** a sample for its rule when the rule is meant to stop matching it, for instance when an
intended regression has merged. A YARA validation then only counts the pair (`retired`,
`docs/SVS_VALIDATION.md`), and it stops showing as *already broken on base*. A reason is required.
Unretiring is soft: the row keeps who unretired it and when, and retiring again reuses it with the
new reason. Retirements are listed with the sample (`retired`, `retired_by`, `retired_at`,
`retired_reason`) and filtered with *Retired*.

**Delete sample** is for legal or privacy requests. It works on the file: every rule's sample of
that sha256 goes. In order:
1. It refuses when the file's bytes are on another node's local pool (409 `wrong_node`: delete it
   on that node) or when the file is under a CAS legal hold (409 `legal_hold`: release the hold
   first, `cas:hold`).
2. It commits an audit row in `svs_sample_deletions`: who, why, when, the rules and the number of
   captures. From then on capture never stores the file again, including a capture that was
   already running.
3. It deletes every capture of the file, its retirements, and its rows in every YARA validation
   report (`docs/SVS_VALIDATION.md`); a report's counts stay as they were.
4. It releases the captures' holds on their match records and purges the file's bytes from the
   pool, which also records the purge in `cas_purges`.

If the purge fails (a legal hold taken meanwhile, a storage failure), the audit row has no
`purged_at` and the bytes stay. Deleting the sample again retries the purge. The deletion audit is
read through `GET /api/v2/svs/samples/deletions`.

Deletion does not reach:
- the alerts' own copies of the file, under their storage directories;
- the YARA QA store (`docs/YARA_QA.md`), which has its own retention;
- the plaintext copies in each node's CAS read cache, until they are evicted;
- with a node-local pool, a copy another node wrote of the same bytes, until that node's
  `ace cas orphans` sweep;
- the match records, until CAS GC collects them once they are unheld (`grace_seconds` later).

## In the GUI

*Signatures → Samples* (`app/signatures/views/samples.py`) lists the samples, for anyone with
`signature:read`. Like *Yara QA Results*, it is a shell: everything on it comes from
`/api/v2/svs/samples`, through the list controller `static/js/filter_list_page.js`.

**The list.** One row per sample:
- the label, drawn like a detection verdict (`TP · inherited`, `FP · explicit`). A conflicted
  sample says *conflicted* in red, and a sample with no label shows a dash;
- the rule and its namespace, linking to the sample's page;
- the file's path and size in the latest capture, and its sha256;
- how many captures it has, and how many of them are missing;
- its votes, `TP n · FP m`, with each strength in the tooltip;
- when it was first and last captured;
- an icon when a capture has signature version `unknown`, another when a capture is missing
  its file or match record, and another when the sample is retired (who, when and why in its
  tooltip).

The newest captures come first. A column header sorts by that column, and clicking it again
reverses the order. Pages are keyset pages of 25 to 250 rows.

**Filters.** *Edit* opens an editor with one row per value: a filter, *NOT*, and the value. Rows
for the same filter are ORed, and different filters are ANDed. The filters are the screen's:
signature (rule uuid), rule name, sha256, alert uuid, file name, label, label source, last
captured, stored, missing data, unknown version and retired. Clicking a filter's name in the bar removes
it, and clicking a value removes that value.

**Saved filters and links.** Saved filters work as on the alert manage page (*Save as*, *Save*,
*Manage…*), but belong to this screen. Pinned ones show as buttons on the filter bar. Every user
starts with *Conflicted* and *Missing data*. The address bar always holds the filters, the order
and the page size, so the address is a link to the same view, and back and forward work. The
copy button copies a link with the filters only. A link that names a filter that no longer exists
still opens, without it, and says so.

**Missing data.** When captures have lost their file or match record, a banner above the list
counts them. It links to those samples, and to the rules with the most.

**Export.** The *Export* menu has CSV and NDJSON (every sample the filters match, in the list's
order), and *Copy API URL*, the list API with the same filters, for a script with an API key.
With `signature:download` it also has *Download files*: the files of every sample the filters
match, in one zip, up to `svs.samples.max_bulk_download_files` files and
`svs.samples.max_bulk_download_bytes` bytes.

**A sample's page** (`/ace/signatures/samples/<sha256>/<rule uuid>`) shows:
- the rule, the file and the sample's label, and whether it is retired;
- its votes at each strength;
- a link to every sample of the rule, and, with `signature:download`, *Download sample*;
- the actions its user may take: *Relabel TP*, *Relabel FP*, *Reset to inherited* (when there are
  explicit votes) and *Confirm* (when there are unconfirmed ones) with `alert:write`; *Retire* or
  *Unretire*, and *Delete sample*, with `svs:admin`. Retire and Delete ask for a reason, and Delete
  says what it removes and what it does not. After a relabel, the page lists the detections that
  were skipped and why;
- every capture, newest first. Each row has its alert, the file's path and meta tags, the
  signature version, the state (and why a capture is missing), and the verdict of each
  contributing detection ("alert deleted" when the alert is gone). It also has the match summary
  (strings, offsets, rule meta) and a link to the full match record.

Files, records and downloads stored on another node's local pool are named with that node, not
linked.

## Nodes

The default pool uses the `local` backend, so the bytes are only on the node that stored them, and
capture runs on whichever node owns the alert. That is right for a single node.

A multi-node site does one of two things before relying on samples:
- redefines the `svs_samples` pool in its own configuration, with a backend every node can reach and
  `shared: true`, as it does for `yara_qa` (`docs/YARA_QA.md`, *Nodes*); or
- disables capture with `analysis_module_svs_yara_sample_capture.enabled: false` until it has one.

With a node-local pool, a node that captures bytes it still has writes them to its own pool
directory, even when another node stored the same bytes first. A node whose copy of the file is
gone can only take a hold on the object another node stored; its capture then records that node
as the one that has the bytes.

That is also why a multi-node site must not keep the default pool: the API serves bytes only from
the node that has them (409 `wrong_node` elsewhere), and it takes a capture's match record to be on
the capture's `node`. In the one case above it is not: the capture whose file was gone wrote its
match record on its own node, while its `node` names the node with the file.

## Configuration

```yaml
cas:
  pools:
    svs_samples:
      backend: local
      encryption: system
      retention: held
      grace_seconds: 86400
      shared: false

svs:
  samples:
    pool: svs_samples
    max_bulk_download_files: 500           # one bulk download (GET /api/v2/svs/samples/download)
    max_bulk_download_bytes: 1073741824
    inventory_refresh_seconds: 300         # how old a YARA rule inventory capture accepts

analysis_module_svs_yara_sample_capture:
  name: svs_yara_sample_capture
  python_module: saq.modules.svs
  python_class: YaraSampleCapture
  enabled: true

analysis_mode_dispositioned:
  enabled_modules:
    - svs_yara_sample_capture
```
