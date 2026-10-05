# YARA QA results

A YARA rule whose `modifiers` meta includes `qa` runs in **QA mode**: it matches live data but never
alerts (`qa` implies `no_alert`, see `docs/YARA_RULES.md`). The point is to see what the rule would
catch before it is allowed to alert. For that, ACE keeps every file a QA rule matches, and its match
record, so analysts can review them. They do that in the GUI under **Signatures → Yara QA Results**,
or through the API.

Rules in QA mode are listed whether or not they have matched anything yet.

## Storage

The files live in the content-addressed store (`docs/CAS.md`), in the pool named by
`yara_qa.pool` (default `yara_qa`). That pool is encrypted with the system key.

QA matches are recorded by the yara scanner service, not by the engine
([YARA_SCANNER.md](YARA_SCANNER.md#qa-matches)). The scanner module
(`saq/modules/file_analysis/yara.py`) tells the service which analysis and file observable it is
scanning. A worker that finds a QA match spools it, and the service's qa recorder process calls
`saq.yara_qa.store.record_qa_match()` for it after the scan was answered. So an engine worker never
waits on any of this, and a match shows up seconds after the scan.

If the service is unavailable and the module scans with its local fallback scanner, QA matches are
logged as not recorded, and dropped.

`record_qa_match()` stores two objects in the pool:

- **The file.** Its digest is the file observable's sha256.
- **The full match record.** This is the yara_scanner match dict as JSON. It is the same content the
  old `var/qa` directory kept next to each file, and it is **never truncated**. A loose string can
  match thousands of times, each match carrying its bytes, so the record can run to megabytes. That
  is why it lives in the CAS and not in the database.

Two tables in the main database index the objects (`saq/database/model.py`). Only `saq/yara_qa`
writes to them.

| Table | One row per | Holds |
|---|---|---|
| `yara_qa_signatures` | (signature uuid, signature version) | `match_count` (every match, including those past the cap), `stored_count` (files kept, which is the slot counter), first and last match |
| `yara_qa_matches` | stored file | the file's sha256, name and size; the analysis it came from; the node that stored it; `match_digest`; a `match_summary`; `hit_count`; `first_seen` / `last_seen`; `expires_at` |

**The match summary.** `match_summary` is derived from the record: the rule, its meta and tags, and
for each string identifier how many times it matched and where it first matched. Its size depends on
the rule, not on the file, so it needs no limit. The match list reads the summary; the full record
is fetched only on request.

**Holds.** The row holds both of its objects with `Hold("yara_qa", <row id>)`, and each hold carries
the row's expiry. The same file matched by two rules, or under two versions of one rule, is stored
once and held twice.

**Versions.** The signature version is the one a detection point would carry: the commit of the
rule's repository, or `unknown` for a rule directory that is not listed in
`service_yara.git_repo_dirs`.

**Rules without a uuid.** A rule with no `uuid` meta has nothing to be filed under, so its matches
are not stored. The service does not spool them, and `record_qa_match()` logs a warning if it is
given one. (The detection path attributes such rules to a shared built-in uuid, which would put
every such rule's files in one bucket.)

## Caps

Two caps limit how many files are kept:

- **`yara_qa.max_files_per_version`** (default 25): distinct files per (uuid, version).
- **`yara_qa.max_files_per_signature`** (default 250): distinct files per uuid, across all of its
  versions.

Because the version is a repository commit, every commit to the signatures repository starts a new
version of every rule in it. The per-uuid ceiling is what keeps that churn from growing storage
without bound.

A match past either cap is still counted in `match_count`, so the listing shows how noisy a rule
really is even when no more files are being kept.

A new match of a file that is already stored, under the same version, does not use another slot.
It increments `hit_count` and renews the expiry.

**How the caps hold under concurrency.** Each node's recorder stores one match at a time, but the
recorders of several nodes can store at once, and none of them waits on a lock for this. The slot
is reserved with a single conditional `UPDATE` of the counter row:

- The per-version cap is **exact**.
- The per-uuid ceiling is read in the same statement. Two recorders storing under *different* versions
  of one uuid at the same instant can both pass it, so it can be exceeded by the number of versions
  racing, which in practice is one.

## Retention

A stored file is kept for `yara_qa.retention_days` (default 30) after it **last** matched.

`ace yara-qa prune` runs daily from `etc/cron/daily/yara-qa-prune`, on the primary node only. It:

1. removes expired rows, in primary-key batches of `yara_qa.prune_batch_size`, one short transaction
   per batch;
2. gives their slots back;
3. releases their holds.

The hourly CAS GC then reclaims the bytes once the pool's grace period has passed.

The holds carry the expiry themselves, so an object is collected even if a prune never runs.

## Nodes

The default pool uses the `local` backend, so a file's bytes are only on the node that matched it.
The node recorded with a match is the yara service's `saq_node`, which is the engine's: they run on
the same host with the same configuration and share `DATA_DIR`.
The API marks each match `local: true` or `false`. For a match stored on another node, anything
that reads bytes (a download, or the full match record) answers **409 `wrong_node`** and names that
node.

The default single-node install never sees this.

A multi-node site redefines the pool in its own configuration, with a backend every node can reach
and `shared: true`. The configuration below uses the CAS `custom` backend. Once the pool is shared,
every match counts as local and nothing answers `wrong_node`.

```yaml
cas:
  pools:
    yara_qa:
      backend: custom
      custom:
        python_module: site_package.cas_backend
        python_class: SharedBackend
        config: {...}
      shared: true
```

## API

These routes are served by `aceapi_v2/yara_qa/`, mounted at `/api/v2/signatures/yara-qa`.

| Method, path | Permission | Returns |
|---|---|---|
| `GET /` | `signature:read` | Rules in QA mode, and rules with recorded matches, with counts. Filters: `q`, `status` (`qa`, `not_qa`, `missing`), `has_matches`. Sort: `name`, `last_match` or `match_count`, with `descending`. Paging: `limit` and `offset`, returning `{data, total, limit, offset, inventory_error}` |
| `GET /{uuid}` | `signature:read` | One signature, with its counts per version |
| `GET /{uuid}/matches?version=` | `signature:read` | Its stored files, newest first, each with `local` and, when the analysis became an alert, `alert_uuid` |
| `GET /matches/{id}` | `signature:read` | One match, with its `match_summary` |
| `GET /matches/{id}/record` | `signature:read` | The full match record (`application/json`), read from the CAS |
| `GET /matches/{id}/download` | `signature:download` | The file and its record, zipped |
| `GET /{uuid}/download?version=&match_id=…` | `signature:download` | Bulk download. With `match_id`s, the selection; otherwise every stored file of the signature, or of one version. Limited to `yara_qa.max_bulk_download_files` and `yara_qa.max_bulk_download_bytes`, with 413 past either |

The status values mean:

- `qa`: the rule is in QA mode now.
- `not_qa`: the rule still exists but has left QA mode. Its counts and unexpired files remain.
- `missing`: no loaded rule has this uuid any more.

**Where the rule list comes from.** The list of QA rules is read from rule source through the
YARA rule inventory (`saq/signatures/yara_inventory.py`, which uses the loader in
`saq/signatures/loaders/yara.py`), at `service_yara.signature_dir`. QA mode and `enabled` are
interpreted by the same helpers the scanner uses (`saq/signatures/yara_meta.py`). Parsing every rule
file takes seconds, so each process caches the inventory. The QA listing accepts one up to
`yara_qa.inventory_refresh_seconds` old, and a rebuild parses again only the files that changed.

**Downloads.** Every download is a zip encrypted with the password `infected`
(`aceapi_v2/common/archive.py`), laid out as:

```
<label>/manifest.json                      what is in the zip, and what was skipped and why
<label>/<match id>-<sha256>/<file name>    the file, under a sanitized version of its name
<label>/<match id>-<sha256>/match.json     the full match record
```

In a bulk download, matches stored on another node's local pool, or collected since the listing,
are recorded in `manifest.json` under `skipped` rather than failing the download. Every download is
logged at INFO with the user and the match ids.

## GUI

The **Signatures** navigation item appears when the user has `signature:read`. It opens a hub laid
out like Admin, and `signature:read` gates the whole `/signatures` area (`app/signatures/`).

The hub has one module, **Yara QA Results**. That page is a shell: all its data comes from the API
above, fetched by `app/static/js/signatures_yara_qa.js`. It lets an analyst:

- filter and sort the rules;
- open a rule to see its versions and stored files;
- view a match's summary and full record;
- download files one at a time, as a selection, or all at once.

The download controls appear only with `signature:download`.

## CLI

- `ace yara-qa list [--status …] [--sort …] [-q …] [--json]`: the same listing as the API.
- `ace yara-qa prune [--dry-run] [--force]`: the daily cleanup. It exits without doing anything on a
  node that is not the primary, unless `--force` is given.

## Configuration

```yaml
analysis_module_yara_scanner_v3_4:
  save_qa_scan_results: true     # false stops storing QA matches (they still never alert)

service_yara:
  qa_spool_dir: var/yss/qa_spool # where scans hand QA matches to the recorder (docs/YARA_SCANNER.md)
  qa_spool_max_jobs: 10000

yara_qa:
  pool: yara_qa
  max_files_per_version: 25
  max_files_per_signature: 250
  retention_days: 30
  prune_batch_size: 500
  prune_batch_pause_seconds: 0.5
  max_bulk_download_files: 500
  max_bulk_download_bytes: 1073741824
  inventory_refresh_seconds: 60
```

## Upgrading from `var/qa`

Before this change, QA matches were copied as plaintext to `$DATA_DIR/var/qa/<rule>/` and never
cleaned up. The `qa_dir` setting is gone, and nothing reads or writes that directory any more.
Nothing is migrated from it.

After upgrading, delete it on every node:

```bash
rm -rf "$SAQ_HOME/data/var/qa"
```
