# Analysis Module Crash Reports

When an analysis module fails, ACE marks it failed and keeps going. That is the right behavior
— one bad module should not stop an alert from being analyzed — but it means the interesting
part is whatever got written down on the way past.

A **crash report** is one self-contained directory per crash, named by an opaque `crash_id`
that is logged when the crash happens. Given that id, an analyst pulls the whole thing over the
API.

## Getting a crash report

1. Find the id. Every crash logs one line at `ERROR`:

   ```
   analysis module crash recorded crash_id=aa265767-3b77-4b74-97b7-91d14e21e48b crash_type=killed \
     module_path=saq.modules.test:BasicTestAnalysis root_uuid=55a6bfbf-... node=ace1
   ```

   These are `extra={}` fields, so `crash_id` is a real field in Splunk as well as greppable in
   `saq.log`. An analyst who has the *alert* instead of the log line has two other routes: the
   crash id is written into the alert's own tree (`RootAnalysis.get_analysis_failed_message()`)
   for the killed path, and `GET /api/v2/crashes/?root_uuid=<alert uuid>` lists every crash
   recorded while analyzing it.

2. Pull it:

   ```bash
   curl -k -H "x-ace-auth: $KEY" -O \
     https://ace/api/v2/crashes/aa265767-3b77-4b74-97b7-91d14e21e48b/download
   unzip -P infected crash-aa265767-....zip
   ```

The archive is encrypted with the password `infected` because it contains, by construction,
whatever the module choked on. That is the same convention the alert download uses.

## The three kinds of crash

| `crash_type` | What happened | Who writes the report |
|---|---|---|
| `exception` | The module raised. | The worker that ran it, with the full traceback. |
| `timeout` | The module blew past `maximum_analysis_time` and the in-process watchdog is about to `os._exit(1)`. | The watchdog thread, **inside the stuck process**. |
| `killed` | The worker manager SIGKILLed the worker. | The *replacement* worker, from the `TrackingRecord` the manager preserved. |

The `timeout` report is written from inside the wedged process, which makes it the only thing
in ACE that can say *where the module was stuck* — `thread_stacks.txt` carries every thread's
stack, captured with `faulthandler` so it works even when the thread in question is blocked in
a syscall and will never run Python again. Every other observer of a hang runs in a different
process and only ever sees the corpse.

A single hang can legitimately produce both a `timeout` and a `killed` report: the in-process
watchdog and the manager race, and whichever loses still has something to say. Correlate them by
`root_uuid` + `module_path`.

## What is in a report

```
<data_dir>/crash_reports/YYYY/MM/DD/<crash_id>/
├── metadata.json        # always; written last (see below)
├── stack_trace.txt      # exception path
├── thread_stacks.txt    # timeout path
├── root.json            # the analysis tree (data.json), not the storage directory
└── file/<name>          # the bytes of the file observable the module crashed on
```

`metadata.json` carries the module, the observable, the root, the node, the pid and worker, the
exception, and an `omitted` list. **`omitted` is the honest-report mechanism**: anything skipped
by a size cap or missing on disk is recorded there with a reason, so a truncated report says so
rather than looking complete.

### Write ordering

A worker can be SIGKILLed *while writing its own crash report*. So the expensive, kill-prone
copies happen first and `metadata.json` is written last, atomically via a temp sibling and
`os.replace`. A directory with no `metadata.json` is therefore by definition incomplete, which is
what lets a reader tell "killed mid-write" from "done" without a lock. Such a report is reported
as `complete: false` and still served — partial evidence beats none, and "the worker died writing
its own crash report" is itself a finding.

### Finding the file when the tree doesn't have it

A file observable created during the analysis pass that the crash destroyed is not in the tree
that was last saved to disk. That is exactly the interesting case — the module died on something
it had just extracted — and a naive lookup finds nothing.

Since a file observable's *value* **is** its sha256, and the file manager stores content-addressed
copies under `<storage_dir>/hardcopies/<sha256>`, the bytes are still findable by value alone.
`_resolve_file_source()` tries the live observable, then the saved tree, then the hardcopy.

## Nothing here is allowed to raise

A crash reporter that can break analysis, or that can keep a wedged process from exiting, is
worse than no crash reporter. Every public entry point in `saq/crash_report.py` swallows and logs
its own failures and returns `None`. This is the same contract `saq.engine.tracking.TrackingWriter`
documents for itself, and `tests/saq/test_crash_report.py::test_record_crash_never_raises` is the
guard.

The timeout path additionally passes `index=False`: it must reach `os._exit(1)`, and an unwell
database is a plausible reason for a module to be stuck in the first place, so a blocking insert
there would turn the watchdog into a second hung thing. It spools the report for indexing instead
(see below), so it still shows up in the listing.

## The database index

`analysis_module_crashes` is a **derived index**, not the record. The filesystem is authoritative.
The insert is best effort for the reason above — a module crash is exactly when the database is
most likely to be the thing that is unwell — so losing a row costs a *listing*, not a report:
`find_crash_report_dir()` globs the date partitions when there is no row, and both the detail and
download endpoints work without one.

### Deferred indexing

A report that is written without a row is not left unlisted. After `metadata.json` is written,
`record_module_crash()` drops an empty file named by the crash id into
`<crash_reports>/index_pending/`. It does this when `index=False` (always the case for the timeout
watchdog) and when the inline insert fails. The file create is local disk only, the same kind of
work as writing the report, so the watchdog can still reach `os._exit(1)` without blocking.

The spool is drained by `drain_index_spool()`:

- **Every engine worker, as it starts.** The watchdog's exit is what gets a replacement worker
  started, so a `timeout` report is normally indexed within seconds. The drain runs before the
  replacement records its `killed` report, and when it finds the `timeout` report for the same
  root and module, it puts that crash id in the failure message written into the alert's tree
  (`...; thread stacks in crash_id <id>`). An analyst looking at the alert is then one hop from
  the stacks.
- **`ace crash index`** from `etc/cron/hourly/crash-reports`: the hourly catch-up for a node whose engine is
  not running. `ace crash index --all` ignores the spool, walks every report on disk and indexes
  anything with no row. Use it to backfill reports written before the spool existed.

The insert is idempotent, so more than one process can drain the spool at the same time. A
deferred row's `insert_date` is the crash time, not the indexing time, so the listing's
newest-first order stays correct. An entry whose report has been pruned is dropped. An entry that
fails to insert stays in the spool, and the drain stops, because the database is unwell and the
next drain will retry.

The spool lives outside every report directory, so it never shows up in a report's file inventory
or archive, and never changes the directory mtime that prune uses to age reports.

## Multi-node

A crash report is written to the disk of the node whose worker died. The index is cluster-wide but
the bytes are not, so by default only that node can serve it; every other node answers **409
naming the node** rather than 404, because "it is not here" and "it does not exist" are different
answers and only one tells you what to do next.

Set **`crash_reporting.replicate`** and every report is also copied into a shared bucket, so any
node can serve any report:

```yaml
storage:
  target: s3          # or the local backend with base_dir on a filesystem every node shares
crash_reporting:
  replicate: true
  storage_bucket: ace-crash-reports
```

The built-in `s3` backend talks to an S3-compatible endpoint with a static access key and secret
(`saq/storage/factory.py::_create_s3_storage` reads the top-level `s3:` block). A deployment whose
object store authenticates some other way — an IAM instance role, STS, a signing proxy — supplies
its own backend instead, through the same plugin convention `analysis_cache.blob_store` uses:

```yaml
storage:
  target: custom
  backend:
    python_module: mypackage.my_storage
    python_class: MyStorage
    config:
      region: us-east-2
```

The class is imported, its `get_config_class()` model validates the `config:` sub-dict, and the
resulting model is its single constructor argument. It has to implement the seven methods of
`StorageInterface` (`saq/storage/interface.py`), and it can get all of them by subclassing
`S3Storage` and replacing only the client. Note `S3Storage._ensure_bucket_exists()` does
`head_bucket` and then `create_bucket` on first upload per process — a backend running under a
least-privilege policy that denies those should override it and let the bucket be pre-created.

This is an explicit opt-in rather than something inferred from `storage.target`, because a cluster
running the local backend with `base_dir` on NFS is a perfectly good deployment — inferring would
silently disable replication in exactly that case. The 409 names the setting, so the failure mode
explains its own fix.

With replication on, node identity stops being an access decision: the API looks for the bytes
locally, then in the bucket, and only then refuses. `local` in a listing changes meaning from
"written here" to **"downloadable from here"**; `node` still says where it came from, and a detail
response sets `remote: true` when it was served from the bucket.

Credentials are origin-scoped (`x-ace-auth` and the session cookie), so a client talks to
whatever node it already reached. Replication is how a report stays downloadable when the
owning node is **down, rebuilt, or decommissioned**.

### How the copy is made

Per file, at `<crash_id>/<relative path>`, with **`metadata.json` uploaded last**. That reproduces
the local completeness sentinel exactly: a `<crash_id>/metadata.json` object means the remote copy
is finished, and objects without it mean an interrupted upload, which is served and reported
`complete: false` like any other partial report.

Keys are derivable from the crash id, so **no database column and no migration** — the
`analysis_module_crashes` row is unchanged.

The upload runs on a **daemon thread that is never joined**. S3 requests are bounded — `S3Config`
sets `connect_timeout`, `read_timeout` and `max_attempts` — but bounded is not instant: a report is
several objects, each a multipart transfer of several requests, and the caller is a worker holding
a work item lock. The local report is already durable before replication starts, so it is pure
best-effort; at most two uploads run at once per process and the rest are left to the sweeper.
`timeout` reports are never replicated inline at all, because `os._exit(1)` would annihilate the
thread.

**`ace crash sync`** is the catch-up: it lists the bucket once, compares against the local reports,
and uploads the difference. It runs hourly from `etc/cron/hourly/crash-reports` **after** `ace crash prune`, so
a run never uploads reports it is about to delete. It is stateless — it asks the bucket rather than
tracking a marker file locally, which would have leaked into the API's file inventory, into the
archive handed to the analyst, and (worst) would have refreshed the directory mtime that prune ages
reports by, silently extending retention.

### Operating the bucket

- **Keep it dedicated.** It holds the file observables that crashed modules — live malware. That is
  the same reason the download is an encrypted zip.
- **Set a lifecycle expiration rule.** `ace crash prune` deletes the shared copy alongside the
  local one (remote first, and it skips the local delete if that fails, so the two never drift),
  but a decommissioned node's reports have nobody left to prune them. A bucket lifecycle rule is
  the backstop.
- Least-privilege policies that deny `HeadBucket`/`CreateBucket` will break the automatic bucket
  creation in `saq/storage/s3.py`; pre-create the bucket in that case.

## Configuration

```yaml
crash_reporting:
  enabled: true
  directory: crash_reports      # relative to DATA_DIR
  copy_file: true
  max_file_size: 104857600      # skipped above this, and recorded in "omitted"
  copy_root_json: true
  max_root_json_size: 33554432
  retention_days: 30
  max_reports_per_module_per_root: 5
  replicate: false                 # see Multi-node
  storage_bucket: ace-crash-reports
```

On by default, including the file copy. What is capped is how much a single crash may write.

`max_reports_per_module_per_root` is the other half of that budget. A module that raises on
*every* file in a tree with hundreds of extracted attachments would otherwise write hundreds of
reports, each with its own copy of the bytes — turning "we captured the evidence" into "we filled
the disk". After the limit, further reports for that module on that root are suppressed and the
suppression is logged, so it is never silent. The count is per worker process, which is the right
scope: a worker handles one root at a time. The in-process timeout watchdog is exempt, because its
report is the only record of where a hung module was stuck.

Note `root.json` is the analysis tree **only**. The full storage directory is never copied:
that would mean copying every file observable in the tree, twice (a copy does not preserve the
hard links between `files/` and `hardcopies/`), which is the part that fills disks. It also means
a report does not carry `.ace/`, where analysis `details` payloads are stored externally — so you
get the shape of what earlier modules produced, not their full output.

## Retention

`ace crash prune` removes reports past `retention_days` **and their index rows together**, so
a listing never points at a directory that is gone, and drops any index spool entry for them.
With replication on it also deletes the shared copy, remote first and in lockstep with the local
one. It runs hourly from `etc/cron/hourly/crash-reports`, followed by `ace crash index` and then `ace crash
sync`. `ace crash list`, `ace crash prune --dry-run` and `ace crash index [--all] --dry-run` are
the operator's read-only views.

## Error reports

`report_exception()` is a separate mechanism. It writes a stack-trace file under
`data/error_reports/` for any caller, including the engine's per-module exception handler
(which also writes a crash report). Crash reports are the analyst-facing record of a
*module* failure; error reports are the process-local traceback dump used everywhere else.

## Permission

`crash:read` gates all three endpoints. It is its own pair rather than reusing `alert:read`
because a crash report archive contains the file observable that was hostile enough to take a
module down, and a deployment may reasonably want to grant that separately.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/v2/crashes/` | list, newest first; filters `root_uuid`, `module`, `crash_type`, `node`, `limit`, `offset` |
| `GET /api/v2/crashes/{crash_id}` | full metadata plus a file inventory |
| `GET /api/v2/crashes/{crash_id}/download` | the whole report as an encrypted zip |

All three serve reports from any node when `crash_reporting.replicate` is on; see **Multi-node**.

`crash_id` is validated against a strict uuid4 pattern at the boundary, before any path is built,
and the resolved directory is checked to be the one the id names. The endpoint turns a URL
parameter into a filesystem path and then serves the result as malware, so it does not trust the
value because "it came from our own log".
