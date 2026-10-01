# Content-Addressed Storage (CAS)

> **Status: implemented in `saq/cas/`** for the `held` and `permanent` retention modes with the
> `local` and `custom` backends. Deferred, and recorded below where they apply: the `ttl` mode
> (the config schema accepts the word and rejects it as not implemented; no `cas_touches` table,
> no partition task) and an object-store (S3) backend (`backend:` accepts `local | custom`). The
> design was settled during the SVS design review (`docs/SVS_REVIEW.md` §7); bracketed IDs such as
> `[CAS-4]` point at the item there that records the reasoning. The first consumer is SVS
> (`docs/SVS.md`).

ACE stores a lot of immutable bytes: file observables, extracted payloads, cached analysis blobs,
archived email, crash evidence. Today that happens in several independent places, each with its
own key scheme, retention mechanism and failure modes:

| Store | Key | Encrypted | Retention |
|---|---|---|---|
| Alert `hardcopies/` | `<storage_dir>/hardcopies/<sha256>` | no | life of the alert |
| Analysis-cache blobs (`saq/analysis/blob_store.py`) | `<root>/<sha[:3]>/<sha>` + `blob_refs` | no | references expire with a ~35-day partition |
| Email archive (`saq/email_archive/`) | `<sha[:2]>/<sha>.gz.e`; S3 key = sha | AES-GCM, system key | 30 days (S3 copies never deleted) |
| Crash report bytes | per crash directory | no | 30 days |
| YARA `qa_dir` (before the `yara_qa` pool) | `var/qa/<rule>/<file>-<sha>` | no | never cleaned |

None of them can keep a byte "until I say so", and none can be shared between nodes without
bespoke code. The CAS is one subsystem for **immutable bytes identified by content**. Each use sets
its own policy (retention, encryption, backend, sharing), and the lifecycle is correct: nothing is
deleted while something holds it, and nothing lingers once nothing does. [CAS-1]

It does not handle mutable objects, whole alert storage directories (the JSON trees stay files),
a user-facing browser, or dedup across pools with different encryption. [CAS-1]

## Concepts

- **Object.** Immutable bytes. Identified by its **digest**, the lowercase hex sha256 of the
  *plaintext*.
- **Pool.** A named policy: backend, encryption, retention mode, grace period, and whether it must
  be shared between nodes. Objects belong to a pool, and dedup happens within a pool. SVS samples
  and analysis-cache blobs are different pools, because they need opposite policies. [CAS-2]
- **Hold.** An explicit reference `(pool, digest, holder_kind, holder_id)`, optionally with an
  expiry. An object in a `held` pool lives while at least one hold is live. A **legal hold** is a
  hold with `holder_kind='legal_hold'` and no expiry. [CAS-3, CAS-4]
- **Index.** Database tables that are *authoritative* for which objects exist. Backends are dumb
  byte stores. GC and existence checks read the index and never list a bucket. [CAS-3]

## API

```python
from saq.cas import get_cas, Hold

pool = get_cas().pool("svs_samples")

digest = pool.put(src, hold=Hold("svs_capture", capture_id))  # src: path | bytes | BinaryIO
pool.hold(digest, Hold("svs_capture", other_id))
pool.release(digest, Hold("svs_capture", capture_id))

with pool.open(digest) as stream: ...        # integrity verified before any byte is released
pool.materialize(digest, dest_path)          # hardlink if local + plaintext, else decrypt / download
pool.exists(digest); pool.stat(digest)
pool.purge(digest, reason="…", actor=user)   # forced delete across holds, audited
```

- **`put` is atomic and idempotent.** Content is hashed while it is written. If the caller passes
  the digest it expects, a mismatch fails the `put`. `put(..., hold=…)` takes the hold in the same
  step, so there is no window between "exists" and "reference" (the analysis cache's current race,
  see [F-21]). `src` may be a path (hashed in place, not copied), bytes, or a readable stream
  (spooled to a temp file while hashing).
- **Holds are idempotent and renewable.** Repeating a hold is a no-op; repeating it with a new
  `expires_at` replaces the old one. `release` returns whether a hold was actually removed and
  restarts the object's grace period. `Hold.legal(id)` is the legal hold.
- **`hold` on a `deleting` object raises `ObjectDeleting`**; the caller should `put` the content
  again instead (which waits for the deletion to finish and re-uploads).
- **`open` and `materialize` never hand out unverified bytes.** For encrypted pools the GCM tag is
  checked before release; for plaintext pools the sha256 is.
- **`purge` is the only way to delete an object that is still held.** It is audited in
  `cas_purges` and refuses while a legal hold exists. The legal hold has to be released first.
  The library records the actor it is given; enforcing `cas:purge` and `cas:hold` is the caller's
  job (an API surface). `ace cas purge|hold` take `--actor` and do not check permissions. [CAS-4]

The package: `saq/cas/pool.py` is the API (`CASPool`), `index.py` holds every statement against
the index tables and nothing else writes them, `backend.py` the backend protocol and the local
backend, `cache.py` the read cache, `crypto` work is in `saq/crypto.py`, and `registry.py` the
process-wide `get_cas()` (rebuilt after fork and by `reset_cas()` in tests). Errors are in
`saq/cas/errors.py`: `ObjectNotFound`, `DigestMismatch`, `IntegrityError` (and its subclass
`KeyMismatch`, for an object encrypted under a different system key than the loaded one),
`ObjectDeleting`, `LegalHoldActive`, `PoolNotFound`, `CASConfigError`. `health.py` computes what
the monitors report (see Observability).

Every operation runs in a private database session on the main engine (`index.transaction()`),
never on the thread-shared `get_db()` session: a `put` from an analysis module must not commit or
roll back the caller's transaction.

## Retention modes and churn

| Mode | An object lives while… | Churn | Index layout | Example |
|---|---|---|---|---|
| `held` | it has a live hold, plus `grace` | low | `cas_objects` + `cas_holds`, main DB | SVS samples |
| `ttl` | it was *touched* within `ttl`; holds optional | high | `cas_objects` + day-partitioned `cas_touches`, in the pool's own DB | analysis cache (future). **Not implemented**: the config schema rejects `retention: ttl` until the load test below has run |
| `permanent` | always; only `purge` deletes | — | `cas_objects` | reference sets, if ever needed |

[CAS-4, CAS-7]

## Data model

Final models are written in `saq/database/model.py`, and the migration is autogenerated. This is
the shape:

- **`cas_objects`** `(pool, digest CHAR(64), size, stored_size, key_id NULL, created_at,
  last_held_at, verified_at NULL, state ENUM('present','deleting'))`, primary key `(pool, digest)`.
- **`cas_holds`** `(pool, digest, holder_kind VARCHAR(32), holder_id VARCHAR(128), created_at,
  expires_at NULL, created_by NULL)`, primary key `(pool, digest, holder_kind, holder_id)`.
  - No timestamp in the key, so repeating a hold is idempotent. `blob_refs` gets this wrong.
- **`cas_touches`** (`ttl` pools only) `(day, pool, digest)`, primary key `(day, pool, digest)`,
  `PARTITION BY RANGE` on `day`.
  - Append-only (`INSERT IGNORE`). A use never updates a shared row.
  - A partitioned table can't have foreign keys, and every unique key must include `day`.
- **`cas_purges`** `(pool, digest, reason, actor, purged_at)`.

`held` pools keep their index in the main ACE database. A `ttl` pool names its own database chain,
so a high-churn index never shares locks with alert inserts. [CAS-7]

As built (`saq/database/model.py`, migration `56cafaed6b55`): `cas_objects` has the index
`(pool, state, last_held_at)` for the GC candidate scan; `cas_holds` has a composite foreign key
to `cas_objects` with `ON DELETE CASCADE`, so deleting the object row removes its expired holds in
the same statement, plus the index `(pool, holder_kind, holder_id)`; `cas_purges` has an
autoincrement id. `cas_touches` does not exist yet (`ttl` is deferred). The `cas:hold` and
`cas:purge` permissions are seeded by migration `61b26390b94e`.

## Lifecycle

**`put`.** One transaction: insert the `cas_objects` row if it is absent, lock it `FOR UPDATE`, and
**while holding the lock** write the bytes if the backend does not have them, then take the hold
and bump `last_held_at`. The bytes are written under the row lock rather than before the
transaction (a small change from the design) because that is the only order that is safe against
a GC pass that removed the bytes between an unlocked "already there" check and the row insert.
The crash property is the same: a crash before the commit leaves orphan bytes, which the orphan
sweep finds, and never a row pointing at nothing. Concurrent puts of one digest, first-time or
not, serialize on the insert (the second blocks on the first's row until it commits, then finds
the bytes present). The insert is `INSERT … ON DUPLICATE KEY UPDATE` with a no-op update, not
`INSERT IGNORE`: on a duplicate key `INSERT IGNORE` takes a *shared* lock on the existing row, and
two puts that then both asked for `FOR UPDATE` deadlocked on the upgrade (found by the stress test:
16 workers putting one sample lost 30 of 32 processes to MySQL error 1213 in 20 seconds). `ON
DUPLICATE KEY UPDATE` takes the exclusive record lock straight away.

**GC.** For `held` pools:
1. A candidate is a `present` object with no live hold and `last_held_at < now - grace`.
2. One conditional statement flips it: `UPDATE cas_objects SET state='deleting' WHERE … AND
   state='present' AND NOT EXISTS (live hold)`. If zero rows change, skip it: someone took a hold
   in the meantime.
3. Delete the bytes, then the row.

`put` and `hold` lock the object row (`SELECT … FOR UPDATE`). A `put` that finds `deleting` waits
for the row to go (polling, up to `cas.put_deleting_wait_seconds`) and re-uploads. Taking a hold
and the GC flip therefore serialize on one row. [CAS-4]

Two more steps in every GC run, as built: it first **resumes** objects a previous run or a purge
left in `deleting` (deletes the bytes, then the row), and it finishes by **pruning expired hold
rows** in batches, because an expired hold on an object that still has another live hold would
otherwise stay forever. The candidate scan already excludes objects with a live hold, so a dry
run's count is what a real run would delete; the conditional flip repeats the check.

A reader that opens an object between the flip and the byte delete may find the bytes gone and
get `ObjectNotFound`. That is the accepted race; a hardlinked `materialize` destination keeps
its inode either way.

For `ttl` pools, expiry drops `cas_touches` partitions older than `ttl`, the same way the email
archive and `blob_refs` are pruned. GC then removes `cas_objects` rows that have no touch left.

**Orphans.** `ace cas orphans` lists the backend occasionally and removes bytes that have no row,
older than `cas.orphan_grace_seconds`. This is the only operation that lists a bucket. Keys the CAS
would not have written are reported and left alone; the local backend's leftover temp files are
swept at the same time.

**Verify.** `ace cas verify` re-hashes a sample of objects (`cas.verify_sample_size`, from a random
starting point in digest order) and records `verified_at`. A corrupt, wrong-key or missing object is
logged, makes the command exit 2, and is never deleted. Wrong-key objects are counted apart from
corrupt ones: the bytes may well be intact, and the fix is the key, not the object. An object that
GC or a purge deleted after the sample was taken is counted as `removed`, not missing: the hourly
GC and the weekly verify start in the same minute, so this is expected, and only bytes missing
under a row that is still `present` are a failure.

## Operating constraints

**Never an unbounded `DELETE`.** Every CAS deletion from an index table runs in primary-key order,
in batches of at most N rows (default 500), one short transaction per batch, with a pause between
batches. High-churn expiry uses partition drops, never row deletes. [CAS-7, D-18]

This is not hypothetical. The email archive once pruned with `DELETE … WHERE insert_date < cutoff`.
It ran for a long time and blocked inserts while it did. It was replaced by weekly range partitions
dropped with `ALTER TABLE … DROP PARTITION` (`bin/manage-email-archive-partitions.sh`, PR #601),
which is a metadata operation: no row locks and no undo log. The analysis cache's `blob_refs` uses
the same pattern daily. Any new high-volume table in ACE should start from that pattern, not arrive
at it after an incident.

**The load test gates high-churn pools.** Before the first `ttl` pool (the analysis cache) goes
live, a load test runs a synthetic pool at production volume (millions of objects, a day of churn),
with GC running while a writer inserts at peak rate. Nothing migrates until insert latency is flat
under GC. [CAS-7, CAS-8]

## Encryption

- **Per pool:** `none` or `system`. `system` reuses `saq/crypto.py`'s AES-256-GCM with the single
  system data key. [CAS-5]
- **Two fixes to `saq/crypto` came with it** (`saq/crypto.py`, see its module docstring):
  1. **Verify before release.** `decrypt()` decrypts to a temp file next to the target and renames
     it only after the GCM tag verifies; on failure nothing is left behind. `decrypt_stream()` is
     the stream form the CAS uses, with the contract that the destination is private until it
     returns.
  2. **A versioned header with a key id**, bound as authenticated data: the v1 format
     (`ACE-GCM`, version, an 8-byte fingerprint of the data key, size, nonce). This makes rotating
     the system key possible later without re-encrypting everything at once; multi-key decryption
     itself is not built (a key id mismatch raises `KeyMismatchError`). Files in the old v0
     format keep decrypting, and **`encrypt()` still writes v0 by default**: a lot of existing
     encrypted data (the email archive's `.gz.e`, stream archives) is read across nodes, and a
     node on older code cannot read v1, so the default only flips once every node runs code that
     understands v1. The CAS asks for v1 explicitly (`encrypt_stream(..., format_version=1)`).
     The in-memory chunk format (`encrypt_chunk`), which is persisted in the database, is unchanged.
- **Dedup still works.** The digest is of the plaintext. Each pool writes a digest once, so the
  random nonce doesn't defeat dedup.
- **Object names are plain** (`<sha[:2]>/<sha[2:4]>/<sha>`). A reader who can list the bucket
  learns which hashes ACE holds; this was accepted. [CAS-5]
- **SSE on S3 complements this; it doesn't replace it.** SSE protects the disks, not the bucket
  credentials.

## Backends

The CAS has its own small backend protocol rather than widening `saq/storage`: [CAS-6]

```python
class CASBackend(Protocol):
    node_local: ClassVar[bool]                                 # a shared pool refuses a node-local backend
    def write(self, key: str, stream: BinaryIO) -> None: ...   # atomic; if-absent
    def exists(self, key: str) -> bool: ...                    # put re-checks the bytes under the row lock
    def open(self, key: str) -> ContextManager[BinaryIO]: ...
    def delete(self, key: str) -> None: ...                    # missing is not an error
    def iter_entries(self, prefix: str = "") -> Iterator[BackendEntry]: ...   # (key, size, mtime)
    # optional capability
    def link(self, key: str, dest: str) -> bool: ...          # hardlink; local + plaintext only
```

Two small changes from the design sketch: `iter_keys` became `iter_entries`, yielding size and
mtime, because the orphan sweep needs the age and every object store's list call returns both
anyway; and `exists` was added for `put`'s check under the row lock. (`saq/cas/backend.py`)

- **Local.** Temp file, `fsync`, `rename` within the same directory, under
  `<root>/<pool>/<sha[:2]>/<sha[2:4]>/<sha>` where `<root>` is `cas.local_root` (or the pool's
  `root`), relative to the data directory. Supports `link`, which keeps the analysis cache's
  hardlink trick available: a plaintext object in a local pool is verified by re-hashing and then
  hardlinked out (`materialize`) or read in place (`open`), with no copy.
- **S3.** Not implemented yet. When it is, it uses `saq.storage.s3.get_s3_client()`, which honors
  `s3.secure`, `s3.cert_check` and `s3.region` (the storage factory currently does not, see
  [F-13]).
  - Conditional writes (`If-None-Match: *`) avoid redundant uploads. Where the object store
    doesn't support them, a redundant upload of identical content is harmless, because the index
    decides existence.
- **Custom.** `python_module` / `python_class` / `config`, following the pattern `saq/storage` and
  the analysis cache already use. The class declares `node_local` and `get_config_class()`.
- **Sharing between nodes.** A pool declared `shared: true` refuses the `local` backend at config
  validation, and a custom backend that says `node_local` when the pool is built.
- **Read cache.** `materialize` and `open` of anything that cannot be hardlinked out of the backend
  (encrypted pools, non-local backends) go through a bounded node-local LRU directory
  (`cas.read_cache`), because most tools (YARA included) need a file path. The verified plaintext
  is produced once and hardlinked (or copied) to each destination. `max_bytes: 0` disables it.
  Readers take the cache entry as an open file, never a path: another process can evict the entry
  at any moment, and only an open file survives that (a `materialize` that finds the name gone
  copies from the open file).

## Configuration

```yaml
cas:
  local_root: cas                  # local pools live under <DATA_DIR>/cas/<pool>
  gc_batch_size: 500
  gc_batch_pause_seconds: 0.5
  default_grace_seconds: 86400
  orphan_grace_seconds: 86400
  verify_sample_size: 1000
  put_deleting_wait_seconds: 30
  gc_overdue_seconds: 7200         # see Observability
  read_cache:
    dir: cas_cache                 # relative to DATA_DIR
    max_bytes: 10737418240
  pools:
    svs_samples:
      backend: local         # local | custom {python_module, python_class, config} under `custom`
      encryption: system     # none | system
      retention: held        # held | permanent   (ttl is reserved and rejected)
      grace_seconds: 86400
      shared: false          # true requires a backend that is not node-local
```

The schema (`CASConfig`, `CASPoolConfig` in `saq/configuration/schema.py`) rejects unknown keys
explicitly (`extra="forbid"`; most of the rest of the config silently ignores them). Paths are
relative to the data directory, like `crash_reporting.directory`, which is what gives every test
slot its own store. `etc/saq.default.yaml` carries the defaults, the `yara_qa` pool (the one pool
defined out of the box, `docs/YARA_QA.md`) and a commented `svs_samples` example. A site redefines a
pool by overriding its keys in its own configuration, for example to give `yara_qa` a shared backend
on a multi-node install.

## Permissions, CLI, cron

- **Permissions:** `cas:purge` and `cas:hold` (legal holds), in `saq/permissions/catalog.py`
  with the seeding migration `61b26390b94e`. Nothing in the repo enforces them yet; they exist so
  an API surface can, without a catalog migration.
- **CLI** (`saq/cli/commands/cas.py`): `ace cas pools | stat | get | gc | verify | orphans |
  node-stats | purge | hold add | hold release`. `gc`, `verify` and `orphans` take `--pool`,
  `--dry-run` and `--force`; `purge` and `hold` take `--actor`, which is recorded, not checked.
  `gc`, `verify` and `orphans` exit 2 when anything failed: `gc` when an object's bytes could not
  be deleted, `verify` when an object is corrupt, under the wrong key or missing, and any of them
  when a pool raised (the other pools still run).
- **Cron:**
  - `etc/cron/hourly/cas-gc`;
  - `etc/cron/hourly/cas-node-stats`, which runs on **every** node (it describes the node);
  - `etc/cron/weekly/cas-verify` and `cas-orphans`;
  - for `ttl` pools, when they exist, a partition-management task shaped like
    `bin/manage-email-archive-partitions.sh`.

  All the others run on the primary node only: the commands exit 0 without doing anything unless
  `ACE_IS_PRIMARY_NODE` is `1` (`is_primary_node()`), and `--force` overrides that for a dry run
  from another node.

## Observability

Everything below goes through the monitor emitter (`saq/monitor.py`) onto the `monitoring`
fluent-bit tag, so it lands in `data/logs/monitoring*` with every field intact. The `extra={}`
fields on CAS log lines reach a structured sink, but the local `ace-*` log files render only the
message text, so the monitor records are the place to look. Definitions are in
`saq/monitor_definitions.py`.

| Path | From | One record per |
|---|---|---|
| `cas.pool` | `CASPoolMonitor`, monitoring service, every 300 s | pool |
| `cas.node` | `ace cas node-stats`, hourly cron on every node | read cache, and local-backend pool, on that node |
| `cas.gc`, `cas.verify`, `cas.orphans` | `CASPool.gc/verify/orphans` | pool per run (`dry_run` says whether anything changed) |
| `error.cas_integrity` | the read path (`open`, `materialize`, `verify`) | failure |

- **`cas.pool`** (`saq/cas/health.py`, `pool_health()`): `objects_present`, `objects_deleting`,
  `size_bytes`, `stored_bytes`, `holds_live`, `holds_expired`, `legal_holds`, `objects_held`,
  `never_verified`, `verified_last_7d`, `purges_last_24h`, `gc_overdue`, and the pool's
  `configured`/`backend`/`encryption`/`retention`. A pool that has rows but is no longer
  configured is reported with `configured: false`. The index is shared, so the record describes
  the cluster and carries no `node`.
  - **`gc_overdue`** is the one to alert on. It counts present, unheld objects further past their
    grace than `cas.gc_overdue_seconds` (default two hourly runs), in held pools (`null`
    otherwise). It stays above zero when GC keeps failing, and also when GC runs nowhere: the
    maintenance commands exit 0 on a node that is not the primary, so if no node has
    `ACE_IS_PRIMARY_NODE=1` every cron record says success.
  - `objects_deleting` that stays above zero across samples is a deletion GC keeps failing to
    finish (each attempt also logs an ERROR).
- **`cas.node`** (`node_stats()`): `kind: read_cache` with `entries`, `bytes`, `max_bytes`; and
  `kind: pool` per local-backend pool. Both carry `path`, `fs_free_bytes` and `fs_total_bytes` of
  the filesystem underneath (measured at the nearest existing directory), and `node`.
- **Run records** are the run's stats dataclass (`GCStats`, `VerifyStats`, `OrphanStats`) plus
  `node` and `duration_seconds`; verify's `failures` is capped at 20 digests
  (`failures_truncated`). GC on a `permanent` pool emits nothing, because nothing runs. `GCStats`
  also says where the run's time went: `scan_seconds`, `flip_seconds`, `delete_seconds`,
  `prune_seconds` and `pause_seconds`.
- **Operation timings** (`saq/cas/metrics.py`) are per process, not a monitor record: every
  `put`, `hold`, `release`, `open` and `materialize` is timed as a whole (`total`) and by phase
  (`put`: `spool`, `encrypt`, `index`, `lock`, `write`; reads: `row`, `verify`, `cache`), plus the
  read cache's budget check (`read_cache`/`evict`) and counters such as `put`/`deduplicated`, into
  fixed latency buckets keyed by (pool, operation, phase). `metrics.snapshot()` returns them; a
  forked worker starts from zero. Recording is always on (a `perf_counter()` pair and a locked
  dict update).
- **`error.cas_integrity`** carries `pool`, `digest`, `operation`, `failure`, `error`, and for a
  key mismatch `stored_key_id` / `loaded_key_id`. It is emitted alongside an ERROR log line
  (`cas_pool`, `cas_digest`, `cas_operation`, `cas_failure` in `extra`), by the CAS itself, so a
  failure is reported whether or not the caller logs the exception. `failure` is one of:
  - `digest_mismatch`: plaintext bytes hash to something else (corruption or tampering);
  - `authentication`: an encrypted object failed its GCM tag or header check (the same);
  - `key_mismatch`: encrypted under another system key; raised as `KeyMismatch`. A configuration
    problem, not corruption;
  - `missing_bytes`: the index row is `present` but the backend has no bytes. The index and the
    backend disagree. A reader that loses the accepted race with GC or purge (the row is
    `deleting` or gone) is not reported.

## Consumers

| Order | Store | Pool | Status |
|---|---|---|---|
| 1 | SVS YARA samples | `svs_samples` (`held`, encrypted, shared) | first; built with the CAS |
| 2 | YARA `qa_dir` | `yara_qa` (`held`, encrypted, local by default) | **done** (`docs/YARA_QA.md`): the files and full match records of QA-mode rules, held for 30 days after the last match, capped per rule |
| 3 | Analysis-cache blobs | `analysis_cache` (`ttl`, plaintext, local `link`) | gated on the load test |
| 4 | Crash report bytes | `crash_files` | later |
| 5 | Email archive | `email_archive` | later; has its own DB and retention semantics |
| 6 | Alert hardcopies | `alert_files` | last; largest disk win and largest blast radius (node transfer, archive, hardlinks) |

Steps 1 and 2 are built; the rest are not scheduled. [CAS-8]

## Prerequisites (phase 0)

- The two `saq/crypto` fixes above shipped with the CAS. [F-20]
- The `saq/storage` defects are separate and still open: `saq/storage/factory.py:166` hardcodes
  `secure=False`; `S3Storage.object_exists` reports False on any error, including 403; the local
  backend isn't atomic. The CAS does not use `saq/storage`, so they do not block it.
  [F-13, F-18, F-19]

## Left for implementation

These were not design questions; the implementation picked them:
- GC batch size 500, pause 0.5 s between batches (`cas.gc_batch_size`,
  `cas.gc_batch_pause_seconds`); default grace 24 h; orphan grace 24 h; verify sample 1000 objects
  per pool per run; a `put` waits up to 30 s for a `deleting` object.
- Read cache 10 GiB under `<DATA_DIR>/cas_cache`, evicted oldest-first by mtime. Its size
  accounting walks the directory, and a process only walks it on its first fill and then after
  filling another 1% of `max_bytes`, so the cache can run over budget by up to 1% per process
  between checks. Walking on every fill, as first built, was the bottleneck at the default budget:
  at ~33k entries (~300 KiB each) the walk took ~290 ms per fill with 8 readers, a hundred times
  the decrypt it followed, and held cold reads to ~75/s; throttled, the same load ran at ~2,800
  materializes/s. The eviction pass re-checks each victim's mtime, so an entry read since the
  walk is kept.
- Conditional writes are moot until an object-store backend exists; the index decides existence
  either way.

Still open, for the pools that need them:
- the `ttl` mode (`cas_touches`, its own database chain, the partition task) and the load test
  that gates it;
- the S3 backend, needed before any pool can be `shared: true`;
- multi-key decryption once the system key is ever rotated (the key id in every v1 header and
  `cas_objects.key_id` is the hook).
