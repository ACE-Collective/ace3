# Per-Module Analysis Diff Tracking & Caching

Status: Phases 1–3, the Phase 2.5 write-only bake, a capture/replay hardening
pass (2026-06-10 — see Part II), Phase 4 (file-observable caching +
tool-version helper + OCR/QR opt-ins, 2026-06-12), and the phishkit opt-in
(2026-06-29 — first delayed *and* file-producing cached module; see the
Phishkit opt-in notes in Part II) have shipped. Phase 3.5
(single-flight dedup) is designed but not yet implemented — deliberately
re-sequenced to land *after* Phase 4 (it is a work-dedup optimization with no
dependents; file-observable support unblocked the modules we most wanted
cached).
Origin: design sessions starting 2026-04-09. This document merges the original
design proposal with the former tactical implementation/progress log.

This document has two parts:

- **Part I — Design** — the problem, the ACE3 design (§1–§8), the rollout-phase
  roadmap, the detailed design addenda (§A1–§A9), open questions, and rationale.
- **Part II — Implementation & progress** — the per-phase build steps, bake-in
  results, and dated/PR-tagged implementation notes recording what actually
  shipped.

---

# Part I — Design

## Current state at a glance (2026-06-12)

This document grew as a running log across five PRs and two hardening
passes; several sections below describe earlier states with "superseded
by" callouts. This table is the current truth — each row links to the
section with the full design.

| Aspect | Current state | Detail |
|--------|---------------|--------|
| **Cache key** | v2: sha256 over `label:length:bytes` fields — format constant, observable type+value, module name+version, **config hash** (module YAML config minus operational/eligibility fields), sorted `ext:<k>=<v>` extended_version pairs. `observable.time` excluded. | §8 |
| **Storage** | Append-only `analysis_result_cache` in the dedicated `analysis-result-cache` DB; PK `(cache_key, created_at)`; daily `RANGE COLUMNS(created_at)` partitions; zstd-compressed delta payload; `details` > 16 KiB spill to the blob store (`blob_refs` table alongside); **file observable bytes always blob-backed** (Phase 4 — content sha256 = `spec.value` is the blob key). | §4, §A3, §A8 |
| **Read path** | `WHERE cache_key=? AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1` — freshest *data* wins (not longest-lived). Legacy-shape, blob-missing (spilled details **or file blobs**), decode errors → miss; replay errors fall through to a live run. | §5, §A8 |
| **Write refusals** | empty delta; removals (incl. **root-level**); still-delayed analysis; **non-COMPLETED module result**; **out-of-scope relationships** (target neither the analyzed observable nor delta-created — incl. relationships/redirections on *new* observables); compressed size > 1 MiB; per-file refusals (`file_observables_no_root` / `file_spec_missing_path` / `file_missing` / `file_too_large` > `file_blob_max_bytes` 16 MiB / `file_hash_mismatch`). | §A4, Phase 4 notes |
| **What replays** | Analysis object (summary, summary_details, details, **tags**), new observables + initial state (incl. **relationships, redirection, volatile** — Phase 4 spec fidelity), **file observables materialized from the blob store via `store_file`**, observable diff additions + scalar transitions, relationships (resolved by uuid-map → uuid → (type,value,time) spec), root-level additions. NOT: analysis detection points / pivot_links (uncaptured), wide-diff structures. | §5, Phase 4 notes |
| **root.json attribution** | Every non-empty delta recorded per module execution, **details-stripped** (cache row keeps details); cache hits recorded as `from_cache_hit=True` copies with `cached_at`. | §3, Part II hardening notes |
| **Delayed modules** | Cacheable: final-cycle delta is merged with prior cycles' recorded deltas at write time; mid-delay cycles never cached (COMPLETED gate). | open question 3 |
| **Config guards** | `cache_ttl` mutually exclusive with `wide_diff` and with `is_grouped_by_time` (pydantic validators); CI contract lint per opt-in (removals / relationship scope / file specs blob-backable for `file_capable` modules, no files otherwise). | §A6, §A1 |
| **Lifecycle** | Daily partition maintenance (drop > `partition_retention_days`=35, reorganize catchall, provision ahead); read-time `expires_at` filter owns precision; blob GC is a separate grace-period sweep. No row DELETEs anywhere. File blobs ride the same `blob_refs`/GC mechanism as spilled details. | §A8 |
| **Opt-ins (core)** | `rdap_analyzer` 7d; `nrd_analyzer` 24h + DB-file `extended_version`; `site_tagger` 30d + CSV `extended_version`; **`ocr` 7d + tesseract-version `extended_version`; `qrcode` 7d + zbarimg/gs/pdfinfo versions + filter-file content sha256** (Phase 4); **`phishkit_analyzer` 6h + `extended_version` = scanner-config content hash + running scanner image id via the dedicated `scanner_image_id` task** (2026-06-29). OCR/QR also cache **negative results** (clean scan, nothing found → summary-less analysis recorded; scan *failures* record nothing and are never cached). Phishkit caches **partial/timeout results on purpose** (a timeout is usually the target site blocking our crawl — a stable property — not transient noise; staleness is bounded by the 6h TTL). | Phase 3/4 notes, §A4, phishkit opt-in notes |
| **Metrics** | Per-(root, module) fields on the per-root summary event: hit/miss/write counts, lookup latency (**hits + misses**), write latency/bytes. `cache_stats` heartbeat (15 min) from partition statistics. | PR #242 notes |
| **Not implemented** | Phase 3.5 single-flight dedup (redesigned 2026-06-10: non-blocking, delayed-analysis requeue, `single_flight` opt-in — §A9). Deliberately re-sequenced after Phase 4; it has no dependents. Yara opt-in deferred — not for version reasons (the ruleset under `signature_dir` IS fingerprintable, nrd-style): its filtered output depends on file name and observable meta-tags, which sit outside the content-keyed cache; its SANDBOX directive lands on the *redirection target* (cross-observable, unreplayable); and a local yss socket scan is cheaper than a cache hit anyway. | §A9, Phase 4 notes |

## Problem

ACE3 today has no way to attribute a given mutation (tag, detection point,
child observable, directive, relationship) on the analysis tree back to the
specific analysis module that produced it. The current execution loop
(`saq/engine/executor.py:1094-1105`) calls `analysis_module.analyze(observable, ...)`
which mutates the `RootAnalysis` in place, then calls `root.save()`. By the
time the call returns, the module's contribution is indistinguishable from the
rest of the tree.

This blocks analysis caching: if `SomeIPAnalyzer` and `SomeGeoAnalyzer` both
add the `suspicious` tag to the same observable, we can't cache either one's
output independently, because replaying `SomeIPAnalyzer` against a fresh root
means "add the tag that SomeIPAnalyzer would have added" — and we don't know
which tag that was.

The ace2-core project (`https://github.com/unixfreak0037/ace2-core/blob/main/ace/analysis.py`)
solved this with a merge/diff protocol: each module execution carries an
`original_root` (pre-execution snapshot) and a `modified_root` (post-execution
snapshot), and `apply_diff_merge(before, after)` applies only the delta to a
target root. The cache (`https://github.com/unixfreak0037/ace2-core/blob/main/ace/system/caching.py`,
`https://github.com/unixfreak0037/ace2-core/blob/main/ace/system/base/caching.py`,
`https://github.com/unixfreak0037/ace2-core/blob/main/ace/system/base/request_tracking.py#L207-L326`)
stores these AnalysisRequest objects and replays the delta on cache hit. We want
the same capability in ACE3.

## Goals

1. Every module execution records the delta it produced against a specific
   observable, attributable to `(module_path, instance, version, observable)`.
2. Deltas can be replayed against a different root to reproduce the module's
   effect without re-running it.
3. A cache keyed on `(observable.type, observable.value, module_name,
   module_version, extended_version)` can short-circuit module execution.
4. Modules opt in to caching via a `cache_ttl` config field — modules with
   non-deterministic side effects or external dependencies stay uncached.
5. Incremental rollout: record deltas first, then cache writes, then cache
   reads. Each phase shippable independently.

## Non-goals

- Full replay-from-scratch of an alert (the delta log is enough for cache
  hits; we are not building a time-travel debugger).
- Distributed cache coordination across ACE3 nodes beyond what a shared
  database table gives us.
- Caching of modules that mutate shared mutable state (`root.state`,
  `root.action_counters`) or produce side effects beyond the analysis tree
  (filesystem, network writes). These remain opt-out by default.

---

## ace2-core reference

Before getting to the ACE3 design, it helps to make the ace2-core pattern
explicit because it's the model we're adapting:

- **`MergableObject`** (`https://github.com/unixfreak0037/ace2-core/blob/main/ace/analysis.py#L57-L66`): abstract mixin with
  `apply_merge(target)` and `apply_diff_merge(before, after)`. Implemented by
  `DetectableObject`, `TaggableObject`, `Analysis`, `Observable`, and
  `RootAnalysis`.
- **`apply_merge`** copies everything from source to target (idempotent union).
- **`apply_diff_merge(before, after)`** copies only what changed between
  before and after — the module's contribution.
- **Per-observable, per-module granularity**: `Observable.apply_diff_merge`
  (`https://github.com/unixfreak0037/ace2-core/blob/main/ace/analysis.py#L1413-L1487`) takes an optional `type` (AnalysisModuleType)
  argument. When set, it only merges in *the one Analysis object* produced by
  that module type, not every analysis on the observable.
- **Cache key** (`https://github.com/unixfreak0037/ace2-core/blob/main/ace/system/caching.py#L8-L33`): sha256 over observable
  type+value+time and module name+version+extended_version.
- **Replay on cache hit** (`https://github.com/unixfreak0037/ace2-core/blob/main/ace/system/base/request_tracking.py#L312-L326`):
  when a cached result exists for `(observable, amt)`, the engine copies the
  cached `original_root` and `modified_root` onto a new `AnalysisRequest`,
  marks `cache_hit=True`, and sends it through `process_analysis_request`.
  That function calls `target_observable.apply_diff_merge(original, modified, amt)`
  at line 233 — the same code path as a live module result.

The critical architectural point: ace2-core models every analysis run as a
**request with before/after roots**. The engine passes messages; each message
already carries its own before/after. In ACE3, modules run inline and mutate
the root directly, so we must *synthesize* the before/after snapshot at the
executor boundary.

---

## ACE3 design

### 1. Snapshot & diff at the executor boundary

The single choke point where a module touches the tree is
`AnalysisExecutor._execute_module_analysis` at
`saq/engine/executor.py:1012-1128`, specifically the `analysis_module.analyze(...)`
call on lines 1094-1100. Wrap that call:

```
# pseudo-code, inside _execute_module_analysis
before = ModuleExecutionSnapshot.capture(root, work_item.observable, analysis_module)
try:
    analysis_result = analysis_module.analyze(
        work_item.observable, context.final_analysis_mode, context.is_delayed_analysis
    )
finally:
    after = ModuleExecutionSnapshot.capture(root, work_item.observable, analysis_module)
    delta = ModuleExecutionDelta.compute(before, after, analysis_module, work_item.observable)
    root.record_module_execution(delta)

root.save()
```

`ModuleExecutionSnapshot.capture` does *not* deep-clone the entire root. It
captures only the fields that a module can mutate:

- On the **target observable** (the one being analyzed): current set of tags,
  detection points, directives, relationships, excluded/limited analysis,
  grouping_target, redirection, the list of child analysis module paths, and
  the set of linked observable uuids.
- On the **root**: set of observable uuids currently in the tree and the set
  of root-level tags/detections.
- On the **generated Analysis object** for this module: at the start, it
  typically doesn't exist yet. At the end it does, and the whole object is
  the "diff" for the analysis slot — captured by reference and serialized as
  part of the delta.

Snapshots are structural (sets of primitive identifiers), not JSON dumps of
the whole tree, so capture is cheap: it's proportional to what the target
observable holds, not to total tree size.

### 2. `ModuleExecutionDelta`

A new dataclass (proposed home: `saq/analysis/module_execution_delta.py`) with
the following fields:

| field | type | meaning |
|-------|------|---------|
| `cache_key` | `str` | sha256 of (observable type/value, module name, version, extended version). `None` if module has no `cache_ttl`. (`observable.time` was dropped from the key in PR #262 — see §8.) |
| `module_path` | `str` | fully-qualified module path (matches Observable._analysis keys). |
| `module_instance` | `str \| None` | for multi-instance modules. |
| `module_version` | `int` | from `AnalysisModule.version`. |
| `observable_uuid` | `str` | the observable the module was analyzing. |
| `observable_type` | `str` | denormalized for cache lookup. |
| `observable_value` | `str` | denormalized for cache lookup. |
| `root_uuid` | `str` | root provenance; rewritten to the current alert on cache-hit replay (`with_cache_hit_metadata`). |
| `created_at` | `str` (ISO) | when the delta was recorded; rewritten to the replay time on a cache hit. |
| `execution_time_ms` | `int` | metric (lookup + replay time on a cache hit). |
| `analysis` | `dict \| None` | serialized Analysis object produced, or `None` if the module returned INCOMPLETE / added no analysis. Includes summary, `details` (inlined since Phase 3 Step 3.1), analysis-object tags, completed/delayed flags. **The copy recorded into root.json is details-stripped** (`without_analysis_details()`, 2026-06-10) — only the cache row carries `details`; see the capture/replay hardening notes in Part II. Analysis-object detection points / pivot_links / llm_context_documents are NOT captured (deferred — a cacheable module must not rely on them). |
| `target_observable_diff` | `ObservableDiff` | what changed on the analyzed observable (see below). |
| `new_observables` | `list[ObservableSpec]` | observables this module added to the root (type, value, time, initial tags, detections, directives). |
| `root_diff` | `RootDiff` | root-level tag/detection additions (rare but possible). |
| `wide_diff` | `bool` | True when captured by a wide snapshot (§A6). |
| `other_observable_diffs` | `dict[str, ObservableDiff]` | wide-diff only: per-observable-uuid changes to observables *other* than the analyzed one (§A6). |
| `analysis_children_diffs` | `list[AnalysisChildrenDiff]` | wide-diff only: additions/removals to an Analysis object's child-observable list (e.g. ObservableModifier's `ignore`; §A6). |
| `from_cache_hit` | `bool` | Phase 3: True when this attribution delta was synthesized by cache replay rather than a live run. |
| `cached_at` | `str \| None` | Phase 3: ISO timestamp of the *original* live capture, preserved when `created_at` is rewritten to replay time. |

`ObservableDiff` captures only *added* items for each field (tags, detections,
directives, relationships, excluded_analysis, limited_analysis). It also
captures scalar transitions (grouping_target, redirection) when they change.
Removals are intentionally not supported — analysis modules in ACE3 are
additive by convention; if we find modules that remove state, they must
opt out of caching.

`ObservableSpec` is enough information to re-add an observable to a target
root via `root.add_observable(type, value, time=...)`, plus the initial
state the module set on it (tags, detections, directives). Crucially it
does NOT carry child Analysis objects — if the new observable was itself
analyzed, that's a *separate* `ModuleExecutionDelta` recorded against a
different module execution.

### 3. Storing deltas in the root

Add a new field to `RootAnalysis`: `self._module_executions: list[ModuleExecutionDelta]`.
Serialize it through the existing `RootAnalysisSerializer`
(`saq/analysis/serialize/root_serializer.py`). This gives us:

- Per-alert audit of which module did what, visible in the existing root JSON.
- Replay attribution for free.
- No schema migration for Phase 1 — just new keys in `root.json`.

Add a method `RootAnalysis.record_module_execution(delta)` that appends and
bumps a mutation counter so the JSON writer knows to re-emit.

### 4. Cache schema (Phase 2+)

> **Updated by PR #279 (merged 2026-05-27).** The cache no longer lives in the
> main `ace` database as a uniquely-keyed, upserted table swept by a periodic
> delete job. It is now an **append-only, daily-partitioned table in a
> dedicated `analysis-result-cache` database**, with lifecycle managed by
> partition drops (§A8). The schema block below reflects that design; §A3
> carries the full column set and §A8 the lifecycle. PR #279 is the upgrade
> path (it recreates the table in the new database).

The cache lives in its own MySQL database, `analysis-result-cache`
(`analysis-result-cache-unittest` for tests), separate from the main `ace`
schema so its multi-billion-row growth and partition churn never touch the
operational tables. Models bind to a dedicated declarative base
(`CacheBase`, `saq/database/meta.py`) rather than the main `Base`, and all
cache access routes through `get_db(DB_ANALYSIS_RESULT_CACHE)` where
`DB_ANALYSIS_RESULT_CACHE = "analysis_result_cache"` (`saq/constants.py`)
names the `database_analysis_result_cache` connection block in
`etc/saq.default.yaml`.

```
analysis_result_cache (
    cache_key           VARCHAR(64)  NOT NULL
    module_name         VARCHAR(512) NOT NULL
    module_version      INTEGER      NOT NULL
    observable_type     VARCHAR(64)  NOT NULL
    observable_value    TEXT         NOT NULL
    delta_zstd          LONGBLOB     NOT NULL   -- zstd-compressed ModuleExecutionDelta (§A3)
    delta_uncompressed_size INTEGER  NOT NULL
    has_blob_refs       BOOLEAN      NOT NULL
    created_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
    expires_at          DATETIME     NOT NULL   -- created_at + cache_ttl, computed DB-side
    PRIMARY KEY (cache_key, created_at)         -- created_at is the partition column
    KEY idx_module_expires (module_name, expires_at)
    KEY (expires_at)
)
-- PARTITION BY RANGE COLUMNS(created_at): one partition per day, pYYYYMMDD
```

The primary key is the composite `(cache_key, created_at)` rather than
`cache_key` alone. MySQL requires the partitioning column to appear in every
unique key, and the table is partitioned daily on `created_at` (§A8), so
`cache_key` can no longer be unique on its own. The practical consequence is
that **the cache is append-only**: a repeat analysis of the same observable
inserts another row rather than upserting, several non-expired rows can share
a `cache_key`, and the read path picks the most recently created one
(`ORDER BY created_at DESC LIMIT 1`; changed from `expires_at DESC` on
2026-06-10 — ordering by expiry let rows written under a longer,
since-reduced `cache_ttl` shadow fresher data until they expired). See
revised §open-question 5.

Migration: the cache database has its own Alembic environment,
`alembic/analysis_cache` (config `alembic/analysis_cache.ini`), separate from
the main `alembic/ace` environment. Revisions are generated with
`make cache-db-revision MESSAGE="..."` / applied with `make cache-db-upgrade`.

A small service module `saq/analysis/cache.py` exposes:

- `get_cached_delta(observable, module, blob_store) -> CacheLookupResult`
- `put_cached_delta(delta, module, blob_store) -> CacheWriteResult | None`
- `apply_delta(root, target_observable, delta) -> None` (replay)
- `collect_stats() -> dict` (partition-statistics snapshot, §A8)

There is no `delete_expired()` / `delete_for_module()` — row deletion is no
longer a code path. Expiry is handled by dropping whole partitions, and a
`cache_ttl`/rules-file bump is handled by the cache key changing (the old
entries simply stop being looked up and age out with their partition).

### 5. Replay path (Phase 3)

> **Implemented in PR #211 (merged 2026-05-14).** The pseudo-code below was the
> original proposal; the shipped path is the same shape with a few refinements
> (a richer `CacheLookupResult`, `with_cache_hit_metadata()` rather than a bare
> flag, a `_apply_cached_delta` helper that records telemetry, and an inner
> try/except that falls through to a live run on replay failure). See the
> "Phase 3 implementation notes" in Part II for the as-built detail.

In `_execute_module_analysis`, before the module runs (gated on
`analysis_module.cache_ttl is not None and analysis_cache.enabled`):

```
lookup = get_cached_delta(work_item.observable, analysis_module, get_blob_store())
if lookup.delta is not None:                       # cache hit
    self._apply_cached_delta(context, root, work_item.observable,
                             analysis_module, lookup.delta, lookup.lookup_ms)
    self._process_generated_analysis(
        AnalysisExecutionResult.COMPLETED, root, work_item, ...)
    root.save()
    return
elif lookup.miss_reason is not None:               # real miss (a row was sought)
    context.cache_miss_count[...] += 1
# else miss_reason is None → module not cacheable / cache disabled; not counted
```

`get_cached_delta` returns a `CacheLookupResult` — `delta`, `miss_reason`
(`not_found` / `decode_error` / `legacy_no_details` / `blob_missing`),
`lookup_ms`, and `cache_key_prefix`. The whole block is wrapped so any replay
error logs a warning and **falls through to a live run** rather than poisoning
the analysis (a replay bug must never block real work).

`_apply_cached_delta` calls `apply_delta(root, target_observable, delta)`, then
records a `from_cache_hit=True` attribution delta via
`delta.with_cache_hit_metadata(...)` (which rewrites `created_at` to the replay
time, preserves the original capture time in `cached_at`, and rewrites
`root_uuid`/`observable_uuid` to the current alert), and bumps the per-(root,
module) cache-hit / lookup-latency counters (§Phase 3 metrics).

`apply_delta(root, target_observable, delta)` does, in order:

1. **Rehydrate the Analysis object first** from `delta.analysis` — instantiate
   the right subclass via `SPLIT_MODULE_PATH(module_path)` and attach it under
   `target_observable._analysis[module_path]`. A *slot-collision skip* leaves an
   already-present analysis untouched (re-analysis / retry paths). Doing this
   first lets step 2's new observables hang off the analysis as children,
   matching a live run's tree shape.
2. For each `ObservableSpec` in `delta.new_observables`, add it as a child of
   the rehydrated analysis (or the root if none), deduped by type/value/time,
   then apply the spec's initial tags/detections/directives.
3. Add the target observable's tags/detections/directives/relationships and
   scalar transitions from `delta.target_observable_diff` — all additive, all
   idempotent. Relationship targets resolve by uuid (same-root), then a
   self-target shortcut, then `(target_type, target_value, target_time)` spec
   lookup — uuids are per-alert, so cross-alert replay relies on the spec
   fields the snapshot captures alongside each relationship (2026-06-10).
   Unresolvable targets (legacy uuid-only rows) log a WARNING and skip.
4. Apply `delta.root_diff` to root-level tags/detections.

File-observable deltas replay too (Phase 4, 2026-06-12): before any tree
mutation, `apply_delta` materializes every file spec's blob into a temp
staging dir under the target root's `storage_dir` (so a missing blob aborts
cleanly — the executor's replay-failure handler falls through to a live run
with the tree untouched), then routes each staged file through
`Analysis.add_file_observable(staged, target_path=spec.file_path, move=True)`
— the same `store_file` path a live module uses, so hashing, hardcopy dedup,
and tree wiring are identical. On the local blob backend the whole
blob→staging→hardcopy→file_dir chain is hardlinks of one inode (zero byte
copies). A second pass applies each new observable's captured
relationships/redirection through a source-uuid→created-observable map.
`apply_delta` is the ACE3 analogue of `Observable.apply_diff_merge(before, after, type)`
from ace2-core (`ace/analysis.py:1413-1487`), simplified: because we stored the
delta directly rather than before/after snapshots, replay is a pure additive
pass — no set-difference logic, and re-applying the same delta is a no-op.

After replay, the executor's existing `_process_generated_analysis` code runs
exactly as it would after a live module call, so the new observables introduced
by replay get queued for analysis (via the normal `EVENT_OBSERVABLE_ADDED` →
work-stack path) by the rest of the pipeline.

### 6. File observables and external details

Many modules store their bulk output in `analysis.details`, which is
persisted separately via `external_details_path`. The delta's `analysis` dict
references that path. Two options:

- **Option A (preferred for Phase 2):** Cache the `details` content *inline*
  in `delta_json`. Simpler, uses more DB space, and works because the cache
  is scoped to (observable value, module version) — so the details blob is
  precisely what needs to be reproduced.
- **Option B:** Store a content-addressed blob store reference and copy on
  replay. Defer unless Option A proves too large.

Similarly, file observables referenced by `delta.new_observables` need their
backing file to be present in the target root's storage dir. Phase 2 shipped
without file-observable caching; **Phase 4 (2026-06-12) added it**: at cache
write the file's bytes go into the content-addressed blob store
(`spec.value` is already the content sha256 — `FileObservable.value` is the
hash — so `exists()` dedupes identical content for free), and replay
materializes them back out (see §5). Modules producing files larger than
`analysis_cache.file_blob_max_bytes` (default 16 MiB per file) are refused at
write time.

### 7. Module config changes

Add to `saq/modules/config.py` (`AnalysisModuleConfig`):

```python
cache_ttl: Optional[timedelta] = Field(default=None)
extended_version: dict[str, str] = Field(default_factory=dict)
```

`cache_ttl=None` means "do not cache" — identical semantics to ace2-core
(`ace/system/caching.py:18`). Existing `version: int` is already present.
`extended_version` lets a module bake external signals (e.g., a rules file
hash) into the cache key so the cache invalidates when rules change.

`AnalysisModule` grows two properties backed by config:

```python
@property
def cache_ttl(self) -> Optional[timedelta]: ...
@property
def extended_version(self) -> dict[str, str]: ...
```

### 8. Cache key

> **Format v2 (2026-06-10).** The original (v1) key concatenated raw field
> bytes with no delimiters and hashed only extended_version *values* — so
> `{"tool_a": "1.0"}` and `{"tool_b": "1.0"}` collided, and field boundaries
> were ambiguous in principle. v2 hashes each component as
> `label:length:bytes` under a format-version prefix, and adds a **module
> config hash**. Bumping the format constant orphans all existing rows
> (their keys are never generated again); they age out with their daily
> partitions — a key-format change never needs a migration.

```python
CACHE_KEY_FORMAT = "ace-analysis-cache-key-v2"

def generate_cache_key(observable, module):
    if module.cache_ttl is None:
        return None
    h = hashlib.sha256()
    _update(h, "format", CACHE_KEY_FORMAT)      # each field: label:length:bytes
    _update(h, "type", observable.type)
    _update(h, "value", observable.value)
    _update(h, "module", module.config.name)
    _update(h, "version", str(module.version))
    _update(h, "config", _config_hash(module))  # see below
    for key in sorted(module.extended_version):
        _update(h, f"ext:{key}", module.extended_version[key])
    return h.hexdigest()
```

Lives in `saq/analysis/cache.py`.

**The config hash** closes an invalidation gap: a module's YAML config can
change its output (thresholds, endpoints, any module-specific
`get_config_class()` field) without `version` being bumped — silently
serving stale results until TTL. `_config_hash` is sha256 over the module's
resolved pydantic config `model_dump`, minus an explicit exclusion set
(`CONFIG_HASH_EXCLUDED_FIELDS`): operational knobs (`priority`,
`maximum_analysis_time`, `semaphore_name`, `cache_ttl` itself — a TTL
change must not orphan live entries — etc.) and eligibility filters that
gate *whether* the module runs rather than what it produces
(`valid_observable_types`, `required_directives`, queue filters, etc. —
the executor applies these before any cache lookup). Everything else
participates, including `python_module`/`python_class` and all
subclass-specific fields, so an analyst config edit invalidates that
module's cache automatically. Over-invalidation from an
unnecessarily-included field costs only cache misses; under-invalidation
is the bug the hash exists to prevent.

**`observable.time` is deliberately excluded** (ace2-core's formula included
it; ACE3 dropped it — it was hashed into the key in an early build and
**removed in PR #262** once it proved to defeat dedup in production). A
cacheable module's result is a pure function of the observable *value* plus
external state — never of when the observable was seen. Including `time` also
defeats dedup for observable types that commonly carry one: ACE IP observables
are routinely created with an event time, so keying on time would give every
occurrence of the same IP a distinct key — a write-only cache row with a ~0%
hit rate, growing the table roughly one row per occurrence. Result drift over time (a
domain re-registered, a host re-imaged) is bounded by `cache_ttl`, which is
the single knob for staleness. A module whose result genuinely depends on
the observable's event time (point-in-time historical lookups) is not a
viable cache candidate for the same dedup reason, and should leave
`cache_ttl = None`.

---

## Rollout phases

### Phase 1 — Record deltas (no cache)

- New `ModuleExecutionDelta` / `ObservableDiff` / `ObservableSpec` /
  `RootDiff` dataclasses and JSON serialization.
- `RootAnalysis._module_executions` list + serializer support.
- Executor snapshot-and-diff wrapping around the `module.analyze` call.
- Unit tests covering: add-tag attribution, add-observable attribution,
  add-detection attribution, module that touches nothing, module that raises.

Ship and bake. No behavior change for users, but root JSON now carries a
complete per-module attribution log we can inspect in the field to validate
the diff computation is correct before we start *acting* on it.

### Phase 2 — Cache writes

- Alembic migration for the `analysis_result_cache` table.
- `cache_ttl` and `extended_version` on `AnalysisModuleConfig`.
- `saq/analysis/cache.py` with `put_cached_delta` + key generator.
- Executor, on successful module run, writes delta to cache if
  `module.cache_ttl is not None`.
- Scheduled job to reclaim expired entries.

Ships dark — no module opts in during this phase. Validates that the
plumbing loads, validates pydantic config rules, and exercises the
lifecycle job against an empty table.

> **Schema/lifecycle note (PR #279).** Phase 2 originally shipped the cache as
> a uniquely-keyed table in the `ace` database with a periodic delete sweep.
> PR #279 (merged 2026-05-27, after the Phase 2 bake) moved it to a dedicated
> `analysis-result-cache` database, made it append-only/daily-partitioned, and
> replaced the delete sweep with partition drops. The "delete expired entries"
> job above is now `bin/manage-analysis-result-cache-partitions.sh`. See §4 and
> §A8 for the current design.

### Phase 2.5 — Write-only opt-in bake

Opt in `analysis_module_whois_analyzer` with `cache_ttl: 604800`
(7 days). No code changes — YAML only.

Whois is latency-slow rather than CPU-heavy, lightweight in details
size, content-addressable by domain, purely additive, and produces
no child observables. That last property is what selects it over
file-extraction modules (OCR/QR) for this slot: those produce file
children whose bytes-on-disk would be missing on replay until Phase
4's `FileObservable.materialize()` lands, so they're held back to
opt in alongside Phase 4.

> **Status update.** Whois served as the write-only bake subject as planned,
> but is no longer the standing opt-in — once Phase 3 read/replay landed the
> opt-in set was reworked to `rdap_analyzer`, `nrd_analyzer`, and `site_tagger`
> (read+write; see the revised Phase 3 below). Whois's `cache_ttl` is now
> commented out in the dev config.

Goal: exercise the Phase 2 write path under real production load
*before* adding read/replay complexity. Without this step, the Phase 2
monitoring (`cache_stats`, refusal warnings) only produces signal once
Phase 3 lands, commingling write-path failure modes with replay
correctness questions. (The `prune_backlog` warning that earlier drafts
listed here was removed in PR #279 along with the delete sweep — §A8.)
See Part II for the detailed monitoring plan and
confidence criteria.

### Phase 3 — Cache reads / replay — **Implemented (PR #211, 2026-05-14)**

- `apply_delta` + `get_cached_delta` (→ `CacheLookupResult`) in
  `saq/analysis/cache.py`; replay primitives (`from_cache_hit`, `cached_at`,
  `has_file_observables`, `with_cache_hit_metadata`) on `ModuleExecutionDelta`.
- Executor consults the cache before calling `module.analyze`; on hit it
  replays the delta and skips the module (§5), falling through to a live run if
  replay errors.
- Delayed-analysis modules made cacheable via snapshot Step 3.0 (capture on the
  `delayed: True→False` transition) plus a write-time refusal of still-delayed
  deltas.
- Metrics: per-(root, module) cache hit/miss/write counts and latency/byte
  accumulators aggregated onto the existing per-root summary event, **not**
  per-event log lines (reworked in PR #242 — see Part II).
- CI lint: `tests/saq/modules/test_cacheable_modules_contract.py` asserts every
  YAML-shipped `cache_ttl` module is registered and produces no removals, no
  file observables, and no out-of-scope relationships (2026-06-10).
- Modules opted in (current shipped state, `etc/saq.default.yaml`):
  `rdap_analyzer` (7d), `nrd_analyzer` (24h), `site_tagger` (30d) — all small,
  deterministic, additive, and each driving cache invalidation through
  `extended_version` (a file mtime+size hash; §A5). Downstream integrations may
  opt additional modules in via their own overlay configs. Risky /
  file-producing / wide-diff modules remain opted out.
- Not yet shipped as of Phase 3: phishkit read-side opt-in, the tool-version
  `extended_version` helper, and Phase 3.5 single-flight dedup. (The
  tool-version helper has since shipped with Phase 4.)

### Phase 4 — File observables and cross-alert observables — **Implemented (2026-06-12)**

> Sequenced *before* Phase 3.5 (a deliberate re-order from the original
> roadmap — single-flight is a work-dedup optimization with no dependents,
> while file support unblocked the modules we most wanted cached).

- `ObservableSpec` fidelity extension: `file_path` (relative to the source
  root's file dir), `volatile`, `initial_relationships`,
  `initial_redirection` — captured at diff time, serialized
  omit-when-default (old rows/root.json load unchanged).
- Cache write (`put_cached_delta`, now taking the source `root`): per file
  spec, validate (path captured, backing file present, ≤
  `analysis_cache.file_blob_max_bytes`), then `blob_store.exists(spec.value)`
  -or-`put()` (the spec value IS the content sha256 — identical content
  dedupes for free; a `put()` hash mismatch refuses the delta), then
  `reference()` under the cache row exactly like the details spill.
- Replay (`apply_delta`): pre-mutation staging pass materializes every blob
  under the target `storage_dir`, then `add_file_observable(staged,
  target_path=spec.file_path, move=True)` reuses `store_file` semantics;
  missing blob = lookup-time `blob_missing` miss (or a clean replay abort →
  live-run fall-through). See §5/§6.
- Tool-version helper (`saq/modules/tool_version.py`,
  `probe_binary_version`) shipped alongside (former Step 3.6). The same module
  carries `file_content_version` (sha256 of a small backing file) for the QR
  filter — a content hash, not mtime+size, so the key is stable across hosts
  (the filter ships from a git repo, whose checkout sets mtime per host).
- Opt-ins: `ocr` (7d, tesseract version in `extended_version`) and `qrcode`
  (7d, zbarimg/gs/pdfinfo versions + filter-file content sha256).
  **Yara deferred** — not for version reasons (the module exposes
  `signature_dir` and the ruleset is fingerprintable nrd-style): its output
  depends on the file's *name* and the observable's *meta-tags*, which are
  outside the content-keyed cache, and its sandbox directive lands on a
  *different* observable — see the Phase 4 implementation notes for the
  full breakdown. **Phishkit opt-in shipped 2026-06-29 in core**
  (`saq/modules/phishkit.py`) — see the "Phishkit opt-in" notes in Part II.
- See "Phase 4 implementation notes" in Part II for as-built detail and
  known limitations (shared-inode immutability assumption, mixed-version
  fleet behavior).

---

## Open questions

1. **Analysis object rehydration:** The existing root.json loader reconstructs
   `Analysis` subclasses via `module_path`. The delta's `analysis` field needs
   to use the same mechanism so replay produces an instance of the correct
   subclass (not a bare `Analysis`). Audit
   `saq/analysis/serialize/root_serializer.py` to confirm the
   module_path→class lookup is reusable outside the full-root load path.

   *Resolved in Phase 3 (PR #211):* `apply_delta`'s `_rehydrate_analysis`
   instantiates the subclass via `SPLIT_MODULE_PATH(module_path)`, falling back
   to `UnknownAnalysis` if the import fails, with a slot-collision skip when the
   slot is already populated.

2. **Multi-instance modules:** ACE3 supports multiple configured instances of
   the same `AnalysisModule` class. The cache key must include the module's
   config instance identifier, not just the class name — otherwise two
   instances with different configs collide. Confirm `config.name` is unique
   per instance.

3. **Dependency-ordered analysis:** Some modules use `WaitForAnalysisException`
   to defer until a dependency analysis is complete
   (`saq/engine/executor.py:1130-1148`). Snapshot capture must handle the
   case where the module raises without producing a delta — the `finally`
   block catches this, and we should suppress delta recording when the
   module raised (not complete yet). The Phase 1 wrapper needs to check the
   exception state before recording.

   *Resolved across Phases 1 and 3:* Phase 1 records nothing when the module
   raises; Phase 3 (PR #211) additionally handles the *delayed-analysis*
   variant — snapshot Step 3.0 captures the analysis dict on the
   `delayed: True→False` transition, and `put_cached_delta` refuses any delta
   still flagged `delayed`, so only the final post-delay result is cached.

   *Hardened 2026-06-10 (capture/replay hardening, Part II):* two gaps in
   that resolution were fixed. (a) The still-delayed refusal inspects the
   analysis dict, but a module that delays **2+ times** produces intermediate
   deltas with `analysis=None` (slot already present, no transition) which
   slipped past it — partial mid-delay results were cached. The executor
   cache write is now gated on the module returning COMPLETED. (b) The final
   cycle's diff only covers the final cycle, so pre-delay tree mutations
   (tags, child observables) were missing from the cached delta. On a delayed
   resume the executor now merges the prior cycles' recorded deltas (from
   `root.module_executions`, persisted across restarts) into the cached delta
   via `merge_module_execution_deltas()`.

4. **Modules that mutate other observables:** Rare but possible — a module
   analyzing observable A might `root.add_tag` or tag observable B. The
   snapshot focuses on the *analyzed* observable; cross-observable mutations
   would leak attribution. Decide whether to (a) widen the snapshot to all
   observables, or (b) declare this pattern unsupported for cached modules.
   Recommend (b) with a lint in Phase 3.

5. **Concurrent cache fills:** Two engines analyzing the same observable
   with the same module simultaneously — both will write to the cache. The
   original design resolved this with `INSERT ... ON DUPLICATE KEY UPDATE`
   (last-write-wins). **PR #279 made the cache append-only** (the partition
   column `created_at` is part of the primary key, so `cache_key` is not
   unique — §4), so there is no key conflict to resolve: both engines simply
   `INSERT` and both rows coexist. Both results are valid by construction;
   the read path picks the freshest non-expired one
   (`ORDER BY created_at DESC LIMIT 1` since 2026-06-10; originally
   `expires_at DESC`) and the daily partition drop reclaims the rest.
   Last-write-wins is preserved, just realized by read ordering instead
   of by upsert.
   *Note:* this addresses DB integrity only, not duplicate *work*. See §A9
   for the single-flight dedup design that prevents thundering-herd
   re-execution of expensive modules.

6. **Cache size:** Need a back-of-envelope on how big `delta_json` gets for
   a typical module. If `details` blobs are multi-MB (file content analyses),
   Option A in §6 becomes untenable and we need Option B earlier.

---
## Addendum: answers to specific concerns

### A1. Can `ObservableModifierAnalyzer` be cached?

No — it should stay opted out (`cache_ttl = None`) by design, and that is
fine. Reading `saq/modules/util/observable_modifier.py` confirms why:

1. **Its output depends on non-local tree state.** `TreeCondition.evaluate`
   (`observable_modifier.py:67-92`) walks ancestors, globals, self, or
   parent analyses and regex-matches their `details`. Two roots with the
   same input observable value will legitimately produce *different*
   outputs from this module, because the surrounding tree is different.
   No practical cache key can capture "the state of every other analysis
   on this tree at the moment the module ran" without becoming so specific
   that it never hits.

2. **It does removals.** The `ignore` action at
   `observable_modifier.py:552-579` does
   `parent_analysis._observables.remove(observable)` and sets
   `observable.ignored = True`. Per §A4 below, removals disqualify a
   delta from caching anyway.

3. **There's no payoff.** The module is pure local Python: regex matches
   against in-memory data. It's not the kind of module caching is for.
   The caching payoff is for expensive/external modules — threat-intel
   lookups, sandbox detonations, yara scans of large files, LLM calls.
   Skipping a few ms of regex matching is not worth the complexity cost.

**Generalization — the "cacheability contract":** a module is cacheable
only if its output is a pure function of `(observable.type,
observable.value, module.version, module.extended_version)` plus any
deterministic external inputs hashed into `extended_version`.
Modules whose output depends on *other observables*, *other analyses*,
*the root's tags*, *wall-clock time*, *the observable's event time*, or
*global mutable state* are not cacheable, full stop. (`observable.time` is
not part of the key — see §8. A module whose result depends on it is, by
this contract, uncacheable.)

Two further consequences of this contract are enforced mechanically:
relationships must stay within the module's own output (§A4's
`relationship_out_of_scope` refusal), and `is_grouped_by_time` cannot be
combined with `cache_ttl` (config-load validator, 2026-06-10 — a cache
hit bypasses `analyze()` and therefore `analysis_covered()`, so
time-grouping and caching are incoherent together, same argument as the
`wide_diff` exclusion in §A6).

Crucially, the Phase 1 attribution machinery still records deltas for
these modules — we just don't cache them. Seeing "ObservableModifier:my_rule
added tag `suspicious` to obs X and removed obs Y from FileAnalysis" in
root.json is valuable on its own for debugging and audit, independent of
caching. So the design does *not* reduce to "cacheable modules only get
attribution."

### A2. File observables and a central blob store

Per-alert `storage_dir` copies are the wrong shape for caching. Proposal:
introduce a content-addressed blob store at `data/blob_store/ab/cdef...`
(sha256-keyed, two-level sharded) that is reused across alerts.

**Write path** (normal module run that produces a file observable):
1. Module writes the file into the alert's `storage_dir` as today.
2. A post-hook in the file observable's `add_file`/constructor path
   computes sha256 (ACE3 already hashes files — `Observable._sha256_hasher`).
3. If `data/blob_store/ab/cdef...` doesn't exist, hardlink the alert file
   into the blob store.
4. If it does exist, *replace* the alert-side copy with a hardlink to the
   blob store entry (saves one inode's worth of disk).

**Cache-write path:** the `ModuleExecutionDelta` records, for each new
file observable, its sha256 and metadata (filename, mime type, size). The
actual bytes are already in the blob store by the write-path step above —
the delta doesn't duplicate them.

**Cache-hit replay path:**
1. Look up the delta; for each file observable spec, confirm the blob
   exists at `data/blob_store/<sha>`. If missing, treat as a cache miss
   and re-run the module. (This handles blob-store GC or deployment
   mismatches safely.)
2. Hardlink `data/blob_store/<sha>` into the target alert's `storage_dir`
   under the appropriate filename.
3. Construct the `FileObservable` pointing at that path exactly as if a
   module had produced it.

**Lifecycle:** the blob store's filesystem link count is a free reference
counter. A GC job deletes blobs with `st_nlink == 1` (only the blob store
itself points at them) that are older than some grace period. Alert
deletion naturally decrements link counts by removing the alert-side
hardlink.

**Constraints:**
- Blob store and alert storage dirs must share a filesystem (hardlinks
  require it). In a standard ACE3 deployment both live under `data/`, so
  this is already true.
- Symlinks are explicitly rejected: alert deletion would break symlinks
  for other alerts referencing the same blob.
- On copy-on-write filesystems (btrfs/zfs), hardlink semantics still
  hold; the mild behavioral differences don't matter for our use case.

This unifies the "file cache" with the general "delta blob" store from §A3
below — same directory layout, same GC, same code path.

### A3. Compressing and offloading `delta_json`

Yes, the DB is the wrong place for large deltas. Three-layer strategy:

**Layer 1 — always zstd-compress.** JSON deltas compress 3-5x with
`zstandard` at level 3. Column becomes `delta_zstd LONGBLOB`. One
dependency (`python-zstandard`), one-line compress/decompress. Do this
unconditionally even for small deltas; the overhead is negligible.

**Layer 2 — spill large `analysis.details` to the blob store.** The
`details` dict is usually what's large (full sandbox reports, extracted
text, parsed binary structures). The rest of a delta (tags, detection
points, observable specs) is small. So:

- Before writing the delta, if `serialize(analysis.details)` exceeds a
  threshold (start at 16 KiB uncompressed), compute its sha256, write it
  to the blob store (same blob store as §A2 — deterministic modules with
  identical details will dedupe for free), and replace the inline
  `details` in the delta with `{"__blob_ref__": "<sha256>"}`.
- On replay, if `details` is a blob ref, fetch from the blob store and
  rehydrate.

**Layer 3 — row-level size cap.** If a compressed delta is still
> 1 MiB after details spill, refuse to cache it and log a warning. This
catches pathological modules that emit mountains of small structured
data in non-details fields (shouldn't happen, but don't let a bad module
blow up the cache table).

Schema update to §4:

```
cache_key           VARCHAR(64)  NOT NULL
module_name         VARCHAR(512) NOT NULL
module_version      INTEGER      NOT NULL
observable_type     VARCHAR(64)  NOT NULL
observable_value    TEXT         NOT NULL
delta_zstd          LONGBLOB     NOT NULL  -- zstd-compressed JSON
delta_uncompressed_size INTEGER  NOT NULL  -- for monitoring
has_blob_refs       BOOLEAN      NOT NULL  -- whether delta references blob store
created_at          DATETIME(6)  NOT NULL  -- partition column
expires_at          DATETIME     NOT NULL
PRIMARY KEY (cache_key, created_at)        -- created_at forced into PK by partitioning
```

(Per PR #279: this table is append-only and partitioned daily on `created_at`
— see §4 and §A8. `created_at` is part of the primary key because MySQL
requires the partitioning column in every unique key; `cache_key` alone is no
longer unique.)

When `has_blob_refs = true`, the cache entry's validity depends on the
referenced blobs still existing. The blob-store GC must treat "referenced
by an unexpired cache row" as a retention reason — cheapest
implementation is to walk the cache table's blob refs and bump mtime on
referenced blob files (or maintain an explicit `blob_references` table
if that gets slow).

### A4. Guarding against removal actions that forget to opt out

The diff should detect removals, not just additions, so we have a safety
net for modules where a human forgot to set `cache_ttl = None`.

Revised snapshot/diff semantics:

- Snapshot captures **sets** for each mutable field (tags, detections,
  directives, relationships, excluded_analysis, limited_analysis,
  observable-uuid membership in parent analyses, `ignored` flag).
- Diff computes both `added = after - before` *and*
  `removed = before - after` for each set.
- Scalar fields (`display_type`, `display_value`, `grouping_target`,
  `redirection`) capture `(before_value, after_value)`.

Policy in the executor:

1. **Phase 1:** if any module produces a delta with non-empty removals or
   scalar changes, log at INFO with the module name. This builds a
   census — we learn which modules mutate-in-place and which are purely
   additive, before we ship caching.
2. **Phase 2+:** before writing to the cache table, inspect the delta.
   If removals are present AND `module.cache_ttl is not None`, log at
   ERROR, increment a `analysis.cache.removal_refused` metric with the
   module name, and *do not write the cache entry*. The delta still
   lands in `root.json` for attribution; we just won't replay it.
3. **Test-time lint:** a pytest fixture that iterates over all
   registered modules with `cache_ttl is not None`, runs them against a
   synthetic fixture tree, and asserts their deltas contain no removals
   or scalar changes. Catches the problem at CI time instead of
   production time.

**Empty deltas are also refused** (added in **PR #262**). A delta with no
mutations (the module ran and changed nothing) has nothing to replay, so
`put_cached_delta` returns without writing a row. This is the *cache-write*
guard, distinct from the Phase 1 *recording-time* `is_empty` filter that keeps
empty deltas out of `root.json` — the cache-write path originally lacked the
equivalent guard, so a broad opt-in could still write a row per observable.
It is not a safety concern like removals — it is a volume one: a module that
runs broadly (e.g. one with `valid_observable_types = None`) produces an empty
delta for every observable it merely *looks at*, and caching each would write
one row per observable in the system with no hit-rate benefit. The refusal is
silent (empty deltas are the common, expected case, not a misbehaving opt-in).
Consequence: a non-matching observable re-runs the module live on every
recurrence — acceptable, because a module cheap enough to run that broadly
is cheap enough to re-run. Negative caching of an *expensive* module's
"found nothing" result, if ever needed, is a separate explicit opt-in and
is better served at the module's own client/lookup layer than in the
analysis-result cache.

> **Phase 4 follow-up (2026-06-12): OCR/QR opted into negative caching at
> the module layer**, exactly as prescribed above — the cache machinery is
> unchanged. Both modules now record a summary-less Analysis when their
> scans *complete cleanly* with no result (`QRCodeAnalysis` with
> `extracted_text=None`; `OCRAnalysis` with `ocr=False` — both
> `generate_summary()` shapes return `None`, so the alert view stays
> clean, and the default tree view prunes detection-less nodes anyway).
> The analysis dict makes the delta non-empty → cached → replay installs
> the slot, skipping the re-scan. This matters because the negative path
> is these modules' *expensive* path (a clean QR scan triggers a second
> inverted-image scan; PDFs pay pdfinfo + gs rendering first) and the
> dominant one. **Failure paths deliberately record nothing**: a zbarimg
> timeout/error exit (`_scan_image` now distinguishes exit codes 0/4 =
> trusted scan from anything else = failure) or a raising OCR pass leaves
> the delta empty, so a transient failure can never be cached as a
> multi-day negative verdict. Volume trade-off: one tiny cache row per
> unique image/PDF sha (details are two near-null fields) — and recurring
> email imagery (logos, signature images, tracking pixels) makes the
> negative hit rate high.

Why refuse to replay removals rather than support them? Replaying a
removal means "I once saw a state where X existed and I removed it." On
the target root X may not exist at all, may exist for a different reason
(added by a module that isn't running this time), or may be load-bearing
for a module that hadn't run yet when the cache was populated. Removing
it is a correctness hazard that we cannot verify from the delta alone.
The safer default is: cacheable modules must be monotonic.

Since 2026-06-10 `has_removals` also counts **root-level** removals
(`root_diff.removed_tags/removed_detections`) — replay only ever applies
root *additions*, so a root-level removal was previously cacheable but
silently unreplayable.

**Relationships have their own write-time scope refusal**
(`refusal_reason=relationship_out_of_scope`, 2026-06-10): a cacheable
module's relationships must target either the analyzed observable itself
or an observable the same delta created. Anything else points at
surrounding tree context a replay onto a different root cannot guarantee
to reproduce. In-scope relationships ARE replayable — the snapshot
captures each relationship target's `(type, value, time)` spec alongside
the uuid, and replay re-resolves through it (§5). *(Resolved in Phase 4,
2026-06-12:)* a relationship hung on a *new* observable
(`child.add_relationship(...)`) was previously invisible to the narrow
diff; `ObservableSpec` now carries `initial_relationships` (plus
`initial_redirection` and `volatile`), captured at diff time and applied
in a second replay pass once all new observables exist. The scope refusal
covers these spec-level relationships/redirections too — OCR/QR's
`R_EXTRACTED_FROM` back to the analyzed file is the motivating in-scope
case.

Scalar-change handling is similar but laxer: a scalar change is
effectively "set to new value", and replay sets it. If two modules both
set the same scalar, the last replay wins, which matches live-execution
ordering semantics. So scalar changes *are* cacheable, but they trigger
the same INFO-level logging in Phase 1 so we can spot surprises.

### A5. Dynamic `extended_version` for auto-updating rules files

> **Implemented and in use.** `extended_version` ships as a property on
> `AnalysisModule` (`saq/modules/base_module.py`, delegated through
> `saq/modules/adapter.py`) and the file-fingerprint pattern below is live, not
> hypothetical. The current cacheable user is `qrcode`
> (`saq/modules/file_analysis/qrcode.py`), which mixes a **content sha256** of
> its URL filter file (via `file_content_version` in `saq/modules/tool_version.py`)
> into the cache key, so an analyst edit invalidates the key without a redeploy.
> A content hash — not the mtime+size signature shown in the example below —
> keeps the key deterministic across hosts: the filter ships from a git repo,
> whose checkout/pull sets mtime per host, so an mtime fingerprint would diverge
> per system for identical content. (`nrd_analyzer` and `site_tagger` carried
> an mtime+size signature when they were cacheable, but were since removed from
> the cache.) The tool-version flavor (hashing a CLI tool's `--version`) ships
> in the same module as `probe_binary_version`.

The ace2-core shape of `extended_version` (a static dict on the AMT
dataclass) doesn't fit ACE3's watch-file pattern. Change it from a
config field to a **property** on the module:

```python
class AnalysisModule:
    @property
    def extended_version(self) -> dict[str, str]:
        """Dynamic inputs to mix into the cache key. Override in subclasses
        that depend on external state (rules files, feed versions, model
        weights, etc.). Default: empty dict."""
        return {}
```

A module backed by a YAML rules file (pretend it's a hypothetical
cacheable variant of ObservableModifier):

```python
class MyRulesBasedModule(AnalysisModule):
    @property
    def extended_version(self) -> dict[str, str]:
        return {"rules_sha256": self._rules_hash()}

    def _rules_hash(self) -> str:
        yaml_path = os.path.join(get_base_dir(), self.config.rules_config_path)
        st = os.stat(yaml_path)
        key = (yaml_path, st.st_mtime_ns, st.st_size)
        cached = self._rules_hash_cache.get(key)
        if cached is None:
            with open(yaml_path, "rb") as f:
                cached = hashlib.sha256(f.read()).hexdigest()
            self._rules_hash_cache = {key: cached}
        return cached
```

Properties of this scheme:

- **No redeploy needed when rules change.** The analyst updates the YAML
  in the external repo, the periodic git pull lands the new file, mtime
  changes, next cache-key generation picks up the new hash, old cache
  entries become unreachable (their keys no longer collide), new runs
  populate fresh entries under the new key.
- **Old entries become unreachable immediately** (their keys no longer
  collide on the next lookup) and their space is reclaimed when their daily
  partition is dropped (§A8). The stale space is bounded by
  `partition_retention_days`.
- **Fast path:** mtime-keyed in-process cache means hashing happens at
  most once per file change per module instance, not on every cache
  lookup.
- **No explicit invalidation hook is needed.** Earlier drafts proposed a
  `cache.delete_for_module(module_name)` call from the module's
  `watch_file(yaml_path, self._load_config)` reload callback — analogous to
  ace2-core's `delete_cached_analysis_results_by_module_type`
  (`ace/system/base/module_tracking.py:74`) — to evict stale entries on a
  rules change. PR #279 made the cache append-only and partition-managed (§A8),
  removing the targeted-delete path: a rules change shifts the key, the old
  rows simply stop being read, and they age out with their partition. The key
  shift *is* the invalidation.

Because `extended_version` is now a *property*, not a config field, §7
of the main design changes: drop `extended_version` from
`AnalysisModuleConfig`, keep only `cache_ttl`. The property lives on
`AnalysisModule` with a default-empty implementation.

Generalization — anything a module depends on that isn't the observable
itself should go into `extended_version`: yara rule file hashes, threat
intel feed version, ML model file hash, external service version strings
if the module can query them. If the module can't compute a hash for an
input it depends on, it can't be cached — because we have no way to
know when that input changes.

### A6. Modules that mutate other observables (= ObservableModifier)

The original design said "unsupported for cached modules, declare and
lint." That was a punt, and ObservableModifier proves it's insufficient
— this module is the *point* of having cross-observable mutations, and
it definitely needs attribution even though it isn't cached.

Revised: add an opt-in per-module flag `wide_diff: bool = False`. When
`True`, the snapshot captured at the executor boundary widens from "just
the analyzed observable + root observable-uuid set" to "every observable
in the root and its mutable fields + every analysis and its child
observable membership." The diff then attributes any change anywhere in
the tree to this module execution.

ObservableModifier sets `wide_diff = True`. Its delta can say things
like:

- "added directive `D` to observable `obs-123`" (the analyzed one — the
  delta's normal `target_observable_diff`)
- "added tag `suspicious` to observable `obs-456`" (a different one — rare but
  possible — carried in `other_observable_diffs`, a `dict[uuid → ObservableDiff]`)
- "removed observable `obs-789` from parent analysis `FileAnalysis`"
  (the `ignore` action — carried in `analysis_children_diffs`, a list of
  `AnalysisChildrenDiff`)
- "set `obs-999.ignored = True`" (in that observable's `other_observable_diffs`
  entry)

As built, a wide capture populates two extra structures on the delta beyond the
narrow `target_observable_diff`: **`other_observable_diffs`** (per-uuid field
changes to other observables) and **`analysis_children_diffs`** (additions/
removals to an Analysis object's child-observable list). `apply_delta`
deliberately ignores both — they only ever appear on uncacheable wide-diff
deltas, so cache replay never needs them.

`observable_modifier` is not the only shipped `wide_diff: true` module —
`mailbox_email_analyzer` sets it too (it rewrites fields across the email's
related observables). Both are uncacheable by the invariant below.

Cost of wide snapshots: O(observables × fields per observable). For a
typical ACE3 root with tens to a few hundred observables that's a few
thousand field reads and set constructions per module execution. Still
cheap relative to module execution itself.

Invariant: `wide_diff = True` implies `cache_ttl = None` is enforced.
Mixing wide-diff with caching is logically valid (the delta captures
enough to replay), but the cacheability contract from §A1 — output is a
pure function of the input observable — is almost certainly violated
when a module is touching the whole tree, so we refuse the combination
in `AnalysisModuleConfig` validation and a startup check. If a future
module genuinely needs both, it can be reconsidered then.

What wide-diff means for the snapshot struct (§1): `ModuleExecutionSnapshot`
gains two constructors — `narrow(root, observable, module)` and
`wide(root, module)`. The diff constructor branches on which kind of
snapshot it received. Narrow snapshots are the common case and stay
cheap; wide is opt-in.

### A7. Forward-compatibility with S3 storage and Lambda execution

The hardlink-based blob store from §A2 is local-filesystem-specific and
will not survive two roadmap items:

1. **ACE storage moves from local disk to S3.** Hardlinks don't exist
   in object storage. "Reference count via `st_nlink`" goes away. Alert
   storage dirs become S3 prefixes. File observables become S3 keys.
2. **Analysis modules move to Lambda.** Lambdas have no shared
   filesystem. Every invocation is cold with respect to disk. Anything
   a module needs to read must come from S3; anything it produces must
   be written to S3 before the invocation returns.

The caching design survives this migration cleanly if we do one thing
up front: **factor blob storage behind an interface, with the local
hardlink implementation being one backend and an S3 backend being the
other.** The cache logic, the delta writer, and the replay path all
talk to the interface, not the filesystem.

#### `BlobStore` interface

```python
class BlobStore(ABC):
    @abstractmethod
    def put(self, data: bytes | BinaryIO) -> str:
        """Store bytes, return sha256."""

    @abstractmethod
    def get(self, sha256: str) -> BinaryIO:
        """Open a read stream. Raises BlobNotFound."""

    @abstractmethod
    def exists(self, sha256: str) -> bool: ...

    @abstractmethod
    def reference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        """Record that <referrer> depends on <sha256>. Idempotent."""

    @abstractmethod
    def unreference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        """Drop the dependency. Safe to call for non-existent refs."""

    @abstractmethod
    def maintain_global(self, grace_period: timedelta, dry_run: bool = False) -> GlobalMaintenanceStats:
        """GC the durable tier: delete blobs with zero references whose
        durable-tier object is older than grace_period. Primary node only."""

    @abstractmethod
    def maintain_local(self, budget: LocalCacheBudget, dry_run: bool = False) -> LocalMaintenanceStats:
        """Evict entries from THIS node's local cache tier. Safe on every node;
        backends without a separate cache tier (the pure-local store) return
        empty stats."""

    @abstractmethod
    def materialize(self, sha256: str, dest_path: str) -> None:
        """Escape hatch: make the blob available at a local filesystem
        path. Local backend hardlinks; S3 backend downloads to /tmp."""
```

`reference()`/`unreference()` are explicit on *both* backends. We don't
lean on `st_nlink` as a free refcount even for the local backend,
because that free-lunch semantics diverges from S3's and would force a
second code path at migration time. Uniformity is worth the small cost.

**Two-tier maintenance.** Earlier drafts had a single `gc(grace_period)`
method, which conflated two genuinely different operations. The durable
tier (filesystem for `LocalHardlinkBlobStore`; the S3 bucket for the
future `S3BlobStore`) is the source of truth, mutated by one node only;
GC against it is global state mutation. The local cache tier — only
meaningful for backends like S3 that keep a per-node read cache over a
remote durable tier — is per-node state, evictable on every node
independently. The two operations have different node-scope semantics
and different inputs (a `grace_period` for durable GC; a `LocalCacheBudget`
of `max_age`/`max_bytes` for local eviction). Splitting them keeps the
contract honest: `maintain_global` mutates global state and runs on the
primary node only; `maintain_local` mutates per-node state and is safe to
run everywhere. The pure-local store treats the FS as the durable tier
and implements `maintain_global` as the real GC, with `maintain_local` as
a no-op (evicting would destroy the only copy).

#### Backend selection via `BlobStoreSpec`

Concrete backend selection is operator-configurable via Pydantic. The
`AnalysisCacheConfig.blob_store` field accepts an optional `BlobStoreSpec`
with three keys — `python_module`, `python_class`, and a backend-specific
`config` dict. `get_blob_store()` dynamically imports the class, validates
`config` against the class's `get_config_class()` Pydantic model (mirroring
the `AnalysisModule.get_config_class()` pattern), and instantiates it.
When the field is unset, the default is `LocalHardlinkBlobStore` rooted at
`analysis_cache.blob_store_dir` (which itself defaults to
`<data_dir>/blob_store`).

```yaml
# default (no spec) — local hardlink store, current Phase 2 deployment
analysis_cache:
  blob_store_dir: null   # resolves to <data_dir>/blob_store

# S3 backend (example downstream integration) — pure config switch, no core code change
analysis_cache:
  blob_store:
    python_module: your_integration.s3_blob_store
    python_class: S3BlobStore
    config:
      s3_bucket: env:ACE_ANALYSIS_CACHE_S3_BUCKET
      s3_region: env:AWS_REGION
      enable_s3_gc: false              # prefer S3 bucket lifecycle policies
      verify_s3_before_evict: false    # skip per-eviction head_object (saves $)
```

This is what the original §A7 "factor blob storage behind an interface"
line implied without spelling out — the configuration plumbing that makes
the migration a config edit instead of a code change.

#### Multi-node safety

`LocalHardlinkBlobStore` is unsafe for multi-node ACE3 clusters because
its spilled blobs live on the writing node's local filesystem and are
invisible to other nodes. A cache row written on node A with a spilled
`details` blob would miss on node B's read attempt even though the cache
row itself is in the shared database. To make this hard to deploy by
accident, `warn_if_blob_store_not_multi_node_safe()` runs at engine
startup: when the `nodes` table has more than one row and no pluggable
backend is configured, it emits a WARNING pointing operators at
`analysis_cache.blob_store`. Multi-node deployments need a global backend
(S3 once available, or a shared-filesystem backend if a deployment is
willing to maintain one).

#### Reference-counting table (both backends)

```
blob_refs (
    sha256           VARCHAR(64)   NOT NULL,
    referrer_kind    VARCHAR(32)   NOT NULL,   -- 'cache_row' | 'alert' | 'analysis_details'
    referrer_id      VARCHAR(128)  NOT NULL,
    created_at       DATETIME(6)   NOT NULL,   -- partition column (PR #279)
    PRIMARY KEY (sha256, referrer_kind, referrer_id, created_at),
    KEY idx_by_referrer (referrer_kind, referrer_id)
)
-- lives in the analysis-result-cache database; partitioned daily on created_at
```

(Per PR #279 `blob_refs` lives in the dedicated `analysis-result-cache`
database alongside `analysis_result_cache` and is partitioned the same way, so
`created_at` is part of its primary key too. The same daily partition-drop job
reclaims it — see §A8.)

- On cache-row insert: one `blob_refs` row per blob the delta references.
- On cache-row expire/delete: delete matching rows.
- On alert delete: delete rows for `('alert', alert_uuid)`.
- GC: `SELECT sha FROM blobs WHERE NOT EXISTS (SELECT 1 FROM blob_refs WHERE sha256 = blobs.sha) AND created_at < NOW() - grace_period` → delete from the backend.

Backends:

- **`LocalHardlinkBlobStore`** (Phase 2 default): stores bytes at
  `data/blob_store/<abc>/<def...>` (3-char shard to match
  `storage_dir_from_uuid`), uses the `blob_refs` table above.
  `maintain_global()` walks the shard tree, batches sha256s through a
  `blob_refs` lookup, and `unlink()`s orphans whose mtime is older than
  the grace period. `maintain_local()` is a no-op — the local FS *is*
  the durable tier. `materialize()` hardlinks into the target path when
  same-FS, falls back to copy otherwise.
- **`S3BlobStore`** (a backend a downstream integration can implement via the
  `BlobStoreSpec` mechanism above — sketched here as the canonical example of a
  remote durable tier): stores bytes at `s3://<bucket>/<sha256>`
  with no path-shard prefix (S3 already partitions internally; the local
  cache tier preserves the 3-char shard layout). Wraps a
  `LocalHardlinkBlobStore` as a per-node **write-through / read-through
  cache** — so a blob spilled by one worker survives a `maintain_local`
  eviction by re-downloading from S3 on the next read, and conversely a
  blob still being uploaded to S3 stays available locally during the
  upload window.
  - `put()` writes the bytes through the local cache first, then issues
    `head_object` + `upload_file` to S3. Uploads are **fail-soft**: a
    transient S3 outage logs a warning but doesn't fail the cache write,
    because the bytes are already in the local cache and the
    `_LOCAL_EVICT_MIN_AGE_SECONDS` floor (5 minutes) keeps
    `maintain_local` from evicting them out from under an in-flight
    upload.
  - `get()` / `materialize()` check the local cache first; on miss,
    `download_file` from S3 into a tempfile, then `put()` it through the
    local cache (re-hashing in the process — catches a corrupted S3
    transfer).
  - `reference()` / `unreference()` delegate to the embedded local
    store, but those operations are pure DB writes against `blob_refs`
    and are backend-independent anyway.
  - `maintain_global()` is **opt-in** via `enable_s3_gc` and **defaults
    off**, deferring object lifetime to an S3 **bucket lifecycle
    policy** on the blob-key prefix. The opt-in path paginates the
    entire bucket via `list_objects_v2`, batches sha256s through
    `blob_refs`, and `delete_objects` orphans older than the grace
    period — costs money (LIST + DELETE are metered) and scales with
    bucket size, so the default of "let lifecycle policies handle it"
    is the recommended posture.
  - `maintain_local()` evicts entries from the per-node cache tier by
    the configured `LocalCacheBudget(max_age, max_bytes)`, oldest-mtime
    first when over the size budget. Blobs younger than
    `_LOCAL_EVICT_MIN_AGE_SECONDS` (5 min) are always retained to
    protect in-flight uploads. Opt-in `verify_s3_before_evict` issues a
    `head_object` per candidate to confirm the durable copy exists in
    S3 — costs money, leave off unless paranoid.
  - `materialize()` ensures the blob is in the local cache (downloading
    from S3 on miss), then delegates to `LocalHardlinkBlobStore.materialize`
    for the hardlink-into-place.

This shape — local cache as durability buffer plus read coalescer — is
slightly richer than the pure "read cache over remote durable tier"
that §A7 originally implied. The two-tier maintenance contract still
holds (`maintain_global` is primary-only / mutates global state;
`maintain_local` is per-node), but the local tier additionally serves
as the fail-soft staging area for writes.

Migration then becomes a single config switch plus a one-time backfill
script (walk local `data/blob_store/`, upload to S3, leave the
`blob_refs` rows untouched).

#### Alert storage dirs on S3

Today every alert has a `storage_dir` on local disk containing
`root.json` plus file observable payloads. After S3 migration the
storage dir becomes an S3 prefix like `s3://ace3-data/alerts/<uuid>/`.
Two design choices, and the caching design strongly favors one:

- **Duplicate bytes per alert.** Each alert stores its own copy of
  every file observable under its prefix. Simple; transparent to legacy
  code that does `open(path)`. Storage cost scales with (alerts ×
  observable size). No dedup. *Not the right choice.*
- **Alert prefix holds manifests; file observable payloads live only
  in the blob store.** Each alert's prefix contains `root.json` and
  small per-alert metadata. Every file observable is a pointer
  (`{sha256, filename, mime, size}`). Consumers that need bytes call
  `blob_store.get(sha256)` or `blob_store.materialize(sha256, tmp_path)`.
  Storage cost scales with (unique file content), not (alerts ×
  observables). Natural dedup across alerts and across cache hits.

The second choice is what makes the caching design pay off in S3. It
does require a shim in ACE3's file I/O layer — `FileObservable.path`
becomes a lazy property that calls `materialize()` on first access,
downloading from S3 to `/tmp` on demand. Modules that iterate over
bytes transparently work; modules that pass `path` to subprocesses
(yara, clamav) also work because the materialized path is real.

Worth doing this shim *before* the S3 migration, as part of Phase 2,
even while the backend is still local — that way we shake out modules
that assume a specific path layout while we still have a local FS to
fall back on. Phase 2 ships with `LocalHardlinkBlobStore` and every
file observable going through the shim; the S3 migration later swaps
only the backend.

#### Lambda execution model

The intended Lambda architecture is **one Lambda invocation per root
analysis**, not one per module. A single Lambda receives a
`RootAnalysis`, runs the full `AnalysisExecutor` loop internally
(all modules, all observables, full work-stack), and returns the
completed root. This is architecturally simpler and avoids per-module
invocation overhead.

This shapes the caching design in several important ways:

1. **Cache lookups happen inside the Lambda, not on the
   orchestrator.** The Lambda runs the same `_execute_module_analysis`
   code path that runs locally today — including the cache-hit
   short-circuit from Phase 3. When the executor encounters a
   (module, observable) pair with a cache hit, it skips that module's
   `analyze()` call and applies the cached delta. Same code, same
   logic, just executing inside a Lambda process.

   The orchestrator does not need to know about individual modules,
   cache keys, or deltas. It submits a root, gets back a completed
   root. All per-module caching intelligence lives in the executor,
   which is the same code in both environments.

2. **The Lambda needs DB and blob store access.** Since cache lookups
   happen inside the Lambda, it must reach MySQL (for
   `analysis_result_cache`) and the blob store (S3). This is a
   networking/IAM concern — Lambda in a VPC with RDS access is
   standard — not a design concern. But it does mean the Lambda is
   not a pure compute function; it has storage dependencies.

3. **Request/response shape is simple.** The orchestrator sends the
   serialized `RootAnalysis` (or an S3 reference to it). The Lambda
   returns the completed root plus a manifest of new blobs it
   uploaded to S3:

   ```
   request  = { root_analysis_ref }
   response = { completed_root, new_blob_sha256s: [...] }
   ```

   The Lambda uploads file observable payloads and spilled
   `analysis.details` blobs directly to S3 during execution. The
   orchestrator receives the finished root, persists it, and
   registers `blob_refs` for the new sha256s.

   Optionally the Lambda can also return the full list of
   `ModuleExecutionDelta` objects it recorded, so the orchestrator
   can persist them in `root.json` for attribution — or the
   completed root already contains `_module_executions` from
   Phase 1.

4. **The caching payoff changes shape.** A cache hit inside the
   Lambda avoids one `module.analyze()` call — the same CPU/time
   savings as local execution. You still pay for the Lambda
   invocation itself. The savings are in module execution time
   (which can be huge: sandbox detonation, LLM inference, yara on
   large binaries), not in Lambda startup. This is still very much
   worth doing — the expensive modules are why caching exists.

   Contrast with a per-module-Lambda model (not our plan) where a
   cache hit would avoid an entire invocation including cold start
   and network round-trip. Our whole-root model doesn't get that
   benefit, but it avoids the complexity of orchestrating hundreds
   of per-module Lambda calls with dependency ordering, which is a
   worthwhile trade.

5. **`BlobStore.materialize()` and `/tmp` budget.** When a module
   inside the Lambda needs a file observable, `materialize()`
   downloads from S3 to `/tmp`. On a cache hit that references
   file blobs, the replay path may also need to materialize if
   downstream modules in the *same invocation* need those files.
   Lambda `/tmp` is up to 10 GiB, which should be fine for
   typical alert sizes but could be tight for roots with many
   large file observables (multi-GB PCAPs, sample collections).
   Mitigation: stream through `/tmp` and clean up between modules;
   or flag roots with estimated total file size > threshold for
   local (non-Lambda) execution.

6. **Cache-hit correctness.** The cacheability contract (§A1)
   remains load-bearing: if a module's output depends on the
   Lambda runtime environment (wall-clock time, cold-start state,
   random seed), caching replays stale results. The CI-time lint
   fixture from §A4 should run against the Lambda packaging
   pipeline too.

#### Summary: what the main design changes to accommodate S3/Lambda

- **Phase 2 gains a `BlobStore` interface** with `LocalHardlinkBlobStore`
  as initial implementation. File observable I/O routes through the
  interface via a `materialize()` shim on `FileObservable.path`.
- **Phase 2 adds the `blob_refs` table**, used by the local backend
  from day one. No free `st_nlink` refcount — explicit everywhere.
- **Phase 3 cache logic calls `blob_store.reference()` /
  `blob_store.unreference()`** around cache-row lifecycle instead of
  relying on filesystem link counts.
- **Phase 3 cache lookup path is backend-agnostic** — same code
  whether the blob store is local or S3.
- **S3 backend** (the canonical pluggable backend for `analysis.details`
  spill): an `S3BlobStore` implemented in a downstream integration wires
  through the `BlobStoreSpec` mechanism (§A7 "Backend selection") with no edits
  to core ACE3. It runs the local hardlink store as a per-node write-through /
  read-through cache in front of S3 and defers durable-tier object lifetime to
  an S3 bucket lifecycle policy by default. Alert `storage_dir` migration to S3
  prefixes and the file observable shim are still future work — none of which
  requires changes to the delta format, the cache schema, or the replay logic.
- **Post-Lambda migration** (also out of scope): cache lookup stays
  on the orchestrator; Lambda returns deltas rather than mutated
  roots; same `ModuleExecutionDelta` serialization flows end-to-end.

The forward-compatibility cost paid up front is: (a) write the
`BlobStore` interface and the `blob_refs` table in Phase 2 instead of
relying on hardlinks, and (b) route file observable I/O through a
materialization shim. Both are modest. The alternative — shipping a
hardlink-native Phase 2 and rewriting it later — would mean redoing
the GC story, the cache-row lifecycle, and potentially the delta
schema after the migration lands. Worth eating the small cost now.

### A8. Expiring cache rows: mechanism and scheduling

> **Rewritten for PR #279 (merged 2026-05-27).** The original mechanism — a
> batched `DELETE ... WHERE expires_at < NOW()` sweep run every 5 minutes by
> cron — was replaced by **dropping whole daily partitions**. Phase 2 shipped
> with the delete-sweep design described in earlier drafts of this section
> (`prune()` / `prune_analysis_result_cache`, `prune_batch_size`,
> `bin/analysis-cache-prune`); PR #279 removed all of it. The reason: at the
> intended billion-row scale a `DELETE` sweep is both slow (row-by-row, undo
> log pressure, replication lag) and never quite caught up. Dropping a
> partition is a near-instant DDL metadata operation that reclaims a whole
> day of expired rows at once. The text below describes the partition design.

The §4 schema introduced `expires_at DATETIME`, but *what reclaims expired
rows* is no longer a `DELETE`. The `analysis_result_cache` and `blob_refs`
tables are **partitioned by `RANGE COLUMNS(created_at)`, one partition per
day** (`pYYYYMMDD`), with a `p_catchall VALUES LESS THAN (MAXVALUE)` partition
so a row whose day-partition doesn't exist yet still lands somewhere. Expiry
is reclaimed by dropping the partitions whose day has aged past the retention
window.

#### Mechanism: daily partition maintenance + read-time safety check

**Primary — partition maintenance via cron.** A single shell script,
`bin/manage-analysis-result-cache-partitions.sh`, runs **daily at 04:00**
(`etc/cron.yaml`, `concurrencyPolicy: Forbid`). Each run, for both
`analysis_result_cache` and `blob_refs`:

1. **Drops** partitions older than `analysis_cache.partition_retention_days`
   (default 35). Dropping `pYYYYMMDD` for an aged day reclaims every cache
   row created that day in one metadata operation — no row scan, no undo log.
2. **Reorganizes the catchall** — splits any rows that landed in `p_catchall`
   (because their day-partition hadn't been provisioned yet) out into the
   correct daily partitions, by reading the catchall's `created_at` range and
   `REORGANIZE PARTITION p_catchall INTO (...)`.
3. **Provisions ahead** — ensures partitions exist for today and the next 7
   days, so incoming inserts always have a real partition to land in and a
   missed cron run doesn't dump a backlog into the catchall.

The script reads `partition_retention_days` from `ace config` and **refuses to
run with a window `< 31`**. The retention window MUST exceed the longest module
`cache_ttl` (currently 30 days) — otherwise dropping a partition could delete
cache rows still inside their TTL. This invariant replaces the old "the sweep
deletes exactly the rows past `expires_at`" guarantee: a row now physically
outlives its `expires_at`, getting dropped only when its whole day-partition
ages out — i.e. up to `partition_retention_days - ttl_days` days *after*
expiry. The read-time filter (below) makes that lingering invisible to callers
(they never see an expired row), and the retention-vs-ttl invariant guarantees
a partition drop never reclaims a row that is still live.

**Secondary — read-time check.** On cache read, the SELECT still filters with
`WHERE cache_key = ? AND expires_at > NOW()` and takes the most recently
created match (`ORDER BY created_at DESC LIMIT 1` since 2026-06-10 — the
original `expires_at DESC` ordering preferred the longest-lived row, which
after a `cache_ttl` reduction is the *oldest* data; the clustered PK
`(cache_key, created_at)` serves the new ordering in index order). This is
what makes the coarse,
once-a-day partition granularity correct: a row that has passed `expires_at`
but whose partition hasn't been dropped yet is simply never returned. Expiry
precision is owned by the read filter; the partition drop only reclaims space.

Because reclamation is a partition drop rather than a `DELETE`, there is no
`prune()` function, no `prune_batch_size`, no `FOR UPDATE SKIP LOCKED`
batching, and no `delete_for_module()` — all of which the original design
needed and PR #279 deleted. A `cache_ttl` reduction or a rules-file change is
handled entirely by the cache *key* changing (§A5) plus TTL/partition aging;
there is no targeted delete path.

#### `blob_refs` reclamation rides the same partitions

`blob_refs` is partitioned and dropped on the same daily schedule and the same
retention window. Dropping a `blob_refs` partition removes the reference rows
for cache entries created that day. This is safe because the downstream blob
GC (next subsection) is grace-period gated: a blob whose only ref was just
dropped is not deleted until it has been unreferenced for `blob_gc_grace_seconds`.
Note the original design coupled cache-row and `blob_refs` deletion in one
transaction; with partition drops they are instead coupled by both tables
sharing the same daily partition boundaries and retention window.

#### Blob GC is a separate, downstream sweep

Partition drops reclaim *references* (the `blob_refs` rows). Blob bytes are
deleted by a different sweep that walks blobs with zero refs older than a grace
period — this is what `BlobStore.maintain_global(grace_period, dry_run)`
implements (§A7). For `LocalHardlinkBlobStore` it walks the shard tree
via `iter_blobs()`, batches sha256s through a `blob_refs` lookup, and
`unlink()`s orphans whose mtime is older than the grace period. The
grace period defaults to 24h (`analysis_cache.blob_gc_grace_seconds`),
generously sized so that a blob transiently at zero refs — because a
cache row was just deleted but a new alert is about to reference the
same sha — isn't prematurely GC'd.

Recommended cron cadence:

| Job | Schedule | Purpose | Node scope |
|-----|----------|---------|------------|
| `analysis cache partition maintenance` (`bin/manage-analysis-result-cache-partitions.sh`) | `0 4 * * *` | Drop partitions older than `partition_retention_days`, reorganize the catchall, provision the next 7 days | single node (shared-DB DDL; the bash script has no `is_primary_node()` gate of its own, so deploy it on one node) |
| `analysis-cache-stats` | `*/15 * * * *` | Emit the `cache_stats` heartbeat from `INFORMATION_SCHEMA.PARTITIONS` (calls `emit_cache_stats`, which gates on `is_primary_node()`) | primary only |
| `analysis-cache-gc` | `0 * * * *` | Delete blob bytes with zero refs older than `blob_gc_grace_seconds` (calls `blob_store.maintain_global`) | primary only |
| `analysis-cache-local-maintenance` | `*/15 * * * *` | Evict stale/excess blobs from this node's local cache tier (calls `blob_store.maintain_local`; no-op for `LocalHardlinkBlobStore`) | every node |

(PR #279 replaced the `*/5` `analysis-cache-prune` delete sweep with the daily
`analysis cache partition maintenance` job, and moved the `cache_stats`
heartbeat — which used to piggyback on the prune run — onto its own 15-minute
`analysis-cache-stats` job.)

The Python-backed global jobs (`analysis-cache-stats`, `analysis-cache-gc`)
check `is_primary_node()` at the top and log-and-exit on non-primary nodes.
The partition-maintenance bash script has no such gate — it issues DDL against
the shared cache database, so it must be deployed to run on a single node
(`concurrencyPolicy: Forbid` only prevents overlapping runs on the *same*
node). The local maintenance job runs everywhere — its target is per-node
state.

Not currently scheduled: a separate `prune_orphaned_blob_refs`
reconciliation sweep. With partition drops, `blob_refs` rows and the cache
rows they describe age out on the same daily boundaries and retention window,
so there's no path that produces `blob_refs` rows pointing at nonexistent
cache rows. If reconciliation drift is ever observed in production, that sweep
can be added later — but it isn't load-bearing.

#### Observability

The partition-maintenance script logs each drop / reorganize / create at INFO.
Cache population is tracked by the separate `cache_stats` heartbeat (see §4 /
Part II), which reads per-partition InnoDB statistics
from `INFORMATION_SCHEMA.PARTITIONS` rather than `COUNT(*)`:

```
cache_stats total_rows=... total_on_disk_bytes=... blob_refs_rows=...
blob_gc blobs_scanned=... blobs_deleted=... bytes_reclaimed=... ...
```

`COUNT(*)`/`SUM(...)` health gauges were dropped in PR #279 — at billion-row
scale they scan the whole table or index, while the statistics lookup is
O(partitions). `total_rows` and `total_on_disk_bytes` are therefore *estimates*
(InnoDB statistics can drift ~10%), which is fine for a 15-minute heartbeat.
The old "expired rows unpruned" backlog gauge no longer applies — there is no
sweep to fall behind; instead alert on the partition-maintenance cron failing
to run (a dropped partition is the only thing reclaiming space).

#### Edge cases worth explicitly handling

1. **Module `cache_ttl` reduced after entries written.** Existing rows keep
   their original `expires_at`; we do not backfill. They stop being returned
   the moment `NOW()` passes `expires_at` (read-time filter), and their space
   is reclaimed when their daily partition is dropped. There is no targeted
   per-module delete; immediate eviction is not supported (and rarely needed,
   since the cache key already changes on a version/rules bump — §A5).

2. **Module removed from config.** Cache rows for the removed module are never
   looked up again (no module generates the key) and age out with their
   partition. No startup scan needed.

3. **Clock skew between app server and DB.** `expires_at` is compared against
   `NOW()` in MySQL, so the DB's clock is the single source of truth.
   Application-side clocks don't matter. At *write* time `expires_at` is
   computed DB-side (`DATE_ADD(NOW(), INTERVAL ? SECOND)`), avoiding
   Python-vs-DB drift. `created_at` (the partition column) likewise defaults
   to `CURRENT_TIMESTAMP(6)` on the DB.

4. **Partition-maintenance run missed or crashed.** The script provisions 7
   days of future partitions, so several missed runs are tolerated — inserts
   keep landing in real daily partitions. Rows that do land in `p_catchall`
   (e.g. all future partitions were consumed) are split back out into daily
   partitions by the next successful run's reorganize step. The only hard
   requirement is that `partition_retention_days` stay `> max(cache_ttl)`.

5. **Very high churn during a rules-file reload.** No longer a concern — there
   is no `delete_for_module()` mass-DELETE to batch. A rules change shifts the
   cache key (§A5); old entries simply stop being read and age out with their
   partition.

### A9. Single-flight dedup for concurrent analyses of the same observable

§open-question 5 acknowledged that two engines analyzing the same
observable simultaneously both write to the cache, and declared that
fine for DB integrity (originally via `INSERT ... ON DUPLICATE KEY UPDATE`;
since PR #279 via plain append-only inserts whose freshest non-expired row
wins at read time — see the revised §open-question 5). But it said nothing
about *work*: under that design,
both engines run the full analysis. In a thundering-herd scenario — an
attacker sends the same phishing URL to 10 users, all 10 alerts enter
the engine within seconds — all 10 workers cache-miss, all 10 crawl
the URL, and we burn 9× the phishkit capacity we needed. The cache is
written 10 times against one key and provides zero work savings for
the triggering batch (it only helps the 11th-and-later alerts).

This addendum expands the design to close that gap with a
**pending-marker** protocol: before a cacheable module runs, workers
race a claim on a dedicated coordination table. Exactly one worker
wins and does the work; the others **requeue themselves through the
engine's existing delayed-analysis machinery** and re-check the cache
when they resume.

> **Redesigned 2026-06-10 (still unimplemented).** The original draft of
> this addendum had deferred workers *block* in a sleep-poll loop
> (`wait_for_cache`) for up to `maximum_analysis_time`. That design is
> rejected — see "Why not blocking-wait?" below — in favor of the
> non-blocking requeue described here. Single-flight is also now a
> separate per-module opt-in (`single_flight: true`) rather than implied
> by `cache_ttl`: the claim/release adds two DB writes to every cache
> miss, which is pure overhead for cheap modules where concurrent
> duplication doesn't matter. Only expensive, herd-prone modules
> (phishkit-style crawlers, sandbox detonations) should opt in.

#### Schema

A new table `analysis_cache_pending` — intentionally separate from
`analysis_result_cache` so the hot path of completed entries stays
clean:

```
analysis_cache_pending (
    cache_key    VARCHAR(64)   PRIMARY KEY,
    module_name  VARCHAR(512)  NOT NULL,
    claimed_at   TIMESTAMP     NOT NULL,
    claimed_by   VARCHAR(128)  NOT NULL,    -- "<hostname>:<pid>"
    expires_at   DATETIME      NOT NULL,    -- claimed_at + maximum_analysis_time + buffer
    KEY idx_expires (expires_at)
)
```

Rationale for a separate table:

- The pending lifecycle is "born, briefly exists, deleted on success"
  — very different from cache entries' "born, updated, TTL-expires".
- Completed cache rows never carry a `pending` flag to filter past;
  SELECT on `analysis_result_cache` stays on the simple hot path.
- Stale-pending reaping is a cheap delete against a tiny table.

#### Executor flow (Phase 3.5, layered onto Phase 3's read path)

```python
# Phase 3: try cache read first
cached = get_cached_delta(observable, module)
if cached is not None:
    apply_delta(root, observable, cached)
    return  # cache hit

# Phase 3.5: claim-or-defer (modules with single_flight: true only)
claim_result = claim_pending(cache_key, module, worker_id)
if claim_result == "owned":
    try:
        analysis_module.analyze(...)
        # existing put_cached_delta runs after the delta is recorded
    finally:
        release_pending(cache_key)
elif claim_result == "deferred":
    # NON-BLOCKING: create the module's Analysis slot as a flagged
    # single-flight placeholder (delayed=True), register a delayed-
    # analysis request for a short interval, and RETURN — the worker
    # is free to do other work. No sleep, no poll loop.
    analysis = create_placeholder_analysis(observable, module)
    analysis.single_flight_deferred = True   # distinguishes from a real module delay
    delay_analysis(observable, analysis, seconds=RECHECK_INTERVAL_SECONDS)
    return AnalysisExecutionResult.INCOMPLETE
```

On resume (the delayed-analysis request fires, possibly on a different
worker or node), the executor — *not* the module, the placeholder has no
module logic to continue — runs the re-check:

```python
# resume path for a single_flight_deferred placeholder
cached = get_cached_delta(observable, module)
if cached is not None:
    remove_placeholder(observable, module)   # before apply_delta — the
    apply_delta(root, observable, cached)    # slot-collision skip would
    return                                   # otherwise keep the placeholder
if not pending_exists(cache_key):
    # owner finished without caching (refused delta) or crashed:
    # run live ourselves via execute_analysis() (NOT continue_analysis —
    # this module never started).
    remove_placeholder(observable, module)
    analysis_module.analyze(...)             # fresh run; populates cache
elif now() >= claim.expires_at:
    # owner exceeded its claim: treat as crashed, same as above
    remove_placeholder(observable, module)
    analysis_module.analyze(...)
else:
    # owner still working: re-delay until min(next interval, claim expiry)
    delay_analysis(observable, analysis, seconds=RECHECK_INTERVAL_SECONDS)
```

`RECHECK_INTERVAL_SECONDS` should be coarse (~30–60s): the deferred
alert's total latency only matters against the owner's multi-minute
module run, and each re-check costs one cache SELECT + one pending
SELECT. Open mechanics to resolve at implementation time:

- the acceptance-check carve-out — `_check_module_acceptance` skips
  delayed slots, so the resume path must recognize the
  `single_flight_deferred` flag and route to the re-check above instead
  of skipping (the existing `is_resuming_delayed_module` machinery is
  the model, but the *executor* owns this resume, not the module's
  `continue_analysis`);
- placeholder cleanup — `apply_delta`'s slot-collision skip would
  preserve the placeholder, so it must be removed before replay (or the
  rehydration taught to replace flagged placeholders);
- the placeholder must never be cached or counted as module output
  (it is `delayed=True` and empty, so the existing refusal gates already
  cover it — verify in tests).

#### Claim mechanics

```python
def claim_pending(cache_key, module, worker_id) -> "owned" | "deferred":
    stmt = mysql_insert(AnalysisCachePending).values(
        cache_key=cache_key,
        module_name=module.config.name,
        claimed_at=func.now(),
        claimed_by=worker_id,
        expires_at=func.date_add(
            func.now(),
            text("INTERVAL :sec SECOND").bindparams(
                sec=module.maximum_analysis_time + PENDING_BUFFER_SECONDS
            ),
        ),
    ).prefix_with('IGNORE')
    result = get_db().execute(stmt)
    get_db().commit()
    return "owned" if result.rowcount == 1 else "deferred"
```

The `INSERT IGNORE` + `rowcount` check is the atomic claim. No locks,
no transactions beyond the single insert, no risk of deadlock.

#### Why not blocking-wait?

The original draft had deferred workers sleep-poll until the owner
populated the cache (exponential backoff, timeout at
`maximum_analysis_time + buffer`). Rejected for three reasons:

1. **It burns the resource it's protecting.** In the motivating
   thundering-herd (10 identical phishing URLs, one multi-minute crawl),
   blocking-wait parks 9 engine workers in `time.sleep` loops for the
   crawl's full duration. Workers are precisely the scarce capacity the
   dedup exists to save — the design would trade 9 redundant crawls for
   9 idle workers, a wash at best.
2. **The wait counts against the root's analysis budget.** The executor's
   cumulative-time check (`_check_for_analysis_timeout`) sees wall time;
   a long blocked wait inside one module execution pushes otherwise-fast
   roots toward their analysis-mode timeout.
3. **The engine already has the right primitive.** Delayed analysis is
   purpose-built "come back later" machinery: persistent
   (`delayed_analysis` table), node-aware, resumable in another process,
   and already integrated with the work-stack and acceptance checks.
   A bespoke poll loop duplicates that infrastructure poorly.

#### Stale-pending reaping

> **Scheduling note (post PR #279).** This addendum predates PR #279, which
> removed the 5-minute `analysis-cache-prune` cron it originally proposed to
> piggyback on. `analysis_cache_pending` is a small, short-lived coordination
> table — it is NOT a partition candidate and still needs an actual `DELETE`
> reaper. When Phase 3.5 lands, attach `reap_stale_pending()` to a surviving
> frequent cron (e.g. `analysis-cache-stats`, which already runs every 15
> minutes on the primary node) or give it its own short-interval entry, rather
> than the deleted prune job.

`reap_stale_pending()` is a single `DELETE FROM analysis_cache_pending WHERE
expires_at < NOW()`:

```python
reaped = reap_stale_pending()  # DELETE FROM analysis_cache_pending WHERE expires_at < NOW()
if reaped > 0:
    logging.info("reaped %d stale analysis_cache_pending rows", reaped)
```

Stale entries come from crashed workers. Deferred workers already
handle the in-flight case themselves — the resume re-check treats a
missing or expired claim as "owner gone, run live" — so this sweep only
cleans up lingering rows that no deferred work item will ever revisit.

#### Worker identity

`claimed_by = f"{socket.gethostname()}:{os.getpid()}"` is enough.
Useful in Splunk for post-mortem ("which worker held URL X for too
long before crashing"). If we later adopt async workers or finer
worker tracking, this field can carry richer identifiers.

#### Observability

Three new Splunk log lines:

- `cache_claim result=owned|deferred cache_key=… module=… observable_type=…`
  — who won the race.
- `cache_defer_resume cache_key=… module=… deferred_ms=… recheck_count=…
  result=hit|owner_gone_ran_live|claim_expired_ran_live|redeferred`
  — emitted on each resume re-check; `deferred_ms` is time since the
  original claim race, `recheck_count` the number of re-delays so far.
- `stale_pending_reaped rows=N` — cron sweep count.

Splunk queries worth having:

```
# thundering-herd reduction ratio — ideally approaches (owners / total)
index=<ace_index> "cache_claim"
  | stats count by result module
# → if result=owned is 1 and result=deferred is 9 on the same cache_key
# within a few seconds, single-flight is working

# deferred-resolution latency and outcome mix per module
index=<ace_index> "cache_defer_resume" result!=redeferred
  | stats perc50(deferred_ms), perc99(deferred_ms), max(deferred_ms),
          count by module, result

# workers that abandoned claims (crash diagnostic)
index=<ace_index> "stale_pending_reaped" | timechart max(rows)
```

#### Interaction with the cacheability contract

Single-flight runs only for modules with `single_flight: true`, which
itself requires `cache_ttl` (config validator: `single_flight` without
`cache_ttl` is rejected — the protocol's whole resolution path is the
cache). Wide-diff modules, file-emitting modules, and anything else
currently uncacheable remain unaffected — they always run, as today.
This keeps the dedup surface aligned with the contract from §A1.

#### Why not a network semaphore?

`NetworkSemaphore` already exists in ACE3 and could be extended to
take a per-observable key. Rejected because:

1. Semaphores are process-coordination primitives. The claim table
   lives in MySQL alongside the cache it coordinates with — one
   source of truth, no split-brain between the semaphore server and
   the DB.
2. The semaphore server is a single process and a single point of
   failure. The claim table inherits MySQL's HA story.
3. Pending rows give us audit data (who claimed what, when) for free.

#### Why not a "processing" flag on the cache row itself?

Tempting but mixes two very different lifecycles (pending: short-lived,
coordinate-only; complete: long-lived, serve reads) into one table.
SELECT on `analysis_result_cache` then has to filter out pending rows;
upsert semantics get awkward. The separation above costs one small
table and pays off in conceptual clarity.

---

## Why this shape and not alternatives

**Why not instrument `add_tag` / `add_observable` / `add_detection_point`
directly?** Because modules can mutate the same objects in many ways
(setattr on `analysis.details`, direct list append in ad-hoc code,
iteration patterns that touch multiple observables). Wrapping the
mutation API would require changing every caller and still miss
`details` dict edits. Snapshot + diff at the module boundary is
coarser but complete.

**Why not clone the full root before each module?** Cost. The target
observable + a handful of fields is O(1) in observable count; full root
clone is O(tree size) and modules run in the hundreds per alert.

**Why store deltas instead of before/after snapshots (ace2-core style)?**
Two reasons. First, ACE3 has no analysis-request messaging layer where
before/after roots naturally live — grafting one on would be a much
bigger lift. Second, storing the delta directly makes replay a simple
"apply additive changes" pass instead of `apply_diff_merge`'s
set-difference logic, which is error-prone at the boundary between
old and new observables. We keep the ace2-core mental model (modules
produce attributable deltas that can be replayed) while trading the
symmetric-diff representation for an asymmetric additive one that
fits ACE3's in-place mutation model.

---

# Part II — Implementation & progress

This part is the build log for the design in Part I: ordered implementation
steps per phase, validation gates, bake-in results, and dated implementation
notes (with PR references) recording deviations and what actually shipped. Phase
1 was built first as a record-only foundation; each later phase depends on the
preceding phase's bake-in results.

## Phase 1: Record Deltas (no cache, no behavior change)

### Step 1.1 — Data structures (`saq/analysis/module_execution_delta.py`, new)

Create the core dataclasses that represent a module's contribution:

- **`ObservableDiff`** — captures added/removed items per mutable field on the
  target observable:
  - `added_tags: list[str]`, `removed_tags: list[str]`
  - `added_detections: list[dict]`, `removed_detections: list[dict]`
    (serialized `DetectionPoint`)
  - `added_directives: list[str]`, `removed_directives: list[str]`
  - `added_relationships: list[dict]`, `removed_relationships: list[dict]`
    (serialized `Relationship`)
  - `added_excluded_analysis: list[str]`, `removed_excluded_analysis: list[str]`
  - `added_limited_analysis: list[str]`, `removed_limited_analysis: list[str]`
  - Scalar transitions: `grouping_target: tuple[bool, bool] | None`,
    `redirection: tuple[str|None, str|None] | None`,
    `ignored: tuple[bool, bool] | None`

- **`ObservableSpec`** — enough to re-add an observable on replay:
  - `uuid: str`, `type: str`, `value: str`, `time: str | None` (ISO)
  - `initial_tags: list[str]`, `initial_directives: list[str]`,
    `initial_detections: list[dict]`,
    `initial_excluded_analysis: list[str]`, `initial_limited_analysis: list[str]`

- **`RootDiff`** — root-level changes:
  - `added_tags: list[str]`, `removed_tags: list[str]`
  - `added_detections: list[dict]`, `removed_detections: list[dict]`

- **`ModuleExecutionDelta`** — the top-level record:
  - `module_path: str`, `module_instance: str | None`, `module_version: int`
  - `observable_uuid: str`, `observable_type: str`, `observable_value: str`
  - `created_at: datetime`, `execution_time_ms: int`
  - `analysis: dict | None` (serialized Analysis object)
  - `target_observable_diff: ObservableDiff`
  - `new_observables: list[ObservableSpec]`
  - `root_diff: RootDiff`
  - `cache_key: str | None` (always None in Phase 1)
  - `wide_diff: bool` (False for most modules)
  - JSON serialization via `to_dict()` / `from_dict()` classmethods

**Key codebase references:**
- Observable mutable fields: `saq/analysis/observable.py:49-61`
- Tags/detections on BaseNode: `saq/analysis/base_node.py:25-26`
- Relationship structure: `saq/analysis/relationship.py:7-58`

**Validation gate:** Unit tests for serialization round-trip (`to_dict` →
`from_dict` produces equal object). No integration needed yet.

---

### Step 1.2 — Snapshot capture (`saq/analysis/snapshot.py`, new)

Create `ModuleExecutionSnapshot` with two factory methods:

- **`narrow(root, observable, module)`** — captures:
  - Target observable: `set(tags)`, `set(detections)`, `set(directives)`,
    `set(relationships)`, `set(excluded_analysis)`, `set(limited_analysis)`,
    `grouping_target`, `redirection`, `ignored`, `set(analysis keys)`
  - Root: `set(observable uuids)`, `set(root.tags)`, `set(root.detections)`

- **`wide(root, module)`** — captures all of the above for *every* observable
  in the root. Used when module has `wide_diff = True`.

- **`ModuleExecutionSnapshot.diff(before, after, module, observable) ->
  ModuleExecutionDelta`** — computes the delta by set-differencing before/after
  snapshots.

**Implementation details:**
- Observable tags are `list[str]` (`base_node.py:25`), convert to `set` for
  diffing
- Detections are `list[DetectionPoint]` — need a stable identity for diffing
  (use `description` + `details` tuple)
- Relationships are `list[Relationship]` — identity is `(r_type, target_uuid)`
- `root.all_observables` comes from
  `root.analysis_tree_manager.all_observables` (`root.py:752-754`)
- New observables = `after_observable_uuids - before_observable_uuids`
- For each new observable, build an `ObservableSpec` from the observable's
  current state
- Analysis object: if module's analysis exists in `observable._analysis` after
  but not before, capture its serialized form

**Validation gate:** Unit tests that construct a RootAnalysis, take a snapshot,
mutate it (add tag, add observable, add detection, add directive, add
relationship), take another snapshot, diff, and assert the delta captures
exactly the mutations made. Also test "module does nothing" (delta with
all-empty diffs).

---

### Step 1.3 — Wire into RootAnalysis (`saq/analysis/root.py`)

- Add `self._module_executions: list[ModuleExecutionDelta] = []` to
  `RootAnalysis.__init__` (after line 82)
- Add method `record_module_execution(self, delta: ModuleExecutionDelta)` that
  appends to the list
- Add property `module_executions` returning the list (read-only access)

**Validation gate:** Trivial — covered by step 1.4 serialization tests.

---

### Step 1.4 — Serialization support (`saq/analysis/serialize/root_serializer.py`)

- Add `KEY_MODULE_EXECUTIONS = "module_executions"` constant
- In `serialize()` (around line 80): add
  `KEY_MODULE_EXECUTIONS: [d.to_dict() for d in root._module_executions]`
- In `deserialize()` (around line 143): load module executions from dict,
  reconstructing via `ModuleExecutionDelta.from_dict()`

**Key codebase references:**
- Serialization: `root_serializer.py:47-82` (serialize), `85-144` (deserialize)
- The serializer builds a dict and writes it to `root.json` via `save_to_disk`
  (`root_serializer.py:149-173`)

**Validation gate:** Round-trip test: create RootAnalysis with
module_executions populated, serialize to dict, deserialize, assert
module_executions match. Also test backward compatibility: deserialize a root
dict that has no `module_executions` key (should default to empty list).

---

### Step 1.5 — Executor integration (`saq/engine/executor.py`)

Wrap the `analyze()` call in `_execute_module_analysis` (lines 1092-1100) with
snapshot/diff. Structure:

```python
snapshot_before = ModuleExecutionSnapshot.narrow(
    root, work_item.observable, analysis_module
)
module_start_time_ns = time.monotonic_ns()
try:
    # existing analyze call (with or without semaphore)
    analysis_result = analysis_module.analyze(...)
except (WaitForAnalysisException, AnalysisFailedException, Exception):
    raise  # re-raise, no delta recorded
else:
    # only on success
    snapshot_after = ModuleExecutionSnapshot.narrow(
        root, work_item.observable, analysis_module
    )
    delta = ModuleExecutionSnapshot.diff(
        snapshot_before, snapshot_after, analysis_module, work_item.observable
    )
    delta.execution_time_ms = (
        (time.monotonic_ns() - module_start_time_ns) // 1_000_000
    )
    root.record_module_execution(delta)

# existing root.save() now includes the delta in root.json
```

**Exception handling:**
- `WaitForAnalysisException` (line 1130): module incomplete — do NOT record
- Generic exceptions (line 1178): module failed — do NOT record
- The `finally` block (lines 1107-1112) is for monitor cleanup, not deltas

**Semaphore handling:** The snapshot must wrap the analyze call regardless of
whether the semaphore path is taken (lines 1092-1100). Restructure so snapshot
logic sits outside the semaphore branch.

**Removal logging (§A4):** If a delta has non-empty `removed_*`
fields, log at INFO with the module name. This is Phase 1's census of
non-additive modules.

**Validation gate:** Unit test with a mock AnalysisModule that adds known
mutations, verify the recorded delta. Integration test later.

---

### Step 1.6 — Wide-diff support for ObservableModifier

- Add `wide_diff: bool = False` to `AnalysisModuleConfig`
  (`saq/modules/config.py`, after `version` field around line 33)
- In executor wrapping (step 1.5), check `analysis_module.config.wide_diff` to
  choose `narrow()` vs `wide()` snapshot
- ObservableModifier's config should set `wide_diff: True`

**Validation gate:** Unit test with a mock wide-diff module that mutates a
*different* observable than the one being analyzed, verify the delta captures
the cross-observable mutation.

---

### Step 1.7 — Tests

**New test files:**
- `tests/saq/analysis/test_module_execution_delta.py` — dataclass serialization
- `tests/saq/analysis/test_snapshot.py` — snapshot capture and diff computation
- `tests/saq/analysis/test_root_delta_serialization.py` — root serialization
  with deltas, backward compat
- `tests/saq/engine/test_executor_delta_recording.py` — executor integration
  with mock modules

**Test scenarios:**

| # | Scenario | Asserted field |
|---|----------|---------------|
| 1 | Module adds a tag to the target observable | `added_tags` |
| 2 | Module adds a child observable | `new_observables` |
| 3 | Module adds a detection point | `added_detections` |
| 4 | Module adds a directive | `added_directives` |
| 5 | Module adds a relationship | `added_relationships` |
| 6 | Module does nothing | all diffs empty |
| 7 | Module raises exception | no delta recorded |
| 8 | Module raises `WaitForAnalysisException` | no delta recorded |
| 9 | Wide-diff module mutates another observable | delta captures it |
| 10 | Root-level tag addition | `root_diff.added_tags` |
| 11 | Delta serialization round-trip through root.json | equality |

---

### Phase 1 Bake-in

**What to monitor in production (Splunk queries):**

- `"failed to record module execution delta"` — snapshot/diff errors
  caught by the safety net (should be zero)
- `"failed to capture pre-execution snapshot"` — pre-snapshot errors
  (should be zero)
- `"produced removals in delta"` — census of non-additive modules

**Dev validation results (2026-04-10):**

1. **Correctness** — Verified on PDF, QR-phish, and DD-escalation alerts.
   Tag additions, new observables, directives, detection points, ignore
   actions all attributed correctly.
2. **Size impact** — 29% overhead on a heavy PDF alert (4,057 module runs).
   Most overhead is analysis-object-only deltas (modules that produce an
   Analysis but no other tree mutations). Acceptable — these are needed
   for Phase 2+ cache replay.
3. **Removal census** — No unexpected removals. ObservableModifier's ignore
   action correctly captured via `analysis_children_diffs`.
4. **Performance** — No subjective slowdown observed. Snapshot overhead is
   negligible relative to module execution time.
5. **Backward compat** — Existing alerts without `module_executions` key
   load normally in the GUI.

**Confidence criteria to proceed to Phase 2:**

- [x] Deltas correctly attribute known module behaviors (spot-checked 4 alerts)
- [x] No modules produce surprising removals
- [x] No measurable analysis throughput regression
- [x] 47 unit tests pass, 0 regressions in existing 140 analysis tests
- [ ] No `"failed to record"` warnings in production logs (monitoring)
- [ ] Bake-in period in production complete

### Implementation deviations from original plan

Four deviations — the `AnalysisChildrenDiff` addition, the
`AnalysisModuleAdapter` `version` property, the failure-safe executor
wrapping, and the empty-delta recording filter — are detailed in the **Phase 1
implementation notes** immediately below. One more is worth recording here:

**Deferred: executor integration test.** The plan called for
`tests/saq/engine/test_executor_delta_recording.py` but this requires
mocking the full executor context. Core logic is well-tested through
snapshot and serialization tests. Can be added later if needed.

---

## Phase 1 implementation notes

Lessons learned during Phase 1 implementation (2026-04-10) that affect
the design and future phases:

### AnalysisModuleAdapter

The executor passes `AnalysisModuleAdapter` objects, not raw
`AnalysisModule` instances. The adapter (`saq/modules/adapter.py`)
implements `AnalysisModuleInterface` but didn't delegate all properties
from the underlying module. We had to add a `version` property to the
adapter. **Phase 2 will need to verify that any new properties added to
`AnalysisModule` (e.g., `cache_ttl`, `extended_version`) are also
exposed on the adapter.**

### Snapshot/diff must be failure-safe

If the snapshot or diff code throws an exception between `module.analyze()`
and `root.save()`, the module's analysis results are lost and the GUI
doesn't show incremental updates. The executor wrapping uses try/except
around both the pre-snapshot and the post-snapshot/diff so that failures
are logged as warnings but never block `root.save()`. Phase 2 cache
writes should follow the same pattern — a cache write failure must not
prevent the analysis from being saved.

### Empty deltas filtered at recording time

Most module executions (~86% in a typical PDF alert) produce no tree
mutations — the module runs and either finds nothing or only creates
its own Analysis object. Recording all of these inflated `data.json` by
73%. The executor now skips recording deltas where `delta.is_empty` is
True. The `is_empty` check intentionally *includes* the `analysis` dict:
a module that only creates an Analysis object (no tags, observables, or
other mutations) is still recorded, because Phase 2+ cache replay needs
the analysis dict to reconstruct the module's output on cache hit. This
means ~29% size overhead on heavy alerts, which is acceptable.

### Analysis children tracking (not in original design)

The original design's `ObservableDiff` only tracked mutations on
Observable objects' mutable fields. The `ignore` action in
ObservableModifier (`observable_modifier.py:552-579`) mutates an
*Analysis* object's `_observables` list — removing an observable from
its parent analysis. This was invisible to the narrow snapshot.

Added `AnalysisChildrenDiff` to capture additions/removals from each
Analysis's child observable list, and the wide snapshot now captures
`analysis_children` (a map of `(parent_observable_uuid, module_path)` →
`frozenset(child_uuids)`). This is only captured in wide-diff mode
since it requires iterating all analyses in the root.

A wide capture also produces **`other_observable_diffs`** —
`dict[observable_uuid → ObservableDiff]` — for field-level changes (tags,
detections, directives, scalar transitions like `ignored`) on observables
*other than* the analyzed one. Together with `analysis_children_diffs`, these
two structures are what let a wide-diff delta attribute a mutation made
anywhere in the tree to the module that made it (§A6). Both are populated only
in wide mode and are ignored by `apply_delta` (wide-diff deltas are never
cacheable).

### `MODULE_PATH()` requires real module objects

`saq/analysis/module_path.py:MODULE_PATH()` asserts on the type of its
argument — it must be an `AnalysisModule`, `Analysis`, or
`AnalysisModuleInterface` instance. Mock objects in tests fail this
assertion. The snapshot code uses `_get_module_path()` which wraps
`MODULE_PATH()` in a try/except and falls back to `module.config.name`.

### Size characteristics observed in production-like alerts

On a PDF alert with deep extraction (4,057 total module runs, hundreds
of observables):

- Without empty-delta filtering: 1.47 MB module_executions (73% of
  data.json)
- With empty-delta filtering: 250 KB module_executions (29% of
  data.json), 467 non-empty deltas
- Of the 467 non-empty deltas, 401 are analysis-object-only (no tree
  mutations beyond creating the Analysis). These account for 190 KB.
- Deltas with real tree mutations: 66 entries, 59 KB

### Files actually touched in Phase 1

- `saq/analysis/module_execution_delta.py` (new) — `ObservableDiff`,
  `ObservableSpec`, `RootDiff`, `AnalysisChildrenDiff`,
  `ModuleExecutionDelta`
- `saq/analysis/snapshot.py` (new) — `ModuleExecutionSnapshot` with
  `narrow()`, `wide()`, `diff()`
- `saq/analysis/root.py` — `_module_executions`, `record_module_execution`
- `saq/analysis/serialize/root_serializer.py` — serialize/deserialize
- `saq/engine/executor.py` — snapshot wrapping with failure safety
- `saq/modules/adapter.py` — added `version` property
- `saq/modules/config.py` — added `wide_diff` field
- `etc/saq.default.yaml` — set `wide_diff: true` on observable_modifier
- `tests/saq/analysis/test_module_execution_delta.py` (new) — 23 tests
- `tests/saq/analysis/test_snapshot.py` (new) — 19 tests
- `tests/saq/analysis/test_root_delta_serialization.py` (new) — 5 tests
## Phase 2: Cache Writes (outline — detail after Phase 1 bake-in)

### Step 2.1 — Module config additions
- Add `cache_ttl: Optional[timedelta] = None` to `AnalysisModuleConfig`
- Add `extended_version` as a property on `AnalysisModule` (not config — see
  §A5)
- Add validation: `wide_diff = True` implies `cache_ttl = None`

### Step 2.2 — Cache key generation
- `saq/analysis/cache.py` (new) — `generate_cache_key()` mirroring ace2-core
- Populate `delta.cache_key` in the executor when `module.cache_ttl is not None`

### Step 2.3 — Database table + migration
- `analysis_result_cache` table (§4 / §A3 revised schema)
- `blob_refs` table (§A7)
- Alembic migration via `make db-revision`
- ORM model `AnalysisResultCache` in `saq/database/model.py`

### Step 2.4 — BlobStore interface + local implementation
- `saq/analysis/blob_store.py` (new) — `BlobStore` ABC +
  `LocalHardlinkBlobStore`
- Reference counting via `blob_refs` table
- File observable materialization shim

### Step 2.5 — Cache write path
- In executor, after recording delta: if `module.cache_ttl` and no removals
  in delta, write to cache
- zstd compression of delta JSON
- Details spill to blob store if > 16 KiB

### Step 2.6 — Cache lifecycle
- Reclaim expired entries per §A8. (Originally a
  `prune_analysis_result_cache()` delete sweep; replaced by daily partition
  drops in PR #279 — see "Phase 2 follow-up" below.)
- Bin script + yacron entry
- Blob store GC sweep

### Phase 2 Bake-in Monitoring

> The row-deletion prune sweep referenced in some bullets below was replaced
> by daily partition drops in PR #279 (see "Phase 2 follow-up" below). Read
> "pruning job" as "partition-maintenance job" and the `cache_stats` field
> list as the post-#279 one (`total_rows`, `total_on_disk_bytes`,
> `blob_refs_rows`).

- Cache table row count and size growth rate
- `delta_zstd` average and p99 sizes
- Blob store disk usage
- Partition-maintenance job execution time and partitions dropped/created
- No cache writes for modules with removals (verify refusal logging works)
- `blob_gc ...` structured log line (per-run durable-tier GC summary:
  `blobs_scanned`, `blobs_deleted`, `bytes_reclaimed`,
  `skipped_referenced`, `skipped_within_grace`, `errors`)
- `local_cache_maintenance ...` structured log line (per-run local
  eviction summary; no-op fields all zero for `LocalHardlinkBlobStore`,
  meaningful once a two-tier backend lands)
- Multi-node warning (`analysis cache blob store is node-local ... but N
  nodes are registered`) — should be absent on single-node installs and
  on multi-node clusters with a pluggable backend configured

---

## Phase 2.5: Write-only opt-in bake (real cache load, no read path)

### Goal

Validate the Phase 2 write path under real production load before adding
read/replay complexity. Phase 2 shipped dark (no module opted in), so the
write path, partition-maintenance cron, and observability hooks have only been exercised by
unit tests. Phase 2.5 turns the firehose on by opting in two modules
without touching any plumbing — no code changes, just YAML.

This step was inserted after Phase 2 implementation. The original plan
went straight from Phase 2 plumbing to Phase 3 read/replay, on the
assumption that opt-in and read landing together would let us measure
correctness and hit rate in the same bake. Splitting them isolates
write-path failure modes (compression sizing, partition-maintenance keeping
up, refusal warnings, lock contention) from replay correctness.

### Modules opted in

- `analysis_module_whois_analyzer` — `cache_ttl: 604800` (7 days)

**Why this module:** Whois is wall-clock slow (network round-trip to
the registrar, occasional rate-limit-driven retries) but lightweight
on CPU — a perfect bake target since the cost shape it caches is
*latency*, not compute. Its observable type is `F_FQDN`, so
`observable.value` is the domain string itself: naturally
content-addressable across alerts. The same domain appearing in two
alerts within 7 days produces the same cache key.

The module is purely additive: `execute_analysis` only calls
`create_analysis(observable)` and sets fields on `analysis.details`.
No tags, child observables, directives, relationships, detection
points, redirections, or removals. The §A4 refusal safety net should
never trigger; if it does, that's a finding.

Crucially, **no child observables of any kind are produced** — file
or otherwise. This sidesteps the Phase 4 file-materialization concern
entirely: a Phase 3 read-side opt-in for whois will replay cleanly
without waiting on Phase 4 work. (OCR and QR were considered for
this slot but deferred — their `add_file_observable(...)` calls
produce file children whose bytes-on-disk would be missing on replay
until Phase 4's `FileObservable.materialize()` lands.)

`extended_version` stays at the default empty dict — the module has
no external rules files, model weights, or shelled-out tools whose
versions need to participate in the cache key. Staleness is bounded
by `cache_ttl` alone.

### Blob GC posture for the bake

Whois `Analysis.details` includes the parsed `whois_data` dict and
`whois_raw_text` (the full registrar response). For typical domains
the raw text is a few hundred bytes to ~2 KiB — well under the
`details_spill_bytes` (16 KiB) threshold. Pathological cases (very
verbose registrars) could occasionally spill, but the rate will be
low. Durable-tier blob GC (`blob_store.maintain_global`) is fully
implemented before the bake begins (it shipped in the Phase 2
hardening pass — PR #245), so the bake exercises the full path
including GC. The only remaining deferred work — a
`prune_orphaned_blob_refs` reconciliation sweep — is not load-bearing:
after PR #279 the `blob_refs` rows and the cache rows that reference them
share the same daily partition boundaries and retention window, so they age
out together and no orphaned-ref drift is produced.

### Configuration change

Single edit: add `cache_ttl: 604800` to `analysis_module_whois_analyzer`
in `etc/saq.default.yaml`. This is the open-source default config so
the opt-in applies to every deployment running ACE3 with caching enabled.

### Validation gate

`pydantic` already validates `cache_ttl` + `wide_diff` mutual
exclusion at config load time. After the YAML edit, restart engines
and confirm:

- No config-load errors for either module
- `cache_stats` heartbeat begins reporting a non-zero `total_rows` within the
  first stats cycle (the `analysis-cache-stats` cron runs every 15 minutes;
  post PR #279 the `modules_with_entries` field no longer exists — it relied
  on a `COUNT(DISTINCT module_name)` that doesn't scale)

### What to monitor (Splunk)

The Phase 2 monitoring queries become meaningful once writes land (field
list updated for PR #279 — the cache is now append-only and partition-managed):

- `"wrote analysis cache entry"` — write throughput; `op` is always
  `insert` now (the cache is append-only — there is no `update`), so inspect
  the `compressed_bytes` distribution and `write_ms` latency
- `"cache_stats"` — heartbeat every 15 minutes (its own
  `analysis-cache-stats` cron); track `total_rows` and
  `total_on_disk_bytes` trajectory (both are partition-statistics estimates)
- `"refusing to cache delta ... contains removals"` — would indicate
  an unexpected mutation in whois (none expected)
- `"refusing to cache delta ... exceeds cap"` — would indicate a
  pathologically verbose registrar response. Cap is 1 MiB
  compressed; whois responses are typically a few hundred bytes
  uncompressed
- `"failed to write analysis cache entry"` — any DB-side failure;
  baseline should be zero
- partition-maintenance log (`bin/manage-analysis-result-cache-partitions.sh`)
  — confirm the daily run drops aged partitions and provisions future ones;
  this is what bounds table growth now (there is no `prune_backlog` warning)

### Confidence criteria to advance to Phase 3

- [ ] Sustained write traffic visible for the module across the bake
- [ ] Repeat domains produce repeat inserts (the same cache_key recurring
  across alerts proves cross-alert repetition; the append-only cache keeps
  one row per occurrence and the read path picks the freshest non-expired one)
- [ ] No `refusing to cache delta` warnings
- [ ] No `failed to write analysis cache entry` warnings
- [ ] `cache_stats.total_rows` plateaus at a steady state bounded by
  `partition_retention_days` (daily partition drops keeping up; not
  monotonically growing)
- [ ] `cache_stats.total_on_disk_bytes` stays within operator-defined
  bounds (set an alerting threshold before bake starts)
- [ ] `cache_stats.blob_refs_rows` stays at or near zero (validates
  the §A3 spill threshold is sized correctly for whois payloads)
- [ ] Daily partition-maintenance cron runs cleanly (drops aged partitions,
  provisions future ones); no rows stuck accumulating in `p_catchall`
- [ ] Bake runs ≥ 2 full TTL windows (≥ 14 days) so both write
  saturation and partition-drop behaviour are observed end-to-end

### What this bake intentionally does NOT validate

- **Replay correctness** — no read path exists. Phase 3 owns this.
- **Single-flight dedup** — concurrent writes for the same key both
  land as independent append-only inserts (post PR #279; the read path
  picks the freshest non-expired row). Deduping the *work* — so only one
  worker runs the module — is Phase 3.5.
- **Blob store I/O** — whois deltas almost never spill. Phase 4 will
  exercise blob paths via larger-detail modules.
- **File observable replay** — whois produces no child observables,
  so this bake gives zero signal on the file-materialization gap.
  Phase 4 owns this.

---

## Phase 3: Cache Reads / Replay (outline)

> **✅ Implemented in PR #211 (merged 2026-05-14)**, with the metrics step
> reworked in PR #242 and an empty-delta/`observable.time` fix in PR #262. The
> as-built shipped as Steps 3.0–3.8 (not the 3.1–3.6 below). Full detail in the
> "Phase 3 implementation notes" section near the end of this document. The
> step list below is the original outline; Step 3.4's opt-in set was reworked
> after the bake (rdap/nrd/site_tagger, not whois) and Step 3.6's tool-version
> helper remains **deferred** (see notes).

### Step 3.1 — `apply_delta()` function — *shipped (Step 3.5 as-built)*
### Step 3.2 — Executor cache-hit short-circuit — *shipped (Step 3.6 as-built)*
### Step 3.3 — Metrics (hit/miss per module) — *shipped, then reworked to per-(root,module) aggregation in PR #242*
### Step 3.4 — Opt-in first modules — *shipped; current opt-ins are rdap/nrd/site_tagger via `extended_version`*
### Step 3.5 — CI lint: cacheable modules produce no removals — *shipped (`test_cacheable_modules_contract.py`, Step 3.8 as-built)*
### Step 3.6 — Tool-version helper for `extended_version` — **✅ shipped with Phase 4 (2026-06-12)**

> As-built deviations from the sketch below: negative probe results are
> cached too (a broken tool must not be re-spawned per cache-key
> computation); OCR uses `probe_binary_version("tesseract")` rather than
> `pytesseract.get_tesseract_version()` (the latter spawns a subprocess on
> every call and isn't mtime-invalidated); QR probes `pdfinfo` with `-v`
> and the helper falls back to stderr (where pdfinfo prints its version);
> QR additionally fingerprints its URL-filter file (mtime+size) because
> the filter's *contents* change output while only its *path* is in the
> config hash.

Many ACE3 analysis modules shell out to CLI tools whose version
participates in correctness (OCR uses `tesseract`; QR uses `zbarimg`,
`gs`, `pdfinfo`; future opt-ins likely add others). When such a
module opts into caching, its `extended_version` must include those
tool versions so a container/package upgrade invalidates stale
cache entries. Without this, an apt-upgrade that changes tool
behaviour silently keeps serving stale replays under the same key.

Ship a shared helper before opting in any tool-using module — Phase
3 if a first-opt-in needs it (e.g., a DNS module shelling out to
`dig`), or Phase 4 alongside the OCR/QR opt-in. The helper is
small and orthogonal to the rest of Phase 3 work, so it can also
land alongside Step 3.4 with no architectural impact.

**Sketch (`saq/modules/tool_version.py`):**

- `probe_binary_version(name, args=["--version"]) -> Optional[str]`
- Resolves the binary via `shutil.which()` so we record what
  `Popen` will actually run.
- Caches results in a process-global dict keyed by
  `(resolved_path, st_mtime_ns, st_size)` — same shape as the
  rules-file pattern in §A5. apt-upgrade replaces the
  binary, mtime changes, key invalidates, next probe re-runs.
- Returns the first non-empty line of stdout/stderr stripped.
- Returns `None` on probe failure (missing tool, timeout, exec
  error). Callers must decide whether to (a) omit the tool from
  the dict — accepts staleness across upgrades but never poisons
  the cache key with a transient failure, or (b) raise so the
  surrounding `extended_version` propagates and the executor
  skips caching that run. Default: (a). Document the choice on
  each consuming module.

**Per-module override pattern:**

```python
class OCRAnalyzer(AnalysisModule):
    @property
    def extended_version(self) -> dict[str, str]:
        import pytesseract  # already a dependency
        return {"tesseract": str(pytesseract.get_tesseract_version())}

class QRCodeAnalyzer(AnalysisModule):
    @property
    def extended_version(self) -> dict[str, str]:
        return {
            tool: v
            for tool in ("zbarimg", "gs", "pdfinfo")
            if (v := probe_binary_version(tool)) is not None
        }
```

**Tests:** mtime-bumping a tool binary invalidates the cache;
missing tool returns `None` and emits a warning; cached probe
result is reused within a process.

### Phase 3 Bake-in Monitoring
- Cache hit rate per module — derived from the per-(root, module) fields on the
  per-root summary event (`cache_hit_count` / `cache_miss_count`), not from
  per-event log lines (PR #242 — see the Phase 3 implementation notes)
- Hit-cost vs. live-cost — `cache_lookup_ms_sum` / `cache_lookup_ms_max` against
  the module's live `analysis_time_seconds`
- Correctness: compare replay output vs. live-run output for same inputs
- Analysis result equivalence spot checks

---

## Phase 3.5: Single-Flight Dedup (outline)

> **Redesigned 2026-06-10** to be non-blocking: deferred workers requeue
> through the delayed-analysis machinery instead of sleep-polling (the
> original `wait_for_cache` loop parked a worker for the owner's full
> module runtime — see §A9 "Why not blocking-wait?"). Single-flight is a
> per-module `single_flight: true` opt-in (requires `cache_ttl`), not
> implied by it.

Background: see §A9. Phase 3's read/replay short-circuits subsequent
analyses but doesn't help simultaneous arrivals of the same observable —
a thundering-herd of 10 identical phishing emails still produces 10 full
module runs. Phase 3.5 adds a pending-marker protocol: exactly one worker
runs the module; the rest record a flagged placeholder analysis, register
a delayed-analysis request, and re-check the cache when they resume.

### Step 3.5.1 — Schema + Alembic migration
- `analysis_cache_pending` table (§A9) — in the cache DB, so
  `make cache-db-revision MESSAGE="add analysis_cache_pending table"`.
  NOT partitioned (small, short-lived rows; needs a real DELETE reaper)
- ORM class `AnalysisCachePending` on `CacheBase`

### Step 3.5.2 — Config + claim helpers
- `single_flight: bool = False` on `AnalysisModuleConfig`, with a
  validator requiring `cache_ttl` when set
- In `saq/analysis/cache.py`:
  - `claim_pending(cache_key, module, worker_id) -> "owned" | "deferred"`
    via `INSERT IGNORE` and `rowcount` check
  - `release_pending(cache_key)` — single DELETE
  - `pending_claim(cache_key)` — fetch the live claim row (for the
    resume re-check's expiry decision)
  - `reap_stale_pending()` — single DELETE WHERE `expires_at < NOW()`
- Worker identity helper: `f"{socket.gethostname()}:{os.getpid()}"`

### Step 3.5.3 — Executor integration (non-blocking, §A9 flow)
- Inside `_execute_module_analysis` between the Phase 3 cache-read
  miss path and the live `module.analyze()` call, gated on
  `config.single_flight`
- Owned branch: wrap `analyze()` in `try/finally` that always calls
  `release_pending()`
- Deferred branch: create a `single_flight_deferred` placeholder
  analysis (delayed=True), `delay_analysis(seconds=RECHECK_INTERVAL)`,
  return INCOMPLETE — the worker is released
- Resume branch (executor-owned, not `continue_analysis`): re-check
  cache → replace placeholder + `apply_delta` on hit; run live via
  `execute_analysis` when the claim is gone or expired; re-delay
  otherwise. Open mechanics flagged in §A9: acceptance-check carve-out
  for the placeholder resume, placeholder removal vs `apply_delta`'s
  slot-collision skip, and keeping placeholders out of the cache (the
  existing delayed/empty refusal gates should already cover that —
  verify in tests)

### Step 3.5.4 — Stale-pending reaper
- `analysis_cache_pending` is small and short-lived, so it is NOT a partition
  candidate and still needs an actual `DELETE` reaper. PR #279 removed the
  5-minute prune cron this step originally extended; attach
  `reap_stale_pending()` to a surviving frequent primary-node cron (e.g.
  `analysis-cache-stats`, every 15 min) or give it its own short-interval entry
- One additional INFO log line: `reaped N stale analysis_cache_pending rows`

### Step 3.5.5 — Splunk signals
- New INFO lines: `cache_claim result=owned|deferred ...`,
  `cache_defer_resume ... result=hit|owner_gone_ran_live|claim_expired_ran_live|redeferred deferred_ms=... recheck_count=...`
- Extend the Splunk reference doc with these signals and the
  "thundering-herd reduction ratio" query from §A9

### Step 3.5.6 — Tests
- `tests/saq/analysis/test_cache_pending.py` (new):
  - Claim race: two concurrent `claim_pending` for same cache_key →
    exactly one `owned`, one `deferred`
  - `release_pending` deletes the row
  - `reap_stale_pending` removes expired rows and leaves fresh ones
- Executor resume re-check tests:
  - cache row present on resume → placeholder replaced, delta applied,
    nothing run live
  - claim gone + no cache row → live `execute_analysis` (not
    `continue_analysis`), placeholder removed
  - claim live and unexpired → re-delayed, no module run
  - placeholder is never cached (delayed/empty refusal gates)
- Integration test: mock module with `cache_ttl` + `single_flight`, two
  simulated concurrent executions → exactly one `analyze()` call, both
  roots end with the same delta

### Phase 3.5 Bake-in Monitoring
- Ratio of `cache_claim result=owned` vs `result=deferred` per module
  — higher deferred count on simultaneous arrivals = single-flight
  is doing its job
- `cache_defer_resume` p99 `deferred_ms` per module — bounded by the
  owner's module runtime + one re-check interval; and the
  `recheck_count` distribution (should be small for well-chosen
  intervals)
- `stale_pending_reaped` rows per sweep — baseline should be near
  zero; spikes correlate with worker crashes
- Correctness: the delta applied to deferred alerts must equal the
  delta the owner produced (spot check via attribution in root.json)

---

## Phase 4: File Observables + Blob Store — **✅ Implemented (2026-06-12)**

> Landed *before* Phase 3.5 (re-sequenced — see the status table note).
> No DB schema change was needed: `blob_refs`, `has_blob_refs`, and the
> blob store (incl. `materialize()`) all shipped with PR #279.

### Step 4.1 — File observable caching via blob store — *shipped*
### Step 4.2 — Cache replay copies files into target storage dir — *shipped*
### Step 4.3 — Expand opt-in module list — *shipped (ocr, qrcode)*

OCR (`tesseract`) and QR (`zbarimg`, `gs`, `pdfinfo`) opted in here, with
the Step 3.6 tool-version helper shipped in the same change.

### Phase 4 implementation notes (as built, 2026-06-12)

- **Spec fidelity came first.** OCR sets `volatile=True`, an
  `R_EXTRACTED_FROM` relationship, directives, and `redirection` on its
  output file; QR sets a relationship, tags, and an `exclude_analysis`.
  `ObservableSpec` previously captured none of
  relationships/redirection/volatile — replay would have been silently
  unfaithful. The spec grew `file_path`, `volatile`,
  `initial_relationships` (the enriched `_serialize_relationship` shape
  with target `(type, value, time)`), and `initial_redirection`, all
  serialized omit-when-default so pre-Phase-4 rows and root.json load
  unchanged. `out_of_scope_relationship_targets()` covers the new fields.
- **Write path** (`put_cached_delta`, new keyword `root=` passed by
  `_maybe_write_cache_delta`): validation refusals
  (`file_observables_no_root`, `file_spec_missing_path`, `file_missing`,
  `file_too_large`) run before any blob I/O; then per spec
  `exists()`-or-`put()` + `reference()` under the cache row. `put()`
  re-hashes — a mismatch (`file_hash_mismatch`) means the file mutated
  on disk after the observable hashed it; the delta is refused and any
  taken references dropped (`_unreference_blob_refs`, shared with the
  size-cap bailout, which now covers file refs via the extended
  `_extract_blob_refs`).
- **Read path**: `get_cached_delta` checks `blob_store.exists()` per file
  spec → `blob_missing` miss (GC race / failed remote upload → live-run
  fall-through that rewrites both row and blob); a spec with no
  `file_path` → `decode_error` miss.
- **Replay**: staging-then-mutate (see §5). `_apply_observable_spec`
  returns the created observable; `apply_delta` builds a
  source-uuid→created-observable map and a second pass applies spec
  relationships (via `_apply_relationship`, factored out of
  `_apply_observable_diff` — the uuid map subsumes the old self-target
  shortcut) and redirections. Idempotent: `store_file` skips existing
  links, `FileObservable.__eq__` is `(value, file_path)`.
- **Size guard**: `analysis_cache.file_blob_max_bytes` (default 16 MiB
  per produced file) — blob bytes live outside the delta row, so the
  1 MiB compressed-delta cap doesn't cover them. OCR/QR outputs are
  KB-scale; this is a safety net.
- **CI lint**: `CONTRACT_CHECKERS` entries became
  `ContractCheck(runner, file_capable)`. File-capable modules (ocr,
  qrcode — checkers run the real module with only the external tool call
  mocked) assert each file spec is blob-backable: sha256 value, captured
  `file_path`, backing file present, ≤ size cap; plus the standard
  removals/relationship-scope assertions. Non-file-capable modules keep
  the no-files assertion.
- **Negative-result caching (OCR/QR)**: both modules record a
  summary-less analysis when their scans complete cleanly with nothing
  found, making the (dominant, double-scan-expensive) negative case
  cacheable with zero cache-layer changes — see the §A4 follow-up note
  for the full rationale and the failure-vs-negative disambiguation
  (`_scan_image` trusts only zbarimg exit codes 0/4; a raising OCR pass
  sets `ocr_failed`; failures record nothing so they are never cached).
- **Known limitations / notes:**
  - *Shared inodes*: on the local backend, blob → hardcopy → file_dir
    links share one inode across alerts; stored file content is treated
    as immutable in ACE (already true within an alert via hardcopy). If
    in-place mutation ever appears, switch `materialize` callers to copy.
  - *Mixed-version fleet*: file-bearing rows are only written by builds
    that also carry the YAML opt-in (same artifact); an older node
    reading one hits its read-time refusal (silent no-op replay).
  - *S3 blob store backends* need no code change — Phase 4 consumes only
    the `BlobStore` interface. Operationally: a bucket lifecycle policy
    (the recommended GC posture) must expire objects no sooner than the
    longest file-capable `cache_ttl` + GC grace, or live rows degrade to
    `blob_missing` misses; per-node local-cache size budgets may need
    revisiting now that blobs include multi-MB files, and a `head_object`
    per file spec is paid on cold lookups.
  - *Yara*: deferred, for reasons beyond versioning (the ruleset IS
    fingerprintable — `YaraScanner_v3_4.signature_dir` exposes the
    configured rules directory, and an nrd-style mtime+size walk would
    work; only the yss daemon's reload lag would briefly let a fresh
    fingerprint cache results computed from the old rules). The hard
    blockers: (a) yara matches against *content*, but
    `yara_scanner.filter_scan_results()` then post-filters hits against
    rule meta `file_name`/`file_ext`/`full_path` and the observable's
    `meta_tags` — so the module's filtered output depends on the file's
    name and the observable's YARA_META directives, neither of which is
    in the content-sha256 cache key (same bytes, different name/tags →
    wrong cached result; `full_path` rules compare against the absolute
    per-alert path and could never be cache-stable); (b) on an alertable
    match for a decomposed file the module adds `DIRECTIVE_SANDBOX` to
    `_file.redirection` — a *different* observable, invisible to the
    narrow diff, so replay would drop the directive that drives
    detonation; (c) the `$obs_` string path queries the DB at scan time;
    and (d) payoff is marginal — a local yss socket scan costs
    milliseconds, comparable to or cheaper than a cache hit's DB
    round-trip + decode + replay (§A1's "cheap enough to re-run" case).
    *Phishkit*: opted in 2026-06-29 in **core** (not downstream — the module
    lives in `saq/modules/phishkit.py`). See the "Phishkit opt-in" notes below.

### Phishkit opt-in notes (as built, 2026-06-29)

Phishkit is the highest-payoff cache candidate (a multi-second-to-minutes
browser crawl) and the most herd-prone (one phishing URL blasted to many
mailboxes). It is opted in with `cache_ttl: 21600` (6h) in
`etc/saq.default.yaml`. Notable points:

- **Why plain caching, not single-flight (§A9).** Engine workers do not pick up
  all copies of a campaign at once — arrivals stagger. The first scan fills the
  cache; the rest of the burst arrives late enough to replay it. Single-flight
  would only dedup the 1–2 genuinely-concurrent scans at the front of a burst —
  negligible against replaying the rest. Phase 3.5 stays parked.
- **First delayed *and* file-producing cached module.** It exercises the
  intersection of the Phase 3 delayed path (celery submit + multi-cycle poll,
  cached only on the COMPLETED final cycle with prior cycles merged via
  `merge_module_execution_deltas()`) and the Phase 4 file-blob path (captured
  `dom.html`/`requests.json`/screenshots blob-backed; extracted URL observables
  replayed). Covered by `_check_phishkit` in the CI contract lint
  (`file_capable=True`) and a write→replay round-trip in `test_phishkit.py`.
- **`extended_version` (`saq/modules/phishkit.py`).** Two statically-derivable
  signals (the cache key is computed *before* the scan, so neither can come from
  a scan result): `phishkit_config` = `file_content_version()` of the scanner
  YAML (an analyst edit re-keys without a redeploy), and `scanner_image` = the
  running scanner image's content id. The image id is the genuine fix for the
  invalidation gap: `ACE3_PHISHKIT_IMAGE_URL` is a constant `phishkit:latest` in
  production, so keying on the tag string would never invalidate. Instead the
  manager — which already has the Docker socket and shells out to the `docker`
  CLI — reports `docker inspect <image> --format '{{.Id}}'` (a content hash that
  changes on every rebuild) through a dedicated `scanner_image_id` celery task
  (the worker's `ping` stays a pure `"pong"` health check). The id is **cached
  only on the worker**: it resolves the `docker inspect` **once at startup**
  (warmed via `@worker_ready`) and freezes it for its process lifetime — frozen
  only on the first *successful* probe, so a docker-not-ready-at-boot blip
  re-probes rather than pinning a permanent None. The module's
  `get_phishkit_scanner_version()` is an un-memoized passthrough that calls the
  task on each cache-key computation; there is **no client-side memo** because the
  task already returns the frozen dict with no subprocess, so the only per-call
  cost is a cheap celery roundtrip (negligible against a multi-second scan, and on
  a replay hit just part of the lookup). Freezing at startup is correct here
  because the id only changes on a scanner
  rebuild, which coincides with a manager restart: the **manager image bakes in
  `scanner.py` + `Dockerfile.phishkit`** (`phishkit/Dockerfile` `COPY`s both), so
  a scanner code/Dockerfile change rebuilds the manager too, and releases restart
  the whole system. The one caveat — a scanner-dependency-only change
  (`requirements.phishkit.txt`, the Ubuntu base, or the floating Chrome deb)
  deployed via a *rolling* `up --build` that does not recreate the manager —
  leaves the frozen id stale until the next manager restart, bounded meanwhile by
  the 6h `cache_ttl` (the same staleness ceiling the feature already accepts). On
  a query/inspect failure the key degrades to config-hash-only (last-known value
  retained to avoid flapping).
- **Partial/timeout results are cached on purpose.** A phishkit timeout is
  overwhelmingly the target site *detecting and blocking* the automated crawl —
  a stable property of its anti-bot behavior, not transient network noise that a
  retry would fix. Caching the partial result gives the rest of a campaign the
  same answer a fresh scan would and stops us re-hammering a site that is
  fingerprinting us. So there is **no `is_result_cacheable` skip-hook**;
  staleness (including a cached partial) is bounded by the short 6h TTL.
- **Size guard.** `dom.html`/`requests.json` are normally KB-to-low-MB. A heavy
  crawl that exceeds `analysis_cache.file_blob_max_bytes` (16 MiB/file) hits the
  `file_too_large` write-refusal and simply re-runs live — graceful, not a bug.

---

## Implementation Order Summary

```
Phase 1 (this branch, immediate work):
  1.1  Data structures (dataclasses)
  1.2  Snapshot capture + diff
  1.3  RootAnalysis._module_executions
  1.4  Serializer support
  1.5  Executor wrapping
  1.6  Wide-diff support
  1.7  Tests
  --- ship & bake ---

Phase 2 (after Phase 1 confidence criteria met):
  2.1-2.6 as above
  --- ship & bake (plumbing only, no opt-ins) ---

Phase 2.5 (after Phase 2 plumbing ships):
  Opt in analysis_module_whois_analyzer (cache_ttl: 604800)
  in etc/saq.default.yaml
  --- ship & bake (≥ 2 TTL windows) ---

Phase 3 (after Phase 2.5 confidence criteria met):
  3.1-3.5 as above
  --- ship & bake ---

Phase 4 (re-sequenced ahead of Phase 3.5; shipped 2026-06-12):
  4.0  ObservableSpec fidelity (file_path / volatile / relationships /
       redirection) + tool-version helper (former Step 3.6)
  4.1  Cache write: blob-back file specs (validate → put → reference)
  4.2  Replay: stage-materialize → add_file_observable(move=True)
  4.3  Opt-ins: ocr + qrcode (7d each) + contract-lint file_capable mode
  --- shipped ---

Phase 3.5 (deferred to last; after Phase 4 + payoff data):
  3.5.1 analysis_cache_pending schema + migration
  3.5.2 single_flight config flag + claim / release / reap helpers
  3.5.3 Executor integration (claim-or-defer via delayed analysis)
  3.5.4 Stale-pending reaper on a frequent primary-node cron (the 5-min
        prune cron it originally targeted was removed in PR #279)
  3.5.5 Splunk signals: cache_claim, cache_defer_resume, stale_pending_reaped
  3.5.6 Tests
```

## Critical Files

| File | Action | Phase |
|------|--------|-------|
| `saq/analysis/module_execution_delta.py` | Create | 1.1 |
| `saq/analysis/snapshot.py` | Create | 1.2 |
| `saq/analysis/root.py` | Edit (add `_module_executions`) | 1.3 |
| `saq/analysis/serialize/root_serializer.py` | Edit (serialize/deserialize deltas) | 1.4 |
| `saq/engine/executor.py` | Edit (wrap analyze call) | 1.5 |
| `saq/modules/config.py` | Edit (add `wide_diff`) | 1.6 |
| `tests/saq/analysis/test_module_execution_delta.py` | Create | 1.7 |
| `tests/saq/analysis/test_snapshot.py` | Create | 1.7 |
| `tests/saq/analysis/test_root_delta_serialization.py` | Create | 1.7 |
| `tests/saq/engine/test_executor_delta_recording.py` | Create | 1.7 |
| `saq/analysis/cache.py` | Create | 2.2 |
| `saq/analysis/blob_store.py` | Create | 2.4 |
| `saq/database/model.py` | Edit (`AnalysisResultCache` / `BlobRef` on `CacheBase`) | 2.3 |
| `alembic/analysis_cache/versions/` | Create (separate cache-DB Alembic env, PR #279) | 2.3 |
| `bin/manage-analysis-result-cache-partitions.sh` | Create (partition lifecycle, PR #279) | 2.6 |
| `saq/analysis/module_execution_delta.py` | Edit (replay primitives: `from_cache_hit`, `with_cache_hit_metadata`, PR #211) | 3 |
| `saq/analysis/snapshot.py` | Edit (Step 3.0 delayed-transition capture, PR #211) | 3 |
| `saq/analysis/cache.py` | Edit (`get_cached_delta`, `apply_delta`, PR #211) | 3 |
| `saq/engine/executor.py` | Edit (cache-hit short-circuit + `_apply_cached_delta` + metrics, PR #211/#242) | 3 |
| `saq/logging.py` | Create (`ExtraAwareFluentFormatter`, PR #211) | 3 |
| `tests/saq/modules/test_cacheable_modules_contract.py` | Create (cacheability CI lint, PR #211) | 3 |
| `saq/modules/tool_version.py` | Create (`probe_binary_version`, shipped with Phase 4) | 3.6 |
| `saq/analysis/module_execution_delta.py` | Edit (`ObservableSpec` file_path/volatile/relationships/redirection, `file_observable_specs`, spec-aware scope check) | 4 |
| `saq/analysis/snapshot.py` | Edit (capture the Phase 4 spec fields) | 4 |
| `saq/analysis/cache.py` | Edit (file-spec validation + blob write in `put_cached_delta(root=)`; `blob_missing` file check in `get_cached_delta`; staging + `_apply_relationship` second pass in `apply_delta`) | 4 |
| `saq/configuration/schema.py` | Edit (`file_blob_max_bytes`) | 4 |
| `saq/engine/executor.py` | Edit (pass `root` to cache write, `blob_store` to replay) | 4 |
| `saq/modules/file_analysis/ocr.py` / `qrcode.py` | Edit (`extended_version` overrides) | 4.3 |
| `etc/saq.default.yaml` | Edit (ocr/qrcode `cache_ttl: 604800`) | 4.3 |
| `tests/saq/modules/test_tool_version.py` / `test_file_analysis_extended_version.py` | Create | 4 |
| `tests/saq/modules/test_cacheable_modules_contract.py` | Edit (`ContractCheck` + file_capable assertions + ocr/qrcode checkers) | 4.3 |

---

## Phase 2 implementation notes

Lessons learned during Phase 2 implementation (2026-04-20) and deviations
from the outline above.

> **Superseded in part by PR #279 (2026-05-27).** This section records Phase 2
> as it originally shipped: cache tables in the main `ace` database, a unique
> `cache_key` PK written via `INSERT ... ON DUPLICATE KEY UPDATE`, a 5-minute
> `prune_analysis_result_cache` delete sweep, a `cache_stats` heartbeat using
> `COUNT(*)`/`SUM(...)`, and a single `alembic/versions/` tree. PR #279 changed
> all of that — see "**Phase 2 follow-up: cache moved to a dedicated
> partition-managed database (PR #279)**" at the end of this document. The
> historical detail below is kept for the design-evolution trail; where it
> conflicts with the follow-up section, the follow-up wins.

### Scope decisions

- **Shipped dark.** No module opts into `cache_ttl` during Phase 2
  production bake — plumbing only. `phishkit` is the intended first opt-in
  but that crossover happens in Phase 3 alongside the read path, when we
  can measure hit rate and correctness together.
- **`BlobStore` included up front** (§A7 forward-compat argument). Both
  `LocalHardlinkBlobStore` and the `blob_refs` table ship in Phase 2 so
  the S3 migration later is a pure backend swap.
- **`FileObservable.materialize()` shim deferred to Phase 4.** Phase 2
  only needs the blob store for `analysis.details` spill, not for file
  observable I/O. Adding the shim pre-emptively would have been disruptive
  without proportional value.
- **`BlobStore.gc()` shipped stubbed in Phase 2 and landed for real in
  the Phase 2 hardening pass (PR #245).** The single `gc()` method was
  reshaped into `maintain_global` / `maintain_local` and a real
  implementation for the local backend before Phase 2.5 begins writing
  blobs. See "Phase 2 hardening (PR #245)" below.
  `prune_orphaned_blob_refs` remains unimplemented and is now treated as
  an "if-needed reconciliation sweep" rather than a planned deliverable —
  cache-row + `blob_refs` deletion is transactional, so there's no path
  that produces orphaned `blob_refs` rows.

### Config changes

- **Removed the legacy `cache: bool` field** from `AnalysisModuleConfig`.
  It had exactly one reader (a dead property on `AnalysisModule`) and one
  commented-out YAML reference. Kept so the cache config surface stays
  narrow — `cache_ttl` is the only knob.
- **Cache config lives on a dedicated `AnalysisCacheConfig` model**, mounted
  at `get_config().analysis_cache` (`saq/configuration/schema.py`), not as
  loose fields on `GlobalConfig`. *(Earlier drafts of this note described the
  kill switch and blob dir as `global.analysis_cache_enabled` /
  `global.blob_store_dir` on `GlobalConfig`; the config was consolidated onto
  its own model. The current field set:)*
  - `enabled` (default `true`) — kill switch. Halts all cache writes without
    touching per-module `cache_ttl`, **and** short-circuits reads
    (`get_cached_delta` returns a non-attempt when false), so it disables the
    whole subsystem, not just the write path.
  - `blob_store_dir` (default unset → `<data_dir>/blob_store`, resolved against
    `SAQ_HOME`) — `LocalHardlinkBlobStore` root.
  - `blob_store` (`BlobStoreSpec | None`) — pluggable backend selector (§A7).
  - `zstd_level` (3), `details_spill_bytes` (16 KiB), `max_compressed_bytes`
    (1 MiB) — the §A3 size knobs, now real config fields.
  - `partition_retention_days` (35) — §A8 partition lifecycle.
  - `blob_gc_grace_seconds` (24h), `local_cache_max_age_seconds` (7d),
    `local_cache_max_bytes` (None) — blob GC / local-tier maintenance (§A7).
- **Removed the legacy `cache: bool` field** from `AnalysisModuleConfig`.
  It had exactly one reader (a dead property on `AnalysisModule`) and one
  commented-out YAML reference. Removed so the per-module cache surface stays
  narrow — `cache_ttl` is the only knob.
- **Added a pydantic validator** rejecting `wide_diff=True` combined with
  any non-None `cache_ttl` at config load time — enforces §A6 at the
  earliest possible point.

### Blob store

- **3-char shard**, not 2-char, to match the existing
  `storage_dir_from_uuid` convention (`saq/util/uuid.py:32` uses
  `uuid[0:3]`). Two-level sharding preserved for parity with the §A7
  design.
- **No Docker Compose changes needed.** `/opt/ace/data` is already an
  `ace-data` named volume in `docker-compose.yml:74`, so `data/blob_store/`
  inherits persistence and the existing backup/retention story.
  `initialize_volumes.sh` already chowns `/opt/ace/data` to `ace:ace`.

### ORM throughout

All DB writes/reads go through SQLAlchemy ORM:

- `mysql_insert(...).on_duplicate_key_update(...)` for cache row upsert.
- `mysql_insert(...).prefix_with('IGNORE')` for blob refs.
- `select(...).with_for_update(skip_locked=True).limit(...)` for the
  prune batching.
- `delete(Model).where(col.in_(...))` for batched deletes.

The only raw SQL fragment is `text("INTERVAL :ttl SECOND")` inside a
`func.date_add(func.now(), ...)` call so `expires_at` is computed
DB-side (per §A8 edge case 3, to avoid Python-vs-DB clock drift).

### Observability (all emitted as structured key=value lines for Splunk)

> **Superseded by PR #242 and PR #279.** The per-write/per-hit/per-miss plain
> log lines below were dropped in PR #242 (they would not scale past a handful
> of opt-ins) and replaced by per-(root, module) fields aggregated onto the
> existing per-root summary event — see the "Metrics rework (PR #242)" entry in
> the Phase 3 implementation notes. The `cache_stats` heartbeat fields and cron
> cadence were then changed by PR #279 (§A8 / the PR #279 follow-up). This is
> the Phase-2-as-shipped record.

- **Per-write INFO** — `wrote analysis cache entry op=insert|update
  module=X observable_type=Y uncompressed_bytes=... compressed_bytes=...
  has_blob_refs=... ttl_seconds=... write_ms=...`. Insert vs update comes
  from MySQL `rowcount` (1 = insert, 2 = upsert update). *(PR #242 folded these
  counts into the per-root event; PR #279's append-only cache then removed the
  `update` op entirely — only `cache_write_count_insert` survives.)*
- **`cache_stats` heartbeat** emitted by the prune cron every 5 minutes:
  `total_rows`, `expired_rows`, `total_uncompressed_bytes`,
  `blob_refs_rows`, `modules`. Removes any need to query MySQL directly
  for cache population trends. *(PR #279 moved this to a 15-minute
  `analysis-cache-stats` cron and reduced the fields to `total_rows`,
  `total_on_disk_bytes`, `blob_refs_rows`.)*
- **`prune_backlog` warning** when rows remain expired after a sweep —
  signals that `PRUNE_BATCH_SIZE` or cadence needs tuning. *(Removed in PR #279
  with the delete sweep.)*
- **Refusal warnings** (`refusing to cache delta … contains removals` and
  `… exceeds cap`) include module name + observable identity so
  misbehaving opt-ins are locatable without querying MySQL. *(These survive; the
  field is now `module_name=` after the PR #211 logging rename.)*

### Test counts

- 40 new Phase 2 tests across `test_cache_key.py`, `test_cache.py`,
  `test_blob_store.py`, `test_cache_config_validation.py`, and additions
  to `test_maintenance.py`.
- 62 Phase 1 tests still pass.
- Pre-existing `test_load_modules_integration` failure (missing
  `lnkparse` in dev container) is unrelated.

### Files actually touched in Phase 2

- `saq/analysis/cache.py` (new) — key gen, put, prune,
  `delete_for_module`, `collect_stats`
- `saq/analysis/blob_store.py` (new) — `BlobStore` ABC +
  `LocalHardlinkBlobStore` + lazy singleton
- `saq/database/model.py` — added `AnalysisResultCache`, `BlobRef`
- `alembic/versions/71b6228ef435_add_analysis_result_cache_and_blob_refs_.py` (new)
- `saq/modules/config.py` — removed dead `cache: bool`, added
  `cache_ttl`, added wide_diff/cache_ttl validator
- `saq/modules/base_module.py` — removed dead `cache` + `cache_expiration`
  properties, added `cache_ttl` and `extended_version`
- `saq/modules/adapter.py` — delegated `cache_ttl`, `extended_version`
- `saq/engine/executor.py` — best-effort cache write after
  `root.record_module_execution(delta)`
- `saq/util/maintenance.py` — `prune_analysis_result_cache` with
  `cache_stats` heartbeat and `prune_backlog` warning
- `saq/configuration/schema.py` — the `AnalysisCacheConfig` model
  (`enabled`, `blob_store_dir`, …) at `get_config().analysis_cache` (see Config
  changes above; not loose fields on `GlobalConfig`)
- `etc/saq.default.yaml` — the `analysis_cache:` config block
- `etc/saq.unittest.default.yaml` — removed commented-out `cache: true`
  stub
- `etc/cron.yaml` — 5-minute prune entry
- `ace` — `prune-analysis-cache` subparser
- `bin/prune-analysis-cache` (new) — 2-line wrapper
- `installer/requirements.txt` + `requirements-pinned.txt` — added
  `zstandard==0.25.0`
- `tests/saq/analysis/test_cache_key.py` (new)
- `tests/saq/analysis/test_cache.py` (new)
- `tests/saq/analysis/test_blob_store.py` (new)
- `tests/saq/modules/test_cache_config_validation.py` (new)
- `tests/saq/util/test_maintenance.py` — added two telemetry tests

### Phase 2 hardening (PR #245)

The Phase 2 ship left two known gaps the original implementation plan
flagged: (a) `BlobStore.gc()` was a stub, fine while no module wrote
spillable details but a blocker for Phase 2.5's whois opt-in once real
blobs start accumulating; (b) the `BlobStore` interface existed but the
*selection* mechanism for swapping in a non-default backend wasn't wired
through config — picking a different backend required code edits to
`get_blob_store()`. PR #245 closes both, plus a multi-node safety gap
§A7 didn't anticipate.

**What landed:**

- **Pluggable backend selection.** New `BlobStoreSpec` Pydantic model in
  `saq/configuration/schema.py` (`python_module`, `python_class`,
  `config`). `BlobStore.get_config_class()` mirrors
  `AnalysisModule.get_config_class()`. `LocalHardlinkBlobStore.__init__`
  now takes a `LocalHardlinkBlobStoreConfig` rather than a raw path.
  `get_blob_store()` dispatches: if `analysis_cache.blob_store` is set,
  `importlib.import_module(...)` + Pydantic-validate config + instantiate;
  else fall back to the local store rooted at `blob_store_dir`. Pure
  forward-compat — no behaviour change on existing deployments.

- **Two-tier maintenance.** `BlobStore.gc(grace_period)` replaced by two
  abstract methods — `maintain_global(grace_period, dry_run) ->
  GlobalMaintenanceStats` for the durable tier (primary-node-only) and
  `maintain_local(LocalCacheBudget, dry_run) -> LocalMaintenanceStats`
  for per-node read caches (every node). For `LocalHardlinkBlobStore`,
  `maintain_global` is the real GC (walks the shard tree via
  `iter_blobs()`, batches sha256s through `query_referenced_shas()`
  against `blob_refs`, unlinks orphans whose mtime is older than the
  grace period). `maintain_local` is a no-op because the local FS is
  itself the durable tier.

- **Primary-node gating.** `saq/database/util/node.py` gains
  `is_primary_node()` (lifted out of `DistributedNodeManager` —
  env-var-driven, defaults to "1") and
  `warn_if_blob_store_not_multi_node_safe()`. `prune_expired_cache_rows`
  (renamed from `prune_analysis_result_cache` with backward-compat
  alias) and `gc_durable_blobs` both check `is_primary_node()` at the
  top and log-and-exit on non-primary nodes. `maintain_local_cache`
  does not gate — its target is per-node state.

- **Multi-node safety warning.**
  `warn_if_blob_store_not_multi_node_safe()` runs at engine startup
  from `DistributedNodeManager.initialize_node`. When the `nodes` table
  has >1 row and no pluggable backend is configured, it emits a
  WARNING — surfaces an otherwise silent misconfiguration where blobs
  written on node A are invisible to node B.

- **Three new cron entries.** `etc/cron.yaml` rewritten:
  `analysis-cache-prune` every 5 min, `analysis-cache-gc` hourly,
  `analysis-cache-local-maintenance` every 15 min. All carry
  `concurrencyPolicy: Forbid`. The legacy `prune-analysis-cache`
  subparser + `bin/prune-analysis-cache` wrapper remain as deprecated
  aliases.

- **Three new config knobs** on `AnalysisCacheConfig`:
  `blob_gc_grace_seconds` (default 24h),
  `local_cache_max_age_seconds` (default 7d),
  `local_cache_max_bytes` (default None — operators rolling out a
  two-tier backend need to set this to bound local disk).

**Files added/modified:**

- `saq/analysis/blob_store.py` — `BlobStoreConfig`,
  `LocalHardlinkBlobStoreConfig`, `get_config_class()`,
  `GlobalMaintenanceStats`, `LocalMaintenanceStats`, `LocalCacheBudget`,
  `iter_blobs`, `query_referenced_shas`, `maintain_global`,
  `maintain_local`, `path_for`, `_load_blob_store`,
  `resolve_blob_store_dir`. The `gc()` abstractmethod is replaced.
- `saq/configuration/schema.py` — new `BlobStoreSpec`; new
  `AnalysisCacheConfig` fields `blob_store`, `blob_gc_grace_seconds`,
  `local_cache_max_age_seconds`, `local_cache_max_bytes`.
- `saq/database/util/node.py` — `is_primary_node`,
  `warn_if_blob_store_not_multi_node_safe`.
- `saq/engine/node_manager/distributed_node_manager.py` — calls the
  multi-node-safety warning at node init; uses the extracted
  `is_primary_node()`.
- `saq/util/maintenance.py` — rename `prune_analysis_result_cache` →
  `prune_expired_cache_rows` (with alias), add `gc_durable_blobs`,
  `maintain_local_cache`.
- `saq/analysis/cache.py` — comment reference updated from `gc()` to
  `maintain_global()`.
- `ace` — three new subparsers: `analysis-cache-prune`,
  `analysis-cache-gc`, `analysis-cache-local-maintenance`. Old
  `prune-analysis-cache` kept as a deprecated alias.
- `bin/analysis-cache-prune`, `bin/analysis-cache-gc`,
  `bin/analysis-cache-local-maintenance` (new wrappers). The pre-existing
  `bin/prune-analysis-cache` remains in tree as a deprecated alias.
- `etc/cron.yaml` — replaced the single prune entry with the three new
  entries.
- `tests/saq/analysis/test_blob_store.py`,
  `tests/saq/analysis/test_cache.py`,
  `tests/saq/util/test_maintenance.py` — coverage for `iter_blobs`,
  `maintain_global` (referenced/grace/dry-run), `maintain_local` no-op,
  primary-only gating, and an integration test that drives a real blob
  through put → prune → GC.

**Still deferred:**

- `prune_orphaned_blob_refs` reconciliation sweep — not load-bearing
  because cache-row + `blob_refs` deletion is transactional; add only
  if reconciliation drift is observed.
- Explicit operator guidance on `local_cache_max_bytes` — a
  `saq.default.yaml` comment is still missing (it only matters once a
  two-tier remote backend like S3 is configured).
- Phase 4 file-observable hardlink backing — separate workstream.

## Phase 3 implementation notes

> Chronology note: Phase 3 (PR #211, 2026-05-14) actually landed *before* the
> Phase 2 hardening pass (PR #245, 05-19) and the DB move (PR #279, 05-27). It
> appears here, after the Phase 2 notes, because this document grew as a running
> log rather than in strict merge order. Dates in each subsection header are
> authoritative.

### Core read/replay (PR #211, merged 2026-05-14)

Phase 3 turned the dark Phase 2 write path into a working cache: the executor
now consults the cache before running a cacheable module and, on a hit, replays
the stored delta instead of executing. Shipped as Steps 3.0–3.8 (the outline's
3.1–3.6 numbering was superseded):

- **Replay primitives** (`saq/analysis/module_execution_delta.py`):
  `from_cache_hit` and `cached_at` fields, a `has_file_observables` property,
  and `with_cache_hit_metadata(executed_at, execution_time_ms, root_uuid,
  observable_uuid)` — which produces the attribution delta recorded on a hit. It
  rewrites `created_at` to the replay time, preserves the original capture time
  in `cached_at`, and rewrites `root_uuid`/`observable_uuid` to the *current*
  alert (without the UUID rewrite, GUI badge lookups against the replayed
  analysis fail).
- **Snapshot Step 3.0** (`saq/analysis/snapshot.py`): the snapshot now captures
  each analysis's `delayed` flag, and `ModuleExecutionDelta.diff()` captures the
  analysis dict on a `delayed: True→False` transition. This is what makes
  delayed-analysis modules cacheable — the first (incomplete) cycle is refused
  at write time, and only the final post-delay delta is stored.
- **Snapshot Step 3.1**: `_serialize_analysis()` now includes `analysis.details`
  (and a round-trip-clean `summary_details`), closing the Phase 2 gap where a
  cached delta couldn't reproduce the module's bulk output.
- **Cache module** (`saq/analysis/cache.py`): **Step 3.2** refuses to write a
  delta whose analysis is still `delayed` (INFO, expected for delayed modules);
  **Step 3.3** refuses to write a delta that would spawn file observables
  (Phase 4); **Step 3.4** `get_cached_delta()` → `CacheLookupResult` with a
  legacy-shape guard (pre-Step-3.1 rows lacking `details` are treated as a miss
  and drain naturally), blob-ref inlining, and a cache-key recomputation check;
  **Step 3.5** `apply_delta()` — idempotent additive replay that rehydrates the
  Analysis via `SPLIT_MODULE_PATH` (slot-collision skip; `UnknownAnalysis`
  fallback on import failure), spawns new observables as children of it, and
  applies the observable/root diffs.
- **Executor Step 3.6** (`saq/engine/executor.py`): the cache-hit short-circuit
  sits between the is-analysis-failed check and the live `analyze()` call. On a
  hit, `_apply_cached_delta` replays + records the `from_cache_hit=True`
  attribution delta + bumps per-(root, module) counters, then
  `_process_generated_analysis(COMPLETED)` runs and the root is saved. The whole
  block is wrapped so a replay error logs a warning and **falls through to a
  live run** — a replay bug must never poison error reports or block analysis.
  New observables from replay queue through the normal `EVENT_OBSERVABLE_ADDED`
  → `work_stack_buffer` path; no cache-specific queueing.
- **Step 3.8 CI lint** (`tests/saq/modules/test_cacheable_modules_contract.py`):
  scans shipped YAML for `cache_ttl` and asserts each opt-in module is registered
  in `CONTRACT_CHECKERS` and produces no removals and no file observables.
  Adding `cache_ttl` to a module without a contract entry fails CI. (Downstream
  integrations can ship a parallel overlay test for their own opt-ins.)
- **Structured logging** (`saq/logging.py`): new `ExtraAwareFluentFormatter`
  surfaces `extra={}` as top-level JSON fields for Splunk; all Phase 2/3
  telemetry call sites were converted to `extra=`, and the field `module=` was
  renamed to `module_name=` (Python's `LogRecord` reserves `module`).
  (These call sites originally repeated every field as `key=value` text in the
  message as well. They no longer do: `ExtraAwareTextFormatter` renders `extra={}`
  on the plain-text configs too, so the rule is now *the message text describes
  the event, `extra={}` carries the fields*. Assert on `LogRecord` attributes,
  not on message substrings.)

**Explicitly NOT in PR #211** (status as of PR #211): phishkit read-side opt-in
(*since shipped 2026-06-29 — see the Phishkit opt-in notes*); the tool-version
`extended_version` helper (`saq/modules/tool_version.py` did not yet exist —
*since shipped in Phase 4 with the OCR/QR opt-ins*); and Phase 3.5 single-flight
dedup (no `analysis_cache_pending` table or `claim_pending` — *still unshipped,
deliberately parked; see §A9*).

**Files touched:** `saq/analysis/cache.py`, `saq/analysis/module_execution_delta.py`,
`saq/analysis/snapshot.py`, `saq/engine/executor.py`, `saq/logging.py`,
`saq/util/maintenance.py`, `etc/logging_configs/ace_logging.yaml`, plus
`tests/saq/analysis/test_apply_delta.py`, `test_cache_lookup.py`,
`tests/saq/engine/test_executor_cache_hit.py`,
`tests/saq/modules/test_cacheable_modules_contract.py`, `tests/saq/test_logging.py`.

### Metrics rework (PR #242, merged 2026-05-17)

The first cut of Phase 3 emitted a plain `logging.info` line per cache event
(`"analysis cache hit"`, `"analysis cache miss"`, `"wrote analysis cache
entry"`). With only whois opted in that was ~210 events/day, but it would scale
to 30–300 GB/day of Splunk ingest as more modules opted in. PR #242 removed
those per-event lines and instead **aggregates per-(root, module) activity onto
the existing per-root summary event** (`record_execution_statistics` in
`saq/engine/executor.py`). Each `(root, module)` row gained:

`exec_count`, `cache_hit_count`, `cache_miss_count`, `cache_write_count_insert`,
`cache_lookup_ms_sum` / `cache_lookup_ms_max`, `cache_lookup_key_ms_sum` /
`cache_lookup_db_ms_sum` / `cache_lookup_decode_ms_sum` / `cache_lookup_blob_ms_sum`,
`cache_write_ms_sum` / `cache_write_ms_max`, `cache_write_bytes_uncompressed_sum` /
`cache_write_bytes_compressed_sum`, plus `alert_type`, `is_alert`, `queue`.

Cache fields are only attached when the (root, module) actually had cache
activity, so non-cacheable modules pay no byte cost.

> **`lookup_ms` breakdown (2026-07-01):** `cache_lookup_ms_sum` is decomposed
> into four component sums so the payoff panel can show *where* a module's
> lookup cost goes. `cache_lookup_db_ms_sum` (the SELECT),
> `cache_lookup_decode_ms_sum` (zstd decompress + JSON + `from_dict`), and
> `cache_lookup_blob_ms_sum` (spilled-details inline + per-file
> `blob_store.exists` — the S3 round-trip cost) are sub-intervals of the timed
> region and together stay `<= cache_lookup_ms_sum` (each is floored to whole ms
> and the region also holds untimed glue). `cache_lookup_key_ms_sum` is
> **separate and additive**: `generate_cache_key` (which probes each module's
> external tools via `extended_version`) runs *before* the `lookup_ms` timer, so
> it was previously invisible — true per-lookup cost ≈
> `cache_lookup_ms_sum + cache_lookup_key_ms_sum`. Stack the four per module to
> tell blob-store I/O (S3) apart from cache-key/tool-probe cost apart from DB.

> **Semantics change (2026-06-10):** `cache_lookup_ms_sum`/`_max` now
> accumulate on **misses as well as hits** (and are emitted whenever there
> were lookups, not only hits). A miss's lookup time is the cache's pure
> overhead on top of the live run — exactly what the per-module
> lookup-cost-vs-live-cost payoff comparison needs. Divide by
> `(cache_hit_count + cache_miss_count)`, not hits, for a per-lookup
> average. The aggregation is held on
`EngineExecutionContext` counters and flushed at end-of-root. PR #242 also
fixed the per-root `count`/latency semantics (it was counting
`(root, context)` pairs, not individual `analyze()` invocations). Note
`exec_count` counts `analyze()` *invocations*, so a delayed-analysis module
that runs across several cycles for one observable contributes more than one.

> Note: PR #242 originally also emitted `cache_write_count_update` (insert vs
> upsert, from MySQL `rowcount`). PR #279 made the cache append-only, so writes
> are always inserts now — only `cache_write_count_insert` remains in the code.

### Empty-delta + `observable.time` cache fix (PR #262, merged 2026-05-21)

Two independent causes of unbounded `analysis_result_cache` growth, both fixed
in `saq/analysis/cache.py` with no schema change:

1. **Empty deltas were cached.** The executor already skipped *recording* an
   empty delta into `root.json` (the Phase 1 `is_empty` filter), but
   `put_cached_delta` had no equivalent guard — so a broad-population module
   wrote one no-op row per observable it merely looked at. PR #262 added the
   empty-delta refusal to the write path. (See §A4.)
2. **`observable.time` was in the cache key.** Observable types that carry an
   event timestamp got a distinct key per occurrence, so the same value never
   deduplicated and the table grew ~one row per occurrence. PR #262 dropped
   `observable.time` from `generate_cache_key`. (See §8.)

### Read-side opt-ins (current state)

`whois_analyzer` was the Phase 2.5 write-only bake subject but is **no longer
opted in** (its `cache_ttl` is commented out in `etc/saq.yaml`). The standing
read+write opt-ins in `etc/saq.default.yaml` are:

| Module | `cache_ttl` | Invalidation beyond TTL |
|--------|-------------|--------------------------|
| `analysis_module_rdap_analyzer` | 604800 (7d) | none (pure value lookup) |
| `analysis_module_nrd_analyzer` | 86400 (24h) | `extended_version` — backing DB file mtime+size |
| `analysis_module_site_tagger` | 2592000 (30d) | `extended_version` — analyst CSV mtime+size |

`extended_version` is implemented as a property on `AnalysisModule`
(`saq/modules/base_module.py`, delegated via `saq/modules/adapter.py`), with the
file-hash flavor in `saq/modules/nrd.py` and `saq/modules/tag.py` — the §A5
pattern, now real. Each opt-in has a `CONTRACT_CHECKERS` entry in the Step 3.8
lint. Downstream integrations may opt additional modules in via their own
overlay configs, guarded by a parallel overlay contract test.

## Phase 2 follow-up: cache moved to a dedicated partition-managed database (PR #279)

PR #279 (merged 2026-05-27) re-shaped the
storage and lifecycle of the cache before the Phase 2.5 firehose was turned
on. The Phase 2 + hardening design stored cache rows in the main `ace`
database, keyed uniquely on `cache_key`, upserted on write, and reclaimed by a
batched delete sweep. That shape does not survive the intended scale: the cache
is expected to grow to billions of rows, where row-by-row `DELETE` sweeps and
`COUNT(*)`/`SUM(...)` stats both become pathological. PR #279 addresses storage
isolation, write semantics, lifecycle, and observability together. Five change
areas:

**1. Separate database.** `analysis_result_cache` and `blob_refs` moved out of
the `ace` schema into a dedicated `analysis-result-cache` database
(`analysis-result-cache-unittest` for tests). The ORM models bind to a new
declarative base `CacheBase` (`saq/database/meta.py`) instead of the main
`Base`, and all cache access routes through `get_db(DB_ANALYSIS_RESULT_CACHE)`
(`DB_ANALYSIS_RESULT_CACHE = "analysis_result_cache"`, `saq/constants.py`),
which resolves the new `database_analysis_result_cache` connection block in
`etc/saq.default.yaml`. `sql/04-analysis-result-cache.sql` creates the empty
database (tables come from Alembic); grant templates under `sql/templates/` and
a `sql/tools/reset_analysis_result_cache_database.sql` round out the bootstrap.
Isolating the cache keeps its multi-billion-row growth, partition DDL, and
backup characteristics off the operational tables.

**2. Append-only writes.** The table is `PARTITION BY RANGE COLUMNS(created_at)`
(daily, `pYYYYMMDD`). MySQL requires the partitioning column in every unique
key, so the primary key became the composite `(cache_key, created_at)` —
`cache_key` is no longer unique. The write path is therefore a plain `INSERT`
(`put_cached_delta`, `CacheWriteResult.op` is always `"insert"`); the
`INSERT ... ON DUPLICATE KEY UPDATE` upsert is gone. A repeat analysis of the
same observable appends another row, several non-expired rows can share a
`cache_key`, and the read path resolves the winner with
`WHERE cache_key=? AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`
(`get_cached_delta`; the ordering column changed from `expires_at` to
`created_at` on 2026-06-10 — see the key-v2 notes at the end of Part II). `blob_refs` likewise gained `created_at` in its PK
(`(sha256, referrer_kind, referrer_id, created_at)`) and is partitioned the same
way. Open-question 5's "last-write-wins on concurrent fills" still holds —
realized now by read ordering + partition drop rather than by upsert.

**3. Lifecycle by partition drop, not delete sweep.** Removed:
`saq/analysis/cache.py::prune()`, `delete_for_module()`, the
`prune_expired_cache_rows`/`prune_analysis_result_cache` functions and their
backward-compat alias in `saq/util/maintenance.py`, the
`analysis_cache.prune_batch_size` config field, the `bin/analysis-cache-prune`
wrapper, the `ace analysis-cache-prune` subparser, and the 5-minute prune cron.
Added: `bin/manage-analysis-result-cache-partitions.sh` (run daily via
`etc/cron.yaml`) and the `analysis_cache.partition_retention_days` config field
(default 35). The partition-drop mechanism — daily `pYYYYMMDD` partitions, the
`p_catchall` reorganize, the future-day provisioning, the retention-must-exceed-
`cache_ttl` invariant, and the retained read-time `expires_at` filter — is
described in full in §A8; this PR is where it shipped.

**4. Stats off `INFORMATION_SCHEMA.PARTITIONS`, not `COUNT(*)`.** `collect_stats()`
now reads per-partition InnoDB row/byte estimates (O(partitions), ~10%
approximate) instead of `COUNT(*)`/`SUM(...)` table scans. The `cache_stats`
heartbeat dropped the fields that depended on aggregates or the prune sweep —
`expired_rows`, `total_uncompressed_bytes`, `modules_with_entries`, and the
`prune_backlog` warning are gone. It now reports only `total_rows`,
`total_on_disk_bytes`, and `blob_refs_rows`. The heartbeat moved off the
deleted prune cron onto its own `analysis-cache-stats` cron (every 15 min,
primary-node-gated), wired through `emit_cache_stats()`
(`saq/util/maintenance.py`), `bin/analysis-cache-stats`, and the
`ace analysis-cache-stats` subparser.

**5. Alembic reorganized into two environments.** The single `alembic/versions/`
tree was split into `alembic/ace/` (config `alembic/ace.ini`, the main DB) and
`alembic/analysis_cache/` (config `alembic/analysis_cache.ini`, the cache DB).
The Makefile gained `cache-db-revision` / `cache-db-upgrade` /
`cache-db-downgrade` / `cache-db-check` targets (each `-c alembic/analysis_cache.ini`),
and the existing `db-*` targets now pass `-c alembic/ace.ini` explicitly.
Migration `alembic/ace/versions/dbae3bc8cdd5_analysis_cache_refactor.py` drops
the old `analysis_result_cache` + `blob_refs` tables from the `ace` DB;
`alembic/analysis_cache/versions/f02202283a3c_initial_version.py` recreates them
in the cache DB with the composite PKs. CI (`.github/workflows/check-migrations.yml`,
`check-model-drift.yml`) was updated to loop over both Alembic configs so each
environment is independently checked for forked heads / model drift.

**Unchanged by PR #279.** zstd compression, `details_spill_bytes` blob spill,
`max_compressed_bytes` refusal, the removals/empty/file-observable/delayed
refusal gates, the `BlobStore` interface and reference-counting, the
`gc_durable_blobs` / `maintain_local_cache` crons and their `is_primary_node()`
gating, the cacheability contract, and `observable.time` exclusion from the key.

**Upgrade.** PR #279 carries operator upgrade instructions (recreate the docker
volumes for dev, or create the `analysis-result-cache` database in place, grant
`ace-user`, and add the `database_analysis_result_cache` password). They are not
reproduced here — see the PR description.

## Capture/replay hardening (2026-06-10)

A fresh-eyes design review of this document against the shipped code found
three latent correctness gaps, one live bug, and a size regression in the
delta capture/replay layer. All five were fixed in one pass (branch
`mw/analysis-cache-replay-fixes`); none changed the cache schema.

**1. root.json no longer duplicates `analysis.details` (size).** Step 3.1's
details inlining flowed into *both* serializations of a delta — the cache row
(intended) and the `module_executions` attribution log in root.json
(unintended duplication: the analysis tree already persists details once).
Measured before the fix on real dev alerts, `module_executions` had grown to
**43–62% of data.json** (vs the 29% recorded after Phase 1), with the
duplicated details accounting for 14–39% of the whole file. The executor now
records a details-stripped copy (`ModuleExecutionDelta.without_analysis_details()`)
for both live runs and cache-hit attribution; the cache write keeps the full
delta. Post-strip, the same alerts measure 22–30% — back to the Phase 1
envelope. The cache key is computed *before* recording so the stripped copy
still carries it. No reader breaks: the GUI badge map only consumes
identity/timing fields.

**2. Analysis-object tags are captured and replayed.** `analysis.add_tag(...)`
was invisible to the capture (the observable-level tag diff doesn't see it;
`_serialize_analysis` omitted it), so replays silently dropped analysis tags.
Now captured as a copied list in the analysis dict; replay restores them with
no code change through the existing `analysis.json` setter path. Analysis
detection points / pivot_links / llm_context_documents remain uncaptured —
deferred until a cacheable module needs them (detections require
DetectionPoint handling in `set_json_data`).

**3. Relationships replay across alerts.** Relationships were cached as
`{type, target-uuid}`, but uuids are per-alert — cross-alert replay could
never resolve the target and silently dropped every relationship (debug log).
The snapshot now records each target's `(type, value, time)` spec; replay
resolves uuid → self-target shortcut → spec (the shortcut exists because
`Observable.__eq__` compares `time` while the cache key ignores it).
`put_cached_delta` refuses out-of-scope relationship targets (§A4) and the
Step 3.8 contract lint asserts the same per opt-in.

**4. Delayed-analysis caching: live bug + completeness (open question 3).**
(a) *Bug:* a module delaying 2+ times produces intermediate deltas with
`analysis=None`, which slipped past the still-delayed write refusal (it
inspects the analysis dict) — partial mid-delay results were being cached.
The executor cache write (now `_maybe_write_cache_delta`) is gated on the
module returning COMPLETED. (b) *Completeness:* the final cycle's diff only
covers the final cycle, so pre-delay tags/observables were missing from the
cached delta. On a delayed resume the prior cycles' recorded deltas are
merged in (`merge_module_execution_deltas`), with removals merged too so a
cycle-1 removal refuses the whole write. Prior deltas come from
`root.module_executions`, which persists through root.json — so the merge
works even when the resume happens in a different process.

**5. `is_grouped_by_time` + `cache_ttl` rejected at config load** — a cache
hit bypasses `analysis_covered()`, making the combination incoherent (§A1).

**Verification.** 60+ new/extended unit+integration tests across
`test_module_execution_delta.py` (merge semantics, strip), `test_snapshot.py`
(tag/relationship-spec capture), `test_apply_delta.py` (spec resolution,
tag rehydration), `test_cache.py` (scope refusal), `test_executor_cache_hit.py`
(COMPLETED gate, merge wiring, stripped attribution). End-to-end in dev:
`ace correlate` of a site_tagger-matching FQDN twice — first run recorded a
details-stripped delta in root.json while the cache row carried details;
second run replayed from cache (`from_cache_hit=True`) with the tag and
analysis slot intact.

## Cache key v2 + read ordering + payoff metrics (2026-06-10)

The second half of the same review pass, shipped separately so the key
rotation isn't entangled with the replay-behavior changes above.

**Key format v2** (§8): delimited `label:length:bytes` hashing under a
format-version constant, extended_version *keys* now participate (v1
collided `{"tool_a": "1.0"}` with `{"tool_b": "1.0"}`), and the module's
resolved config is hashed in (minus `CONFIG_HASH_EXCLUDED_FIELDS`) so a
YAML config edit invalidates without a `version` bump. All v1 rows became
unreachable on deploy and age out with their partitions — by design, the
key-format bump *is* the migration.

**Read ordering** (§5/§A8): `ORDER BY created_at DESC` replaces
`expires_at DESC`. The old ordering preferred the longest-lived row, which
after a `cache_ttl` reduction is the *oldest* data — old long-TTL rows
shadowed fresher results until they expired. Freshest-created now wins;
the clustered PK `(cache_key, created_at)` serves it in index order.

**Payoff metrics**: `cache_lookup_ms_sum`/`_max` accumulate on misses too
(see the PR #242 note), and the Splunk dashboard gained a "Cache Payoff:
Lookup Cost vs Live Cost by Module" panel comparing per-lookup cost
against per-execution live cost, with
`est_net_saved_s = hits*avg_live_ms − total_lookup_ms`. Purpose: decide
empirically whether microsecond-cheap opt-ins (nrd_analyzer, site_tagger
— chosen as low-risk bake vehicles for `extended_version`, not for
payoff) cost more in lookups than they save, and de-opt them if so.
rdap_analyzer (network-bound) is expected to be strongly positive.

**Not in this pass**: §A9/Phase 3.5 remain design-only — rewritten here to
the non-blocking delayed-analysis requeue shape with a `single_flight`
opt-in flag, replacing the original blocking `wait_for_cache` poll loop.

## Pre-3.5 cleanup: qrcode consult gate + effective hit rate (2026-06-25)

Two cleanups surfaced while reviewing the Phase 4 bake telemetry, landed
ahead of Phase 3.5 (which they don't depend on).

**qrcode was cache-consulted for files it never scans.** `QRCodeAnalyzer`
declares `valid_observable_types = F_FILE` but only ever scans images and
PDFs (the type check lived *inside* `execute_analysis`). Because the executor
consults the cache only after `accepts()` passes (`_check_module_acceptance`
at `executor.py:1261` precedes `get_cached_delta` at `:1290`), every
non-image/non-PDF file (`.eml`, `.html`, headers, `.msg`, …) incurred a cache
lookup that always missed and — being an empty delta — never wrote a row.
Production telemetry: qrcode `execs == misses == ~1.56M/day` with only ~37K
writes (2.4% write/miss) vs OCR's 97.8%, i.e. ~1.53M wasted lookups/day. Its
*effective* hit rate `hits/(hits+writes)` was ~88%, on par with OCR — the
~15% raw rate was a denominator artifact. Fix: a `custom_requirement` on
`QRCodeAnalyzer` that gates on image/PDF (cheap magic-byte / PIL header
sniff) before scheduling, so those files are no longer routed or consulted.
The image/PDF gate inside `execute_analysis` stays as a defensive check. OCR
was left alone — identical code shape but it does not exhibit the firehose in
practice.

**Effective hit rate on the dashboard.** Every hit-rate panel computed
`hits/(hits+misses)`, which understates any consult-broad/scan-narrow module.
Added an "Effective Cache Hit Rate" single-value tile and an
`effective_hit_rate_pct = hits/(hits+writes)` column on the per-module tables
(hit/miss, reality check, payoff). `writes` = `cache_write_count_insert`
≈ real-scan misses, so the metric reflects the workload actually scanned.
