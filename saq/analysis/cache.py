"""Analysis result cache — write path, key generation, lookup/replay.

This module persists ``ModuleExecutionDelta`` records from successful module
executions so that future analyses of the same observable can reuse the work.
Phase 2 ships the write path only; reads/replay land in Phase 3.

Cacheability contract (design doc §A1): a module's output must be a pure
function of ``(observable.type, observable.value, module.name,
module.version, module.extended_version)``. Modules that mutate other
observables or depend on surrounding tree state must leave
``cache_ttl = None``. ``observable.time`` is deliberately NOT part of the
key — cacheable modules produce time-independent results, and result drift
over time is bounded by ``cache_ttl`` rather than by time-segmenting the
key. The caller additionally refuses to cache deltas that contain removals
(§A4) or are empty (nothing to replay) as a safety net.

Size discipline (design doc §A3):

- Every delta is zstd-compressed before it hits the DB. Compression level is
  tunable via ``analysis_cache.zstd_level``.
- ``analysis.details`` dicts larger than
  ``analysis_cache.details_spill_bytes`` (uncompressed) are spilled
  to the blob store and replaced with a ``{"__blob_ref__": "<sha>"}``
  pointer in the cached delta.
- Compressed deltas over ``analysis_cache.max_compressed_bytes``
  are refused outright and logged as a warning.
"""

import hashlib
import importlib
import json
import logging
import os
import shutil
import tempfile
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, NamedTuple, Optional

import zstandard
from sqlalchemy import func, select, text
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.analysis.analysis import Analysis as _Analysis, UnknownAnalysis
from saq.analysis.blob_store import (
    REFERRER_KIND_CACHE_ROW,
    BlobNotFound,
    BlobStore,
    get_blob_store,
)
from saq.analysis.module_execution_delta import ModuleExecutionDelta, ObservableSpec
from saq.analysis.module_path import SPLIT_MODULE_PATH
from saq.configuration.config import get_config
from saq.constants import DB_ANALYSIS_RESULT_CACHE, F_FILE, FILE_SUBDIR
from saq.database.model import AnalysisResultCache
from saq.database.pool import get_db
from saq.util import parse_event_time

if TYPE_CHECKING:
    from saq.analysis.observable import Observable
    from saq.analysis.root import RootAnalysis


# Cache-key format version, hashed into every key. Bump whenever the key
# derivation changes — existing rows become unreachable (their keys are
# never generated again) and age out with their daily partitions. No
# migration is ever needed for a key-format change.
CACHE_KEY_FORMAT = "ace-analysis-cache-key-v2"

# AnalysisModuleConfig base-class fields excluded from the config hash.
# Two categories: operational knobs that don't change a module's output,
# and eligibility filters that gate WHETHER the module runs — the executor
# applies those before any cache lookup, so they can't change what a
# cached result should contain. Everything else, crucially including any
# module-specific field a config subclass adds (the get_config_class()
# pattern), participates in the key — so an analyst editing a module's
# YAML config invalidates that module's cache without a version bump.
CONFIG_HASH_EXCLUDED_FIELDS = frozenset({
    # identity — carried as separate key fields already
    "name", "version",
    # operational
    "enabled", "description", "priority", "automation_limit",
    "maximum_analysis_time", "cooldown_period", "semaphore_name",
    "cache_ttl", "default_collapsed",
    # eligibility filters (pre-execution gates, orthogonal to output)
    "observable_exclusions", "expected_observables", "is_grouped_by_time",
    "observation_grouping_time_range", "file_size_limit",
    "valid_observable_types", "valid_queues", "invalid_queues",
    "invalid_alert_types", "required_directives", "required_tags",
    "requires_detection_path", "wide_diff",
})


def _config_hash(module) -> str:
    """sha256 over the module's resolved config, minus operational and
    eligibility fields (see CONFIG_HASH_EXCLUDED_FIELDS).

    Computed per call — a pydantic model_dump + json.dumps of a small
    config model is microseconds, negligible next to the DB lookup that
    follows. Returns "none" for config objects without model_dump (test
    stubs); python_module/python_class stay included so an implementation
    swap invalidates too.
    """
    config = getattr(module, "config", None)
    if config is None or not hasattr(config, "model_dump"):
        return "none"
    dumped = config.model_dump(mode="json")
    filtered = {k: v for k, v in dumped.items() if k not in CONFIG_HASH_EXCLUDED_FIELDS}
    serialized = json.dumps(filtered, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def generate_cache_key(observable: "Observable", module) -> Optional[str]:
    """sha256 over observable identity + module identity + module config +
    extended version (key format v2).

    Each component is hashed as ``label:length:bytes`` so field boundaries
    are unambiguous (the v1 format concatenated raw values — and hashed
    only extended_version *values*, so ``{"tool_a": "1.0"}`` and
    ``{"tool_b": "1.0"}`` collided).

    NOTE ``observable.time`` is deliberately excluded from the key — a
    cacheable module's output must be a pure function of the observable
    *value*; staleness is bounded by ``cache_ttl`` (design doc §8).

    Returns None when the module hasn't opted into caching.
    """
    if module.cache_ttl is None:
        return None

    h = hashlib.sha256()

    def _update(label: str, value: str) -> None:
        encoded = value.encode("utf-8", "ignore")
        h.update(f"{label}:{len(encoded)}:".encode("utf-8"))
        h.update(encoded)

    _update("format", CACHE_KEY_FORMAT)
    _update("type", observable.type)
    _update("value", observable.value)
    _update("module", module.config.name)
    _update("version", str(module.version))
    _update("config", _config_hash(module))
    # extended_version is an un-memoized property: each access re-probes the
    # module's external tools (e.g. qrcode shells out to zbarimg/gs/pdfinfo and
    # hashes its filter file). Evaluate it exactly once — accessing it per key
    # rebuilt it O(keys) times and dominated cache-key (hence lookup) latency
    # for tool-heavy modules.
    ext = module.extended_version
    for key in sorted(ext):
        _update(f"ext:{key}", ext[key])
    return h.hexdigest()


class CacheWriteResult(NamedTuple):
    """Metadata returned by :func:`put_cached_delta` on a successful write.

    Callers use this to bump per-(root, module) counters on the
    :class:`EngineExecutionContext` — the actual metric emission happens at
    end-of-root in ``record_execution_statistics``.
    """
    op: str  # NOTE always "insert" — cache is append-only
    write_ms: int
    uncompressed_bytes: int
    compressed_bytes: int


def _maybe_spill_details(delta_dict: dict, blob_store: BlobStore, cache_key: str) -> bool:
    """Move ``delta_dict['analysis']['details']`` into the blob store when it exceeds the spill threshold.

    Mutates ``delta_dict`` in place: ``details`` is replaced with a
    ``{"__blob_ref__": "<sha>"}`` pointer, and a ``blob_refs`` row is written
    linking the blob to the cache key.

    Returns True if a spill happened (i.e. the cache row has blob refs).
    """
    analysis = delta_dict.get("analysis")
    if not isinstance(analysis, dict):
        return False

    details = analysis.get("details")
    if details is None:
        return False

    # Serialize separately so we can both measure and avoid double-serializing.
    details_bytes = json.dumps(details, sort_keys=True, default=str).encode("utf-8")
    threshold = get_config().analysis_cache.details_spill_bytes
    if len(details_bytes) < threshold:
        return False

    sha = blob_store.put(details_bytes)
    blob_store.reference(sha, REFERRER_KIND_CACHE_ROW, cache_key)
    analysis["details"] = {"__blob_ref__": sha}
    return True


def put_cached_delta(
    delta: "ModuleExecutionDelta",
    module,
    blob_store: BlobStore,
    root: Optional["RootAnalysis"] = None,
) -> Optional[CacheWriteResult]:
    """Persist a successful module execution's delta.

    Returns a :class:`CacheWriteResult` if a cache row was written, ``None``
    otherwise.

    ``root`` is the source alert the module ran against. Required when the
    delta spawns file observables (Phase 4): the produced files' bytes are
    read from the root's file dir and stored in the blob store so replay
    can materialize them into a different alert. A file-bearing delta with
    no ``root`` is refused.

    All DB failures are caught and logged — this function must never raise
    into the executor.
    """
    try:
        if module.cache_ttl is None:
            return None

        # don't cache empty deltas
        if delta.is_empty:
            return None

        if delta.has_removals:
            logging.warning(
                "refusing to cache delta",
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "refusal_reason": "removals",
                },
            )
            return None

        # Refuse relationships that point outside the delta's own scope
        # (anything other than the analyzed observable or an observable
        # this delta created). Such a relationship depends on surrounding
        # tree context that a replay onto a different root cannot
        # guarantee — replaying it would silently drop the relationship
        # or attach it to the wrong node.
        out_of_scope = delta.out_of_scope_relationship_targets()
        if out_of_scope:
            logging.warning(
                "refusing to cache delta",
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "refusal_reason": "relationship_out_of_scope",
                    "relationship_count": len(out_of_scope),
                },
            )
            return None

        # Step 3.2: refuse to cache deltas captured mid-delay. Replay path
        # unconditionally marks the analysis completed — caching a delayed
        # analysis would lie. Combined with snapshot Step 3.0, the only
        # delta that survives this gate for a delayed-analysis module is
        # the final post-delay one, which is exactly what we want to cache.
        # INFO not WARNING — for delayed modules this fires once per
        # intermediate cycle and is expected behavior.
        if delta.analysis is not None and delta.analysis.get("delayed"):
            logging.info(
                "skipping cache write",
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "skip_reason": "still_delayed",
                },
            )
            return None

        # Phase 4: deltas that spawn file observables are cacheable — their
        # content goes into the blob store (keyed by spec.value, which IS
        # the file's sha256) and is materialized into the target root on
        # replay. Validate that every file spec is blob-backable before
        # touching the store; any failure refuses the whole delta.
        file_specs = delta.file_observable_specs()
        refusal_reason = _validate_file_specs(file_specs, root) if file_specs else None
        if refusal_reason is not None:
            logging.warning(
                "refusing to cache delta",
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "refusal_reason": refusal_reason,
                },
            )
            return None

        # NOTE this comes after the previous checks so we can get visibility
        # into the reason for skipping the cache write
        if not get_config().analysis_cache.enabled:
            return None

        cache_key = delta.cache_key
        if cache_key is None:
            # Caller didn't set it — compute now.
            cache_key = generate_cache_key(_ObservableShim(delta), module)
            delta.cache_key = cache_key

        if cache_key is None:
            return None

        delta_dict = delta.to_dict()
        has_blob_refs = _maybe_spill_details(delta_dict, blob_store, cache_key)

        # Phase 4: store each produced file's bytes in the blob store.
        # exists() short-circuits re-uploading content the store already
        # holds (deterministic modules produce identical bytes; the spec
        # value is the content sha256). put() re-hashes — a mismatch means
        # the file changed on disk after the observable hashed it, and the
        # delta can no longer be trusted.
        for spec in file_specs:
            full_path = _file_spec_source_path(root, spec)
            if not blob_store.exists(spec.value):
                with open(full_path, "rb") as fp:
                    stored_sha = blob_store.put(fp)
                if stored_sha != spec.value:
                    logging.warning(
                        "refusing to cache delta",
                        extra={
                            "module_name": module.config.name,
                            "observable_type": delta.observable_type,
                            "observable_value": delta.observable_value,
                            "refusal_reason": "file_hash_mismatch",
                            "file_path": spec.file_path,
                            "expected_sha256": spec.value,
                            "actual_sha256": stored_sha,
                        },
                    )
                    _unreference_blob_refs(delta_dict, blob_store, cache_key)
                    return None
            blob_store.reference(spec.value, REFERRER_KIND_CACHE_ROW, cache_key)
            has_blob_refs = True

        analysis_cache = get_config().analysis_cache
        zstd_level = analysis_cache.zstd_level
        max_compressed_bytes = analysis_cache.max_compressed_bytes

        delta_json = json.dumps(delta_dict, sort_keys=True, default=str).encode("utf-8")
        uncompressed_size = len(delta_json)
        compressor = zstandard.ZstdCompressor(level=zstd_level)
        delta_zstd = compressor.compress(delta_json)

        if len(delta_zstd) > max_compressed_bytes:
            logging.warning(
                "refusing to cache delta",
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "refusal_reason": "size_cap",
                    "compressed_bytes": len(delta_zstd),
                    "max_compressed_bytes": max_compressed_bytes,
                },
            )

            # If we took blob references (spilled details / file content)
            # but are bailing out, drop them.
            if has_blob_refs:
                _unreference_blob_refs(delta_dict, blob_store, cache_key)
            return None

        ttl_seconds = int(module.cache_ttl.total_seconds())

        # The cache is append-only. analysis_result_cache is partitioned by
        # created_at, which forces created_at into the primary key, so cache_key
        # is no longer unique on its own and an upsert is not possible. A repeat
        # analysis of the same observable just inserts another row — get_cached_delta
        # picks the freshest non-expired one and partition drops reclaim the rest.
        # Last write wins; both results are valid by construction (design doc
        # §open-question 5). expires_at is computed on the DB to avoid clock drift.
        stmt = mysql_insert(AnalysisResultCache).values(
            cache_key=cache_key,
            module_name=module.config.name,
            module_version=module.version,
            observable_type=delta.observable_type,
            observable_value=delta.observable_value,
            delta_zstd=delta_zstd,
            delta_uncompressed_size=uncompressed_size,
            has_blob_refs=has_blob_refs,
            expires_at=func.date_add(
                func.now(),
                text("INTERVAL :ttl SECOND").bindparams(ttl=ttl_seconds),
            ),
        )
        write_start_ns = time.monotonic_ns()
        get_db(DB_ANALYSIS_RESULT_CACHE).execute(stmt)
        get_db(DB_ANALYSIS_RESULT_CACHE).commit()
        write_ms = (time.monotonic_ns() - write_start_ns) // 1_000_000

        return CacheWriteResult(
            op="insert",
            write_ms=write_ms,
            uncompressed_bytes=uncompressed_size,
            compressed_bytes=len(delta_zstd),
        )
    except Exception:
        module_name = getattr(getattr(module, "config", None), "name", "<unknown>")
        logging.warning(
            "failed to write analysis cache entry",
            exc_info=True,
            extra={"module_name": module_name},
        )
        try:
            get_db(DB_ANALYSIS_RESULT_CACHE).rollback()
        except Exception:
            pass
        return None


def collect_stats() -> dict:
    """Snapshot the cache tables for observability via INFORMATION_SCHEMA.

    Row counts and byte totals come from per-partition InnoDB statistics
    rather than COUNT(*)/SUM(...) on the tables — at billion-row scale the
    aggregate queries would scan the whole table or index, while the
    statistics lookup is O(partitions). Counts are approximate (InnoDB
    estimates can drift by ~10%) which is acceptable for a 15-minute
    Splunk heartbeat.
    """
    rows = get_db(DB_ANALYSIS_RESULT_CACHE).execute(text("""
        SELECT TABLE_NAME,
               COALESCE(SUM(TABLE_ROWS), 0) AS row_count,
               COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) AS byte_count
          FROM INFORMATION_SCHEMA.PARTITIONS
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_NAME IN ('analysis_result_cache', 'blob_refs')
         GROUP BY TABLE_NAME
    """)).all()

    by_table = {name: (int(rc), int(bc)) for name, rc, bc in rows}
    cache_rows, cache_bytes = by_table.get("analysis_result_cache", (0, 0))
    blob_refs_rows, _ = by_table.get("blob_refs", (0, 0))

    return {
        "total_rows": cache_rows,
        "total_on_disk_bytes": cache_bytes,
        "blob_refs_rows": blob_refs_rows,
    }


class _ObservableShim:
    """Minimal Observable-like object so ``generate_cache_key`` can accept
    either a real Observable or the denormalized fields on a
    ``ModuleExecutionDelta`` when recomputing a lost key.
    """

    __slots__ = ("type", "value")

    def __init__(self, delta: "ModuleExecutionDelta"):
        self.type = delta.observable_type
        self.value = delta.observable_value


def _file_spec_source_path(root: "RootAnalysis", spec: ObservableSpec) -> str:
    """Full path to a file spec's backing bytes in the source alert."""
    return os.path.join(root.storage_dir, FILE_SUBDIR, spec.file_path)


def _validate_file_specs(file_specs: list[ObservableSpec], root) -> Optional[str]:
    """Returns a refusal reason when a file-bearing delta can't be
    blob-backed, None when all specs check out.

    Checked per spec: a captured ``file_path`` (a spec without one predates
    Phase 4 or came from a capture bug), the backing file still existing on
    disk (a module or cleanup job may have removed it between capture and
    cache write), and the per-file size cap (blob bytes are not covered by
    the compressed-delta size cap).
    """
    if root is None:
        return "file_observables_no_root"
    max_bytes = get_config().analysis_cache.file_blob_max_bytes
    for spec in file_specs:
        if not spec.file_path:
            return "file_spec_missing_path"
        full_path = _file_spec_source_path(root, spec)
        try:
            size = os.path.getsize(full_path)
        except OSError:
            return "file_missing"
        if max_bytes and size > max_bytes:
            return "file_too_large"
    return None


def _extract_blob_refs(delta_dict: dict) -> list[str]:
    """Pull every blob sha a serialized delta references — spilled
    ``analysis.details`` (``__blob_ref__`` pointers) and Phase 4 file
    observable specs (whose ``value`` is the content sha256).

    Only used for cleanup when a cache write is aborted after blobs were
    referenced.
    """
    refs = []
    analysis = delta_dict.get("analysis")
    if isinstance(analysis, dict):
        details = analysis.get("details")
        if isinstance(details, dict):
            sha = details.get("__blob_ref__")
            if sha:
                refs.append(sha)
    for spec_dict in delta_dict.get("new_observables", []):
        if spec_dict.get("type") == F_FILE and spec_dict.get("file_path"):
            refs.append(spec_dict["value"])
    return refs


def _unreference_blob_refs(delta_dict: dict, blob_store: BlobStore, cache_key: str) -> None:
    """Drop the blob references a delta took, after an aborted cache write.

    ``unreference`` is safe to call for refs that were never taken, so this
    can run regardless of how far the write got. Failures are logged — a
    leaked reference only delays blob GC until the blob_refs partition ages
    out.
    """
    for sha in _extract_blob_refs(delta_dict):
        try:
            blob_store.unreference(sha, REFERRER_KIND_CACHE_ROW, cache_key)
        except Exception:
            logging.warning(
                "failed to unreference blob after cache-write bailout",
                exc_info=True,
                extra={"sha256": sha},
            )


def _inline_blob_refs(delta_dict: dict, blob_store: BlobStore) -> None:
    """Inverse of ``_maybe_spill_details`` — walk the delta dict and replace
    every ``{"__blob_ref__": sha}`` pointer with the bytes from the blob
    store, parsed back to its original JSON shape.

    Mutates ``delta_dict`` in place. Raises ``BlobNotFound`` if any
    referenced blob is missing — caller (``get_cached_delta``) translates
    that into a cache miss.

    Currently only ``analysis.details`` ever spills, but the function is
    written to extend cleanly when other fields start spilling.
    """
    analysis = delta_dict.get("analysis")
    if not isinstance(analysis, dict):
        return

    details = analysis.get("details")
    if isinstance(details, dict) and "__blob_ref__" in details:
        sha = details["__blob_ref__"]
        with blob_store.get(sha) as fp:
            blob_bytes = fp.read()

        analysis["details"] = json.loads(blob_bytes.decode("utf-8"))


class CacheLookupResult(NamedTuple):
    """Result of a :func:`get_cached_delta` call.

    - On hit: ``delta`` is the cached ``ModuleExecutionDelta``,
      ``miss_reason`` is ``None``, ``lookup_ms`` is the wall time spent on
      the DB lookup + decompress + deserialize + any blob fetch.
    - On miss: ``delta`` is ``None``, ``miss_reason`` is one of
      ``"not_found"``, ``"decode_error"``, ``"legacy_no_details"``,
      ``"blob_missing"``. Caller increments ``cache_miss_count`` on the
      execution context.
    - On non-attempt (module not cacheable / cache disabled globally):
      ``delta`` is ``None``, ``miss_reason`` is ``None``, ``lookup_ms``
      is 0. Caller does not count this against cache_miss_count.

    ``cache_key_prefix`` is the first 12 hex chars of the cache key (or
    ``"n/a"`` when no lookup happened). Used by the executor to populate
    the per-(root, module) telemetry on cache hits without re-deriving
    the key.

    ``lookup_ms`` decomposes into three components measured within the
    timed region: ``db_ms`` (the SELECT), ``decode_ms`` (zstd decompress +
    JSON parse + ``ModuleExecutionDelta.from_dict``), and ``blob_ms``
    (spilled-details inline + per-file ``blob_store.exists`` — the S3 cost).
    These three sum to ``lookup_ms``. ``key_ms`` is measured SEPARATELY and
    is NOT part of ``lookup_ms``: ``generate_cache_key`` (which probes each
    module's external tools) runs before the ``lookup_ms`` timer starts, so
    it was previously invisible. True per-lookup cost ≈ ``lookup_ms +
    key_ms``. All four default to 0 for non-attempt returns.
    """
    delta: Optional[ModuleExecutionDelta]
    miss_reason: Optional[str]
    lookup_ms: int
    cache_key_prefix: str
    key_ms: int = 0
    db_ms: int = 0
    decode_ms: int = 0
    blob_ms: int = 0


def get_cached_delta(
    observable: "Observable",
    module,
    blob_store: BlobStore,
) -> CacheLookupResult:
    """Look up a cached ``ModuleExecutionDelta`` for ``(observable, module)``.

    Returns a :class:`CacheLookupResult`. See its docstring for the three
    possible shapes (hit, miss, non-attempt).

    All exceptions are caught — cache lookup is best-effort and must
    never propagate into the executor.
    """
    # generate_cache_key probes each module's external tools (e.g. qrcode
    # shells out to zbarimg/gs/pdfinfo), so it can be the dominant per-lookup
    # cost. It runs before lookup_start_ns below, so it is NOT part of
    # lookup_ms — key_ms captures it separately for the payoff breakdown.
    key_start_ns = time.monotonic_ns()
    cache_key = generate_cache_key(observable, module)
    key_ms = (time.monotonic_ns() - key_start_ns) // 1_000_000
    if cache_key is None:
        return CacheLookupResult(None, None, 0, "n/a", key_ms)

    if not get_config().analysis_cache.enabled:
        return CacheLookupResult(None, None, 0, "n/a", key_ms)

    module_name = getattr(getattr(module, "config", None), "name", "<unknown>")
    cache_key_prefix = cache_key[:12]
    lookup_start_ns = time.monotonic_ns()

    # db_ms + decode_ms + blob_ms sum to lookup_ms; each _timed block adds the
    # elapsed ms of exactly one measured call to its bucket.
    comp = {"db_ms": 0, "decode_ms": 0, "blob_ms": 0}

    def _elapsed_ms() -> int:
        return (time.monotonic_ns() - lookup_start_ns) // 1_000_000

    @contextmanager
    def _timed(bucket: str):
        start_ns = time.monotonic_ns()
        try:
            yield
        finally:
            comp[bucket] += (time.monotonic_ns() - start_ns) // 1_000_000

    def _result(delta, miss_reason) -> CacheLookupResult:
        return CacheLookupResult(
            delta, miss_reason, _elapsed_ms(), cache_key_prefix,
            key_ms, comp["db_ms"], comp["decode_ms"], comp["blob_ms"],
        )

    try:
        # The cache is append-only, so several non-expired rows can share a
        # cache_key; order by created_at DESC so the freshest *data* wins.
        # (Ordering by expires_at DESC — the original choice — breaks down
        # when a module's cache_ttl is reduced: rows written under the old,
        # longer TTL keep a later expires_at than any new row and shadow
        # fresher results until they expire.) The clustered PK is
        # (cache_key, created_at), so this is an index-order read.
        with _timed("db_ms"):
            row = get_db(DB_ANALYSIS_RESULT_CACHE).execute(
                select(
                    AnalysisResultCache.delta_zstd,
                    AnalysisResultCache.has_blob_refs,
                )
                .where(
                    AnalysisResultCache.cache_key == cache_key,
                    AnalysisResultCache.expires_at > func.now(),
                )
                .order_by(AnalysisResultCache.created_at.desc())
                .limit(1)
            ).first()

        if row is None:
            return _result(None, "not_found")

        delta_zstd, has_blob_refs = row
        try:
            with _timed("decode_ms"):
                delta_json = zstandard.ZstdDecompressor().decompress(delta_zstd)
                delta_dict = json.loads(delta_json.decode("utf-8"))
        except Exception:
            logging.warning(
                "failed to decode cached delta",
                exc_info=True,
                extra={
                    "module_name": module_name,
                    "cache_key_prefix": cache_key_prefix,
                },
            )
            return _result(None, "decode_error")

        # Step 3.4 legacy-shape guard: pre-Step-3.1 rows wrote
        # `analysis` dicts without a `details` key. Treat as miss so the
        # executor falls through to a live run; that run inserts a fresh
        # Step-3.1-shaped row, which then wins the created_at ordering above.
        analysis_in_dict = delta_dict.get("analysis")
        if isinstance(analysis_in_dict, dict) and "details" not in analysis_in_dict:
            return _result(None, "legacy_no_details")

        if has_blob_refs:
            try:
                with _timed("blob_ms"):
                    _inline_blob_refs(delta_dict, blob_store)
            except BlobNotFound as e:
                logging.warning(
                    "cached delta references missing blob",
                    exc_info=False,
                    extra={
                        "module_name": module_name,
                        "cache_key_prefix": cache_key_prefix,
                        "sha256": str(e),
                    },
                )
                return _result(None, "blob_missing")

        try:
            with _timed("decode_ms"):
                delta = ModuleExecutionDelta.from_dict(delta_dict)
        except Exception:
            logging.warning(
                "failed to deserialize cached delta",
                exc_info=True,
                extra={
                    "module_name": module_name,
                    "cache_key_prefix": cache_key_prefix,
                },
            )
            return _result(None, "decode_error")

        # Phase 4: a file-bearing delta is only usable if every produced
        # file's blob still exists (GC, deployment mismatch, or a failed
        # remote upload can lose one). Missing blob → miss, so the
        # executor falls through to a live run that re-populates both the
        # row and the blob. A spec without file_path predates Phase 4 (a
        # pre-Phase-4 build could never write one — file deltas were
        # refused — but guard anyway) → decode_error.
        for spec in delta.file_observable_specs():
            if not spec.file_path:
                logging.warning(
                    "cached delta has file spec without file_path",
                    extra={
                        "module_name": module_name,
                        "cache_key_prefix": cache_key_prefix,
                    },
                )
                return _result(None, "decode_error")
            with _timed("blob_ms"):
                blob_exists = blob_store.exists(spec.value)
            if not blob_exists:
                logging.warning(
                    "cached delta references missing file blob",
                    extra={
                        "module_name": module_name,
                        "cache_key_prefix": cache_key_prefix,
                        "sha256": spec.value,
                    },
                )
                return _result(None, "blob_missing")

        return _result(delta, None)

    except Exception:
        logging.warning(
            "cache lookup failed",
            exc_info=True,
            extra={
                "module_name": module_name,
                "cache_key_prefix": cache_key_prefix,
            },
        )
        return _result(None, "decode_error")


def apply_delta(
    root: "RootAnalysis",
    target_observable: "Observable",
    delta: ModuleExecutionDelta,
    blob_store: Optional[BlobStore] = None,
) -> None:
    """Apply a cached ``ModuleExecutionDelta`` to a target tree.

    Idempotent additive replay (design doc §5). Re-installs the analysis
    object on the target observable, adds any child observables (Phase 4:
    including file observables, whose bytes are materialized from the blob
    store into this root's file dir), copies over tags / detections /
    directives / relationships / excluded_analysis / limited_analysis,
    applies scalar transitions, and applies root-level additions. All
    primitives used are idempotent — calling ``apply_delta`` twice on the
    same root produces the same state as calling it once.

    Raises on blob-store failures (missing blob, I/O error) — the staging
    pass runs *before* any tree mutation, so a raise leaves the tree
    untouched and the executor's replay-failure handler falls through to a
    live run.

    Does NOT process ``other_observable_diffs`` or ``analysis_children_diffs``
    — those only exist on wide-diff captures, which are uncacheable by
    contract (``AnalysisModuleConfig`` rejects ``wide_diff + cache_ttl``).
    """
    # Defense-in-depth: wide-diff deltas should never reach this path
    # (config validation blocks the combination), but enforce explicitly.
    assert not delta.wide_diff, "wide_diff deltas are not cacheable"

    # 0. Phase 4 staging pass: materialize every produced file's bytes
    # into a temp dir under this root's storage_dir BEFORE any tree
    # mutation. On the local backend materialize() hardlinks, and staging
    # inside storage_dir keeps the later store_file(move=True) a same-FS
    # rename — the whole blob→staging→hardcopy→file_dir chain shares one
    # inode, zero byte copies.
    file_specs = delta.file_observable_specs()
    staging_dir = None
    staged_files: dict[str, str] = {}  # spec.uuid -> staged path
    if file_specs:
        if blob_store is None:
            blob_store = get_blob_store()
        staging_dir = tempfile.mkdtemp(prefix=".cache_replay_", dir=root.storage_dir)
        for spec in file_specs:
            staged_path = os.path.join(staging_dir, spec.uuid)
            blob_store.materialize(spec.value, staged_path)
            staged_files[spec.uuid] = staged_path

    try:
        # 1. Rehydrate the Analysis object first so step 2's new observables
        # can be hung off it as children (matching the live run's structure).
        # _rehydrate_analysis returns the freshly rehydrated analysis, the
        # pre-existing one when the slot-collision skip fires, or None when
        # the delta carries no analysis dict.
        rehydrated_analysis = _rehydrate_analysis(target_observable, delta)

        # 2. Spawn new observables. Parent is the rehydrated/preserved
        # analysis when we have one (matches the live run's parent-child
        # link), else fall back to the root. uuid_map translates
        # source-alert uuids to the observables created in THIS tree —
        # needed because replay-created observables get fresh uuids.
        parent_for_new = rehydrated_analysis if rehydrated_analysis is not None else root
        uuid_map: dict[str, "Observable"] = {delta.observable_uuid: target_observable}
        for spec in delta.new_observables:
            new_obs = _apply_observable_spec(
                parent_for_new, spec, staged_file=staged_files.get(spec.uuid),
            )
            if new_obs is not None:
                uuid_map[spec.uuid] = new_obs

        # 2b. Second pass: relationships and redirections the module set on
        # its new observables (Phase 4 fidelity — OCR/QR relate their output
        # file back to the analyzed file). Done after all specs exist so a
        # relationship between two new observables resolves either way.
        for spec in delta.new_observables:
            new_obs = uuid_map.get(spec.uuid)
            if new_obs is None:
                continue
            for rel_dict in spec.initial_relationships:
                _apply_relationship(new_obs, rel_dict, root, uuid_map)
            if spec.initial_redirection is not None:
                redirect_target = uuid_map.get(spec.initial_redirection)
                if redirect_target is None:
                    redirect_target = root.get_observable(spec.initial_redirection)
                if redirect_target is not None:
                    new_obs._redirection = redirect_target.uuid
                else:
                    logging.warning(
                        "skipping redirection on cache replay — target unresolved",
                        extra={"source_uuid": spec.initial_redirection},
                    )

        # 3. Apply mutations to the target observable.
        _apply_observable_diff(
            target_observable, delta.target_observable_diff, root,
            source_observable_uuid=delta.observable_uuid,
        )

        # 4. Apply root-level mutations.
        _apply_root_diff(root, delta.root_diff)
    finally:
        if staging_dir is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)


def _rehydrate_analysis(
    target_observable: "Observable",
    delta: ModuleExecutionDelta,
):
    """Install the cached analysis on the target observable if absent.

    Returns the analysis instance (newly rehydrated or pre-existing), or
    None if the delta carried no analysis dict. Honors the slot-collision
    skip: if the slot already has an Analysis at ``module_path``, leave
    it alone — the existing instance is good and the analysis_tree_manager
    would otherwise log a noisy "replacing analysis" error.
    """
    if delta.analysis is None:
        return None
    module_path = delta.analysis.get("module_path")
    if not module_path:
        return None

    existing = target_observable._analysis.get(module_path)
    if isinstance(existing, _Analysis):
        # Slot-collision skip: re-analysis path / retry — keep the existing
        # analysis, idempotent diffs above still apply.
        return existing

    try:
        _module_name, _class_name, _instance = SPLIT_MODULE_PATH(module_path)
        _module = importlib.import_module(_module_name)
        _class = getattr(_module, _class_name)
        analysis = _class()
    except Exception as e:
        logging.warning(
            "failed to instantiate analysis for cache replay — falling back to UnknownAnalysis",
            extra={"module_path": module_path, "error": str(e)},
        )
        analysis = UnknownAnalysis(module_path)

    analysis.observable = target_observable
    analysis.file_manager = target_observable.file_manager

    # Strip alert-specific fields from the dict before letting
    # AnalysisSerializer.deserialize apply it. ``external_details_path``
    # is the source alert's path; the persistence manager will re-derive
    # one when we mark details_modified. ``details`` is applied
    # separately because the serializer doesn't deserialize it (it's
    # normally loaded lazily from the path).
    stripped = dict(delta.analysis)
    stripped.pop("external_details_path", None)
    cached_details = stripped.pop("details", None)

    try:
        analysis.json = stripped
    except Exception:
        logging.warning(
            "failed to apply cached analysis dict",
            exc_info=True,
            extra={
                "module_path": module_path,
                "observable_uuid": target_observable.uuid,
            },
        )

    if isinstance(cached_details, dict):
        analysis.details = cached_details
    elif cached_details is not None:
        analysis.details = cached_details
    analysis.set_details_modified()

    target_observable.analysis_tree_manager.add_analysis(target_observable, analysis)
    return analysis


def _apply_observable_spec(parent_analysis, spec, staged_file: Optional[str] = None):
    """Add a cached ObservableSpec as a child of ``parent_analysis`` and
    copy over its initial mutable state. Idempotent — the analysis tree
    manager dedupes by (type, value, time) and the add_* primitives
    dedupe at the field level. Returns the created (or deduped) observable,
    or None.

    For F_FILE specs ``staged_file`` is the materialized blob in the replay
    staging dir; ``add_file_observable(move=True)`` runs it through the
    file manager's normal store_file path (hash verification, hardcopy
    dedup, file_dir link at the captured relative path) exactly as a live
    module would.
    """
    o_time = None
    if spec.time:
        try:
            o_time = parse_event_time(spec.time)
        except Exception:
            o_time = None

    if spec.type == F_FILE:
        if staged_file is None:
            # Shouldn't happen — get_cached_delta validates file specs and
            # apply_delta stages every one of them before this point.
            logging.warning(
                "skipping file spec on cache replay — no staged content",
                extra={"file_path": spec.file_path, "sha256": spec.value},
            )
            return None
        new_obs = parent_analysis.add_file_observable(
            staged_file, target_path=spec.file_path, move=True, volatile=spec.volatile,
        )
    else:
        new_obs = parent_analysis.add_observable_by_spec(
            spec.type, spec.value, o_time=o_time, volatile=spec.volatile,
        )
    if new_obs is None:
        return None
    for tag in spec.initial_tags:
        new_obs.add_tag(tag)
    for directive in spec.initial_directives:
        new_obs.add_directive(directive)
    for det_dict in spec.initial_detections:
        description = det_dict.get("description")
        if description:
            new_obs.add_detection_point(
                description, det_dict.get("details"), det_dict.get("queue"),
                det_dict.get("signature_uuid"), det_dict.get("signature_version"))
    for name in spec.initial_excluded_analysis:
        if name not in new_obs._excluded_analysis:
            new_obs._excluded_analysis.append(name)
    for name in spec.initial_limited_analysis:
        if name not in new_obs._limited_analysis:
            new_obs._limited_analysis.append(name)
    return new_obs


def _apply_relationship(observable, rel_dict, root, uuid_map) -> None:
    """Add one captured relationship to a live observable, resolving its
    target against the current tree.

    Resolution order: source-uuid map (replay-created observables get
    fresh uuids in this tree; the map also carries the analyzed
    observable, which subsumes the old self-target shortcut) → uuid (only
    resolvable on a same-root replay) → (type, value, time) spec. The
    map/shortcut exists because Observable.__eq__ compares ``time``
    whenever either side carries one — the cache key ignores
    observable.time, so the current observable's time can differ from the
    source's and a spec lookup would miss.
    """
    target_uuid = rel_dict.get("target")
    r_type = rel_dict.get("type")
    if not target_uuid or not r_type:
        return
    target_obs = uuid_map.get(target_uuid)
    if target_obs is None:
        target_obs = root.get_observable(target_uuid)
    if target_obs is None and rel_dict.get("target_type"):
        t_time = None
        if rel_dict.get("target_time"):
            try:
                t_time = parse_event_time(rel_dict["target_time"])
            except Exception:
                t_time = None
        target_obs = root.get_observable_by_spec(
            rel_dict["target_type"], rel_dict.get("target_value"), t_time,
        )
    if target_obs is None:
        # Legacy uuid-only delta (pre target-spec capture) or an
        # out-of-scope target from before the write-time refusal.
        logging.warning(
            "skipping relationship on cache replay — target unresolved",
            extra={
                "r_type": r_type,
                "target_uuid": target_uuid,
                "target_type": rel_dict.get("target_type"),
            },
        )
        return
    observable.add_relationship(r_type, target_obs)


def _apply_observable_diff(observable, diff, root, source_observable_uuid=None) -> None:
    """Apply an ObservableDiff's additions and scalar transitions to a
    live observable. All primitives are idempotent; safe to re-apply.

    ``source_observable_uuid`` is the analyzed observable's uuid as
    captured in the *source* alert — used to resolve self-referencing
    relationships when replaying onto a different root.
    """
    for tag in diff.added_tags:
        observable.add_tag(tag)
    for det_dict in diff.added_detections:
        description = det_dict.get("description")
        if description:
            observable.add_detection_point(
                description, det_dict.get("details"), det_dict.get("queue"),
                det_dict.get("signature_uuid"), det_dict.get("signature_version"))
    for directive in diff.added_directives:
        observable.add_directive(directive)
    uuid_map = {source_observable_uuid: observable} if source_observable_uuid else {}
    for rel_dict in diff.added_relationships:
        _apply_relationship(observable, rel_dict, root, uuid_map)
    # excluded_analysis / limited_analysis are simple string lists with no
    # idempotent setter — dedupe manually.
    for name in diff.added_excluded_analysis:
        if name not in observable._excluded_analysis:
            observable._excluded_analysis.append(name)
    for name in diff.added_limited_analysis:
        if name not in observable._limited_analysis:
            observable._limited_analysis.append(name)

    # Scalar transitions: set to "after" value when present.
    if diff.grouping_target is not None:
        _, after_val = diff.grouping_target
        observable._grouping_target = bool(after_val)
    if diff.redirection is not None:
        _, after_val = diff.redirection
        # _redirection is a UUID string; assign directly. (The setter
        # requires an Observable instance — but the captured form is
        # already the UUID, so we skip the setter.)
        observable._redirection = after_val
    if diff.ignored is not None:
        _, after_val = diff.ignored
        observable._ignored = bool(after_val)


def _apply_root_diff(root, root_diff) -> None:
    """Apply RootDiff additions to the root analysis."""
    for tag in root_diff.added_tags:
        root.add_tag(tag)
    for det_dict in root_diff.added_detections:
        description = det_dict.get("description")
        if description:
            root.add_detection_point(
                description, det_dict.get("details"), det_dict.get("queue"),
                det_dict.get("signature_uuid"), det_dict.get("signature_version"))
