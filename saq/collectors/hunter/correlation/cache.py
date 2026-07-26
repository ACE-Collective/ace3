import hashlib
import json
import logging
from typing import Optional

from saq.collectors.hunter.correlation.trace import sanitize_value
from saq.constants import REDIS_DB_HUNT_CACHE
from saq.redis_client import get_redis_connection


def _make_cache_key(command_args: dict) -> str:
    """Generate a cache key from command arguments."""
    serialized = json.dumps(command_args, sort_keys=True, default=str)
    digest = hashlib.sha256(serialized.encode()).hexdigest()
    return f"hunt_cache:{digest}"


def _describe_command(command_args: dict) -> str:
    """Render a compact, single-line summary of what a cache entry is for."""
    ctype = command_args.get("type", "?")
    if ctype == "query":
        query = " ".join((command_args.get("query") or "").split())
        if len(query) > 300:
            query = query[:300] + "…"

        return f"type=query source={command_args.get('source')} query={query!r}"

    if ctype == "executable":
        return (f"type=executable path={command_args.get('path')} "
                f"args={command_args.get('args') or []!r}")

    return f"type={ctype}"


def get_cached_result(command_args: dict, secrets: dict | None = None) -> Optional[str]:
    """Get a cached command result."""
    try:
        r = get_redis_connection(REDIS_DB_HUNT_CACHE)
        key = _make_cache_key(command_args)
        result = r.get(key)
        if result:
            desc = sanitize_value(_describe_command(command_args), secrets or {})
            logging.info(f"cache hit for {key} ({desc})")

        return result

    except Exception:
        logging.warning("failed to read from hunt cache", exc_info=True)
        return None


def set_cached_result(command_args: dict, value: str, ttl_seconds: int, secrets: dict | None = None):
    """Cache a command result with a TTL."""
    try:
        r = get_redis_connection(REDIS_DB_HUNT_CACHE)
        key = _make_cache_key(command_args)
        r.setex(key, ttl_seconds, value)
        desc = sanitize_value(_describe_command(command_args), secrets or {})
        logging.info(f"cached result with key {key} ({desc}) for {ttl_seconds}s, {len(value)} bytes")
    except Exception:
        logging.warning("failed to write to hunt cache", exc_info=True)


class CorrelateQueryRecorder:
    """Captures, and optionally replays, the results of rendered correlate queries.

    Used by the hunt validator (`validate.py --save-correlate-results` /
    `--correlate-results-file`) so analysts can capture a hunt's follow-up
    `correlate:` queries once and then iterate offline — e.g. on a summary_details
    Jinja template — without re-running expensive queries.

    Capture is always on; replay is active only when seeded with prior results.
    Entries are keyed on the *rendered* query text plus its source, which uniquely
    identifies the question actually asked — the same keying the persistent
    `command.cache` uses, so both distinguish per-event queries. The recorder is
    still a separate store because its purpose is different: it persists results to
    a file for offline iteration (e.g. re-rendering a summary_details template)
    without re-running expensive data-source queries.
    """

    def __init__(self, replay: Optional[list[dict]] = None):
        # (source, rendered_query) -> JSONL output string, matching the format
        # _execute_query produces ("\n".join(json.dumps(row) ...)).
        self._replay: dict[tuple[str, str], str] = {}
        if replay:
            for record in replay:
                source = record["source"]
                query = record["query"]
                rows = record.get("results", []) or []
                self._replay[(source, query)] = "\n".join(json.dumps(row) for row in rows)
        self.replay_active = bool(self._replay)
        # insertion-ordered dedup store of everything executed/replayed this run
        self._captured: dict[tuple[str, str], str] = {}

    def lookup(self, source: str, rendered_query: str) -> Optional[str]:
        """Return the saved JSONL output for a rendered query, or None on miss."""
        return self._replay.get((source, rendered_query))

    def record(self, source: str, rendered_query: str, output: str):
        """Record a query's output (first occurrence wins, so replay hits and live
        runs both keep the export complete and stable)."""
        self._captured.setdefault((source, rendered_query), output)

    def export(self) -> list[dict]:
        """Serialize captured results to a list of {source, query, results} records."""
        exported = []
        for (source, query), output in self._captured.items():
            rows = [json.loads(line) for line in output.splitlines() if line.strip()]
            exported.append({"source": source, "query": query, "results": rows})
        return exported
