"""Newly-registered-domains (NRD) refresh logic.

``refresh()`` is the public entry point, exposed via the ``ace nrd refresh``
subcommand and invoked from cron (see ``etc/cron.yaml``). It decides whether
a refresh is needed based on the conditions in
``docs/design/newly_registered_domains.md`` and, when one is, downloads the
configured lists, builds a fresh SQLite database, and atomically swaps it in
place.

Idempotent: invoking ``refresh()`` when the database is already up to date is
a sub-second no-op.
"""

import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import idna
import requests

from saq.configuration.config import get_config
from saq.nrd.util import get_database_path


USER_AGENT = "ACE3-NRD-Refresh/1.0 (+https://github.com/ACE-Collective/ace3)"
HTTP_TIMEOUT = (10, 60)  # (connect, read)
HTTP_RETRY_BACKOFF_SECONDS = 1
STREAM_RETRY_ATTEMPTS = 2  # initial attempt + one retry per URL on streaming-body failures
INSERT_BATCH_SIZE = 10_000

# Domains are at most ~253 chars (RFC 1035) and, in their A-label form, contain
# only LDH (letters, digits, hyphen) plus dots between labels. ``_normalize_domain``
# uses this regex twice: as a fast-path acceptance check (most lines are already
# ASCII LDH) and, on the slow path, as a validation pass on whatever ``idna.encode``
# produced from a Unicode input.
_DOMAIN_LINE_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


# ---------------------------------------------------------------------------
# Decision helpers
# ---------------------------------------------------------------------------


def _compute_config_hash(url_lists) -> str:
    """Hash the sorted list of configured primary URLs.

    Backup URLs are deliberately excluded: they are operational fallbacks and
    do not change which data ends up in the database. Sorting also makes the
    hash insensitive to declaration order.
    """
    primary_urls = sorted(entry.url for entry in url_lists)
    payload = json.dumps(primary_urls, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_meta(db_path: Path) -> dict:
    """Return the meta-table contents from an existing NRD database, or {} if missing/unreadable."""
    if not db_path.exists():
        return {}

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        logging.warning("could not open existing NRD database at %s: %s", db_path, exc)
        return {}

    try:
        rows = conn.execute("SELECT key, value FROM meta").fetchall()
    except sqlite3.Error as exc:
        logging.warning("could not read meta table from %s: %s", db_path, exc)
        return {}
    finally:
        conn.close()

    meta = dict(rows)
    if "sources" in meta:
        try:
            meta["sources"] = json.loads(meta["sources"])
        except (TypeError, ValueError):
            meta["sources"] = []
    return meta


def _hours_since(iso_timestamp: str) -> Optional[float]:
    """Return hours elapsed since the given ISO 8601 UTC timestamp, or None if unparseable."""
    try:
        dt = datetime.fromisoformat(iso_timestamp)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    return delta.total_seconds() / 3600.0


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _http_request(method: str, url: str, *, stream: bool = False) -> Optional[requests.Response]:
    """HEAD or GET a URL with one transient-error retry. Returns None on terminal failure."""
    attempts = 0
    last_exc: Optional[Exception] = None
    while attempts < 2:
        attempts += 1
        try:
            response = requests.request(
                method,
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=HTTP_TIMEOUT,
                stream=stream,
                allow_redirects=True,
            )
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            if attempts < 2:
                time.sleep(HTTP_RETRY_BACKOFF_SECONDS)
            continue

        if response.status_code >= 500 and attempts < 2:
            response.close()
            time.sleep(HTTP_RETRY_BACKOFF_SECONDS)
            continue

        if response.status_code >= 400:
            logging.warning("%s %s failed with HTTP %d", method, url, response.status_code)
            response.close()
            return None

        return response

    logging.warning("%s %s failed after retry: %s", method, url, last_exc)
    return None


def _head_one(url: str) -> Optional[dict]:
    """Return ``{etag, last_modified}`` from a HEAD request, or None on failure / no headers."""
    response = _http_request("HEAD", url)
    if response is None:
        return None
    try:
        etag = response.headers.get("ETag")
        last_modified = response.headers.get("Last-Modified")
    finally:
        response.close()

    if not etag and not last_modified:
        return None
    return {"etag": etag, "last_modified": last_modified}


# ---------------------------------------------------------------------------
# Parsing + DB build
# ---------------------------------------------------------------------------


def _normalize_domain(line: str) -> Optional[str]:
    """Normalize a single line into a canonical domain, or None if malformed."""
    domain = line.strip().lower().rstrip(".")
    if not domain or domain.startswith("#"):
        return None
    # Fast path: already ASCII LDH. Accepts plain ASCII (example.com) and
    # already-encoded A-labels including emoji ones (xn--qj8hl9g.st) that
    # strict IDNA 2008 round-tripping via idna.encode would otherwise reject.
    if _DOMAIN_LINE_RE.match(domain):
        encoded = domain
    else:
        # Slow path: input contains non-LDH bytes (Unicode IDN, garbage, etc.).
        # idna.encode converts U-labels to A-labels and rejects shapes we
        # don't want (wildcards, URLs, underscores, spaces, empty/over-length
        # labels).
        try:
            encoded = idna.encode(domain).decode("ascii")
        except (idna.IDNAError, UnicodeError):
            return None
        if not _DOMAIN_LINE_RE.match(encoded):
            return None
    # Reject IP-shaped lines: a real domain's rightmost label is the TLD,
    # which is never all digits. This also catches "192.168.1.1" etc.
    labels = encoded.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return None
    return encoded


def _iter_lines(response: requests.Response) -> Iterable[str]:
    """Yield decoded lines from a streamed HTTP response."""
    # Some feeds serve text/plain without a charset.
    # requests follows RFC 7231 and defaults to ISO-8859-1, which mangles
    # UTF-8 IDN bytes. Force UTF-8 unless the server declared otherwise.
    if "charset" not in response.headers.get("Content-Type", "").lower():
        response.encoding = "utf-8"
    for raw in response.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        # iter_lines may yield bytes if decode_unicode falls back; coerce.
        if isinstance(raw, bytes):
            try:
                yield raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
        else:
            yield raw


_STREAM_RETRY_EXCEPTIONS = (
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
)


def _ingest_one_list(conn: sqlite3.Connection, entry) -> Optional[dict]:
    """Fetch a single configured list and insert its domains into ``conn``.

    Tries the primary URL first then each backup. Each URL gets up to
    ``STREAM_RETRY_ATTEMPTS`` attempts on streaming-body failures
    (``ChunkedEncodingError`` etc.); on each failure the partial transaction
    is rolled back before the next attempt. Returns the per-source meta dict
    on success, or ``None`` if every URL exhausts its retries.
    """
    urls = [entry.url, *entry.backups]
    for url in urls:
        for attempt in range(STREAM_RETRY_ATTEMPTS):
            response = _http_request("GET", url, stream=True)
            if response is None:
                # _http_request already retried the connection-level failure;
                # no point retrying the same URL again.
                break

            content_length: Optional[int] = None
            try:
                if response.headers.get("Content-Length"):
                    content_length = int(response.headers["Content-Length"])
            except ValueError:
                content_length = None
            etag = response.headers.get("ETag")
            last_modified = response.headers.get("Last-Modified")

            list_unique: set[str] = set()
            dropped = 0
            batch: list[tuple[str]] = []
            try:
                conn.execute("BEGIN")
                for line in _iter_lines(response):
                    normalized = _normalize_domain(line)
                    if normalized is None:
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            dropped += 1
                        continue
                    list_unique.add(normalized)
                    batch.append((normalized,))
                    if len(batch) >= INSERT_BATCH_SIZE:
                        conn.executemany(
                            "INSERT OR IGNORE INTO nrd (domain) VALUES (?)", batch
                        )
                        batch.clear()
                if batch:
                    conn.executemany(
                        "INSERT OR IGNORE INTO nrd (domain) VALUES (?)", batch
                    )
                conn.execute("COMMIT")
            except _STREAM_RETRY_EXCEPTIONS as exc:
                conn.execute("ROLLBACK")
                logging.warning(
                    "Stream failed for %s (attempt %d/%d): %s",
                    url, attempt + 1, STREAM_RETRY_ATTEMPTS, exc,
                )
                if attempt + 1 < STREAM_RETRY_ATTEMPTS:
                    time.sleep(HTTP_RETRY_BACKOFF_SECONDS)
                else:
                    logging.warning("%s exhausted stream retries; trying next URL", url)
                continue
            finally:
                response.close()

            if dropped:
                logging.warning("Dropped %d malformed entries from %s", dropped, url)

            return {
                "url": entry.url,
                "fetched_from": url,
                "etag": etag,
                "last_modified": last_modified,
                "content_length": content_length,
                "row_count": len(list_unique),
            }
    return None


def _build_database(new_db_path: Path, url_lists) -> Optional[dict]:
    """Build a fresh NRD database at ``new_db_path``. Returns aggregated meta or None on failure."""
    new_db_path.parent.mkdir(parents=True, exist_ok=True)
    if new_db_path.exists():
        new_db_path.unlink()

    conn = sqlite3.connect(str(new_db_path))
    try:
        conn.executescript(
            """
            PRAGMA journal_mode = OFF;
            PRAGMA synchronous = OFF;
            CREATE TABLE nrd (
                domain TEXT PRIMARY KEY
            ) WITHOUT ROWID;
            CREATE TABLE meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID;
            """
        )

        sources_meta: list[dict] = []
        for entry in url_lists:
            source_meta = _ingest_one_list(conn, entry)
            if source_meta is None:
                logging.error(
                    "All URLs (primary + backups) failed for list %s; aborting refresh",
                    entry.url,
                )
                return None
            if source_meta["fetched_from"] != entry.url:
                logging.warning(
                    "Primary URL %s failed; falling back to %s",
                    entry.url, source_meta["fetched_from"],
                )
            sources_meta.append(source_meta)

        row_count = conn.execute("SELECT COUNT(*) FROM nrd").fetchone()[0]
        return {"sources": sources_meta, "row_count": row_count}
    finally:
        try:
            conn.execute("PRAGMA optimize")
        except sqlite3.Error:
            pass
        conn.close()


def _write_meta(db_path: Path, meta: dict) -> None:
    """Insert/replace meta rows in the (possibly newly-built) database."""
    conn = sqlite3.connect(str(db_path))
    try:
        with conn:
            conn.executemany(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                [
                    ("config_hash", meta["config_hash"]),
                    ("last_refreshed_at", meta["last_refreshed_at"]),
                    ("row_count", str(meta["row_count"])),
                    ("sources", json.dumps(meta["sources"], separators=(",", ":"))),
                ],
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------


def _do_full_refresh(db_path: Path, url_lists, config_hash: str, *, reason: str) -> int:
    """Execute steps 6-11 of the refresh flow. Returns process exit code."""
    logging.info("Refresh triggered by %s", reason)

    new_db_path = db_path.with_suffix(db_path.suffix + ".new")
    try:
        start = time.monotonic()
        build_result = _build_database(new_db_path, url_lists)
        if build_result is None:
            return 1
        elapsed = time.monotonic() - start

        meta = {
            "config_hash": config_hash,
            "last_refreshed_at": datetime.now(timezone.utc).isoformat(),
            "row_count": build_result["row_count"],
            "sources": build_result["sources"],
        }
        _write_meta(new_db_path, meta)

        os.replace(new_db_path, db_path)

        logging.info(
            "Refresh completed: rebuilt %d domains across %d lists in %.1f seconds",
            build_result["row_count"],
            len(build_result["sources"]),
            elapsed,
        )
        return 0
    except Exception:
        logging.exception("Unexpected failure during NRD refresh; aborting")
        return 1
    finally:
        # On any non-success path, the .new file may still be on disk. Drop it
        # so the next cron run starts clean.
        if new_db_path.exists():
            try:
                new_db_path.unlink()
            except OSError as exc:
                logging.warning("could not remove leftover %s: %s", new_db_path, exc)


def _heads_match(url_lists, stored_sources: list[dict]) -> bool:
    """Return True if every primary URL's HEAD matches its stored ETag/Last-Modified."""
    stored_by_url = {entry.get("url"): entry for entry in stored_sources}
    for entry in url_lists:
        stored = stored_by_url.get(entry.url)
        if not stored:
            return False
        head = _head_one(entry.url)
        if head is None:
            # HEAD failed or returned no caching headers — treat as "might have changed".
            return False
        stored_etag = stored.get("etag")
        head_etag = head.get("etag")
        if stored_etag and head_etag:
            if stored_etag != head_etag:
                return False
            logging.debug("HEAD matched stored ETag for %s", entry.url)
            continue
        # Fall back to Last-Modified comparison when ETag isn't usable.
        stored_lm = stored.get("last_modified")
        head_lm = head.get("last_modified")
        if not stored_lm or not head_lm or stored_lm != head_lm:
            return False
        logging.debug("HEAD matched stored Last-Modified for %s", entry.url)
    return True


def refresh() -> int:
    """Run one refresh cycle. Returns process exit code."""
    nrd_config = get_config().nrd
    if nrd_config is None:
        logging.info("No NRD config present; nothing to do")
        return 0

    # Kill switch: short-circuit before any DB inspection or HTTP work.
    if not nrd_config.enabled:
        logging.info("NRD refresh disabled via nrd.enabled = false")
        return 0

    if not nrd_config.url_lists:
        logging.info("No NRD url_lists configured; nothing to do")
        return 0

    db_path = get_database_path()
    config_hash = _compute_config_hash(nrd_config.url_lists)
    meta = _read_meta(db_path)

    # Hard trigger: missing DB.
    if not db_path.exists():
        return _do_full_refresh(db_path, nrd_config.url_lists, config_hash, reason="missing database")

    # Hard trigger: configured primary URLs changed.
    if meta.get("config_hash") != config_hash:
        return _do_full_refresh(
            db_path, nrd_config.url_lists, config_hash, reason="config_hash change"
        )

    # Soft trigger: still inside the check_interval window.
    last_refreshed_at = meta.get("last_refreshed_at")
    elapsed_hours = _hours_since(last_refreshed_at) if last_refreshed_at else None
    if elapsed_hours is not None and elapsed_hours < nrd_config.check_interval_hours:
        logging.debug(
            "no refresh needed (last refreshed %.2fh ago < %dh interval)",
            elapsed_hours,
            nrd_config.check_interval_hours,
        )
        return 0

    # Soft trigger: HEAD-check upstream. If every primary URL still matches its
    # stored ETag/Last-Modified, do nothing (don't touch last_refreshed_at — we
    # want to keep checking on every cron firing until upstream actually changes).
    stored_sources = meta.get("sources") or []
    if _heads_match(nrd_config.url_lists, stored_sources):
        logging.debug("HEAD check matched all stored ETags; no refresh needed")
        return 0

    return _do_full_refresh(
        db_path,
        nrd_config.url_lists,
        config_hash,
        reason="HEAD-detected change",
    )
