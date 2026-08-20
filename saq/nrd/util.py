"""Helper utilities for the newly-registered-domains (NRD) lookup.

Exposes ``is_newly_registered(domain)`` for analysis modules and other callers
to check whether an FQDN appears in the locally-maintained NRD SQLite
database that ``saq.nrd.refresh`` produces.

A read-only SQLite connection is cached at module level (one per worker
process) and invalidated whenever the database file's mtime changes — so
when the refresh script atomically swaps in a new database, the next call
picks it up automatically. See ``docs/design/newly_registered_domains.md``
for the full design.
"""

import logging
import os
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import idna
import tldextract

from saq.configuration.config import get_config
from saq.environment import get_base_dir

# Module-level cached read-only SQLite connection. Lazily opened on first
# successful lookup; reopened automatically when the database file's mtime
# changes (i.e. when the refresh script atomically replaces it).
_conn: sqlite3.Connection | None = None
_conn_mtime: float | None = None


def get_database_path() -> Path:
    """Return the resolved path to the NRD SQLite database.

    Both the refresh script and the analyzer call this accessor so they
    cannot disagree about where the database lives. Relative paths in the
    config are resolved against ``get_base_dir()``.
    """
    db_path = get_config().nrd.database_path
    if not os.path.isabs(db_path):
        db_path = os.path.join(get_base_dir(), db_path)
    return Path(db_path)


def _extract_lookup_target(value: Any) -> str:
    """Return the host to look up, given either an FQDN or a URL.

    If ``value`` parses as an http/https URL with a hostname, the hostname is
    returned (port and userinfo stripped — ``urlparse(...).hostname`` handles
    both). Otherwise ``value`` is returned unchanged so the caller treats it
    as an FQDN. Auto-detection lets a single public API serve both shapes
    without callers having to specify which.
    """
    if value is not None and not isinstance(value, str):
        logging.error("expected str or None, got %s: %r", type(value).__name__, value)
        value = str(value)

    if value is None:
        return ""

    stripped = value.strip()
    if not stripped:
        return ""

    # urlparse is permissive — only treat as a URL if both scheme and host are
    # populated. Anything else (bare hostnames, junk) falls through to FQDN
    # treatment.
    try:
        parsed = urlparse(stripped)
    except ValueError:
        return stripped

    if parsed.scheme in ("http", "https") and parsed.hostname:
        return parsed.hostname

    return stripped


def _normalize(value: Any) -> str:
    """Normalize an FQDN or URL into the canonical form stored in the NRD table.

    Accepts either a bare FQDN or a full URL — see ``_extract_lookup_target``.
    Strips whitespace, lowercases, removes a trailing dot, and converts IDN
    domains to punycode (ACE-encoding). Returns an empty string if the input
    is empty or fails IDN encoding — callers treat empty as "no match".
    """
    if value is not None and not isinstance(value, str):
        logging.error("expected str or None, got %s: %r", type(value).__name__, value)
        value = str(value)

    domain = _extract_lookup_target(value)
    if not domain:
        return ""

    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return ""

    try:
        return idna.encode(domain).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return ""


def _get_connection() -> sqlite3.Connection | None:
    """Return a cached read-only SQLite connection to the NRD database.

    Returns ``None`` (without raising) if the database file does not exist
    yet — that's the expected state on a fresh deploy whose first refresh
    hasn't completed. If the file's mtime has changed since the cached
    connection was opened (atomic swap by the refresh script), the cached
    connection is closed and a new one is opened against the new file.
    """
    global _conn, _conn_mtime

    db_path = get_database_path()
    try:
        cur_mtime = db_path.stat().st_mtime
    except FileNotFoundError:
        if _conn is not None:
            _conn.close()
            _conn = None
            _conn_mtime = None
        return None

    if _conn is None or _conn_mtime != cur_mtime:
        if _conn is not None:
            _conn.close()
        _conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        _conn_mtime = cur_mtime

    return _conn


def _candidate_domains(normalized: str) -> list[str]:
    """Return the input plus each subdomain parent down to the registrable apex.

    Hagezi-style NRD feeds list registrable domains (eTLD+1), so an input like
    ``login.example.com`` should match a row for ``example.com``. We walk from
    the input down through subdomain parents and stop at the registrable
    domain — identified via the public suffix list — so we never query
    suffixes like ``co.uk`` against the database.

    For inputs with no identifiable public suffix (e.g., bare hostnames like
    ``localhost``), the input itself is the only candidate.
    """
    registrable = tldextract.extract(normalized).top_domain_under_public_suffix
    if not registrable:
        return [normalized]

    candidates: list[str] = []
    current = normalized
    while True:
        candidates.append(current)
        if current == registrable:
            break
        # Strip the leftmost label.
        _, _, current = current.partition(".")
        if not current:
            break
    return candidates


def registrable_domain(value: str) -> str:
    """Return the normalized registrable domain (eTLD+1) for an FQDN or URL.

    Accepts the same inputs as ``is_newly_registered`` (bare FQDN or full
    URL) and applies the same normalization (URL-host extraction, lowercase,
    trailing-dot strip, IDN→punycode). Falls back to the normalized input
    when no public suffix is identifiable (bare hostnames, internal names),
    matching ``_candidate_domains``. Returns an empty string for empty or
    IDNA-invalid input.
    """
    normalized = _normalize(value)
    if not normalized:
        return ""
    return tldextract.extract(normalized).top_domain_under_public_suffix or normalized


def is_newly_registered(value: str) -> bool:
    """Return True iff ``value`` (or a registrable parent of it) is in the NRD database.

    Accepts either a bare FQDN (e.g. ``login.example.com``) or a full URL
    (e.g. ``https://login.example.com:8080/path?q=1``); URL inputs are auto-
    detected via ``urlparse`` and the hostname is extracted before lookup.
    Handles whitespace, casing, trailing-dot, and IDN/punycode normalization
    so callers don't have to. Also walks subdomain parents down to the
    registrable apex (eTLD+1, identified via the public suffix list), so an
    input that resolves to ``login.example.com`` matches when ``example.com``
    is the only domain present in the database. Returns ``False`` (does not
    raise) when the database file does not yet exist (e.g., a fresh deploy
    whose first refresh hasn't completed).
    """
    normalized = _normalize(value)
    if not normalized:
        return False

    conn = _get_connection()
    if conn is None:
        return False

    candidates = _candidate_domains(normalized)
    placeholders = ",".join("?" * len(candidates))
    query = f"SELECT 1 FROM nrd WHERE domain IN ({placeholders}) LIMIT 1"
    try:
        row = conn.execute(query, candidates).fetchone()
    except sqlite3.Error as exc:
        logging.warning("NRD lookup failed for %s: %s", normalized, exc)
        return False

    return row is not None


def _reset_connection_for_tests() -> None:
    """Close and clear the cached SQLite connection.

    Tests that build a new fixture database between cases must call this to
    drop any stale handle the cache is still holding from a previous test.
    """
    global _conn, _conn_mtime
    if _conn is not None:
        _conn.close()
    _conn = None
    _conn_mtime = None
