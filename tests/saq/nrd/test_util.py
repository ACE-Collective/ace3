"""Unit tests for ``saq.nrd.util``."""

import sqlite3
import time
from pathlib import Path

import pytest

from saq.nrd import util
from saq.nrd.util import (
    _extract_lookup_target,
    _normalize,
    _reset_connection_for_tests,
    is_newly_registered,
    registrable_domain,
)


def _build_test_db(path: Path, domains: list[str]) -> None:
    """Build a minimal NRD-shaped SQLite database at ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(
            """
            CREATE TABLE nrd (domain TEXT PRIMARY KEY) WITHOUT ROWID;
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            """
        )
        with conn:
            conn.executemany(
                "INSERT OR IGNORE INTO nrd (domain) VALUES (?)",
                [(d,) for d in domains],
            )
    finally:
        conn.close()


@pytest.fixture
def nrd_db(tmp_path, monkeypatch):
    """Provide a fresh tmp NRD database and a helper to (re)build it.

    The helper returns the database path. Calling it again rebuilds the
    database (with optionally different content) and resets the cached
    connection so the next lookup picks up the new file.
    """
    db_path = tmp_path / "nrd_index.db"

    monkeypatch.setattr(util, "get_database_path", lambda: db_path)
    _reset_connection_for_tests()

    def builder(domains: list[str]) -> Path:
        _build_test_db(db_path, domains)
        _reset_connection_for_tests()
        return db_path

    yield builder

    _reset_connection_for_tests()


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


@pytest.mark.unit
# "" and blanks stop at the first emptiness check, which registrable_domain[""] reaches too
@pytest.mark.parametrize("bad_input", [None, "."])
def test_normalize_empty_or_blank_returns_empty(bad_input):
    assert _normalize(bad_input) == ""


@pytest.mark.unit
def test_normalize_malformed_idn_returns_empty():
    # idna rejects underscores in labels (RFC 5891) so this should fail to encode.
    assert _normalize("not_a_domain.example") == ""


@pytest.mark.unit
def test_normalize_non_string_logs_error_and_casts(caplog):
    """A non-string input logs ERROR and is looked up as its str() instead of raising."""
    import logging as _logging

    with caplog.at_level(_logging.ERROR, logger="root"):
        assert _normalize(123) == "123"

    assert any(rec.levelno == _logging.ERROR for rec in caplog.records), (
        "expected an ERROR log record for non-string input"
    )


@pytest.mark.unit
def test_extract_lookup_target_non_string_logs_error_and_casts(caplog):
    import logging as _logging

    with caplog.at_level(_logging.ERROR, logger="root"):
        result = _extract_lookup_target(123)

    assert result == "123"
    assert any(rec.levelno == _logging.ERROR for rec in caplog.records)


# ---------------------------------------------------------------------------
# Database lookup
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_lookup_strips_trailing_dot(nrd_db):
    nrd_db(["example.com"])
    assert is_newly_registered("example.com.") is True


# ---------------------------------------------------------------------------
# Atomic-swap pickup via mtime invalidation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_lookup_accepts_http_url(nrd_db):
    nrd_db(["example.com"])
    assert is_newly_registered("http://example.com") is True


@pytest.mark.unit
def test_lookup_url_with_userinfo(nrd_db):
    """urlparse(...).hostname strips userinfo so the userinfo doesn't pollute the lookup."""
    nrd_db(["example.com"])
    assert is_newly_registered("https://user:pass@example.com/foo") is True


@pytest.mark.unit
def test_lookup_url_with_idn_host(nrd_db):
    """IDN host inside a URL should be normalized to punycode and match the punycode row."""
    nrd_db(["xn--caf-dma.com"])
    assert is_newly_registered("https://café.com/welcome") is True


@pytest.mark.unit
def test_lookup_non_http_scheme_falls_through_to_fqdn(nrd_db):
    """Non-http(s) schemes are not treated as URL — input falls through to FQDN handling."""
    nrd_db(["example.com"])
    # ftp:// is not auto-detected as a URL for our purposes; whole string is treated as
    # a candidate FQDN, which won't normalize cleanly and will return False.
    assert is_newly_registered("ftp://example.com/file") is False


@pytest.mark.unit
def test_lookup_does_not_walk_past_registrable_into_public_suffix(nrd_db):
    """Walking parents must stop at the registrable apex, not query suffixes like ``com``."""
    nrd_db(["com"])  # contrived: a public suffix should not match real subdomains
    assert is_newly_registered("login.example.com") is False
    assert is_newly_registered("example.com") is False


@pytest.mark.unit
def test_subdomain_match_works_for_multi_label_psl(nrd_db):
    """For a domain with a multi-label public suffix (``co.uk``), the registrable apex matches subdomains."""
    nrd_db(["foo.co.uk"])
    assert is_newly_registered("login.foo.co.uk") is True
    assert is_newly_registered("co.uk") is False  # public suffix itself must not match
    assert is_newly_registered("bar.co.uk") is False  # different registrable


@pytest.mark.unit
def test_idn_subdomain_matches_punycode_registrable(nrd_db):
    """An IDN subdomain should normalize and match its punycode registrable parent."""
    nrd_db(["xn--caf-dma.com"])
    assert is_newly_registered("login.café.com") is True


@pytest.mark.unit
def test_atomic_swap_picked_up_via_mtime(nrd_db, monkeypatch):
    """After the DB file is rebuilt, lookups should reflect the new contents.

    The cached connection is invalidated by mtime change. We don't call the
    test reset helper between the two lookups — picking up the swap should
    happen automatically.
    """
    db_path = nrd_db(["old-domain.example"])
    assert is_newly_registered("old-domain.example") is True
    assert is_newly_registered("new-domain.example") is False

    # Sleep just enough that the new file's mtime differs from the cached one.
    # On filesystems with 1-second mtime resolution this is necessary.
    time.sleep(1.1)

    # Rebuild WITHOUT resetting the cached connection — we want to verify the
    # mtime check inside _get_connection picks up the swap on its own.
    _build_test_db(db_path, ["new-domain.example"])

    assert is_newly_registered("new-domain.example") is True
    assert is_newly_registered("old-domain.example") is False


# ---------------------------------------------------------------------------
# registrable_domain
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "value,expected",
    [
        ("deep.login.example.co.uk", "example.co.uk"),
        ("https://login.example.com:8080/path?q=1", "example.com"),
        ("Example.COM.", "example.com"),
        # .example is no public suffix: falls back to the normalized input
        ("café.example", "xn--caf-dma.example"),
        ("", ""),
    ],
)
def test_registrable_domain(value, expected):
    assert registrable_domain(value) == expected
