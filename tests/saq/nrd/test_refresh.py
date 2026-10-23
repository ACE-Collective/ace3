"""Unit tests for ``saq.nrd.refresh``."""

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests
from requests.exceptions import ChunkedEncodingError

from saq.configuration.config import get_config
from saq.configuration.schema import NRDConfig, NRDURLList
from saq.nrd import refresh as refresh_mod
from saq.nrd import util as util_mod
from saq.nrd.refresh import (
    _compute_config_hash,
    _normalize_domain,
    refresh,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_url_list(url: str, *backups: str) -> NRDURLList:
    return NRDURLList(url=url, backups=list(backups))


@pytest.fixture
def nrd_env(tmp_path, monkeypatch):
    """Provide an isolated tmp database path and a config-stub helper.

    Returns ``(db_path, configure)`` where ``configure(url_lists, check_interval_hours=24)``
    sets the fields of the real ``get_config().nrd``.
    """
    db_path = tmp_path / "nrd_index.db"

    monkeypatch.setattr(util_mod, "get_database_path", lambda: db_path)
    monkeypatch.setattr(refresh_mod, "get_database_path", lambda: db_path)

    def configure(url_lists, check_interval_hours: int = 24, enabled: bool = True):
        monkeypatch.setattr(get_config(), "nrd", NRDConfig(
            enabled=enabled,
            database_path=str(db_path),
            check_interval_hours=check_interval_hours,
            url_lists=list(url_lists),
        ))

    return db_path, configure


def _read_meta(db_path: Path) -> dict:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    finally:
        conn.close()
    if "sources" in rows:
        rows["sources"] = json.loads(rows["sources"])
    return rows


def _domain_count(db_path: Path) -> int:
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute("SELECT COUNT(*) FROM nrd").fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# config_hash
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_config_hash_excludes_backups():
    base = [_make_url_list("https://a.example/list.txt", "https://backup-a.example/list.txt")]
    no_backup = [_make_url_list("https://a.example/list.txt")]
    extra_backup = [
        _make_url_list("https://a.example/list.txt", "https://backup-a.example/list.txt", "https://backup-b.example/list.txt")
    ]
    assert _compute_config_hash(base) == _compute_config_hash(no_backup)
    assert _compute_config_hash(base) == _compute_config_hash(extra_backup)


@pytest.mark.unit
def test_config_hash_insensitive_to_primary_order():
    a = [
        _make_url_list("https://a.example/list.txt"),
        _make_url_list("https://b.example/list.txt"),
    ]
    b = [
        _make_url_list("https://b.example/list.txt"),
        _make_url_list("https://a.example/list.txt"),
    ]
    assert _compute_config_hash(a) == _compute_config_hash(b)


@pytest.mark.unit
def test_config_hash_changes_when_primary_changes():
    a = [_make_url_list("https://a.example/list.txt")]
    b = [_make_url_list("https://different.example/list.txt")]
    assert _compute_config_hash(a) != _compute_config_hash(b)


# ---------------------------------------------------------------------------
# _normalize_domain
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_normalize_domain_skips_blanks_and_comments():
    assert _normalize_domain("") is None
    assert _normalize_domain("   ") is None
    assert _normalize_domain("# this is a comment") is None
    assert _normalize_domain("  # leading-whitespace comment") is None


@pytest.mark.unit
def test_normalize_domain_accepts_plain_domains():
    assert _normalize_domain("example.com") == "example.com"
    assert _normalize_domain("Sub.Example.COM") == "sub.example.com"


@pytest.mark.unit
def test_normalize_domain_drops_non_domain_lines():
    # Wildcards, IPs, paths, and garbage should all be rejected.
    assert _normalize_domain("*.example.com") is None
    assert _normalize_domain("192.168.1.1/24") is None
    assert _normalize_domain("not a domain at all") is None
    assert _normalize_domain("https://example.com/path") is None


@pytest.mark.unit
def test_normalize_domain_punycode_passthrough():
    assert _normalize_domain("xn--caf-dma.example") == "xn--caf-dma.example"


@pytest.mark.unit
def test_normalize_domain_unicode_idn_to_punycode():
    """Unicode IDN inputs (U-labels) must be encoded to A-labels, not dropped."""
    # Real-world example from the cenk feed: 1900+ Chinese-script domains
    # were being silently dropped because the LDH regex ran before idna.encode.
    assert _normalize_domain("001311.企业") == "001311.xn--vhquv"
    # Unicode in the leftmost label, ASCII TLD.
    assert _normalize_domain("café.example") == "xn--caf-dma.example"
    # Unicode in both labels.
    assert _normalize_domain("例え.テスト") == "xn--r8jz45g.xn--zckzah"


@pytest.mark.unit
def test_normalize_domain_accepts_emoji_punycode():
    """A-labels containing emoji codepoints must pass through.

    ``xn--qj8hl9g.st`` decodes to U+1F969 (🥩.st) — a real registered domain.
    Strict IDNA 2008 disallows emoji codepoints, but DNS doesn't care, and
    these are exactly the kind of novelty NRDs we want flagged. The fast
    path accepts them by skipping the idna round-trip on already-LDH input.
    """
    assert _normalize_domain("xn--qj8hl9g.st") == "xn--qj8hl9g.st"
    assert _normalize_domain("xn--1p9h.fm") == "xn--1p9h.fm"


# ---------------------------------------------------------------------------
# Full-refresh end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_disabled_short_circuits_with_no_io(nrd_env, requests_mock):
    """When `nrd.enabled` is false, refresh() must exit 0 with no HTTP calls and no DB created."""
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    # Configure both a list URL and a HEAD/GET mock — neither should ever be hit.
    requests_mock.get(list_url, text="alpha.example\n", headers={"ETag": "etag-v1"})
    requests_mock.head(list_url, headers={"ETag": "etag-v1"})

    configure([_make_url_list(list_url)], check_interval_hours=0, enabled=False)

    assert refresh() == 0
    assert not db_path.exists(), "disabled refresh must not create the database"
    assert requests_mock.call_count == 0, "disabled refresh must not make any HTTP calls"


@pytest.mark.unit
def test_full_refresh_builds_database(nrd_env, requests_mock):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    body = "alpha.example\nbeta.example\n# comment line\n*.invalid.example\nxn--caf-dma.example\n"
    requests_mock.get(list_url, text=body, headers={"ETag": "etag-v1", "Last-Modified": "Wed, 21 Oct 2026 07:28:00 GMT"})

    configure([_make_url_list(list_url)])

    assert refresh() == 0
    assert db_path.exists()
    # alpha.example, beta.example, xn--caf-dma.example. The wildcard line is dropped.
    assert _domain_count(db_path) == 3

    meta = _read_meta(db_path)
    assert meta["row_count"] == "3"
    assert meta["sources"][0]["url"] == list_url
    assert meta["sources"][0]["fetched_from"] == list_url
    assert meta["sources"][0]["etag"] == "etag-v1"
    assert meta["sources"][0]["row_count"] == 3


@pytest.mark.unit
def test_no_refresh_when_within_check_interval(nrd_env, requests_mock):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, text="alpha.example\n", headers={"ETag": "etag-v1"})

    configure([_make_url_list(list_url)], check_interval_hours=24)

    assert refresh() == 0
    first_mtime = db_path.stat().st_mtime
    head_calls_after_first = sum(1 for r in requests_mock.request_history if r.method == "HEAD")

    # Immediate re-run should be a no-op (well within 24h window).
    assert refresh() == 0
    assert db_path.stat().st_mtime == first_mtime
    # No HEAD requests should have been issued because we never crossed the threshold.
    head_calls_after_second = sum(1 for r in requests_mock.request_history if r.method == "HEAD")
    assert head_calls_after_first == head_calls_after_second


@pytest.mark.unit
def test_head_match_does_not_rebuild(nrd_env, requests_mock):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, text="alpha.example\n", headers={"ETag": "etag-v1"})
    requests_mock.head(list_url, headers={"ETag": "etag-v1"})

    configure([_make_url_list(list_url)], check_interval_hours=0)

    assert refresh() == 0
    first_mtime = db_path.stat().st_mtime
    first_meta = _read_meta(db_path)

    # check_interval_hours=0 forces the HEAD path on every run; matching ETag must NOT rebuild.
    assert refresh() == 0
    assert db_path.stat().st_mtime == first_mtime
    assert _read_meta(db_path)["last_refreshed_at"] == first_meta["last_refreshed_at"]


@pytest.mark.unit
def test_head_mismatch_triggers_rebuild(nrd_env, requests_mock):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"

    # First refresh with v1 content + ETag.
    requests_mock.get(list_url, text="alpha.example\n", headers={"ETag": "etag-v1"})
    configure([_make_url_list(list_url)], check_interval_hours=0)
    assert refresh() == 0
    first_meta = _read_meta(db_path)

    # Now upstream "publishes a new version" — HEAD returns a different ETag,
    # GET returns expanded content with the new ETag.
    requests_mock.reset_mock()
    requests_mock.head(list_url, headers={"ETag": "etag-v2"})
    requests_mock.get(list_url, text="alpha.example\nbeta.example\n", headers={"ETag": "etag-v2"})

    assert refresh() == 0
    assert _domain_count(db_path) == 2
    new_meta = _read_meta(db_path)
    assert new_meta["sources"][0]["etag"] == "etag-v2"
    assert new_meta["last_refreshed_at"] != first_meta["last_refreshed_at"]


@pytest.mark.unit
def test_config_hash_change_forces_rebuild(nrd_env, requests_mock):
    db_path, configure = nrd_env

    list_url_a = "https://feed-a.example/nrd.txt"
    list_url_b = "https://feed-b.example/nrd.txt"

    requests_mock.get(list_url_a, text="alpha.example\n", headers={"ETag": "etag-a"})
    requests_mock.get(list_url_b, text="beta.example\n", headers={"ETag": "etag-b"})

    # First refresh: only list A is configured.
    configure([_make_url_list(list_url_a)], check_interval_hours=24)
    assert refresh() == 0
    assert _domain_count(db_path) == 1

    # Reconfigure with a NEW primary URL set — even though we're still inside
    # the 24h check interval, the config_hash mismatch must force a rebuild.
    configure([_make_url_list(list_url_a), _make_url_list(list_url_b)], check_interval_hours=24)
    assert refresh() == 0
    assert _domain_count(db_path) == 2


@pytest.mark.unit
def test_backup_fallback_succeeds(nrd_env, requests_mock):
    db_path, configure = nrd_env

    primary = "https://primary.example/nrd.txt"
    backup = "https://backup.example/nrd.txt"

    requests_mock.get(primary, status_code=503)
    requests_mock.get(backup, text="alpha.example\n", headers={"ETag": "etag-b"})

    configure([_make_url_list(primary, backup)])

    assert refresh() == 0
    assert _domain_count(db_path) == 1
    meta = _read_meta(db_path)
    assert meta["sources"][0]["fetched_from"] == backup
    assert meta["sources"][0]["etag"] == "etag-b"


@pytest.mark.unit
def test_all_fallbacks_failed_aborts_refresh(nrd_env, requests_mock):
    db_path, configure = nrd_env

    primary = "https://primary.example/nrd.txt"
    backup = "https://backup.example/nrd.txt"

    # First, populate the database with a previous-good build via a working URL.
    requests_mock.get(primary, text="alpha.example\n", headers={"ETag": "etag-good"})
    configure([_make_url_list(primary, backup)], check_interval_hours=24)
    assert refresh() == 0
    pre_mtime = db_path.stat().st_mtime
    pre_meta = _read_meta(db_path)

    # Now make BOTH primary and backup fail with 503, force the HEAD path,
    # and confirm the existing DB is left alone.
    requests_mock.reset_mock()
    requests_mock.head(primary, status_code=503)
    requests_mock.get(primary, status_code=503)
    requests_mock.get(backup, status_code=503)
    configure([_make_url_list(primary, backup)], check_interval_hours=0)

    assert refresh() == 1
    # DB still exists, untouched.
    assert db_path.exists()
    assert db_path.stat().st_mtime == pre_mtime
    assert _read_meta(db_path)["last_refreshed_at"] == pre_meta["last_refreshed_at"]


@pytest.mark.unit
def test_malformed_lines_dropped_with_warning(nrd_env, requests_mock, caplog):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"

    body = "\n".join(
        [
            "good.example",
            "*.wildcard.example",
            "192.168.1.1",
            "https://looks-like-url.example/path",
            "another-good.example",
            "not_underscore.example",
            "",
            "# comment",
        ]
    ) + "\n"
    requests_mock.get(list_url, text=body, headers={"ETag": "etag-v1"})

    configure([_make_url_list(list_url)])

    import logging
    with caplog.at_level(logging.WARNING):
        assert refresh() == 0

    # Two valid domains should land in the DB.
    assert _domain_count(db_path) == 2
    # And the malformed-summary warning should have been emitted with the count of dropped non-blank/non-comment lines.
    matching_warnings = [r for r in caplog.records if "Dropped" in r.getMessage() and "malformed entries" in r.getMessage()]
    assert matching_warnings, "expected a 'Dropped N malformed entries' warning"
    # 4 malformed: wildcard, IP, URL, underscore. Blanks/comments don't count.
    assert "4" in matching_warnings[0].getMessage()


@pytest.mark.unit
def test_iter_lines_forces_utf8_when_charset_missing(nrd_env, requests_mock, caplog):
    """A text/plain response without a charset must still decode UTF-8 IDN bytes correctly.

    Reproduces the cenk-feed bug: requests follows RFC 7231 and defaults to
    ISO-8859-1 when no charset is declared, which mangled UTF-8 IDN bytes
    into Latin-1 garbage and made every IDN line look malformed.
    """
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    body = "alpha.example\n001311.企业\nbeta.example\n".encode("utf-8")
    # Note: Content-Type explicitly omits charset, mirroring dl.cenk.app behavior.
    requests_mock.get(
        list_url,
        content=body,
        headers={"Content-Type": "text/plain", "ETag": "etag-v1"},
    )

    configure([_make_url_list(list_url)])

    import logging
    with caplog.at_level(logging.WARNING):
        assert refresh() == 0

    assert _domain_count(db_path) == 3
    rows = {row[0] for row in sqlite3.connect(str(db_path)).execute("SELECT domain FROM nrd")}
    assert rows == {"alpha.example", "beta.example", "001311.xn--vhquv"}
    # No "Dropped N malformed entries" warning should have been emitted.
    drop_warnings = [r for r in caplog.records if "Dropped" in r.getMessage() and "malformed" in r.getMessage()]
    assert not drop_warnings, "IDN lines were mis-decoded and dropped"


@pytest.mark.unit
def test_atomic_swap_does_not_leave_new_file(nrd_env, requests_mock):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, text="alpha.example\n", headers={"ETag": "etag-v1"})

    configure([_make_url_list(list_url)])
    assert refresh() == 0

    new_path = db_path.with_suffix(db_path.suffix + ".new")
    assert not new_path.exists(), "leftover .new file means atomic swap failed"


# ---------------------------------------------------------------------------
# Streaming-body failure handling (mid-body ChunkedEncodingError etc.)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_stream_failure_retries_same_url_then_succeeds(nrd_env, requests_mock, monkeypatch):
    """First stream attempt raises mid-body; same-URL retry succeeds and the partial insert is rolled back."""
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, text="alpha.example\nbeta.example\n", headers={"ETag": "etag-v1"})

    monkeypatch.setattr(refresh_mod, "HTTP_RETRY_BACKOFF_SECONDS", 0)

    real_iter_lines = refresh_mod._iter_lines
    calls = {"n": 0}

    def flaky_iter_lines(response):
        calls["n"] += 1
        if calls["n"] == 1:
            # Yield one valid line so the partial INSERT is visible to ROLLBACK.
            yield "partial.example"
            raise ChunkedEncodingError("simulated mid-body cut")
        yield from real_iter_lines(response)

    monkeypatch.setattr(refresh_mod, "_iter_lines", flaky_iter_lines)

    configure([_make_url_list(list_url)])

    assert refresh() == 0
    # Only the second attempt's content survives — partial.example was rolled back.
    assert _domain_count(db_path) == 2
    rows = {row[0] for row in sqlite3.connect(str(db_path)).execute("SELECT domain FROM nrd")}
    assert rows == {"alpha.example", "beta.example"}
    meta = _read_meta(db_path)
    assert meta["sources"][0]["fetched_from"] == list_url
    assert calls["n"] == 2


@pytest.mark.unit
def test_stream_failure_falls_back_to_backup(nrd_env, requests_mock, monkeypatch):
    """Both stream attempts on the primary URL fail; the backup URL succeeds."""
    db_path, configure = nrd_env
    primary = "https://primary.example/nrd.txt"
    backup = "https://backup.example/nrd.txt"
    requests_mock.get(primary, text="alpha.example\n", headers={"ETag": "etag-p"})
    requests_mock.get(backup, text="beta.example\n", headers={"ETag": "etag-b"})

    monkeypatch.setattr(refresh_mod, "HTTP_RETRY_BACKOFF_SECONDS", 0)

    real_iter_lines = refresh_mod._iter_lines
    per_url_calls = {primary: 0, backup: 0}

    def flaky_iter_lines(response):
        if response.url == primary:
            per_url_calls[primary] += 1
            raise ChunkedEncodingError("simulated mid-body cut on primary")
        per_url_calls[backup] += 1
        yield from real_iter_lines(response)

    monkeypatch.setattr(refresh_mod, "_iter_lines", flaky_iter_lines)

    configure([_make_url_list(primary, backup)])

    assert refresh() == 0
    assert _domain_count(db_path) == 1
    meta = _read_meta(db_path)
    assert meta["sources"][0]["url"] == primary
    assert meta["sources"][0]["fetched_from"] == backup
    assert meta["sources"][0]["etag"] == "etag-b"
    assert per_url_calls[primary] == 2  # primary attempted twice before falling back
    assert per_url_calls[backup] == 1


@pytest.mark.unit
def test_stream_failure_all_urls_exhausted_aborts(nrd_env, requests_mock, monkeypatch):
    """Every URL fails every stream attempt: refresh exits 1, no DB created, no .new left behind."""
    db_path, configure = nrd_env
    primary = "https://primary.example/nrd.txt"
    backup = "https://backup.example/nrd.txt"
    requests_mock.get(primary, text="alpha.example\n", headers={"ETag": "etag-p"})
    requests_mock.get(backup, text="beta.example\n", headers={"ETag": "etag-b"})

    monkeypatch.setattr(refresh_mod, "HTTP_RETRY_BACKOFF_SECONDS", 0)

    calls = {"n": 0}

    def always_fail(response):
        calls["n"] += 1
        raise ChunkedEncodingError("simulated mid-body cut")

    monkeypatch.setattr(refresh_mod, "_iter_lines", always_fail)

    configure([_make_url_list(primary, backup)])

    assert refresh() == 1
    assert not db_path.exists()
    new_path = db_path.with_suffix(db_path.suffix + ".new")
    assert not new_path.exists()
    # Two URLs × two attempts each.
    assert calls["n"] == 4


# ---------------------------------------------------------------------------
# HTTP failures
# ---------------------------------------------------------------------------


@pytest.fixture
def no_backoff(monkeypatch):
    monkeypatch.setattr(refresh_mod, "HTTP_RETRY_BACKOFF_SECONDS", 0)


@pytest.mark.unit
def test_a_refused_list_is_logged_with_its_status(nrd_env, requests_mock, no_backoff, caplog):
    db_path, configure = nrd_env
    primary = "https://primary.example/nrd.txt"
    backup = "https://backup.example/nrd.txt"
    requests_mock.get(primary, status_code=403)
    requests_mock.get(backup, status_code=404)
    configure([_make_url_list(primary, backup)])

    with caplog.at_level(logging.WARNING):
        assert refresh() == 1

    assert f"GET {primary} failed with HTTP 403" in caplog.text
    assert f"GET {backup} failed with HTTP 404" in caplog.text
    assert not db_path.exists()


@pytest.mark.unit
def test_a_connection_failure_is_retried_once(nrd_env, requests_mock, no_backoff, caplog):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, [
        {"exc": requests.ConnectionError("connection reset")},
        {"text": "alpha.example\n", "headers": {"ETag": "etag-v1"}},
    ])
    configure([_make_url_list(list_url)])

    assert refresh() == 0
    assert _domain_count(db_path) == 1


@pytest.mark.unit
def test_a_connection_failure_after_the_retry_is_logged(nrd_env, requests_mock, no_backoff, caplog):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, exc=requests.ConnectTimeout("connect timed out"))
    configure([_make_url_list(list_url)])

    with caplog.at_level(logging.WARNING):
        assert refresh() == 1

    assert requests_mock.call_count == 2
    assert f"GET {list_url} failed after retry: connect timed out" in caplog.text


@pytest.mark.unit
def test_a_server_error_is_retried_once(nrd_env, requests_mock, no_backoff):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, [
        {"status_code": 502},
        {"text": "alpha.example\n", "headers": {"ETag": "etag-v1"}},
    ])
    configure([_make_url_list(list_url)])

    assert refresh() == 0
    assert _domain_count(db_path) == 1


# ---------------------------------------------------------------------------
# HEAD checks
# ---------------------------------------------------------------------------


def _build(nrd_env, requests_mock, list_url, headers):
    db_path, configure = nrd_env
    requests_mock.get(list_url, text="alpha.example\n", headers=headers)
    configure([_make_url_list(list_url)], check_interval_hours=0)
    assert refresh() == 0
    return db_path.stat().st_mtime


@pytest.mark.unit
def test_head_match_on_last_modified_does_not_rebuild(nrd_env, requests_mock):
    list_url = "https://feed.example/nrd.txt"
    last_modified = "Wed, 21 Oct 2026 07:28:00 GMT"
    first_mtime = _build(nrd_env, requests_mock, list_url, {"Last-Modified": last_modified})
    requests_mock.head(list_url, headers={"Last-Modified": last_modified})

    assert refresh() == 0
    assert nrd_env[0].stat().st_mtime == first_mtime


@pytest.mark.parametrize("head_headers", [
    {"Last-Modified": "Thu, 22 Oct 2026 07:28:00 GMT"},
    {},
])
@pytest.mark.unit
def test_head_without_a_matching_last_modified_rebuilds(nrd_env, requests_mock, head_headers):
    list_url = "https://feed.example/nrd.txt"
    _build(nrd_env, requests_mock, list_url, {"Last-Modified": "Wed, 21 Oct 2026 07:28:00 GMT"})
    requests_mock.head(list_url, headers=head_headers)
    requests_mock.get(list_url, text="alpha.example\nbeta.example\n")

    assert refresh() == 0
    assert _domain_count(nrd_env[0]) == 2


@pytest.mark.unit
def test_a_list_missing_from_the_stored_sources_rebuilds(nrd_env, requests_mock):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    _build(nrd_env, requests_mock, list_url, {"ETag": "etag-v1"})
    requests_mock.head(list_url, headers={"ETag": "etag-v1"})
    conn = sqlite3.connect(str(db_path))
    with conn:
        conn.execute("UPDATE meta SET value = '[]' WHERE key = 'sources'")
    conn.close()
    requests_mock.get(list_url, text="alpha.example\nbeta.example\n")

    assert refresh() == 0
    assert _domain_count(db_path) == 2


# ---------------------------------------------------------------------------
# reading the existing database
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_an_unreadable_database_is_rebuilt(nrd_env, requests_mock, caplog):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    db_path.write_bytes(b"not a sqlite database at all, just some bytes" * 10)
    requests_mock.get(list_url, text="alpha.example\n")
    configure([_make_url_list(list_url)])

    with caplog.at_level(logging.WARNING):
        assert refresh() == 0

    assert f"could not read meta table from {db_path}" in caplog.text
    assert _domain_count(db_path) == 1


@pytest.mark.unit
def test_unparseable_meta_values_read_as_missing(nrd_env):
    db_path, _ = nrd_env
    conn = sqlite3.connect(str(db_path))
    with conn:
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO meta VALUES ('sources', '{not json'), ('last_refreshed_at', 'yesterday')")
    conn.close()

    meta = refresh_mod._read_meta(db_path)

    assert meta["sources"] == []
    assert refresh_mod._hours_since(meta["last_refreshed_at"]) is None


@pytest.mark.unit
def test_a_naive_timestamp_is_read_as_utc():
    an_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    assert refresh_mod._hours_since(an_hour_ago) == pytest.approx(1.0, abs=0.01)


# ---------------------------------------------------------------------------
# building the database
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_domains_are_inserted_in_batches(nrd_env, requests_mock, monkeypatch):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, text="".join(f"domain{i}.example\n" for i in range(5)),
                      headers={"Content-Length": "not a number"})
    monkeypatch.setattr(refresh_mod, "INSERT_BATCH_SIZE", 2)
    configure([_make_url_list(list_url)])

    assert refresh() == 0

    assert _domain_count(db_path) == 5
    assert _read_meta(db_path)["sources"][0]["content_length"] is None


@pytest.mark.unit
def test_a_leftover_new_file_is_replaced(nrd_env, requests_mock):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    new_path = db_path.with_suffix(db_path.suffix + ".new")
    new_path.write_bytes(b"left behind by a killed refresh")
    requests_mock.get(list_url, text="alpha.example\n")
    configure([_make_url_list(list_url)])

    assert refresh() == 0
    assert _domain_count(db_path) == 1
    assert not new_path.exists()


@pytest.mark.unit
def test_an_unexpected_failure_aborts_and_removes_the_new_file(nrd_env, requests_mock, monkeypatch, caplog):
    db_path, configure = nrd_env
    list_url = "https://feed.example/nrd.txt"
    requests_mock.get(list_url, text="alpha.example\n")

    def _write_meta(path, meta):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(refresh_mod, "_write_meta", _write_meta)
    configure([_make_url_list(list_url)])

    with caplog.at_level(logging.ERROR):
        assert refresh() == 1

    record = next(r for r in caplog.records if "Unexpected failure during NRD refresh" in r.getMessage())
    assert record.exc_info is not None
    assert not db_path.exists()
    assert not db_path.with_suffix(db_path.suffix + ".new").exists()


@pytest.mark.unit
def test_refresh_does_nothing_without_url_lists(nrd_env, requests_mock):
    db_path, configure = nrd_env
    configure([])

    assert refresh() == 0
    assert not db_path.exists()
    assert requests_mock.call_count == 0


@pytest.mark.unit
def test_refresh_does_nothing_without_nrd_config(monkeypatch, requests_mock):
    monkeypatch.setattr(get_config(), "nrd", None)

    assert refresh() == 0
    assert requests_mock.call_count == 0
