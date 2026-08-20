"""Unit tests for ``saq.modules.nrd``."""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_NRD_ANALYZER,
    F_FQDN,
    F_URL,
    AnalysisExecutionResult,
)
from saq.modules.nrd import TAG_NRD, NRDAnalysis, NRDAnalyzer, NRDAnalyzerConfig
from saq.modules.rdap import DomainCreationLookup
from saq.nrd import util as nrd_util
from saq.nrd.util import _reset_connection_for_tests
from tests.saq.helpers import create_root_analysis


class _LookupStub:
    """Stands in for ``lookup_domain_creation_date``; records calls and
    returns a settable result (default: registered 3 days ago via RDAP)."""

    def __init__(self):
        self.calls: list[str] = []
        self.result = DomainCreationLookup(
            datetime.now(timezone.utc) - timedelta(days=3), "rdap", None
        )

    def __call__(self, domain: str) -> DomainCreationLookup:
        self.calls.append(domain)
        return self.result


@pytest.fixture(autouse=True)
def creation_lookup(monkeypatch):
    """Keep every test offline: NRD hits verify against this stub, never RDAP."""
    stub = _LookupStub()
    monkeypatch.setattr("saq.modules.nrd.lookup_domain_creation_date", stub)
    return stub


def _build_test_db(path: Path, domains: list[str]) -> None:
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
    """Provide an isolated tmp NRD database. Returns a callable to (re)build it."""
    db_path = tmp_path / "nrd_index.db"
    monkeypatch.setattr(nrd_util, "get_database_path", lambda: db_path)
    _reset_connection_for_tests()

    def builder(domains: list[str]) -> Path:
        _build_test_db(db_path, domains)
        _reset_connection_for_tests()
        return db_path

    yield builder

    _reset_connection_for_tests()


# ---------------------------------------------------------------------------
# NRDAnalysis
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_nrd_analysis_initial_state():
    analysis = NRDAnalysis()
    assert analysis.is_nrd is False
    assert analysis.matched_at is None
    assert analysis.generate_summary() is None


@pytest.mark.unit
def test_nrd_analysis_setters():
    analysis = NRDAnalysis()
    analysis.is_nrd = True
    analysis.matched_at = "2026-04-29T12:00:00+00:00"
    assert analysis.is_nrd is True
    assert analysis.matched_at == "2026-04-29T12:00:00+00:00"
    assert "Newly Registered Domain" in analysis.generate_summary()


# ---------------------------------------------------------------------------
# NRDAnalyzer
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_analyzer_tags_match(nrd_db, test_context):
    nrd_db(["phish-test.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "phish-test.example")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.is_nrd is True
    assert analysis.matched_at is not None
    assert analysis.age_created_in_days == "3"
    assert analysis.datetime_created is not None
    assert analysis.lookup_protocol == "rdap"
    assert analysis.lookup_error is None
    assert "registered 3 day(s) ago" in analysis.generate_summary()
    assert observable.has_tag(TAG_NRD)


@pytest.mark.unit
def test_analyzer_no_match_produces_no_analysis(nrd_db, test_context, creation_lookup):
    nrd_db(["other-domain.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "not-in-nrd-list.example")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is None
    assert not observable.has_tag(TAG_NRD)
    # a miss must never cost a registration lookup
    assert creation_lookup.calls == []


@pytest.mark.unit
def test_analyzer_handles_missing_database(tmp_path, monkeypatch, test_context):
    # Point at a nonexistent DB.
    monkeypatch.setattr(nrd_util, "get_database_path", lambda: tmp_path / "no-such-db.db")
    _reset_connection_for_tests()

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "anything.example")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    try:
        result = analyzer.execute_analysis(observable)
    finally:
        _reset_connection_for_tests()

    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(NRDAnalysis) is None


@pytest.mark.unit
def test_analyzer_tags_url_observable_on_match(nrd_db, test_context, creation_lookup):
    """In email mode where parse_url isn't enabled, the analyzer must run on URL observables."""
    nrd_db(["phish-test.com"])

    root = create_root_analysis()
    root.initialize_storage()
    # URL has a subdomain to exercise both URL host extraction and the parent walk.
    observable = root.add_observable_by_spec(F_URL, "https://login.phish-test.com/start?q=1")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.is_nrd is True
    assert observable.has_tag(TAG_NRD)
    # the registration lookup gets the registrable domain of the URL host
    assert creation_lookup.calls == ["phish-test.com"]


@pytest.mark.unit
def test_analyzer_url_observable_no_match(nrd_db, test_context):
    nrd_db(["other-domain.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://safe-host.example/foo")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(NRDAnalysis) is None
    assert not observable.has_tag(TAG_NRD)


@pytest.mark.unit
def test_analyzer_idn_input_matches_punycode_row(nrd_db, test_context, creation_lookup):
    """IDN input should match the punycode-form row stored in the database."""
    nrd_db(["xn--caf-dma.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "café.example")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.is_nrd is True
    # the registration lookup gets the punycode (A-label) form
    assert creation_lookup.calls == ["xn--caf-dma.example"]


# ---------------------------------------------------------------------------
# Registration-age verification (RDAP/WHOIS)
# ---------------------------------------------------------------------------


def _make_analyzer(test_context, max_age_days="unset"):
    config = get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER).model_copy()
    if max_age_days != "unset":
        config.max_registration_age_days = max_age_days
    return NRDAnalyzer(context=test_context, config=config)


@pytest.mark.unit
def test_analyzer_suppresses_old_registration(nrd_db, test_context, creation_lookup):
    """A feed hit whose RDAP registration age exceeds the threshold is treated
    like a miss — no analysis, no tag."""
    nrd_db(["old-domain.example"])
    creation_lookup.result = DomainCreationLookup(
        datetime.now(timezone.utc) - timedelta(days=10000), "rdap", None
    )

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "old-domain.example")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(NRDAnalysis) is None
    assert not observable.has_tag(TAG_NRD)
    assert creation_lookup.calls == ["old-domain.example"]


@pytest.mark.unit
def test_analyzer_age_equal_to_threshold_still_counts(nrd_db, test_context, creation_lookup):
    nrd_db(["boundary.example"])
    creation_lookup.result = DomainCreationLookup(
        datetime.now(timezone.utc) - timedelta(days=90), "rdap", None
    )

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "boundary.example")

    analyzer = _make_analyzer(test_context, max_age_days=90)
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.age_created_in_days == "90"
    assert observable.has_tag(TAG_NRD)


@pytest.mark.unit
def test_analyzer_fails_open_on_lookup_failure(nrd_db, test_context, creation_lookup):
    """When neither RDAP nor WHOIS can produce a creation date, the hit is
    kept (tagged) and the analysis records why it could not be verified."""
    nrd_db(["unverifiable.example"])
    creation_lookup.result = DomainCreationLookup(
        None, None, "rdap: no RDAP service for TLD: example; whois: query failed"
    )

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "unverifiable.example")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.is_nrd is True
    assert analysis.age_created_in_days is None
    assert analysis.datetime_created is None
    assert analysis.lookup_protocol is None
    assert analysis.lookup_error.startswith("rdap:")
    assert "unverified" in analysis.generate_summary()
    assert observable.has_tag(TAG_NRD)


@pytest.mark.unit
@pytest.mark.parametrize("disabled_value", [None, 0])
def test_analyzer_verification_disabled(nrd_db, test_context, creation_lookup, disabled_value):
    """max_registration_age_days of None/0 restores the pre-verification
    behavior: every hit is tagged and no lookup is performed."""
    nrd_db(["hit.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "hit.example")

    analyzer = _make_analyzer(test_context, max_age_days=disabled_value)
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.is_nrd is True
    assert analysis.age_created_in_days is None
    assert analysis.lookup_error is None
    assert analysis.generate_summary() == "Newly Registered Domain: present in local NRD list"
    assert observable.has_tag(TAG_NRD)
    assert creation_lookup.calls == []


@pytest.mark.unit
def test_analyzer_config_class_wiring():
    config = get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER)
    assert isinstance(config, NRDAnalyzerConfig)
    assert config.max_registration_age_days == 90


# ---------------------------------------------------------------------------
# extended_version (cache-key invalidation tied to the NRD database)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_extended_version_returns_db_version_string(nrd_db, test_context):
    nrd_db(["seed.example"])

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )

    ev = analyzer.extended_version
    assert set(ev) == {"nrd_db_version"}
    # Format: "<mtime_ns>-<size>" — both positive integers.
    mtime_str, _, size_str = ev["nrd_db_version"].partition("-")
    assert int(mtime_str) > 0
    assert int(size_str) > 0


@pytest.mark.unit
def test_extended_version_empty_when_db_missing(tmp_path, monkeypatch, test_context):
    monkeypatch.setattr(nrd_util, "get_database_path", lambda: tmp_path / "no-such.db")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )

    assert analyzer.extended_version == {}


@pytest.mark.unit
def test_extended_version_changes_when_db_rotated(nrd_db, test_context):
    """An atomic-swap-style file replacement must produce a new version string."""
    db_path = nrd_db(["before.example"])

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )

    before = analyzer.extended_version["nrd_db_version"]

    # Rebuild with different content. Force mtime forward by 1s so the version
    # string changes deterministically — small SQLite DBs fit in one 4KB page
    # and may share size; rapid rebuilds may share mtime tick on some FS.
    nrd_db(["before.example", "after.example", "another.example"])
    st = os.stat(db_path)
    os.utime(db_path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))

    after = analyzer.extended_version["nrd_db_version"]
    assert before != after


@pytest.mark.unit
def test_extended_version_feeds_cache_key(nrd_db, test_context):
    """End-to-end: two DB snapshots must produce different cache keys for the same observable."""
    from datetime import timedelta

    from saq.analysis.cache import generate_cache_key
    from saq.observables.network.dns import FQDNObservable

    nrd_db(["target.example"])
    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    # Force cache_ttl regardless of YAML state under test so generate_cache_key emits a key.
    analyzer.config.cache_ttl = timedelta(seconds=86400)

    observable = FQDNObservable("target.example")

    key_before = generate_cache_key(observable, analyzer)

    db_path = nrd_util.get_database_path()
    nrd_db(["target.example", "extra.example"])
    st = os.stat(db_path)
    os.utime(db_path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    key_after = generate_cache_key(observable, analyzer)

    assert key_before is not None
    assert key_after is not None
    assert key_before != key_after
