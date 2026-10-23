"""Unit tests for ``saq.modules.tag.SiteTagAnalyzer``.

Focus areas:

- The behavior change from "create_analysis on every observable whose type
  is in tag_mapping" to "create_analysis only when a rule matches."
- The ``extended_version`` property added for Phase 3 cache opt-in: returns
  the rules CSV's ``(mtime_ns, size)`` so analyst edits invalidate the
  cache key in step with the in-process ``watch_file`` reload.
"""
import logging
import os
from pathlib import Path

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_SITE_TAGGER,
    AnalysisExecutionResult,
    F_FQDN,
    F_IP,
)
from saq.environment import get_base_dir
from saq.modules.tag import SiteTagAnalysis, SiteTagAnalyzer
from tests.saq.helpers import create_root_analysis


pytestmark = pytest.mark.unit


@pytest.fixture
def site_tags_csv(tmp_path, monkeypatch):
    """Provide an isolated CSV file. Returns a callable to (re)write rules.

    Each call replaces the file's contents and returns the file's path so
    tests can ``os.utime`` it to force mtime separation when needed.
    """
    csv_path = tmp_path / "site_tags.csv"
    csv_path.write_text("")
    monkeypatch.setattr(
        SiteTagAnalyzer,
        "csv_file",
        property(lambda _self: str(csv_path)),
    )

    def writer(rows: list[str]) -> Path:
        csv_path.write_text("\n".join(rows) + ("\n" if rows else ""))
        return csv_path

    return writer


def _build_analyzer(test_context):
    return SiteTagAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_SITE_TAGGER),
    )


# ---------------------------------------------------------------------------
# Behavior: create_analysis only when a rule matches
# ---------------------------------------------------------------------------


def test_analyzer_creates_analysis_and_tags_on_match(site_tags_csv, test_context):
    site_tags_csv(["ip,cidr,false,10.0.0.0/8,internal-network"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, "10.1.2.3")

    analyzer = _build_analyzer(test_context)
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(SiteTagAnalysis)
    assert analysis is not None
    assert analysis.tags_added == ["internal-network"]
    assert analysis.generate_summary() == "Site Tags: internal-network"
    assert observable.has_tag("internal-network")


def test_analyzer_no_match_no_analysis(site_tags_csv, test_context):
    """Type IS in tag_mapping, but no rule matches the value — under the
    fix, no SiteTagAnalysis should be created."""
    site_tags_csv(["ip,cidr,false,10.0.0.0/8,internal-network"])

    root = create_root_analysis()
    root.initialize_storage()
    # Outside the 10.0.0.0/8 CIDR — rule won't match.
    observable = root.add_observable_by_spec(F_IP, "203.0.113.45")

    analyzer = _build_analyzer(test_context)
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(SiteTagAnalysis) is None
    assert not observable.tags


def test_analyzer_type_not_in_mapping_skips_entirely(site_tags_csv, test_context):
    """Type isn't in tag_mapping at all — fast-exit path, no analysis."""
    site_tags_csv(["ip,cidr,false,10.0.0.0/8,internal-network"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = _build_analyzer(test_context)
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(SiteTagAnalysis) is None


def test_reload_does_not_duplicate_rules(site_tags_csv, test_context):
    """Repeated load_csv_file calls must not duplicate rules — watch_file
    re-fires the callback on every mtime change, and prior to the clear()
    fix each reload appended every rule again.
    """
    site_tags_csv(["ip,cidr,false,10.0.0.0/8,internal-network"])

    analyzer = _build_analyzer(test_context)
    # After __init__ the mapping has exactly one rule for ip.
    assert len(analyzer.tag_mapping["ip"]) == 1

    # Simulate the engine re-firing the callback (e.g., the CSV was touched).
    analyzer.load_csv_file()
    analyzer.load_csv_file()

    assert len(analyzer.tag_mapping["ip"]) == 1

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, "10.1.2.3")
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(SiteTagAnalysis)
    # The tag must appear exactly once even after multiple reloads.
    assert analysis.tags_added == ["internal-network"]


def test_analyzer_multiple_matching_rules_single_analysis(site_tags_csv, test_context):
    """Two rules match the same observable — one analysis, both tags."""
    site_tags_csv([
        "ip,cidr,false,10.0.0.0/8,internal-network",
        "ip,cidr,false,10.1.0.0/16,corp-vpn",
    ])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, "10.1.2.3")

    analyzer = _build_analyzer(test_context)
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(SiteTagAnalysis)
    assert analysis is not None
    assert set(analysis.tags_added) == {"internal-network", "corp-vpn"}
    assert observable.has_tag("internal-network")
    assert observable.has_tag("corp-vpn")


# ---------------------------------------------------------------------------
# extended_version (cache-key invalidation tied to the rules CSV)
# ---------------------------------------------------------------------------


def test_extended_version_returns_csv_version_string(site_tags_csv, test_context):
    site_tags_csv(["ip,cidr,false,10.0.0.0/8,internal-network"])

    analyzer = _build_analyzer(test_context)

    ev = analyzer.extended_version
    assert set(ev) == {"site_tags_version"}
    mtime_str, _, size_str = ev["site_tags_version"].partition("-")
    assert int(mtime_str) > 0
    assert int(size_str) > 0


def test_extended_version_empty_when_csv_missing(tmp_path, monkeypatch, test_context):
    monkeypatch.setattr(
        SiteTagAnalyzer,
        "csv_file",
        property(lambda _self: str(tmp_path / "no-such.csv")),
    )

    # __init__ calls watch_file → check_watched_files which silently no-ops
    # on missing files, so the analyzer constructs fine even without the CSV.
    analyzer = _build_analyzer(test_context)

    assert analyzer.extended_version == {}


def test_extended_version_changes_when_csv_rotated(site_tags_csv, test_context):
    csv_path = site_tags_csv(["ip,cidr,false,10.0.0.0/8,internal-network"])

    analyzer = _build_analyzer(test_context)
    before = analyzer.extended_version["site_tags_version"]

    # Rewrite with different rules — different size at least.
    site_tags_csv([
        "ip,cidr,false,10.0.0.0/8,internal-network",
        "ip,cidr,false,192.168.0.0/16,private",
    ])
    # Force mtime forward 1s in case the two writes land in the same FS tick.
    st = os.stat(csv_path)
    os.utime(csv_path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))

    after = analyzer.extended_version["site_tags_version"]
    assert before != after


# ---------------------------------------------------------------------------
# The rules CSV and the match types
# ---------------------------------------------------------------------------


def _tags_for(analyzer, o_type, value):
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(o_type, value)
    analyzer.root = root
    analyzer.execute_analysis(observable)
    return sorted(observable.tags)


def test_ignore_case_column(site_tags_csv, test_context):
    # bool() of any non-empty string is True, so "false" used to ignore case too
    site_tags_csv([
        "fqdn,default,false,Exact.example.com,exact",
        "fqdn,default,true,Caseless.example.com,caseless",
        "fqdn,default,,Blank.example.com,blank",
    ])
    analyzer = _build_analyzer(test_context)

    assert _tags_for(analyzer, F_FQDN, "exact.example.com") == []
    assert _tags_for(analyzer, F_FQDN, "Exact.example.com") == ["exact"]
    assert _tags_for(analyzer, F_FQDN, "caseless.EXAMPLE.com") == ["caseless"]
    assert _tags_for(analyzer, F_FQDN, "blank.example.com") == []


def test_glob_ignore_case(site_tags_csv, test_context):
    # fnmatch.fnmatch only ignores case on Windows
    site_tags_csv([
        "fqdn,glob,true,*.Caseless.example.com,caseless",
        "fqdn,glob,false,*.Exact.example.com,exact",
    ])
    analyzer = _build_analyzer(test_context)

    assert _tags_for(analyzer, F_FQDN, "www.caseless.example.com") == ["caseless"]
    assert _tags_for(analyzer, F_FQDN, "www.exact.example.com") == []
    assert _tags_for(analyzer, F_FQDN, "www.Exact.example.com") == ["exact"]


def test_match_types(site_tags_csv, test_context):
    site_tags_csv([
        "fqdn|url,regex,true,^https?://EVIL,evil-url",
        "fqdn,regex,false,^Evil,evil-exact",
        "fqdn,subdomain,false,corp.example.com,corp|internal",
        "ip,cidr,false,10.0.0.0/8,internal-network",
    ])
    analyzer = _build_analyzer(test_context)

    assert _tags_for(analyzer, "url", "http://evil.example.com/x") == ["evil-url"]
    assert _tags_for(analyzer, F_FQDN, "evil.example.com") == []
    assert _tags_for(analyzer, F_FQDN, "Evil.example.com") == ["evil-exact"]
    assert _tags_for(analyzer, F_FQDN, "mail.corp.example.com") == ["corp", "internal"]
    assert _tags_for(analyzer, F_FQDN, "corp.example.com.evil.com") == []
    assert _tags_for(analyzer, F_IP, "10.9.8.7") == ["internal-network"]
    assert _tags_for(analyzer, F_IP, "192.168.1.1") == []


def test_invalid_rows_are_skipped(site_tags_csv, test_context, caplog):
    # an invalid row used to raise out of the load and drop every rule after it
    site_tags_csv([
        "fqdn,default,false,first.example.com,first",
        "fqdn,default,false,too-few-columns",
        "",
        "fqdn,regex,false,[unclosed,bad-regex",
        "ip,cidr,false,10.0.0.0/33,bad-cidr",
        "fqdn,fuzzy,false,last.example.com,bad-type",
        "fqdn,default,false,last.example.com,last",
    ])
    analyzer = _build_analyzer(test_context)

    assert _tags_for(analyzer, F_FQDN, "first.example.com") == ["first"]
    assert _tags_for(analyzer, F_FQDN, "last.example.com") == ["last"]
    invalid = [r.getMessage() for r in caplog.records
               if r.levelno == logging.ERROR and "invalid tag specification" in r.getMessage()]
    assert len(invalid) == 4
    assert any("invalid match type: fuzzy" in m for m in invalid)


def test_csv_file_path(monkeypatch, test_context, tmp_path):
    config = get_analysis_module_config(ANALYSIS_MODULE_SITE_TAGGER)
    monkeypatch.setattr(config, "csv_file", "etc/missing_site_tags.csv")
    analyzer = SiteTagAnalyzer(context=test_context, config=config)

    assert analyzer.csv_file == os.path.join(get_base_dir(), "etc/missing_site_tags.csv")
    assert analyzer.tag_mapping == {}
    assert analyzer.extended_version == {}
    with pytest.raises(RuntimeError, match="missing"):
        analyzer.verify_environment()

    monkeypatch.setattr(config, "csv_file", str(tmp_path / "site_tags.csv"))
    assert analyzer.csv_file == str(tmp_path / "site_tags.csv")
