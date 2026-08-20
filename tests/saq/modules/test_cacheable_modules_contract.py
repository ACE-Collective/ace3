"""CI lint: every module configured with ``cache_ttl`` must satisfy the
cacheability contract — its execute_analysis must not produce removals,
must keep relationships within its own output, and (unless registered
``file_capable``) must not spawn file observables.

Phase 3 design doc §A4 / Step 3.8; file-capable handling added in
Phase 4. Catches forgotten opt-outs at PR time before they corrupt the
cache.

Two-layer enforcement:

1. ``test_yaml_cache_ttl_modules_have_contract_check`` — scans
   ``etc/saq.default.yaml`` (and any environment overlays present)
   for entries with ``cache_ttl`` set, then asserts each module is
   covered by an entry in ``CONTRACT_CHECKERS`` below. Adding
   ``cache_ttl`` to a module without registering a contract check
   here fails the suite with a helpful message.

2. ``test_module_contract`` (parametrized) — for each registered
   module, runs ``execute_analysis`` against a synthetic observable
   (with external dependencies mocked) and asserts the delta is
   contract-clean. ``file_capable`` modules (Phase 4: OCR, QR) may
   spawn file observables, but each file spec must be blob-backable:
   sha256 value, captured relative path, backing file present, and
   under the size cap.
"""
from collections.abc import Callable
from datetime import datetime, timezone
from typing import NamedTuple

import pytest
import yaml

from saq.analysis.snapshot import ModuleExecutionSnapshot
from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import (
    ANALYSIS_MODULE_NRD_ANALYZER,
    ANALYSIS_MODULE_OCR,
    ANALYSIS_MODULE_PHISHKIT_ANALYZER,
    ANALYSIS_MODULE_QRCODE,
    ANALYSIS_MODULE_RDAP_ANALYZER,
    ANALYSIS_MODULE_SITE_TAGGER,
    DIRECTIVE_CRAWL,
    DIRECTIVE_OCR,
    F_FQDN,
    F_IP,
    F_URL,
    FILE_SUBDIR,
    AnalysisExecutionResult,
)
from saq.util.hashing import is_sha256_hex
from tests.saq.helpers import create_root_analysis

# ----------------------------------------------------------------------
# Per-module contract runners
# ----------------------------------------------------------------------

def _check_rdap_analyzer(test_context, monkeypatch):
    """Runs RdapAnalyzer with a mocked ``whoisit.domain()`` (and a
    failing ``whois.whois()`` to guard against the fallback firing).
    Returns the delta produced. Mirrors the mock pattern in
    test_rdap.py.
    """
    from saq.modules.rdap import RdapAnalyzer

    fake_rdap = {
        "name": "EXAMPLE.COM",
        "url": "https://rdap.example.test/com/v1/domain/EXAMPLE.COM",
        "nameservers": ["NS1.EXAMPLE.COM"],
        "registration_date": datetime(2000, 1, 1, tzinfo=timezone.utc),
        "last_changed_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "expiration_date": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "entities": {
            "registrar": [{"name": "Test Registrar", "email": "noc@example.test"}],
        },
        "raw": {"objectClassName": "domain"},
    }
    monkeypatch.setattr("saq.modules.rdap.whoisit.is_bootstrapped", lambda: True)
    monkeypatch.setattr("saq.modules.rdap.whoisit.bootstrap", lambda: True)
    monkeypatch.setattr("saq.modules.rdap.whoisit.domain", lambda _d, **_kw: fake_rdap)

    def _whois_must_not_be_called(_domain):
        raise AssertionError(
            "whois.whois must not be called when RDAP succeeds"
        )

    monkeypatch.setattr("saq.modules.rdap.whois.whois", _whois_must_not_be_called)

    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = RdapAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_RDAP_ANALYZER),
    )
    analyzer.root = root

    before = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    result = analyzer.execute_analysis(obs)
    after = ModuleExecutionSnapshot.narrow(root, obs, analyzer)

    assert result == AnalysisExecutionResult.COMPLETED
    return ModuleExecutionSnapshot.diff(before, after, analyzer, obs), root


def _check_nrd_analyzer(test_context, monkeypatch):
    """Runs NRDAnalyzer against a real on-disk SQLite NRD DB containing
    a single hit row. Mirrors the ``nrd_db`` fixture in test_nrd.py.
    """
    import sqlite3
    import tempfile
    from datetime import datetime, timedelta, timezone
    from pathlib import Path

    from saq.modules.nrd import NRDAnalyzer
    from saq.modules.rdap import DomainCreationLookup
    from saq.nrd import util as nrd_util
    from saq.nrd.util import _reset_connection_for_tests

    # Keep the contract run offline: the analyzer verifies hits via RDAP.
    monkeypatch.setattr(
        "saq.modules.nrd.lookup_domain_creation_date",
        lambda _domain: DomainCreationLookup(
            datetime.now(timezone.utc) - timedelta(days=3), "rdap", None
        ),
    )

    tmp_dir = Path(tempfile.mkdtemp())
    db_path = tmp_dir / "nrd_index.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE nrd (domain TEXT PRIMARY KEY) WITHOUT ROWID;
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            """
        )
        with conn:
            conn.execute("INSERT INTO nrd (domain) VALUES ('example.com')")
    finally:
        conn.close()

    monkeypatch.setattr(nrd_util, "get_database_path", lambda: db_path)
    _reset_connection_for_tests()

    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    before = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    result = analyzer.execute_analysis(obs)
    after = ModuleExecutionSnapshot.narrow(root, obs, analyzer)

    _reset_connection_for_tests()

    assert result == AnalysisExecutionResult.COMPLETED
    return ModuleExecutionSnapshot.diff(before, after, analyzer, obs), root


def _check_site_tagger(test_context, monkeypatch):
    """Runs SiteTagAnalyzer against a temp CSV containing one CIDR rule
    that matches an F_IP observable. Verifies the live analyzer's
    delta is contract-clean — single tag added to the target observable,
    no children, no removals, no file observables.
    """
    import tempfile
    from pathlib import Path

    from saq.modules.tag import SiteTagAnalyzer

    tmp_dir = Path(tempfile.mkdtemp())
    csv_path = tmp_dir / "site_tags.csv"
    csv_path.write_text("ipv4,cidr,false,10.0.0.0/8,internal-network\n")

    # Override the CSV path via the analyzer's csv_file property so we don't
    # touch the real shipped file.
    monkeypatch.setattr(
        SiteTagAnalyzer,
        "csv_file",
        property(lambda _self: str(csv_path)),
    )

    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_observable_by_spec(F_IP, "10.1.2.3")

    analyzer = SiteTagAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_SITE_TAGGER),
    )
    analyzer.root = root

    before = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    result = analyzer.execute_analysis(obs)
    after = ModuleExecutionSnapshot.narrow(root, obs, analyzer)

    assert result == AnalysisExecutionResult.COMPLETED
    return ModuleExecutionSnapshot.diff(before, after, analyzer, obs), root


def _make_png(directory) -> str:
    """Write a small synthetic PNG and return its path."""
    import os

    from PIL import Image

    path = os.path.join(directory, "contract_test.png")
    Image.new("RGB", (64, 64), "white").save(path)
    return path


def _check_ocr(test_context, monkeypatch):
    """Runs OCRAnalyzer against a synthetic PNG with the tesseract call
    (``get_image_text``) mocked to fixed text — the delta shape (output
    file write, add_file_observable, relationship, redirection) is real,
    only the text extraction is faked, keeping the lint deterministic.
    """
    import tempfile

    from saq.modules.file_analysis.ocr import OCRAnalyzer

    monkeypatch.setattr(
        "saq.modules.file_analysis.ocr.get_image_text",
        lambda _image: "EXTRACTED TEXT https://example.com/",
    )

    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_file_observable(_make_png(tempfile.mkdtemp()))
    obs.add_directive(DIRECTIVE_OCR)

    analyzer = OCRAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_OCR),
    )
    analyzer.root = root

    before = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    result = analyzer.execute_analysis(obs)
    after = ModuleExecutionSnapshot.narrow(root, obs, analyzer)

    assert result == AnalysisExecutionResult.COMPLETED
    delta = ModuleExecutionSnapshot.diff(before, after, analyzer, obs)
    assert delta.has_file_observables, "OCR contract check failed to produce a file"
    return delta, root


def _check_qrcode(test_context, monkeypatch):
    """Runs QRCodeAnalyzer against a synthetic PNG with the zbarimg call
    (``_scan_image``) mocked to return a URL — the delta shape (output
    file write, add_file_observable, relationship, tags) is real.
    """
    import tempfile

    from saq.modules.file_analysis.qrcode import QRCodeAnalyzer

    monkeypatch.setattr(
        QRCodeAnalyzer, "_scan_image",
        lambda _self, _path: "https://example.com/qr-target\n",
    )

    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_file_observable(_make_png(tempfile.mkdtemp()))

    analyzer = QRCodeAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE),
    )
    analyzer.root = root

    before = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    result = analyzer.execute_analysis(obs)
    after = ModuleExecutionSnapshot.narrow(root, obs, analyzer)

    assert result == AnalysisExecutionResult.COMPLETED
    delta = ModuleExecutionSnapshot.diff(before, after, analyzer, obs)
    assert delta.has_file_observables, "QR contract check failed to produce a file"
    return delta, root


def _check_phishkit(test_context, monkeypatch):
    """Drives PhishkitAnalyzer through its REAL delayed lifecycle with the celery
    scan mocked: cycle 1 (execute_analysis) dispatches and delays (INCOMPLETE);
    the orchestrator's delayed-flag reset is simulated; cycle 2
    (continue_analysis, resuming) harvests a fixture output dir and completes.
    The merged delta is the real cache shape — the completed analysis, a file
    observable (captured ``dom.html``), and an extracted URL observable.
    Phishkit is the first delayed *and* file-producing cacheable module, so this
    exercises that intersection.
    """
    import os
    import tempfile

    from saq.analysis.module_execution_delta import merge_module_execution_deltas
    from saq.modules.phishkit import PhishkitAnalysis, PhishkitAnalyzer

    out_dir = tempfile.mkdtemp()
    # dom.html is a non-special output file → becomes a file observable, and its
    # MARKER URL line drives URL-observable extraction. exit.code is consumed,
    # not turned into an observable.
    dom_path = os.path.join(out_dir, "dom.html")
    with open(dom_path, "w") as fp:
        fp.write("<html></html>\nMARKER URL: https://example.com/next-stage\n")
    exit_code_path = os.path.join(out_dir, "exit.code")
    with open(exit_code_path, "w") as fp:
        fp.write("0")
    output_files = [exit_code_path, dom_path]

    def fake_delay(self, observable, analysis, **kwargs):
        analysis.delayed = True
        return AnalysisExecutionResult.INCOMPLETE

    monkeypatch.setattr(
        "saq.modules.phishkit.scan_url",
        lambda url, output_dir, **kwargs: "contract-job",
    )
    monkeypatch.setattr(
        "saq.modules.phishkit.get_async_scan_result",
        lambda job_id, output_dir, timeout=1: output_files,
    )
    monkeypatch.setattr(
        "saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", fake_delay,
    )
    monkeypatch.setattr(
        "saq.modules.phishkit.create_temporary_directory",
        lambda: out_dir,
    )

    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    obs.add_directive(DIRECTIVE_CRAWL)

    analyzer = PhishkitAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
    )
    analyzer.root = root

    # cycle 1: dispatch + delay
    before1 = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    assert analyzer.execute_analysis(obs) == AnalysisExecutionResult.INCOMPLETE
    after1 = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    delta_a = ModuleExecutionSnapshot.diff(before1, after1, analyzer, obs,
                                           is_resuming_delayed_module=False)
    root.record_module_execution(delta_a.without_analysis_details())
    analysis = obs.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None

    # orchestrator clears the delay flag before the resuming cycle's snapshot
    analysis.delayed = False

    # cycle 2 (resume): harvest + complete
    before2 = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    assert analyzer.continue_analysis(obs, analysis) == AnalysisExecutionResult.COMPLETED
    after2 = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    delta_b = ModuleExecutionSnapshot.diff(before2, after2, analyzer, obs,
                                           is_resuming_delayed_module=True)

    prior = [d for d in root.module_executions
             if d.module_path == delta_b.module_path
             and d.observable_uuid == delta_b.observable_uuid
             and not d.from_cache_hit
             and (d.analysis is None or d.analysis.get("delayed"))]
    delta = merge_module_execution_deltas(prior, delta_b)
    assert delta.has_file_observables, "phishkit contract check failed to produce a file"
    return delta, root


class ContractCheck(NamedTuple):
    runner: Callable  # callable(test_context, monkeypatch) -> (delta, root)
    file_capable: bool  # True: module may spawn file observables (Phase 4)


# Registry of contract checkers — one entry per module with cache_ttl
# set in any deployed YAML. Adding a new ``cache_ttl`` to a module
# without registering it here fails
# ``test_yaml_cache_ttl_modules_have_contract_check``.
#
# Key: YAML config block name (e.g. ``analysis_module_rdap_analyzer``).
# Value: ContractCheck(runner, file_capable).
CONTRACT_CHECKERS: dict[str, ContractCheck] = {
    "analysis_module_site_tagger": ContractCheck(_check_site_tagger, file_capable=False),
    "analysis_module_nrd_analyzer": ContractCheck(_check_nrd_analyzer, file_capable=False),
    "analysis_module_rdap_analyzer": ContractCheck(_check_rdap_analyzer, file_capable=False),
    "analysis_module_ocr": ContractCheck(_check_ocr, file_capable=True),
    "analysis_module_qrcode": ContractCheck(_check_qrcode, file_capable=True),
    "analysis_module_phishkit_analyzer": ContractCheck(_check_phishkit, file_capable=True),
}


# ----------------------------------------------------------------------
# YAML scanner
# ----------------------------------------------------------------------

def _yaml_files_to_scan() -> list[str]:
    """List of YAML config files to scan for cache_ttl opt-ins.

    Includes the open-source default. Local-dev (etc/saq.yaml) and
    integration overlays are deliberately NOT scanned: those are
    operator-controlled overrides and may contain experimental opt-ins
    that don't ship to prod. The test enforces the contract on what
    the project commits to ship.
    """
    import os

    from saq.environment import get_base_dir

    candidates = [
        os.path.join(get_base_dir(), "etc/saq.default.yaml"),
    ]
    return [p for p in candidates if os.path.exists(p)]


def _modules_with_cache_ttl() -> list[str]:
    """Walk shipped YAML files and yield module config block names that
    set a non-null ``cache_ttl``.
    """
    found: set[str] = set()
    for path in _yaml_files_to_scan():
        with open(path, "r") as fp:
            data = yaml.safe_load(fp) or {}
        if not isinstance(data, dict):
            continue
        for key, value in data.items():
            if not isinstance(value, dict):
                continue
            if not key.startswith("analysis_module_"):
                continue
            if value.get("cache_ttl") is not None:
                found.add(key)
    return sorted(found)


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------

@pytest.mark.unit
def test_yaml_cache_ttl_modules_have_contract_check():
    """Every YAML-shipped cacheable module must have a contract check
    registered in CONTRACT_CHECKERS. Catches new opt-ins that ship
    without test coverage of the cacheability contract.
    """
    yaml_modules = set(_modules_with_cache_ttl())
    registered = set(CONTRACT_CHECKERS.keys())
    missing = yaml_modules - registered
    assert not missing, (
        f"Modules with cache_ttl in shipped YAML but no contract check: "
        f"{sorted(missing)}. Add an entry to CONTRACT_CHECKERS in "
        f"tests/saq/modules/test_cacheable_modules_contract.py."
    )


@pytest.mark.unit
@pytest.mark.parametrize("module_key", sorted(CONTRACT_CHECKERS.keys()))
def test_module_contract(module_key, test_context, monkeypatch):
    """For each registered cacheable module, run execute_analysis with
    mocked external dependencies and assert the delta is contract-clean.
    """
    import os

    check = CONTRACT_CHECKERS[module_key]
    delta, root = check.runner(test_context, monkeypatch)

    assert not delta.has_removals, (
        f"{module_key}: delta has removals — the cacheability contract "
        f"requires monotonic (additive-only) modules. Either remove "
        f"cache_ttl from this module's YAML or fix the module to be "
        f"additive."
    )
    assert not delta.out_of_scope_relationship_targets(), (
        f"{module_key}: delta adds relationships targeting observables "
        f"outside the module's own output (not the analyzed observable "
        f"and not created by this delta). Such relationships depend on "
        f"surrounding tree context and cannot be replayed onto a "
        f"different root — remove cache_ttl from this module's YAML."
    )
    if not check.file_capable:
        assert not delta.has_file_observables, (
            f"{module_key}: delta spawns file observables but is not "
            f"registered file_capable. If the module's file output is "
            f"blob-backable (Phase 4), set file_capable=True in its "
            f"ContractCheck; otherwise remove cache_ttl from its YAML."
        )
        return

    # Phase 4 file-capable contract: every file spec must be exactly what
    # the write path needs to blob-back it.
    max_bytes = get_config().analysis_cache.file_blob_max_bytes
    for spec in delta.file_observable_specs():
        assert is_sha256_hex(spec.value), (
            f"{module_key}: file spec value {spec.value!r} is not a "
            f"sha256 — the blob store keys on content hash."
        )
        assert spec.file_path, (
            f"{module_key}: file spec has no file_path — replay cannot "
            f"place the file in the target alert."
        )
        backing = os.path.join(root.storage_dir, FILE_SUBDIR, spec.file_path)
        assert os.path.exists(backing), (
            f"{module_key}: file spec's backing file {backing} does not "
            f"exist — the cache write would be refused (file_missing)."
        )
        assert not max_bytes or os.path.getsize(backing) <= max_bytes, (
            f"{module_key}: produced file exceeds "
            f"analysis_cache.file_blob_max_bytes ({max_bytes}) — the "
            f"cache write would be refused (file_too_large)."
        )
