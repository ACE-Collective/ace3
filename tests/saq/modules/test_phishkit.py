import json
import os
import subprocess
import tempfile
from unittest.mock import MagicMock

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_MODULE_OCR, ANALYSIS_MODULE_PHISHKIT_ANALYZER, DIRECTIVE_CRAWL, DIRECTIVE_RENDER, F_FILE, F_URL, AnalysisExecutionResult
from saq.modules.phishkit import (
    PhishkitAnalysis,
    PhishkitAnalyzer,
    FIELD_OUTPUT_DIR,
    FIELD_JOB_ID,
    FIELD_SCAN_TYPE,
    FIELD_SCAN_RESULT,
    FIELD_OUTPUT_FILES,
    FIELD_ERROR,
    FIELD_EXIT_CODE,
    FIELD_STDOUT,
    FIELD_STDERR,
    FIELD_PROXY_STATUS,
    OCR_SKIP_CONTENT_TYPES,
    SCAN_TYPE_URL,
    SCAN_TYPE_FILE
)
from saq.modules.file_analysis import FileTypeAnalysis, OCRAnalyzer
import saq.phishkit
from saq.analysis.blob_store import LocalHardlinkBlobStore, LocalHardlinkBlobStoreConfig
from saq.analysis.cache import apply_delta, generate_cache_key, get_cached_delta, put_cached_delta
from saq.analysis.module_execution_delta import merge_module_execution_deltas
from saq.analysis.snapshot import ModuleExecutionSnapshot
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


@pytest.mark.unit
def test_phishkit_analysis_init():
    """Test PhishkitAnalysis initialization."""
    analysis = PhishkitAnalysis()
    assert analysis.details[FIELD_EXIT_CODE] is None
    assert analysis.details[FIELD_STDOUT] is None
    assert analysis.details[FIELD_STDERR] is None
    assert analysis.details[FIELD_OUTPUT_DIR] is None
    assert analysis.details[FIELD_JOB_ID] is None
    assert analysis.details[FIELD_SCAN_TYPE] is None
    assert analysis.details[FIELD_SCAN_RESULT] is None
    assert analysis.details[FIELD_OUTPUT_FILES] == []
    assert analysis.details[FIELD_ERROR] is None
    assert analysis.details[FIELD_PROXY_STATUS] is None


@pytest.mark.unit
def test_phishkit_analysis_properties():
    """Test PhishkitAnalysis property getters and setters."""
    analysis = PhishkitAnalysis()

    # Test exit_code
    analysis.exit_code = 0
    assert analysis.exit_code == 0

    # Test stdout
    analysis.stdout = "test stdout"
    assert analysis.stdout == "test stdout"

    # Test stderr
    analysis.stderr = "test stderr"
    assert analysis.stderr == "test stderr"

    # Test output_dir
    analysis.output_dir = "/tmp/test"
    assert analysis.output_dir == "/tmp/test"

    # Test job_id
    analysis.job_id = "test-job-123"
    assert analysis.job_id == "test-job-123"

    # Test scan_type
    analysis.scan_type = SCAN_TYPE_URL
    assert analysis.scan_type == SCAN_TYPE_URL

    # Test scan_result
    analysis.scan_result = "test result"
    assert analysis.scan_result == "test result"

    # Test output_files
    analysis.output_files = ["/tmp/file1.txt", "/tmp/file2.txt"]
    assert analysis.output_files == ["/tmp/file1.txt", "/tmp/file2.txt"]

    # Test error
    analysis.error = "test error"
    assert analysis.error == "test error"

    # Test proxy_status
    proxy_payload = {"configured": True, "final_route": "proxy"}
    analysis.proxy_status = proxy_payload
    assert analysis.proxy_status == proxy_payload


@pytest.mark.unit
def test_phishkit_analysis_generate_summary():
    """Test PhishkitAnalysis summary generation."""
    analysis = PhishkitAnalysis()

    # Test error state
    analysis.error = "Something went wrong"
    assert analysis.generate_summary() == "Phishkit Analysis: failed: Something went wrong"

    # Test URL scan
    analysis.error = None
    analysis.scan_type = SCAN_TYPE_URL
    analysis.output_files = ["/tmp/file1.txt", "/tmp/file2.txt"]
    assert analysis.generate_summary() == "Phishkit Analysis: output files created (/tmp/file1.txt, /tmp/file2.txt)"

    # Test file scan
    analysis.scan_type = SCAN_TYPE_FILE
    analysis.output_files = ["/tmp/file1.txt"]
    assert analysis.generate_summary() == "Phishkit Analysis: output files created (/tmp/file1.txt)"

    # Test unknown scan type
    analysis.scan_type = "unknown"
    assert analysis.generate_summary() == "Phishkit Analysis: completed"


@pytest.mark.unit
@pytest.mark.parametrize("proxy_status,expected_suffix", [
    # No proxy configured — no clause
    ({"configured": False, "fallback_triggered": False, "fallback_reason": None, "final_route": "none"}, ""),
    # Proxy used successfully
    ({"configured": True, "fallback_triggered": False, "fallback_reason": None, "final_route": "proxy"}, " - fetched via proxy"),
    # Proxy failed via error pattern, fell back to direct
    ({"configured": True, "fallback_triggered": True, "fallback_reason": "error_pattern", "final_route": "direct"},
     " - proxy failed (error_pattern), fetched direct"),
    # Proxy failed via status code, fell back to direct
    ({"configured": True, "fallback_triggered": True, "fallback_reason": "status_code", "final_route": "direct"},
     " - proxy failed (status_code), fetched direct"),
    # Proxy timed out, fell back to direct
    ({"configured": True, "fallback_triggered": True, "fallback_reason": "timeout", "final_route": "direct"},
     " - proxy failed (timeout), fetched direct"),
])
def test_phishkit_analysis_generate_summary_proxy_routes(proxy_status, expected_suffix):
    """The summary appends a proxy clause that matches the final_route."""
    analysis = PhishkitAnalysis()
    analysis.scan_type = SCAN_TYPE_URL
    analysis.output_files = ["/tmp/file1.txt"]
    analysis.proxy_status = proxy_status
    expected = "Phishkit Analysis: output files created (/tmp/file1.txt)" + expected_suffix
    assert analysis.generate_summary() == expected


@pytest.mark.integration
def test_phishkit_analyzer_properties():
    """Test PhishkitAnalyzer properties."""
    analyzer = PhishkitAnalyzer(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER))

    assert analyzer.generated_analysis_type == PhishkitAnalysis
    assert analyzer.valid_observable_types == [F_URL, F_FILE]


def _analyzer_with_deny_patterns(tmp_path, root, patterns):
    """Build a PhishkitAnalyzer whose YAML config has the given deny_crawl_url_patterns."""
    import yaml as _yaml
    config_file = tmp_path / "phishkit_config.yaml"
    config_file.write_text(_yaml.safe_dump({"deny_crawl_url_patterns": list(patterns)}))
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root),
    )
    analyzer._yaml_config_path = str(config_file)
    analyzer._load_deny_patterns()
    return analyzer


@pytest.mark.integration
def test_phishkit_custom_requirement_denies_matching_url(tmp_path):
    """custom_requirement returns False for URLs matching a deny pattern."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://login.windows.net/common/oauth2")
    url.add_directive(DIRECTIVE_CRAWL)

    analyzer = _analyzer_with_deny_patterns(tmp_path, root, ["login.windows.net"])

    assert analyzer.custom_requirement(url) is False


@pytest.mark.integration
def test_phishkit_custom_requirement_allows_non_matching_url(tmp_path):
    """custom_requirement returns True for URLs that don't match any deny pattern."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://winecellarsbycoastalblog.com/ls/click")
    url.add_directive(DIRECTIVE_CRAWL)

    analyzer = _analyzer_with_deny_patterns(tmp_path, root, ["login.windows.net", "microsoft.com"])

    assert analyzer.custom_requirement(url) is True


@pytest.mark.integration
def test_phishkit_custom_requirement_case_insensitive(tmp_path):
    """Deny pattern match is case-insensitive."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://LOGIN.Microsoftonline.COM/authorize")
    url.add_directive(DIRECTIVE_CRAWL)

    analyzer = _analyzer_with_deny_patterns(tmp_path, root, ["login.microsoftonline.com"])

    assert analyzer.custom_requirement(url) is False


@pytest.mark.integration
def test_phishkit_custom_requirement_empty_deny_list(tmp_path):
    """Missing deny_crawl_url_patterns means nothing is denied."""
    import yaml as _yaml
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://login.windows.net/common")
    url.add_directive(DIRECTIVE_CRAWL)

    config_file = tmp_path / "phishkit_config.yaml"
    config_file.write_text(_yaml.safe_dump({"skip_body_url_patterns": ["unrelated.com"]}))
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root),
    )
    analyzer._yaml_config_path = str(config_file)
    analyzer._load_deny_patterns()

    assert analyzer._deny_crawl_patterns == []
    assert analyzer.custom_requirement(url) is True


@pytest.mark.integration
def test_phishkit_custom_requirement_missing_yaml_file(tmp_path):
    """A missing YAML config must not crash; deny list stays empty."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://login.windows.net/common")
    url.add_directive(DIRECTIVE_CRAWL)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root),
    )
    analyzer._yaml_config_path = str(tmp_path / "does_not_exist.yaml")
    analyzer._load_deny_patterns()

    assert analyzer._deny_crawl_patterns == []
    assert analyzer.custom_requirement(url) is True


@pytest.mark.integration
def test_phishkit_custom_requirement_invalid_deny_pattern_type(tmp_path):
    """A non-list deny_crawl_url_patterns value should be ignored safely."""
    import yaml as _yaml

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://login.windows.net/common")
    url.add_directive(DIRECTIVE_CRAWL)

    config_file = tmp_path / "phishkit_config.yaml"
    config_file.write_text(_yaml.safe_dump({"deny_crawl_url_patterns": "login.windows.net"}))
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root),
    )
    analyzer._yaml_config_path = str(config_file)
    analyzer._load_deny_patterns()

    assert analyzer._deny_crawl_patterns == []
    assert analyzer.custom_requirement(url) is True


@pytest.mark.integration
def test_phishkit_analyzer_verify_environment(test_context):
    """Test PhishkitAnalyzer environment verification."""
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=test_context
    )
    
    # This should raise an exception if config items are missing
    try:
        analyzer.verify_environment()
    except Exception as e:
        # Expected if config items are not set up
        assert "valid_file_extensions" in str(e) or "valid_mime_types" in str(e)


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_success(monkeypatch, test_context):
    """Test successful URL analysis execution."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable with render directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)
    
    # Mock saq.phishkit functions
    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        return "test-job-123"
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock delay_analysis to mimic the real contract (flag delayed, return
    # INCOMPLETE) without registering an actual delayed request.
    def mock_delay_analysis(self, observable, analysis, **kwargs):
        analysis.delayed = True
        return AnalysisExecutionResult.INCOMPLETE

    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)

    # F_URL returns the delay result (INCOMPLETE) — the scan completes on resume.
    assert result == AnalysisExecutionResult.INCOMPLETE

    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None
    assert analysis.job_id == "test-job-123"
    assert analysis.scan_type == SCAN_TYPE_URL
    # Don't check exact output_dir since it uses temp directory


@pytest.mark.integration
def test_phishkit_custom_requirement_url_requires_crawl_directive(test_context):
    """A URL without the crawl directive is rejected by custom_requirement, not
    execute_analysis. Gating here (before accepts() checks for prior analysis)
    means no "no analysis" sentinel is recorded, so the module is re-dispatched
    if the crawl directive is added later (e.g. by a late observable modifier
    rule). This is the regression guard for the crawl-directive race."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))

    # without the directive the module is skipped and, crucially, records nothing
    assert analyzer.custom_requirement(url_observable) is False
    assert url_observable.get_and_load_analysis(PhishkitAnalysis) is None

    # once the directive lands, the module accepts the observable
    url_observable.add_directive(DIRECTIVE_CRAWL)
    assert analyzer.custom_requirement(url_observable) is True


@pytest.mark.integration
def test_phishkit_custom_requirement_file_requires_render_directive(test_context):
    """A file without the render directive is rejected by custom_requirement
    (same sentinel-avoidance rationale as the URL crawl gate)."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>test</body></html>')
        test_file_path = f.name

    try:
        file_observable = root.add_file_observable(test_file_path)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))

        # no render directive -> rejected, nothing recorded
        assert analyzer.custom_requirement(file_observable) is False
        assert file_observable.get_and_load_analysis(PhishkitAnalysis) is None

        # render directive in correlation mode -> accepted
        file_observable.add_directive(DIRECTIVE_RENDER)
        assert analyzer.custom_requirement(file_observable) is True
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_custom_requirement_file_rejects_non_html_pdf(test_context):
    """A rendered correlation-mode file that is neither html nor pdf is rejected by
    custom_requirement *before* a cache lookup happens, so phishkit stops recording a
    wasted cache miss on every rendered attachment it would immediately skip anyway.
    The mime check reads the file_type declared dependency (FileTypeAnalysis)."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()

    # a non-html/pdf attachment (image) that still carries the render directive
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.png', delete=False) as f:
        f.write(b'\x89PNG\r\n\x1a\n' + b'\x00' * 32)
        test_file_path = f.name

    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)

        # file_type is a declared dependency; provide it directly since we invoke
        # custom_requirement outside the engine (which would normally seed it)
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'PNG image data', 'mime': 'image/png'}
        file_observable.add_analysis(file_type_analysis)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))

        assert analyzer.custom_requirement(file_observable) is False
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_custom_requirement_file_accepts_content_pdf_wrong_extension(test_context):
    """A real PDF whose name lacks a .pdf extension is still accepted by
    custom_requirement via the mime branch, which reads the file_type declared
    dependency (FileTypeAnalysis) -- the authoritative check the engine now guarantees
    is available before this gate runs."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()

    # PDF content but a non-valid extension
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.dat', delete=False) as f:
        f.write(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
        test_file_path = f.name

    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)

        # FileTypeAnalysis (declared dependency) reports the real pdf mime type
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'PDF document', 'mime': 'application/pdf'}
        file_observable.add_analysis(file_type_analysis)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))

        assert analyzer.custom_requirement(file_observable) is True
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_custom_requirement_file_rejects_empty_file(test_context):
    """An empty rendered file is rejected by custom_requirement (mirrors the qrcode
    existence/size guard) so we never inspect or cache-lookup a zero-byte file, even
    though its .pdf extension would otherwise be enabled."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
        test_file_path = f.name  # left empty

    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))

        assert analyzer.custom_requirement(file_observable) is False
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_with_crawl_directive(monkeypatch, test_context):
    """Test URL analysis with crawl directive."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable with crawl directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)
    
    # Mock saq.phishkit functions
    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        return "test-job-456"
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock delay_analysis to mimic the real contract (flag delayed, return
    # INCOMPLETE) without registering an actual delayed request.
    def mock_delay_analysis(self, observable, analysis, **kwargs):
        analysis.delayed = True
        return AnalysisExecutionResult.INCOMPLETE

    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output-2"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)

    assert result == AnalysisExecutionResult.INCOMPLETE

    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None
    assert analysis.job_id == "test-job-456"
    assert analysis.scan_type == SCAN_TYPE_URL


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_error(monkeypatch, test_context):
    """Test URL analysis with error."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable with render directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)
    
    # Mock saq.phishkit functions to raise exception
    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        raise Exception("Network error")
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None
    assert analysis.error == "failed to scan URL https://example.com/phish: Network error"
    assert analysis.scan_type == SCAN_TYPE_URL


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_success(monkeypatch, test_context):
    """Test successful file analysis execution."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        # Create file observable
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to accept html files
        analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock saq.phishkit functions
        def mock_scan_file(file_path, output_dir, is_async=True, **kwargs):
            return "file-job-123"
        
        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        
        # Mock delay_analysis to return the expected result
        def mock_delay_analysis(*args, **kwargs):
            return AnalysisExecutionResult.INCOMPLETE
        
        monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
        
        # Mock create_temporary_directory
        def mock_create_temporary_directory():
            return "/tmp/test-file-output"
        
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
                
        result = analyzer.execute_analysis(file_observable)
        
        # Since file analysis now returns the result of delay_analysis
        assert result == AnalysisExecutionResult.INCOMPLETE
        
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is not None
        assert analysis.job_id == "file-job-123"
        assert analysis.scan_type == SCAN_TYPE_FILE
        # Don't check exact output_dir since it uses temp directory

    finally:
        # Clean up
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)

@pytest.mark.integration
def test_phishkit_analyzer_accepts_html_body_misdetected_as_text_plain(monkeypatch, test_context):
    """Regression: an HTML email body that is a bare fragment is misdetected by
    libmagic as text/plain. EmailAnalyzer now names it with a .html extension, so
    phishkit must accept it via the extension branch even though the mime branch
    fails. This is the path that renders HTML email bodies."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()

    # bare HTML fragment named with a .html extension (what EmailAnalyzer produces)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<div id="isPasted"><span>Hello</span></div>')
        test_file_path = f.name

    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)

        # libmagic misdetects the fragment as text/plain (NOT in valid_mime_types)
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'ASCII text', 'mime': 'text/plain'}
        file_observable.add_analysis(file_type_analysis)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))

        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])

        monkeypatch.setattr("saq.modules.phishkit.scan_file", lambda *a, **k: "file-job-html")
        monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", lambda *a, **k: AnalysisExecutionResult.INCOMPLETE)
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", lambda: "/tmp/test-html-output")

        result = analyzer.execute_analysis(file_observable)

        # accepted via the extension branch despite the text/plain mime
        assert result == AnalysisExecutionResult.INCOMPLETE
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is not None
        assert analysis.job_id == "file-job-html"
        assert analysis.scan_type == SCAN_TYPE_FILE

    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)

@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_invalid_extension(monkeypatch, test_context):
    """Test file analysis skipped for invalid extension."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file with invalid extension
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('Test content')
        test_file_path = f.name
    
    try:
        file_observable = root.add_file_observable(test_file_path)
        
        # Configure analyzer to only accept html files
        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'Plain text', 'mime': 'text/plain'}
        file_observable.add_analysis(file_type_analysis)
        
        # No need for adapter
        result = analyzer.execute_analysis(file_observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # No analysis should be created
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is None
        
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_invalid_mime_type(monkeypatch, test_context):
    """Test file analysis skipped for invalid MIME type."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('Whatever.')
        test_file_path = f.name
    
    try:
        file_observable = root.add_file_observable(test_file_path)
        
        # Mock file type analysis with wrong MIME type
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'Plain text', 'mime': 'text/plain'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to only accept html MIME types
        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
                
        # No need for adapter
        result = analyzer.execute_analysis(file_observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # No analysis should be created
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is None
        
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_error(monkeypatch, test_context):
    """Test file analysis with error."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to accept html files
        analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock saq.phishkit functions to raise exception
        def mock_scan_file(file_path, output_dir, is_async=True, **kwargs):
            raise Exception("File processing error")
        
        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        
        # Mock create_temporary_directory
        def mock_create_temporary_directory():
            return "/tmp/test-file-output"
        
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
                
        result = analyzer.execute_analysis(file_observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is not None
        assert "Failed to scan file" in analysis.error
        assert "File processing error" in analysis.error
        assert analysis.scan_type == SCAN_TYPE_FILE
        
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_no_job_id(test_context):
    """Test completing analysis with no job ID."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    # Don't set job_id
    url_observable.add_analysis(analysis)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)
    
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_not_ready(monkeypatch, test_context):
    """Test completing analysis when results not ready."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-123"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)
    
    # Mock get_async_scan_result to return None (not ready)
    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        return None
    
    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    analyzer.config.scanner_timeout = 100

    # Mock delay_analysis to return the expected result
    def mock_delay_analysis(*args, **kwargs):
        return AnalysisExecutionResult.INCOMPLETE

    analyzer.delay_analysis = MagicMock(side_effect=mock_delay_analysis)

    result = analyzer.continue_analysis(url_observable, analysis)

    # Should call delay_analysis and return its result
    analyzer.delay_analysis.assert_called_once_with(url_observable, analysis, seconds=3, timeout_seconds=230)
    assert result == AnalysisExecutionResult.INCOMPLETE


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_timeout(monkeypatch, test_context):
    """continue_analysis should treat TimeoutError from the async scan as a warning, not an error."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-timeout"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        raise TimeoutError("scan exceeded budget")

    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)

    assert result == AnalysisExecutionResult.COMPLETED
    assert "timed out" in analysis.error
    assert "test-job-timeout" in analysis.error


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_subprocess_timeout(monkeypatch, test_context):
    """continue_analysis should treat subprocess.TimeoutExpired propagated from the celery worker as a warning, not an error."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-subprocess-timeout"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        raise subprocess.TimeoutExpired(cmd=["docker", "run", "scanner"], timeout=60)

    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)

    assert result == AnalysisExecutionResult.COMPLETED
    assert "timed out" in analysis.error
    assert "test-job-subprocess-timeout" in analysis.error


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_worker_exception(monkeypatch, test_context):
    """continue_analysis should absorb worker-side exceptions from the Celery AsyncResult and mark the analysis failed."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-worker-exc"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    worker_error = "scan failed: TypeError: argument of type 'NoneType' is not iterable"

    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        raise Exception(worker_error)

    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)

    assert result == AnalysisExecutionResult.COMPLETED
    assert "test-job-worker-exc" in analysis.error
    assert worker_error in analysis.error


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_success(monkeypatch, test_context):
    """Test successful analysis completion."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-123"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    # Create temporary files for test
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create mock output files
        exit_code_file = os.path.join(temp_dir, "exit.code")
        stdout_file = os.path.join(temp_dir, "std.out")
        stderr_file = os.path.join(temp_dir, "std.err")
        proxy_file = os.path.join(temp_dir, "proxy.json")
        other_file = os.path.join(temp_dir, "result.json")

        with open(exit_code_file, "w") as f:
            f.write("0")
        with open(stdout_file, "w") as f:
            f.write("scan completed")
        with open(stderr_file, "w") as f:
            f.write("no errors")
        proxy_payload = {
            "configured": True,
            "host": "socks5://gate.proxy.example:1080",
            "fallback_enabled": True,
            "fallback_triggered": True,
            "fallback_reason": "error_pattern",
            "fallback_details": {"matched_error_patterns": ["ERR_PROXY_CONNECTION_FAILED"]},
            "final_route": "direct",
        }
        with open(proxy_file, "w") as f:
            json.dump(proxy_payload, f)
        with open(other_file, "w") as f:
            f.write('{"result": "success"}')

        output_files = [exit_code_file, stdout_file, stderr_file, proxy_file, other_file]

        # Mock get_async_scan_result to return file list
        def mock_get_async_scan_result(job_id, output_dir, timeout=1):
            return output_files

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        # Only non-special files are added to output_files, and they're stored as relative paths
        assert len(analysis.output_files) == 1  # Only result.json should be in output_files
        assert analysis.output_files[0].startswith("phishkit/") and analysis.output_files[0].endswith("/result.json")
        assert analysis.scan_result == f"successfully scanned {url_observable}"
        assert analysis.error is None
        assert analysis.exit_code == 0
        assert analysis.stdout == "scan completed"
        assert analysis.stderr == "no errors"
        assert analysis.proxy_status == proxy_payload


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_no_proxy_json(monkeypatch, test_context):
    """Missing proxy.json (older worker / in-flight scan) leaves proxy_status None."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-no-proxy-json"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        exit_code_file = os.path.join(temp_dir, "exit.code")
        stdout_file = os.path.join(temp_dir, "std.out")
        with open(exit_code_file, "w") as f:
            f.write("0")
        with open(stdout_file, "w") as f:
            f.write("scan completed")

        output_files = [exit_code_file, stdout_file]
        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        assert analysis.exit_code == 0
        assert analysis.proxy_status is None


@pytest.mark.unit
def test_phishkit_analyzer_continue_analysis_extracts_marker_urls(monkeypatch, test_context):
    """Test that MARKER URL lines in dom.html are extracted as URL observables."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-marker"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create dom.html with MARKER URL lines mixed with HTML content
        dom_file = os.path.join(temp_dir, "dom.html")
        with open(dom_file, "w") as f:
            f.write("<html><body>page content</body></html>\n")
            f.write("\n\nMARKER URL: https://evil.com/login.php\n\n")
            f.write("<script>var x = 1;</script>\n")
            f.write("\n\nMARKER URL: https://evil.com/steal.js\n\n")
            f.write("more response content\n")
            f.write("\n\nMARKER URL: https://cdn.example.com/payload.html\n\n")

        exit_code_file = os.path.join(temp_dir, "exit.code")
        with open(exit_code_file, "w") as f:
            f.write("0")

        output_files = [exit_code_file, dom_file]
        analysis.output_dir = temp_dir

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        # Track calls to add_observable_by_spec on the analysis
        added_urls = []
        original_add = analysis.add_observable_by_spec
        def tracking_add(o_type, o_value, **kwargs):
            if o_type == F_URL:
                added_urls.append(o_value)
            return original_add(o_type, o_value, **kwargs)
        monkeypatch.setattr(analysis, "add_observable_by_spec", tracking_add)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        assert added_urls == [
            "https://evil.com/login.php",
            "https://evil.com/steal.js",
            "https://cdn.example.com/payload.html",
        ]


@pytest.mark.unit
def test_phishkit_analyzer_continue_analysis_extracts_requests_json_urls(monkeypatch, test_context):
    """Every type=request entry in requests.json should yield a URL observable,
    including URLs that never made it into dom.html as MARKER URLs."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-requests-json"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        # dom.html carries one MARKER URL; requests.json carries three more
        # (a filtered CSS, a failed endpoint, and a duplicate of the MARKER URL)
        # plus noise (response, error, file://, data:, blob:).
        dom_file = os.path.join(temp_dir, "dom.html")
        with open(dom_file, "w") as f:
            f.write("\n\nMARKER URL: https://evil.com/login.php\n\n")

        requests_file = os.path.join(temp_dir, "requests.json")
        with open(requests_file, "w") as f:
            json.dump([
                {"type": "request", "url": "https://evil.com/login.php"},  # dup of MARKER
                {"type": "request", "url": "https://cdn.example.com/styles.css"},  # filtered from dom.html
                {"type": "response", "url": "https://evil.com/login.php"},  # ignored
                {"type": "request", "url": "https://blocked.example.com/captcha.png"},  # failed fetch
                {"type": "error", "url": "https://blocked.example.com/captcha.png"},  # ignored
                {"type": "request", "url": "file:///local/path.html"},  # skipped
                {"type": "request", "url": "data:image/svg+xml;base64,PHN2Zw=="},  # skipped
                {"type": "request", "url": "blob:https://evil.com/abc123"},  # skipped
                {"type": "websocket_created", "url": "wss://evil.com/ws"},  # not a request, ignored here
            ], f)

        exit_code_file = os.path.join(temp_dir, "exit.code")
        with open(exit_code_file, "w") as f:
            f.write("0")

        output_files = [exit_code_file, dom_file, requests_file]
        analysis.output_dir = temp_dir

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        added_urls = []
        original_add = analysis.add_observable_by_spec
        def tracking_add(o_type, o_value, **kwargs):
            if o_type == F_URL:
                added_urls.append(o_value)
            return original_add(o_type, o_value, **kwargs)
        monkeypatch.setattr(analysis, "add_observable_by_spec", tracking_add)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        # MARKER URL pass emits login.php once. requests.json pass then emits
        # login.php (dedup), styles.css, and captcha.png. file:/data:/blob: and
        # non-request types are skipped.
        assert added_urls == [
            "https://evil.com/login.php",
            "https://evil.com/login.php",
            "https://cdn.example.com/styles.css",
            "https://blocked.example.com/captcha.png",
        ]


@pytest.mark.unit
def test_phishkit_analyzer_continue_analysis_skips_scanned_url_self_reference(monkeypatch, test_context):
    """The scanned URL appears as its own top-level MARKER URL in dom.html (and as
    the initial navigation in requests.json), but must NOT be re-promoted as a
    child observable. Re-adding it would re-parent the scanned URL under its own
    PhishkitAnalysis (add_observable_by_spec dedupes by value, making the
    observable its own descendant), giving it a self-referential PhishkitAnalysis
    ancestor and breaking the "no PhishkitAnalysis ancestor" guard used by the
    NRD / RDAP crawl rules. Genuinely discovered URLs are still promoted.
    """
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    scanned = "https://l3cwy5ly93.essencedesigns.de/l/iFoz5AyHD_Q"
    url_observable = root.add_observable_by_spec(F_URL, scanned)
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-self-ref"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        # dom.html: the top-level MARKER URL is the scanned URL itself, plus a
        # genuinely discovered redirect target.
        dom_file = os.path.join(temp_dir, "dom.html")
        with open(dom_file, "w") as f:
            f.write(f"\n\nMARKER URL: {scanned}\n\n")
            f.write("<html>redirected</html>\n")
            f.write("\n\nMARKER URL: https://cdn.example.com/next.html\n\n")

        # requests.json: the scanned URL again (initial navigation) plus a
        # discovered second-stage endpoint.
        requests_file = os.path.join(temp_dir, "requests.json")
        with open(requests_file, "w") as f:
            json.dump([
                {"type": "request", "url": scanned},  # initial navigation -- must be skipped
                {"type": "request", "url": "https://blocked.example.com/step2"},
            ], f)

        exit_code_file = os.path.join(temp_dir, "exit.code")
        with open(exit_code_file, "w") as f:
            f.write("0")

        output_files = [exit_code_file, dom_file, requests_file]
        analysis.output_dir = temp_dir

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        added_urls = []
        original_add = analysis.add_observable_by_spec
        def tracking_add(o_type, o_value, **kwargs):
            if o_type == F_URL:
                added_urls.append(o_value)
            return original_add(o_type, o_value, **kwargs)
        monkeypatch.setattr(analysis, "add_observable_by_spec", tracking_add)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        # the scanned URL is skipped in BOTH passes; only discovered URLs promoted
        assert scanned not in added_urls
        assert added_urls == [
            "https://cdn.example.com/next.html",
            "https://blocked.example.com/step2",
        ]


@pytest.mark.unit
def test_phishkit_analyzer_continue_analysis_partial_on_interrupt(monkeypatch, test_context):
    """A timed-out scan still flushes partial requests.json/metrics.json.

    The worker now returns the output dir even on interruption, so the redirect
    chain captured before the kill must be promoted to URL observables, the scan
    must be labeled partial (not "successfully scanned"), and the analysis must
    NOT be treated as unfinished (so analysts get the observables, not an empty
    "no content captured" stub).
    """
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-partial"
    analysis.scan_type = SCAN_TYPE_URL
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        # SIGTERM-flushed partials: a non-zero exit, interrupted metrics, and a
        # requests.json capturing the redirect to a downstream CDN domain.
        with open(os.path.join(temp_dir, "exit.code"), "w") as f:
            f.write("143")
        with open(os.path.join(temp_dir, "metrics.json"), "w") as f:
            json.dump({"url_scanned": "https://login.microsoftonline.com/...",
                       "total_bytes_downloaded": 1234, "interrupted": True}, f)
        requests_file = os.path.join(temp_dir, "requests.json")
        with open(requests_file, "w") as f:
            json.dump([
                {"type": "request", "url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"},
                {"type": "request", "url": "https://redirect-cdn.example.net/ns"},
                {"type": "request", "url": "https://redirect-cdn.example.net/?user@example.com"},
            ], f)

        output_files = [os.path.join(temp_dir, "exit.code"),
                        os.path.join(temp_dir, "metrics.json"), requests_file]
        analysis.output_dir = temp_dir

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        added_urls = []
        original_add = analysis.add_observable_by_spec
        def tracking_add(o_type, o_value, **kwargs):
            if o_type == F_URL:
                added_urls.append(o_value)
            return original_add(o_type, o_value, **kwargs)
        monkeypatch.setattr(analysis, "add_observable_by_spec", tracking_add)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

    assert result == AnalysisExecutionResult.COMPLETED
    # the redirect/CDN URLs captured before the timeout are promoted to observables
    assert "https://redirect-cdn.example.net/ns" in added_urls
    assert "https://redirect-cdn.example.net/?user@example.com" in added_urls
    # labeled partial, not a clean success, and not abandoned-as-unfinished
    assert analysis.scan_result.startswith("partial scan of")
    assert analysis.error is None
    assert analysis.exit_code == 143
    assert analysis._is_unfinished() is False
    assert "PARTIAL (scanner timed out)" in analysis.generate_summary()


@pytest.mark.unit
def test_phishkit_analyzer_continue_analysis_no_marker_urls(monkeypatch, test_context):
    """Test that dom.html with no MARKER URL lines adds no URL observables."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-no-markers"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        dom_file = os.path.join(temp_dir, "dom.html")
        with open(dom_file, "w") as f:
            f.write("<html><body>just a normal page</body></html>\n")

        exit_code_file = os.path.join(temp_dir, "exit.code")
        with open(exit_code_file, "w") as f:
            f.write("0")

        output_files = [exit_code_file, dom_file]
        analysis.output_dir = temp_dir

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        added_urls = []
        original_add = analysis.add_observable_by_spec
        def tracking_add(o_type, o_value, **kwargs):
            if o_type == F_URL:
                added_urls.append(o_value)
            return original_add(o_type, o_value, **kwargs)
        monkeypatch.setattr(analysis, "add_observable_by_spec", tracking_add)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        assert added_urls == []


@pytest.mark.integration
def test_phishkit_analyzer_file_not_analyzed_in_non_correlation_mode(monkeypatch, test_context):
    """Test that F_FILE observables are NOT analyzed when root analysis is NOT in correlation mode."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        # Create file observable
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to accept html files
        analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
                
        # Verify that custom_requirement returns False.
        # custom_requirement is the gatekeeper the engine evaluates right before
        # running the module - if it returns False, execute_analysis is not called
        assert not analyzer.custom_requirement(file_observable)

    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_file_analyzed_after_mode_switch_to_correlation(monkeypatch, test_context):
    """Test that F_FILE observables ARE analyzed after switching root analysis to correlation mode."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        # Create file observable
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to accept html files
        analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
                
        # First, verify that in non-correlation mode, it's NOT gated in for analysis.
        # custom_requirement (the engine's final gate) should return False
        assert not analyzer.custom_requirement(file_observable)

        # Now switch to correlation mode
        root.analysis_mode = ANALYSIS_MODE_CORRELATION

        # Verify that custom_requirement now returns True (gate passes)
        assert analyzer.custom_requirement(file_observable)
        
        # Mock saq.phishkit functions
        def mock_scan_file(file_path, output_dir, is_async=True, **kwargs):
            return "file-job-after-switch"
        
        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        
        # Mock delay_analysis to return the expected result
        def mock_delay_analysis(*args, **kwargs):
            return AnalysisExecutionResult.INCOMPLETE
        
        monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
        
        # Mock create_temporary_directory
        def mock_create_temporary_directory():
            return "/tmp/test-file-output-after-switch"
        
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
        
        # Now execute analysis - it should create analysis
        result = analyzer.execute_analysis(file_observable)
        
        # Since file analysis now returns the result of delay_analysis
        assert result == AnalysisExecutionResult.INCOMPLETE
        
        # Analysis should now be created
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is not None
        assert analysis.job_id == "file-job-after-switch"
        assert analysis.scan_type == SCAN_TYPE_FILE

    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_url_scan_passes_proxy(monkeypatch, test_context):
    """Test that proxy string is passed through to scan_url when configured."""
    from saq.configuration.config import get_config
    from saq.configuration.schema import ProxyConfig

    # set up a named proxy config
    proxy_config = ProxyConfig(name="testproxy", transport="http", host="proxy.test", port=9090, user="u", password="p")
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("testproxy", proxy_config)

    # set the phishkit analyzer config to use this proxy
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'proxy', 'testproxy')

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)

    captured_kwargs = {}

    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        captured_kwargs.update(kwargs)
        return "proxy-job-123"

    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", lambda *a, **kw: None)
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", lambda: "/tmp/proxy-test")

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    analyzer.execute_analysis(url_observable)

    assert captured_kwargs.get("proxy") == "u:p@proxy.test:9090"


@pytest.mark.integration
def test_phishkit_analyzer_url_scan_no_proxy(monkeypatch, test_context):
    """Test that proxy is None when no proxy is configured."""
    # ensure no proxy is set
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'proxy', None)

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)

    captured_kwargs = {}

    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        captured_kwargs.update(kwargs)
        return "no-proxy-job"

    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", lambda *a, **kw: None)
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", lambda: "/tmp/no-proxy-test")

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    analyzer.execute_analysis(url_observable)

    assert captured_kwargs.get("proxy") is None


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_redacts_proxy_from_stdout(monkeypatch, test_context):
    """Test that proxy credentials are redacted from stdout/stderr in analysis details."""
    from saq.configuration.config import get_config
    from saq.configuration.schema import ProxyConfig

    proxy_config = ProxyConfig(name="testproxy", transport="http", host="gate.proxy.com", port=10001, user="proxyuser", password="s3cr3t+pass")
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("testproxy", proxy_config)
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'proxy', 'testproxy')

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "redact-test-job"
    analysis.output_dir = "/tmp/test-redact"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        exit_code_file = os.path.join(temp_dir, "exit.code")
        stdout_file = os.path.join(temp_dir, "std.out")
        stderr_file = os.path.join(temp_dir, "std.err")

        with open(exit_code_file, "w") as f:
            f.write("0")
        with open(stdout_file, "w") as f:
            f.write("using proxy: proxyuser:s3cr3t+pass@gate.proxy.com:10001\nopening https://example.com\n")
        with open(stderr_file, "w") as f:
            f.write("some error mentioning proxyuser:s3cr3t+pass@gate.proxy.com\n")

        output_files = [exit_code_file, stdout_file, stderr_file]

        def mock_get_async_scan_result(job_id, output_dir, timeout=1):
            return output_files

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        # Credentials must not appear in stdout or stderr
        assert "s3cr3t+pass" not in analysis.stdout
        assert "proxyuser" not in analysis.stdout
        assert "****:****" in analysis.stdout
        assert "s3cr3t+pass" not in analysis.stderr
        assert "proxyuser" not in analysis.stderr
        assert "****:****" in analysis.stderr
        # Host:port should still be visible
        assert "gate.proxy.com" in analysis.stdout


@pytest.mark.integration
def test_phishkit_analyzer_file_scan_passes_proxy(monkeypatch, test_context):
    """Test that proxy string is passed through to scan_file when configured."""
    from saq.configuration.config import get_config
    from saq.configuration.schema import ProxyConfig

    proxy_config = ProxyConfig(name="testproxy", transport="http", host="proxy.test", port=9090, user="u", password="p")
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("testproxy", proxy_config)

    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'proxy', 'testproxy')
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])

    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test</body></html>')
        test_file_path = f.name

    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)

        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)

        captured_kwargs = {}

        def mock_scan_file(file_path, output_dir, is_async=True, **kwargs):
            captured_kwargs.update(kwargs)
            return "proxy-file-job"

        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", lambda *a, **kw: AnalysisExecutionResult.INCOMPLETE)
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", lambda: "/tmp/proxy-file-test")

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))

        analyzer.execute_analysis(file_observable)

        assert captured_kwargs.get("proxy") == "u:p@proxy.test:9090"
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


# ----------------------------------------------------------------------
# Caching (analysis-result cache opt-in): extended_version, scanner-version
# helper, and a write→replay round-trip across the delayed × file-producing
# path. See docs/ANALYSIS_CACHING.md (phishkit opt-in).
# ----------------------------------------------------------------------

def _drive_phishkit_scan(monkeypatch, out_dir, *, interrupted=False,
                         url="https://example.com/phish"):
    """Drive PhishkitAnalyzer through its REAL delayed lifecycle and return
    (analyzer, root, observable, merged_delta) — the delta the executor would
    cache.

    Phishkit is delayed: cycle 1 (execute_analysis) creates a delayed
    placeholder analysis and returns INCOMPLETE; the engine resumes it later and
    cycle 2 (continue_analysis) harvests the scan and completes. Crucially we
    reproduce the orchestrator resetting ``analysis.delayed = False`` *before*
    the resuming cycle's before-snapshot (analysis_orchestrator.py) and pass
    ``is_resuming_delayed_module=True`` to the resuming diff — the exact
    conditions under which the completed analysis must still be captured. An
    earlier version of this helper mocked delay_analysis to a no-op, which left
    delayed=False and hid the capture bug.
    """
    os.makedirs(out_dir, exist_ok=True)
    dom_path = os.path.join(out_dir, "dom.html")
    with open(dom_path, "w") as fp:
        fp.write("<html></html>\nMARKER URL: https://evil.example/next-stage\n")
    exit_code_path = os.path.join(out_dir, "exit.code")
    with open(exit_code_path, "w") as fp:
        fp.write("143" if interrupted else "0")
    files = [exit_code_path, dom_path]
    if interrupted:
        metrics_path = os.path.join(out_dir, "metrics.json")
        with open(metrics_path, "w") as fp:
            json.dump({"interrupted": True}, fp)
        files.append(metrics_path)

    def fake_delay(self, observable, analysis, **kwargs):
        # mimic the real delay_analysis: register the resume (no-op here),
        # flag the analysis delayed, return INCOMPLETE.
        analysis.delayed = True
        analysis.completed = False
        return AnalysisExecutionResult.INCOMPLETE

    monkeypatch.setattr("saq.modules.phishkit.scan_url",
                        lambda u, o, **k: "job-xyz")
    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                        lambda j, o, timeout=1: files)
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis",
                        fake_delay)
    monkeypatch.setattr("saq.modules.phishkit.create_temporary_directory",
                        lambda: out_dir)

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    obs = root.add_observable_by_spec(F_URL, url)
    obs.add_directive(DIRECTIVE_CRAWL)
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))

    # cycle 1: dispatch + delay (delayed placeholder analysis captured via the
    # absent→present path).
    before1 = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    assert analyzer.execute_analysis(obs) == AnalysisExecutionResult.INCOMPLETE
    after1 = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    delta_a = ModuleExecutionSnapshot.diff(before1, after1, analyzer, obs,
                                           is_resuming_delayed_module=False)
    root.record_module_execution(delta_a.without_analysis_details())
    analysis = obs.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None and analysis.delayed

    # the orchestrator clears the delay flag before the resuming cycle's snapshot
    analysis.delayed = False

    # cycle 2 (resume): harvest + complete. The completed analysis must be
    # captured even though delayed is already False (is_resuming_delayed_module).
    before2 = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    assert analyzer.continue_analysis(obs, analysis) == AnalysisExecutionResult.COMPLETED
    after2 = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    delta_b = ModuleExecutionSnapshot.diff(before2, after2, analyzer, obs,
                                           is_resuming_delayed_module=True)

    # merge prior delayed-cycle deltas exactly as the executor does
    prior = [d for d in root.module_executions
             if d.module_path == delta_b.module_path
             and d.observable_uuid == delta_b.observable_uuid
             and not d.from_cache_hit
             and (d.analysis is None or d.analysis.get("delayed"))]
    merged = merge_module_execution_deltas(prior, delta_b)
    return analyzer, root, obs, merged


@pytest.mark.unit
def test_phishkit_get_scanner_version_delegates_to_worker(monkeypatch):
    """get_phishkit_scanner_version is an un-memoized passthrough: it returns the
    worker task's dict on each call (the id is cached on the worker side, not
    here)."""
    calls = []

    def fake_scanner_image():
        calls.append(1)
        return {"image_url": "phishkit:latest", "image_id": "sha256:aaa"}

    monkeypatch.setattr("saq.phishkit.get_phishkit_scanner_image", fake_scanner_image)
    first = saq.phishkit.get_phishkit_scanner_version()
    second = saq.phishkit.get_phishkit_scanner_version()
    assert first == second == {"image_url": "phishkit:latest", "image_id": "sha256:aaa"}
    assert len(calls) == 2  # no client-side memo — delegates every call


@pytest.mark.unit
def test_phishkit_get_scanner_version_returns_empty_on_failure(monkeypatch):
    """A query failure yields {} without raising, so extended_version omits the
    scanner_image key (degrades to config-hash-only)."""
    def boom():
        raise RuntimeError("broker down")

    monkeypatch.setattr("saq.phishkit.get_phishkit_scanner_image", boom)
    assert saq.phishkit.get_phishkit_scanner_version() == {}


@pytest.mark.integration
def test_phishkit_extended_version_includes_config_and_image(monkeypatch, test_context):
    """extended_version mixes the scanner YAML content hash and the running
    image id (both statically derivable before the scan)."""
    monkeypatch.setattr("saq.modules.phishkit.get_phishkit_scanner_version",
                        lambda: {"image_id": "sha256:cafef00d"})
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=test_context)
    ev = analyzer.extended_version
    assert ev["scanner_image"] == "sha256:cafef00d"
    assert "phishkit_config" in ev and len(ev["phishkit_config"]) == 64  # sha256 hex


@pytest.mark.integration
def test_phishkit_extended_version_omits_image_when_unavailable(monkeypatch, test_context):
    """When the image id can't be resolved the key degrades gracefully to the
    config hash alone — it does not poison the key with a sentinel."""
    monkeypatch.setattr("saq.modules.phishkit.get_phishkit_scanner_version",
                        lambda: {})
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=test_context)
    ev = analyzer.extended_version
    assert "scanner_image" not in ev
    assert "phishkit_config" in ev


@pytest.mark.integration
def test_phishkit_extended_version_image_change_changes_key(monkeypatch, tmp_path):
    """A scanner rebuild (new image id) must re-key, even under the floating
    :latest tag whose URL string never changes."""
    analyzer, root, obs, _ = _drive_phishkit_scan(monkeypatch, str(tmp_path / "s"))
    monkeypatch.setattr("saq.modules.phishkit.get_phishkit_scanner_version",
                        lambda: {"image_id": "sha256:v1"})
    key_v1 = generate_cache_key(obs, analyzer)
    monkeypatch.setattr("saq.modules.phishkit.get_phishkit_scanner_version",
                        lambda: {"image_id": "sha256:v2"})
    key_v2 = generate_cache_key(obs, analyzer)
    assert key_v1 and key_v2 and key_v1 != key_v2


@pytest.mark.integration
def test_phishkit_cache_write_and_replay(monkeypatch, tmp_path):
    """A successful scan's delta writes a file-backed cache row, and a fresh
    analysis of the same URL replays it: the captured dom.html is materialized
    and the extracted URL observable is reproduced, without re-scanning. This
    exercises the delayed × file-producing path end to end."""
    monkeypatch.setattr("saq.modules.phishkit.get_phishkit_scanner_version",
                        lambda: {"image_id": "sha256:deadbeef"})
    blob_store = LocalHardlinkBlobStore(
        LocalHardlinkBlobStoreConfig(root_dir=str(tmp_path / "blobs")))

    analyzer, root, obs, delta = _drive_phishkit_scan(monkeypatch, str(tmp_path / "scan"))
    delta.cache_key = generate_cache_key(obs, analyzer)
    assert delta.cache_key is not None
    # Regression: the completed analysis must survive the delayed-merge into the
    # cached delta (the bug cached analysis=None, losing the PhishkitAnalysis).
    assert delta.analysis is not None, "delayed-module merge lost the analysis object"

    write = put_cached_delta(delta, analyzer, blob_store, root=root)
    assert write is not None  # non-empty, file-backed delta accepted

    # fresh root + same URL → cache hit → replay (no module run)
    root2 = create_root_analysis(analysis_mode="test_single")
    root2.initialize_storage()
    obs2 = root2.add_observable_by_spec(F_URL, obs.value)
    lookup = get_cached_delta(obs2, analyzer, blob_store)
    assert lookup.delta is not None, f"expected cache hit, got miss: {lookup.miss_reason}"
    apply_delta(root2, obs2, lookup.delta, blob_store)

    # The replay must recreate the PhishkitAnalysis node and nest the extracted
    # observables UNDER it — not dump them at root (the original-bug symptom).
    replayed = obs2.get_and_load_analysis(PhishkitAnalysis)
    assert replayed is not None, "replay did not recreate the PhishkitAnalysis node"
    child_files = [o for o in replayed.observables if o.type == F_FILE]
    assert any(o.file_name == "dom.html" for o in child_files), \
        "dom.html not materialized as a child of PhishkitAnalysis"
    assert any(o.type == F_URL and o.value == "https://evil.example/next-stage"
               for o in replayed.observables), \
        "extracted URL not nested under PhishkitAnalysis on replay"
    # and it is NOT a loose root-level observable
    assert not any(o.type == F_URL and o.value == "https://evil.example/next-stage"
                   for o in root2.observables), \
        "extracted URL leaked to root instead of nesting under the analysis"


@pytest.mark.integration
def test_phishkit_partial_scan_is_cached(monkeypatch, tmp_path):
    """A partial/interrupted scan is cached on purpose (a timeout is usually the
    site blocking our crawl — a stable property; re-scanning reproduces it).
    Staleness is bounded by the short cache_ttl, not a skip-hook. Assert the
    interrupted delta is non-empty and accepted by put_cached_delta."""
    monkeypatch.setattr("saq.modules.phishkit.get_phishkit_scanner_version",
                        lambda: {"image_id": "sha256:deadbeef"})
    blob_store = LocalHardlinkBlobStore(
        LocalHardlinkBlobStoreConfig(root_dir=str(tmp_path / "blobs")))

    analyzer, root, obs, delta = _drive_phishkit_scan(
        monkeypatch, str(tmp_path / "scan"), interrupted=True)
    analysis = obs.get_and_load_analysis(PhishkitAnalysis)
    assert "partial scan" in analysis.scan_result

    delta.cache_key = generate_cache_key(obs, analyzer)
    write = put_cached_delta(delta, analyzer, blob_store, root=root)
    assert write is not None  # partial results are cached, not refused


@pytest.mark.integration
def test_phishkit_on_cache_hit_emits_cache_served(test_context):
    """A cache hit replays the cached analysis; on_cache_hit should emit a
    cache_served event recording the exact bytes and scan time it avoided."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "cache-hit-job"
    analysis.scan_type = "url"
    analysis.metrics = {"total_bytes_downloaded": 12345, "scan_duration_seconds": 42}
    url_observable.add_analysis(analysis)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    analyzer.fluent_bit_metrics_sender = MagicMock()

    analyzer.on_cache_hit(root, url_observable)

    analyzer.fluent_bit_metrics_sender.emit.assert_called_once()
    _, payload = analyzer.fluent_bit_metrics_sender.emit.call_args.args
    assert payload["event"] == "cache_served"
    assert payload["job_id"] == "cache-hit-job"
    assert payload["scan_type"] == "url"
    assert payload["observable_value"] == "https://example.com/phish"
    assert payload["saved_bytes"] == 12345
    assert payload["saved_duration_seconds"] == 42


@pytest.mark.integration
def test_phishkit_on_cache_hit_no_sender_is_noop(test_context):
    """With no fluent-bit sender configured, on_cache_hit must not raise."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.metrics = {"total_bytes_downloaded": 1, "scan_duration_seconds": 1}
    url_observable.add_analysis(analysis)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    analyzer.fluent_bit_metrics_sender = None

    analyzer.on_cache_hit(root, url_observable)  # should be a no-op, no exception


#
# OCR content-type gate: a screenshot of Chrome rendering source text (JS/CSS/JSON) as plain text
# carries no information the captured body doesn't already have, and running domain extraction over
# source code manufactures observables like "b.call" out of JavaScript method calls.
#

def _write_requests_json(output_dir, entries):
    with open(os.path.join(output_dir, "requests.json"), "w") as fp:
        json.dump(entries, fp)


def _response(content_type=None, status_code=200, header_name="Content-Type", url="https://example.com/x"):
    entry = {"type": "response", "status_code": status_code, "url": url, "headers": {}}
    if content_type is not None:
        entry["headers"][header_name] = content_type
    return entry


@pytest.mark.unit
@pytest.mark.parametrize("entries,expected", [
    # the top-level document is the first non-redirect response
    ([_response("text/javascript")], "text/javascript"),
    ([_response("text/html")], "text/html"),
    # parameters are stripped and the value lowercased
    ([_response("application/javascript; charset=utf-8")], "application/javascript"),
    ([_response("TEXT/JavaScript; charset=UTF-8")], "text/javascript"),
    # header casing varies between scanner versions and origins
    ([_response("application/javascript", header_name="content-type")], "application/javascript"),
    # redirect hops are skipped -- the document is the response they land on
    ([_response("text/html", status_code=301), _response("text/javascript")], "text/javascript"),
    # subresources follow the document and must not win
    ([_response("text/html"), _response("application/javascript")], "text/html"),
    # requests precede responses in the log
    ([{"type": "request", "url": "https://example.com/x"}, _response("text/html")], "text/html"),
    # unknown => None => falls back to running OCR
    ([_response(content_type=None)], None),
    ([], None),
    ([{"type": "request", "url": "https://example.com/x"}], None),
])
def test_phishkit_top_level_content_type(tmp_path, entries, expected):
    """_top_level_content_type reads the document response out of requests.json."""
    _write_requests_json(str(tmp_path), entries)
    analyzer = PhishkitAnalyzer(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER))
    assert analyzer._top_level_content_type(str(tmp_path)) == expected


@pytest.mark.unit
def test_phishkit_top_level_content_type_missing_file(tmp_path):
    """A missing requests.json is unknown content, not a failure."""
    analyzer = PhishkitAnalyzer(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER))
    assert analyzer._top_level_content_type(str(tmp_path)) is None


@pytest.mark.unit
def test_phishkit_top_level_content_type_malformed_json(tmp_path):
    """A malformed requests.json is unknown content, not a failure."""
    with open(os.path.join(str(tmp_path), "requests.json"), "w") as fp:
        fp.write("{not json")
    analyzer = PhishkitAnalyzer(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER))
    assert analyzer._top_level_content_type(str(tmp_path)) is None


@pytest.mark.unit
def test_phishkit_unknown_content_types_are_not_skipped():
    """The gate is a denylist: anything not listed still gets OCR'd."""
    assert "text/html" not in OCR_SKIP_CONTENT_TYPES
    assert "image/png" not in OCR_SKIP_CONTENT_TYPES
    assert None not in OCR_SKIP_CONTENT_TYPES
    assert "text/javascript" in OCR_SKIP_CONTENT_TYPES
    assert "application/javascript" in OCR_SKIP_CONTENT_TYPES


def _ocr_excluded(observable):
    """is_excluded() takes a module instance, not a type."""
    return observable.is_excluded(OCRAnalyzer(get_analysis_module_config(ANALYSIS_MODULE_OCR)))


def _run_continue_analysis_with_screenshots(monkeypatch, tmp_path, content_type):
    """Runs continue_analysis over a fake job dir and returns {basename: file_observable}."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    output_dir = str(tmp_path / "job")
    os.makedirs(output_dir)
    _write_requests_json(output_dir, [_response(content_type)])

    artifacts = ["screenshot.png", "pre_bypass_screenshot.png", "pre_bypass_screenshot_iter2.png", "dom.html"]
    scan_results = []
    for name in artifacts:
        path = os.path.join(output_dir, name)
        with open(path, "w") as fp:
            fp.write("content")
        scan_results.append(path)
    scan_results.append(os.path.join(output_dir, "requests.json"))

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/x")
    analysis = PhishkitAnalysis()
    analysis.job_id = "job-1"
    analysis.output_dir = output_dir
    url_observable.add_analysis(analysis)

    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                        lambda job_id, out, timeout=1: scan_results)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)
    assert result == AnalysisExecutionResult.COMPLETED

    return {os.path.basename(o.full_path): o for o in analysis.observables if o.type == F_FILE}


@pytest.mark.integration
def test_phishkit_screenshot_ocr_skipped_for_javascript(monkeypatch, tmp_path):
    """A screenshot of Chrome rendering JS as plain text must not be sent to OCR."""
    observables = _run_continue_analysis_with_screenshots(monkeypatch, tmp_path, "application/javascript")

    for name in ("screenshot.png", "pre_bypass_screenshot.png", "pre_bypass_screenshot_iter2.png"):
        assert _ocr_excluded(observables[name]), f"{name} should be excluded from OCR"

    # non-screenshot artifacts are never touched by the gate
    assert not _ocr_excluded(observables["dom.html"])


@pytest.mark.integration
def test_phishkit_screenshot_ocr_kept_for_html(monkeypatch, tmp_path):
    """A rendered page is exactly what OCR is for -- don't skip it."""
    observables = _run_continue_analysis_with_screenshots(monkeypatch, tmp_path, "text/html")

    for name in ("screenshot.png", "pre_bypass_screenshot.png", "pre_bypass_screenshot_iter2.png"):
        assert not _ocr_excluded(observables[name]), f"{name} should still be OCR'd"


@pytest.mark.integration
def test_phishkit_screenshot_ocr_kept_when_content_type_unknown(monkeypatch, tmp_path):
    """Unknown content type falls back to the pre-existing behavior of running OCR."""
    observables = _run_continue_analysis_with_screenshots(monkeypatch, tmp_path, None)

    assert not _ocr_excluded(observables["screenshot.png"])
