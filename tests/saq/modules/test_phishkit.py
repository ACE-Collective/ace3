import os
import tempfile
from unittest.mock import MagicMock

import pytest

from saq.analysis import Observable
from saq.constants import DIRECTIVE_CRAWL, DIRECTIVE_RENDER, F_FILE, F_URL, AnalysisExecutionResult
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
    SCAN_TYPE_URL,
    SCAN_TYPE_FILE
)
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis import FileTypeAnalysis
from saq.observables.file import FileObservable
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
def test_phishkit_analysis_generate_summary():
    """Test PhishkitAnalysis summary generation."""
    analysis = PhishkitAnalysis()
    
    # Test error state
    analysis.error = "Something went wrong"
    assert analysis.generate_summary() == "Phishkit Analysis Failed: Something went wrong"
    
    # Test URL scan
    analysis.error = None
    analysis.scan_type = SCAN_TYPE_URL
    analysis.output_files = ["/tmp/file1.txt", "/tmp/file2.txt"]
    assert analysis.generate_summary() == "Phishkit URL Analysis: 2 output files generated"
    
    # Test file scan
    analysis.scan_type = SCAN_TYPE_FILE
    analysis.output_files = ["/tmp/file1.txt"]
    assert analysis.generate_summary() == "Phishkit File Analysis: 1 output files generated"
    
    # Test unknown scan type
    analysis.scan_type = "unknown"
    assert analysis.generate_summary() == "Phishkit Analysis Completed"


@pytest.mark.integration
def test_phishkit_analyzer_properties():
    """Test PhishkitAnalyzer properties."""
    analyzer = PhishkitAnalyzer()
    
    assert analyzer.generated_analysis_type == PhishkitAnalysis
    assert analyzer.valid_observable_types == [F_URL, F_FILE]


@pytest.mark.integration
def test_phishkit_analyzer_verify_environment(test_context):
    """Test PhishkitAnalyzer environment verification."""
    analyzer = PhishkitAnalyzer(context=test_context)
    
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
    url_observable.add_directive(DIRECTIVE_RENDER)
    
    # Mock saq.phishkit functions
    def mock_scan_url(url, output_dir, is_async=True):
        return "test-job-123"
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock delay_analysis to avoid delayed execution issues
    def mock_delay_analysis(*args, **kwargs):
        pass
    
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None
    assert analysis.job_id == "test-job-123"
    assert analysis.scan_type == SCAN_TYPE_URL
    # Don't check exact output_dir since it uses temp directory


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_no_directive(test_context):
    """Test URL analysis skipped when no directive present."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable without directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    
    analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
    # No analysis should be created
    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is None


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_with_crawl_directive(monkeypatch, test_context):
    """Test URL analysis with crawl directive."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable with crawl directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)
    
    # Mock saq.phishkit functions
    def mock_scan_url(url, output_dir, is_async=True):
        return "test-job-456"
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock delay_analysis to avoid delayed execution issues
    def mock_delay_analysis(*args, **kwargs):
        pass
    
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output-2"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
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
    url_observable.add_directive(DIRECTIVE_RENDER)
    
    # Mock saq.phishkit functions to raise exception
    def mock_scan_url(url, output_dir, is_async=True):
        raise Exception("Network error")
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None
    assert analysis.error == "failed to scan URL https://example.com/phish: Network error"
    assert analysis.scan_type == SCAN_TYPE_URL


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_success(monkeypatch, test_context):
    """Test successful file analysis execution."""
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
        analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
        
        def mock_config_get(key):
            if key == 'valid_file_extensions':
                return ['.html']
            elif key == 'valid_mime_types':
                return ['text/html']
            return []
        
        monkeypatch.setattr(analyzer.config, '__getitem__', mock_config_get)
        
        # Mock saq.phishkit functions
        def mock_scan_file(file_path, output_dir, is_async=True):
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
        
        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
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
def test_phishkit_analyzer_execute_analysis_file_no_directive(test_context):
    """Test file analysis skipped when no render directive."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file without render directive
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        file_observable = root.add_file_observable(test_file_path)
        
        analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
        result = analyzer.execute_analysis(file_observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # No analysis should be created
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is None
        
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
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Configure analyzer to only accept html files
        analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
        
        def mock_config_get(key):
            if key == 'valid_file_extensions':
                return ['.html']  # Only accept HTML files, not .txt
            elif key == 'valid_mime_types':
                return ['text/html']
            return []
        
        monkeypatch.setattr(analyzer.config, '__getitem__', mock_config_get)
        
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
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis with wrong MIME type
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'Plain text', 'mime': 'text/plain'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to only accept html MIME types
        analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
        
        def mock_config_get(key):
            if key == 'valid_file_extensions':
                return ['.html']
            elif key == 'valid_mime_types':
                return ['text/html']  # Only accept text/html, not text/plain
            return []
        
        monkeypatch.setattr(analyzer.config, '__getitem__', mock_config_get)
        
        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
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
    root = create_root_analysis(analysis_mode='test_single')
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
        analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
        
        def mock_config_get(key):
            if key == 'valid_file_extensions':
                return ['.html']
            elif key == 'valid_mime_types':
                return ['text/html']
            return []
        
        monkeypatch.setattr(analyzer.config, '__getitem__', mock_config_get)
        
        # Mock saq.phishkit functions to raise exception
        def mock_scan_file(file_path, output_dir, is_async=True):
            raise Exception("File processing error")
        
        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        
        # Mock create_temporary_directory
        def mock_create_temporary_directory():
            return "/tmp/test-file-output"
        
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
        
        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
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
def test_phishkit_analyzer_complete_analysis_no_job_id(test_context):
    """Test completing analysis with no job ID."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    # Don't set job_id
    url_observable.add_analysis(analysis)
    
    analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
    result = analyzer.complete_analysis(url_observable, analysis)
    
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.integration
def test_phishkit_analyzer_complete_analysis_not_ready(monkeypatch, test_context):
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
    
    analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
    
    # Mock delay_analysis to return the expected result
    def mock_delay_analysis(*args, **kwargs):
        return AnalysisExecutionResult.INCOMPLETE
    
    analyzer.delay_analysis = MagicMock(side_effect=mock_delay_analysis)
    
    result = analyzer.complete_analysis(url_observable, analysis)
    
    # Should call delay_analysis and return its result
    analyzer.delay_analysis.assert_called_once_with(url_observable, analysis, seconds=3, timeout_seconds=60)
    assert result == AnalysisExecutionResult.INCOMPLETE


@pytest.mark.integration
def test_phishkit_analyzer_complete_analysis_success(monkeypatch, test_context):
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
        other_file = os.path.join(temp_dir, "result.json")
        
        with open(exit_code_file, "w") as f:
            f.write("0")
        with open(stdout_file, "w") as f:
            f.write("scan completed")
        with open(stderr_file, "w") as f:
            f.write("no errors")
        with open(other_file, "w") as f:
            f.write('{"result": "success"}')
        
        output_files = [exit_code_file, stdout_file, stderr_file, other_file]
        
        # Mock get_async_scan_result to return file list
        def mock_get_async_scan_result(job_id, output_dir, timeout=1):
            return output_files
        
        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)
        
        analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
        result = analyzer.complete_analysis(url_observable, analysis)
        
        assert result == AnalysisExecutionResult.COMPLETED
        assert analysis.output_files == output_files
        assert analysis.scan_result == f"successfully scanned {url_observable}"
        assert analysis.error is None
        assert analysis.exit_code == 0
        assert analysis.stdout == "scan completed"
        assert analysis.stderr == "no errors"


@pytest.mark.integration
def test_phishkit_analyzer_complete_analysis_with_existing_analysis(monkeypatch, test_context):
    """Test executing analysis when continuing existing analysis."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    existing_analysis = PhishkitAnalysis()
    existing_analysis.job_id = "existing-job-123"
    existing_analysis.output_dir = "/tmp/existing-output"
    url_observable.add_analysis(existing_analysis)
    
    # Mock get_async_scan_result to return success
    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        return ["/tmp/result.txt"]
    
    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)
    
    analyzer = PhishkitAnalyzer(context=create_test_context(root=root))
    
    # Mock complete_analysis to verify it's called
    analyzer.complete_analysis = MagicMock(return_value=AnalysisExecutionResult.COMPLETED)
    
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    analyzer.complete_analysis.assert_called_once_with(url_observable, existing_analysis)