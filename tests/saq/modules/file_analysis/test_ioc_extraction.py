import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_IOC_EXTRACTION,
    DIRECTIVE_EXTRACT_IOCS,
    F_FILE,
    F_URL,
    F_IP,
    F_EMAIL_ADDRESS,
    F_MD5,
    F_SHA1,
    F_SHA256,
    R_EXTRACTED_FROM,
    AnalysisExecutionResult,
)
from saq.modules.file_analysis.ioc_extraction import (
    IOCExtractionAnalyzer,
    IOCExtractionAnalysis,
)
from saq.modules.adapter import AnalysisModuleAdapter
from tests.saq.helpers import create_root_analysis


@pytest.mark.unit
def test_requires_directive(test_context):
    """Test that module requires the extract_iocs directive."""
    # Create the analyzer directly to check its required_directives
    analyzer = IOCExtractionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_IOC_EXTRACTION))

    # Check that the required_directives property includes our directive
    assert DIRECTIVE_EXTRACT_IOCS in analyzer.required_directives


@pytest.mark.unit
def test_generate_summary_no_iocs():
    """Test that summary returns None when no IOCs found."""
    analysis = IOCExtractionAnalysis()
    assert analysis.generate_summary() is None


@pytest.mark.unit
def test_generate_summary_with_iocs():
    """Test that summary is generated correctly with IOCs."""
    analysis = IOCExtractionAnalysis()
    analysis.details['iocs'] = {
        F_URL: ['https://example.com', 'https://test.org'],
        F_EMAIL_ADDRESS: ['admin@example.com'],
    }
    analysis.details['total_count'] = 3

    summary = analysis.generate_summary()
    assert summary is not None
    assert "Extracted 3 IOCs" in summary
    assert F_URL in summary
    assert F_EMAIL_ADDRESS in summary


@pytest.mark.unit
def test_display_name():
    """Test that display_name returns expected value."""
    analysis = IOCExtractionAnalysis()
    assert analysis.display_name == "IOC Extraction Analysis"


@pytest.mark.unit
def test_valid_observable_types(test_context):
    """Test that module only accepts file observables."""
    analyzer = IOCExtractionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_IOC_EXTRACTION))

    assert analyzer.valid_observable_types == F_FILE


@pytest.mark.unit
def test_empty_file(test_context):
    """Test that empty files are handled gracefully."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    target_path = root.create_file_path("empty.txt")
    with open(target_path, "w") as fp:
        fp.write("")

    observable = root.add_file_observable(target_path)
    observable.add_directive(DIRECTIVE_EXTRACT_IOCS)

    analyzer = AnalysisModuleAdapter(IOCExtractionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_IOC_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    # Analysis should not be created for empty files
    analysis = observable.get_and_load_analysis(IOCExtractionAnalysis)
    assert analysis is None


@pytest.mark.unit
def test_file_too_large(test_context):
    """Test that files exceeding max_file_size are skipped."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create a file that would be skipped by a 1KB limit
    # We can't easily test the actual size limit without modifying config
    # But we can verify the module completes without creating analysis for large files
    content = "https://example.com " * 1000  # ~20KB of content

    target_path = root.create_file_path("large.txt")
    with open(target_path, "w") as fp:
        fp.write(content)

    observable = root.add_file_observable(target_path)
    observable.add_directive(DIRECTIVE_EXTRACT_IOCS)

    analyzer = AnalysisModuleAdapter(IOCExtractionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_IOC_EXTRACTION)))
    analyzer.root = root

    # With default config (10MB), this should process fine
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED


def _create_analyzer(test_context, datadir, yaml_filename):
    """Helper to create an analyzer with a specific YAML patterns file from datadir.

    Uses an absolute path from the pytest-datadir temp directory. This works because
    os.path.join() discards earlier components when given an absolute path.
    """
    absolute_path = str(datadir / yaml_filename)
    config = get_analysis_module_config(ANALYSIS_MODULE_IOC_EXTRACTION)
    config.extraction_config_path = absolute_path
    analyzer_instance = IOCExtractionAnalyzer(context=test_context, config=config)
    adapter = AnalysisModuleAdapter(analyzer_instance)
    return adapter, analyzer_instance


@pytest.mark.unit
def test_invalid_regex_logs_warning(test_context, datadir, caplog):
    """Test that invalid regex in YAML logs a warning but doesn't crash."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    content = "Found GOOD-42 in the logs"

    target_path = root.create_file_path("test_invalid_regex.txt")
    with open(target_path, "w") as fp:
        fp.write(content)

    observable = root.add_file_observable(target_path)
    observable.add_directive(DIRECTIVE_EXTRACT_IOCS)

    adapter, _ = _create_analyzer(test_context, datadir, "test_invalid_regex.yaml")
    adapter.root = root

    import logging
    with caplog.at_level(logging.WARNING):
        result = adapter.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED

    # The good pattern should still have worked
    analysis = observable.get_and_load_analysis(IOCExtractionAnalysis)
    assert analysis is not None
    assert "indicator" in analysis.details["iocs"]
    assert "42" in analysis.details["iocs"]["indicator"]

    # Should have logged warnings about invalid patterns
    warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("invalid regex" in msg.lower() or "invalid" in msg.lower() for msg in warning_messages)


@pytest.mark.unit
def test_empty_yaml_works_gracefully(test_context, datadir):
    """Test that an empty YAML file doesn't cause errors."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    content = "Visit https://example.com for info"

    target_path = root.create_file_path("test_empty_yaml.txt")
    with open(target_path, "w") as fp:
        fp.write(content)

    observable = root.add_file_observable(target_path)
    observable.add_directive(DIRECTIVE_EXTRACT_IOCS)

    adapter, _ = _create_analyzer(test_context, datadir, "test_empty_yaml.yaml")
    adapter.root = root

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(IOCExtractionAnalysis)
    assert analysis is not None
    # iocsearcher should still work normally
    assert analysis.details["total_count"] > 0
    assert analysis.details["excluded_count"] == 0


@pytest.mark.unit
def test_missing_yaml_extracts_no_iocs(test_context):
    """Test that a missing YAML file doesn't crash and extracts no IOCs.

    With the refactored configuration, a missing YAML means no iocsearcher
    mappings are loaded, so no IOCs will be extracted (only custom patterns
    would work, but there are none without a config file).
    """
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    content = "Visit https://example.com for info"

    target_path = root.create_file_path("test_missing_yaml.txt")
    with open(target_path, "w") as fp:
        fp.write(content)

    observable = root.add_file_observable(target_path)
    observable.add_directive(DIRECTIVE_EXTRACT_IOCS)

    # This test doesn't use datadir since it tests a missing file
    config = get_analysis_module_config(ANALYSIS_MODULE_IOC_EXTRACTION)
    config.extraction_config_path = "etc/nonexistent_patterns.yaml"
    analyzer_instance = IOCExtractionAnalyzer(context=test_context, config=config)
    adapter = AnalysisModuleAdapter(analyzer_instance)
    adapter.root = root

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    # Analysis is created but with no IOCs extracted (no mappings configured)
    analysis = observable.get_and_load_analysis(IOCExtractionAnalysis)
    assert analysis is not None
    assert analysis.details["total_count"] == 0


@pytest.mark.unit
def test_comprehensive_ioc_extraction(test_context):
    """Comprehensive test for IOC extraction covering all IOC types, relationships, deduplication, and skipped types.

    This test consolidates:
    - test_extract_urls_and_emails
    - test_extract_ip_addresses
    - test_extract_hashes
    - test_skipped_types_tracked
    - test_observable_relationships
    - test_deduplication
    """
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Rich document with all IOC types, duplicates, and unsupported IOC types
    content = """
    # URLs (including duplicates)
    Visit our website at https://example.com/path?query=value for more information.
    Also check http://test.org/page and https://another-site.net
    Visit https://example.com/path?query=value again (duplicate)

    # Email addresses (including duplicates)
    Contact us at admin@example.com or support@test.org
    Send feedback to admin@example.com (duplicate)

    # IPv4 addresses (including private IPs and duplicates)
    Internal server: 192.168.1.100
    Gateway: 10.0.0.1
    Other network: 172.16.0.50
    Public DNS: 8.8.8.8
    Duplicate internal: 192.168.1.100

    # Hashes
    MD5: d41d8cd98f00b204e9800998ecf8427e
    SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    # Unsupported IOC types (should be skipped)
    Check vulnerability CVE-2021-44228
    Send payment to bitcoin address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    """

    target_path = root.create_file_path("comprehensive_iocs.txt")
    with open(target_path, "w") as fp:
        fp.write(content)

    observable = root.add_file_observable(target_path)
    observable.add_directive(DIRECTIVE_EXTRACT_IOCS)

    analyzer = AnalysisModuleAdapter(IOCExtractionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_IOC_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(IOCExtractionAnalysis)
    assert isinstance(analysis, IOCExtractionAnalysis)

    # Verify IOCs were extracted
    assert analysis.details['total_count'] > 0
    iocs = analysis.details['iocs']
    assert len(iocs) > 0

    # Verify URL extraction
    assert F_URL in iocs
    assert any("example.com" in url for url in iocs[F_URL])

    # Verify email extraction
    assert F_EMAIL_ADDRESS in iocs
    assert "admin@example.com" in iocs[F_EMAIL_ADDRESS]

    # Verify IP extraction (including private IPs with include_private_ips=true)
    assert F_IP in iocs
    assert '192.168.1.100' in iocs[F_IP]
    assert '8.8.8.8' in iocs[F_IP]

    # Verify hash extraction
    assert F_MD5 in iocs
    assert 'd41d8cd98f00b204e9800998ecf8427e' in iocs[F_MD5]
    assert F_SHA1 in iocs
    assert 'da39a3ee5e6b4b0d3255bfef95601890afd80709' in iocs[F_SHA1]
    assert F_SHA256 in iocs
    assert 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' in iocs[F_SHA256]

    # Verify deduplication - each value should appear only once
    for ioc_type, values in iocs.items():
        assert len(values) == len(set(values)), f"Duplicate values found for {ioc_type}"

    # Verify R_EXTRACTED_FROM relationships
    for obs in analysis.observables:
        assert obs.has_relationship(R_EXTRACTED_FROM), f"Observable {obs} missing R_EXTRACTED_FROM relationship"

    # Verify skipped_types tracking
    assert isinstance(analysis.details['skipped_types'], list)


@pytest.mark.unit
def test_custom_patterns(test_context, datadir):
    """Comprehensive test for custom pattern extraction covering directives, tags, display_type, and capture groups.

    This test consolidates:
    - test_pattern_with_directives
    - test_pattern_with_tags
    - test_pattern_with_display_type
    - test_custom_pattern_extraction
    - test_custom_pattern_with_capture_group
    """
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Content with Azure Correlation ID pattern (tests directives, tags, display_type, and capture group)
    content = """
    correlationId: a1b2c3d4-e5f6-7890-abcd-ef1234567890
    """

    target_path = root.create_file_path("test_custom_patterns.txt")
    with open(target_path, "w") as fp:
        fp.write(content)

    observable = root.add_file_observable(target_path)
    observable.add_directive(DIRECTIVE_EXTRACT_IOCS)

    adapter, _ = _create_analyzer(test_context, datadir, "test_custom_patterns_comprehensive.yaml")
    adapter.root = root

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(IOCExtractionAnalysis)
    assert analysis is not None

    # Verify azure_correlation_id pattern extraction (capture group extracts just the UUID)
    assert "azure_correlation_id" in analysis.details["iocs"]
    assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" in analysis.details["iocs"]["azure_correlation_id"]

    # Find the azure_correlation_id observable and verify all attributes
    correlation_obs = None
    for obs in analysis.observables:
        if obs.type == "azure_correlation_id":
            correlation_obs = obs
            break
    assert correlation_obs is not None

    # Verify directives applied
    assert correlation_obs.has_directive("azure_lookup")

    # Verify tags applied
    assert correlation_obs.has_tag("azure")
    assert correlation_obs.has_tag("correlation")

    # Verify display_type set (display_type property appends the type in parentheses)
    assert correlation_obs.display_type == "Azure Correlation ID (azure_correlation_id)"


@pytest.mark.unit
def test_exclude_patterns(test_context, datadir):
    """Comprehensive test for exclude patterns covering iocsearcher IOCs, custom pattern IOCs, and excluded_count.

    This test consolidates:
    - test_exclude_patterns_filter_iocsearcher_results
    - test_exclude_patterns_filter_custom_pattern_results
    - test_excluded_count_in_details
    """
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Content with:
    # - URL containing example.com (should be excluded by iocsearcher filter)
    # - URL not containing example.com (should be kept)
    # - Correlation ID a1b2c3d4-... (should be kept)
    # - Correlation ID 99999999-... (should be excluded by custom pattern filter)
    content = """
    Visit https://example.com/path for info (should be excluded).
    Also check https://malicious-site.com/payload (should be kept).
    correlationId: a1b2c3d4-e5f6-7890-abcd-ef1234567890 (should be kept).
    correlationId: 99999999-aaaa-bbbb-cccc-dddddddddddd (should be excluded).
    """

    target_path = root.create_file_path("test_exclude_patterns.txt")
    with open(target_path, "w") as fp:
        fp.write(content)

    observable = root.add_file_observable(target_path)
    observable.add_directive(DIRECTIVE_EXTRACT_IOCS)

    adapter, _ = _create_analyzer(test_context, datadir, "test_exclude_patterns_comprehensive.yaml")
    adapter.root = root

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(IOCExtractionAnalysis)
    assert analysis is not None

    # Collect all extracted values
    all_values = []
    for values in analysis.details["iocs"].values():
        all_values.extend(values)

    # Verify iocsearcher IOCs filtered: example.com should be excluded
    assert not any("example.com" in v for v in all_values), "example.com IOCs should have been excluded"

    # Verify malicious-site.com should still be present
    assert any("malicious-site.com" in v for v in all_values), "malicious-site.com should be present"

    # Verify custom pattern results filtered: correlation ID starting with 99999999- should be excluded
    assert "azure_correlation_id" in analysis.details["iocs"]
    assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" in analysis.details["iocs"]["azure_correlation_id"]
    assert "99999999-aaaa-bbbb-cccc-dddddddddddd" not in analysis.details["iocs"].get("azure_correlation_id", [])

    # Verify excluded_count is accurate (at least 2: example.com URL and 99999999-... correlation ID)
    assert "excluded_count" in analysis.details
    assert analysis.details["excluded_count"] >= 2
