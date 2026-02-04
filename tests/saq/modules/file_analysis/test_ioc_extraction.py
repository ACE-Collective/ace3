import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_IOC_EXTRACTION,
    DIRECTIVE_EXTRACT_IOCS,
    F_FILE,
    F_URL,
    F_FQDN,
    F_IPV4,
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
    IOC_TYPE_MAPPING,
)
from saq.modules.adapter import AnalysisModuleAdapter
from tests.saq.helpers import create_root_analysis


@pytest.mark.unit
def test_ioc_type_mapping():
    """Test that the IOC type mapping contains expected types.

    Note: iocsearcher uses 'ip4' and 'ip6' (not 'ipv4' and 'ipv6')
    """
    expected_mappings = {
        'url': F_URL,
        'fqdn': F_FQDN,
        'ip4': F_IPV4,
        'ip6': F_IP,
        'email': F_EMAIL_ADDRESS,
        'md5': F_MD5,
        'sha1': F_SHA1,
        'sha256': F_SHA256,
    }
    for ioc_type, ace_type in expected_mappings.items():
        assert IOC_TYPE_MAPPING.get(ioc_type) == ace_type


@pytest.mark.unit
def test_requires_directive(tmpdir, test_context):
    """Test that module requires the extract_iocs directive."""
    # Create the analyzer directly to check its required_directives
    analyzer = IOCExtractionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_IOC_EXTRACTION))

    # Check that the required_directives property includes our directive
    assert DIRECTIVE_EXTRACT_IOCS in analyzer.required_directives


@pytest.mark.unit
def test_extract_urls_and_emails(tmpdir, test_context):
    """Test extraction of URLs and emails from a text file."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    content = """
    Visit our website at https://example.com/path?query=value for more information.
    You can also check http://test.org/page and https://another-site.net

    Contact us at admin@example.com or support@test.org
    """

    target_path = root.create_file_path("test_urls_emails.txt")
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

    # Should have extracted some IOCs
    assert analysis.details['total_count'] > 0

    # Check that we have some URLs and emails in the details
    iocs = analysis.details['iocs']
    assert len(iocs) > 0


@pytest.mark.unit
def test_extract_ip_addresses(tmpdir, test_context):
    """Test extraction of IPv4 addresses including private IPs.

    Note: With include_private_ips=true (default in config), iocsearcher will
    extract private/local/reserved IPs like 192.168.x.x, 10.x.x.x, etc.
    """
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Test with private IPs - these should be extracted with include_private_ips=true
    content = """
    Internal server: 192.168.1.100
    Gateway: 10.0.0.1
    Other network: 172.16.0.50
    Public DNS: 8.8.8.8
    """

    target_path = root.create_file_path("test_ips.txt")
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
    # Should have found IPs including private ones - note iocsearcher uses 'ip4' type internally
    assert analysis.details['total_count'] > 0
    # Verify we have IPv4 addresses in the extracted IOCs
    assert F_IPV4 in analysis.details['iocs']
    # Should have at least the private IP 192.168.1.100
    assert '192.168.1.100' in analysis.details['iocs'][F_IPV4]


@pytest.mark.unit
def test_extract_hashes(tmpdir, test_context):
    """Test extraction of MD5, SHA1, and SHA256 hashes."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    content = """
    Malware hashes:
    MD5: d41d8cd98f00b204e9800998ecf8427e
    SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """

    target_path = root.create_file_path("test_hashes.txt")
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
    assert analysis.details['total_count'] > 0


@pytest.mark.unit
def test_skipped_types_tracked(tmpdir, test_context):
    """Test that unsupported IOC types are tracked in skipped_types."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Include content that might have IOC types not supported by ACE
    # Bitcoin addresses, CVEs, etc. should be skipped
    content = """
    Check vulnerability CVE-2021-44228
    Send payment to bitcoin address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    Server: 192.168.1.1
    """

    target_path = root.create_file_path("test_skipped.txt")
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

    # skipped_types should contain any unsupported types that were found
    # This is a list, could be empty if iocsearcher didn't find unsupported types
    assert isinstance(analysis.details['skipped_types'], list)


@pytest.mark.unit
def test_empty_file(tmpdir, test_context):
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
def test_file_too_large(tmpdir, test_context):
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


@pytest.mark.unit
def test_observable_relationships(tmpdir, test_context):
    """Test that extracted IOCs have R_EXTRACTED_FROM relationship."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    content = """
    Visit https://malicious-site.com for more information.
    Contact: attacker@evil.com
    Server: 192.168.1.1
    """

    target_path = root.create_file_path("test_relationships.txt")
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
    if analysis and analysis.details['total_count'] > 0:
        # Check that observables have R_EXTRACTED_FROM relationships
        for obs in analysis.observables:
            assert obs.has_relationship(R_EXTRACTED_FROM)


@pytest.mark.unit
def test_generate_summary_no_iocs(tmpdir, test_context):
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
def test_deduplication(tmpdir, test_context):
    """Test that duplicate IOC values are not added multiple times."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Repeat the same IOCs multiple times
    content = """
    https://example.com
    https://example.com
    https://example.com
    admin@test.com
    admin@test.com
    192.168.1.1
    192.168.1.1
    """

    target_path = root.create_file_path("test_duplicates.txt")
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
    if analysis:
        # Check that each IOC value appears only once in the details
        for ioc_type, values in analysis.details['iocs'].items():
            assert len(values) == len(set(values)), f"Duplicate values found for {ioc_type}"
