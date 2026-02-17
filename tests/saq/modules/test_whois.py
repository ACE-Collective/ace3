import pytest
from datetime import datetime, timezone

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_WHOIS_ANALYZER, F_FQDN, AnalysisExecutionResult
from saq.modules.whois import WhoisAnalysis, WhoisAnalyzer
from tests.saq.helpers import create_root_analysis
from whois.exceptions import PywhoisError


@pytest.mark.unit
def test_whois_analysis_properties():
    """Test WhoisAnalysis properties and initialization."""
    analysis = WhoisAnalysis()
    
    # Test initial values
    assert analysis.error is None
    assert analysis.age_created_in_days is None
    assert analysis.age_last_updated_in_days is None
    assert analysis.datetime_created is None
    assert analysis.datetime_of_analysis is None
    assert analysis.datetime_of_last_update is None
    assert analysis.domain_name is None
    assert analysis.registrar is None
    assert analysis.whois_server is None
    assert analysis.name_servers is None
    assert analysis.emails is None
    assert analysis.whois_data is None
    assert analysis.whois_raw_text is None
    
    # Test property setters
    analysis.error = "test error"
    assert analysis.error == "test error"
    
    analysis.age_created_in_days = "30"
    assert analysis.age_created_in_days == "30"
    
    analysis.age_last_updated_in_days = "5"
    assert analysis.age_last_updated_in_days == "5"
    
    analysis.datetime_created = "2023-01-01 00:00:00"
    assert analysis.datetime_created == "2023-01-01 00:00:00"
    
    analysis.datetime_of_analysis = "2023-01-31 12:00:00"
    assert analysis.datetime_of_analysis == "2023-01-31 12:00:00"
    
    analysis.datetime_of_last_update = "2023-01-25 10:00:00"
    assert analysis.datetime_of_last_update == "2023-01-25 10:00:00"
    
    analysis.domain_name = "example.com"
    assert analysis.domain_name == "example.com"
    
    analysis.registrar = "Test Registrar"
    assert analysis.registrar == "Test Registrar"
    
    analysis.whois_server = "whois.example.com"
    assert analysis.whois_server == "whois.example.com"
    
    analysis.name_servers = ["ns1.example.com", "ns2.example.com"]
    assert analysis.name_servers == ["ns1.example.com", "ns2.example.com"]
    
    analysis.emails = ["admin@example.com"]
    assert analysis.emails == ["admin@example.com"]
    
    whois_data = {"domain_name": "example.com"}
    analysis.whois_data = whois_data
    assert analysis.whois_data == whois_data


@pytest.mark.unit
def test_whois_analysis_generate_summary_with_error():
    """Test generate_summary method when there's an error."""
    analysis = WhoisAnalysis()
    analysis.error = "domain not found"
    
    summary = analysis.generate_summary()
    assert summary == "Whois Analysis: error: domain not found"


@pytest.mark.unit
def test_whois_analysis_generate_summary_success():
    """Test generate_summary method with successful whois data."""
    analysis = WhoisAnalysis()
    analysis.age_created_in_days = "30"
    analysis.age_last_updated_in_days = "5"
    analysis.name_servers = ["ns1.example.com", "ns2.example.com"]
    analysis.registrar = "Test Registrar"
    analysis.whois_server = "whois.example.com"
    analysis.emails = ["admin@example.com", "tech@example.com"]
    
    summary = analysis.generate_summary()
    expected = "Whois Analysis: created: 30 day(s) ago, last updated: 5 day(s) ago, nameservers: (ns1.example.com, ns2.example.com), registrar: Test Registrar, whois server: whois.example.com, emails: (admin@example.com, tech@example.com)"
    assert summary == expected


@pytest.mark.unit
def test_whois_analysis_generate_summary_empty():
    """Test generate_summary method with no data."""
    analysis = WhoisAnalysis()
    
    summary = analysis.generate_summary()
    assert summary is None


@pytest.mark.unit
def test_whois_analyzer_properties():
    """Test WhoisAnalyzer properties."""
    analyzer = WhoisAnalyzer(config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER))
    
    assert analyzer.generated_analysis_type == WhoisAnalysis
    assert analyzer.valid_observable_types == F_FQDN


@pytest.mark.unit
def test_whois_analyzer_success(test_context, monkeypatch):
    """Test successful whois analysis execution."""
    
    # Mock the whois.whois function
    mock_whois_result = {
        "domain_name": "BV.COM",
        "registrar": "Network Solutions, LLC",
        "registrar_url": "http://networksolutions.com",
        "reseller": None,
        "whois_server": "whois.networksolutions.com",
        "referral_url": None,
        "updated_date": [
            datetime(2023, 12, 2, 5, 6, 36),
            datetime(2025, 3, 21, 7, 55, 58),
        ],
        "creation_date": datetime(1993, 12, 2, 5, 0),
        "expiration_date": datetime(2033, 12, 1, 5, 0),
        "name_servers": ["NS4.BV.COM", "NS6.BV.COM", "NS7.BV.COM"],
        "status": "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
        "emails": [
            "domain.operations@web.com",
            "dm2zq2vv7vq@networksolutionsprivateregistration.com",
        ],
        "dnssec": "unsigned",
        "name": "PERFECT PRIVACY, LLC",
        "org": None,
        "address": "5335 Gate Parkway care of Network Solutions PO Box 459",
        "city": "Jacksonville",
        "state": "FL",
        "registrant_postal_code": "32256",
        "country": "US",
        "text": "mock whois text response"
    }
    
    # Create a mock whois result object with get method and text attribute
    class MockWhoisResult:
        def __init__(self, data):
            self.data = data
            self.text = data.get("text", "mock whois text")
        
        def get(self, key, default=None):
            return self.data.get(key, default)
    
    mock_result = MockWhoisResult(mock_whois_result)
    
    def mock_whois(domain):
        return mock_result
    
    monkeypatch.setattr("saq.modules.whois.whois.whois", mock_whois)
    
    # Create test setup
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "bv.com")
    
    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER))
    analyzer.root = root
    
    # Execute analysis
    result = analyzer.execute_analysis(observable)
    
    # Verify execution result
    assert result == AnalysisExecutionResult.COMPLETED
    
    # Get the analysis and verify results
    analysis = observable.get_analysis(WhoisAnalysis)
    assert analysis is not None
    assert analysis.error is None
    
    # Verify basic properties
    assert analysis.domain_name == "BV.COM"
    assert analysis.registrar == "Network Solutions, LLC"
    assert analysis.name_servers == ["NS4.BV.COM", "NS6.BV.COM", "NS7.BV.COM"]
    assert analysis.whois_data == mock_result
    
    # Verify whois_raw_text is set (this is what the module actually sets)
    assert analysis.whois_raw_text == "mock whois text response"
    
    # Verify date calculations (should have values since creation_date was provided)
    assert analysis.datetime_created is not None
    assert analysis.age_created_in_days is not None
    assert analysis.datetime_of_analysis is not None
    
    # Verify updated date calculations
    assert analysis.datetime_of_last_update is not None
    assert analysis.age_last_updated_in_days is not None


@pytest.mark.unit
def test_whois_analyzer_pywhois_error(test_context, monkeypatch):
    """Test whois analysis when PywhoisError is raised."""
    
    def mock_whois_error(domain):
        raise PywhoisError("No whois server is known for this kind of object.")
    
    monkeypatch.setattr("saq.modules.whois.whois.whois", mock_whois_error)
    
    # Create test setup
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "unknown.tld")
    
    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER))
    analyzer.root = root
    
    # Execute analysis
    result = analyzer.execute_analysis(observable)
    
    # Verify execution result
    assert result == AnalysisExecutionResult.COMPLETED
    
    # Get the analysis and verify error handling
    analysis = observable.get_analysis(WhoisAnalysis)
    assert analysis is not None
    assert analysis.error == "No whois server is known for this kind of object."
    
    # Other properties should remain None when there's an error
    assert analysis.domain_name is None
    assert analysis.registrar is None
    assert analysis.age_created_in_days is None


@pytest.mark.unit
def test_whois_analyzer_multiline_error(test_context, monkeypatch):
    """Test whois analysis when PywhoisError has multiline message."""
    
    def mock_whois_multiline_error(domain):
        raise PywhoisError("First line of error\nSecond line of error\nThird line")
    
    monkeypatch.setattr("saq.modules.whois.whois.whois", mock_whois_multiline_error)
    
    # Create test setup
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "error.domain")
    
    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER))
    analyzer.root = root
    
    # Execute analysis
    result = analyzer.execute_analysis(observable)
    
    # Verify execution result
    assert result == AnalysisExecutionResult.COMPLETED
    
    # Get the analysis and verify error handling (should only get first line)
    analysis = observable.get_analysis(WhoisAnalysis)
    assert analysis is not None
    assert analysis.error == "First line of error"


@pytest.mark.unit
def test_whois_analyzer_creation_date_list(test_context, monkeypatch):
    """Test whois analysis when creation_date is a list."""
    
    mock_whois_result = {
        "domain_name": "TEST.COM",
        "registrar": "Test Registrar",
        "creation_date": [datetime(2020, 1, 1, 12, 0, 0), datetime(2020, 1, 1, 12, 0, 0)],
        "updated_date": [datetime(2023, 1, 1, 12, 0, 0)],
        "name_servers": ["ns1.test.com"],
        "text": "mock whois text"
    }
    
    class MockWhoisResult:
        def __init__(self, data):
            self.data = data
            self.text = data.get("text", "mock whois text")
        
        def get(self, key, default=None):
            return self.data.get(key, default)
    
    mock_result = MockWhoisResult(mock_whois_result)
    
    def mock_whois(domain):
        return mock_result
    
    monkeypatch.setattr("saq.modules.whois.whois.whois", mock_whois)
    
    # Create test setup
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "test.com")
    
    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER))
    analyzer.root = root
    
    # Execute analysis
    result = analyzer.execute_analysis(observable)
    
    # Verify execution result
    assert result == AnalysisExecutionResult.COMPLETED
    
    # Get the analysis and verify it handled the list properly
    analysis = observable.get_analysis(WhoisAnalysis)
    assert analysis is not None
    assert analysis.error is None
    assert analysis.datetime_created is not None  # Should use first item from list
    assert analysis.datetime_of_last_update is not None  # Should use first item from list


@pytest.mark.unit
def test_whois_analyzer_invalid_date_types(test_context, monkeypatch, caplog):
    """Test whois analysis when date fields are not datetime objects."""
    
    mock_whois_result = {
        "domain_name": "TEST.COM",
        "registrar": "Test Registrar", 
        "creation_date": None,  # None will trigger warning but not error
        "updated_date": None,  # None will trigger warning but not error
        "name_servers": ["ns1.test.com"],
        "text": "mock whois text"
    }
    
    class MockWhoisResult:
        def __init__(self, data):
            self.data = data
            self.text = data.get("text", "mock whois text")
        
        def get(self, key, default=None):
            return self.data.get(key, default)
    
    mock_result = MockWhoisResult(mock_whois_result)
    
    def mock_whois(domain):
        return mock_result
    
    monkeypatch.setattr("saq.modules.whois.whois.whois", mock_whois)
    
    # Create test setup
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "test.com")
    
    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER))
    analyzer.root = root
    
    # Execute analysis
    result = analyzer.execute_analysis(observable)
    
    # Verify execution result
    assert result == AnalysisExecutionResult.COMPLETED
    
    # Get the analysis and verify it handled invalid dates
    analysis = observable.get_analysis(WhoisAnalysis)
    assert analysis is not None
    assert analysis.error is None
    
    # Date fields should remain None when invalid
    assert analysis.datetime_created is None
    assert analysis.datetime_of_last_update is None
    assert analysis.age_created_in_days is None
    assert analysis.age_last_updated_in_days is None
    
    # Should have logged warnings about unexpected date formats
    assert "unexpected creation date format/contents" in caplog.text
    assert "unexpected updated date format/contents" in caplog.text


@pytest.mark.unit
def test_whois_analyzer_negative_time_delta(test_context, monkeypatch):
    """Test whois analysis when creation/update dates are in the future."""
    
    # Use dates in the future to test negative time delta handling
    future_date = datetime(2030, 1, 1, 12, 0, 0)
    
    mock_whois_result = {
        "domain_name": "FUTURE.COM",
        "registrar": "Future Registrar",
        "creation_date": future_date,
        "updated_date": future_date,
        "name_servers": ["ns1.future.com"],
        "text": "mock whois text"
    }
    
    class MockWhoisResult:
        def __init__(self, data):
            self.data = data
            self.text = data.get("text", "mock whois text")
        
        def get(self, key, default=None):
            return self.data.get(key, default)
    
    mock_result = MockWhoisResult(mock_whois_result)
    
    def mock_whois(domain):
        return mock_result
    
    monkeypatch.setattr("saq.modules.whois.whois.whois", mock_whois)
    
    # Create test setup
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "future.com")
    
    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER))
    analyzer.root = root
    
    # Execute analysis
    result = analyzer.execute_analysis(observable)
    
    # Verify execution result
    assert result == AnalysisExecutionResult.COMPLETED
    
    # Get the analysis and verify negative deltas are handled as "0"
    analysis = observable.get_analysis(WhoisAnalysis)
    assert analysis is not None
    assert analysis.error is None
    assert analysis.age_created_in_days == "0"
    assert analysis.age_last_updated_in_days == "0"


@pytest.mark.unit
def test_whois_analyzer_tz_aware_creation_date(test_context, monkeypatch):
    """Test whois analysis when whois returns tz-aware creation_date (avoids naive/aware subtraction error)."""
    # Whois can return aware datetimes (e.g. tzoffset('UTC', 0)); "now" is UTC-aware - subtraction must not raise
    creation_date = datetime(1997, 3, 29, 5, 0, tzinfo=timezone.utc)
    updated_date = datetime(2024, 1, 15, 12, 0, tzinfo=timezone.utc)

    mock_whois_result = {
        "domain_name": "EXAMPLE.ORG",
        "registrar": "Example Registrar",
        "creation_date": creation_date,
        "updated_date": updated_date,
        "name_servers": ["ns1.example.org"],
        "text": "mock whois text",
    }

    class MockWhoisResult:
        def __init__(self, data):
            self.data = data
            self.text = data.get("text", "mock whois text")

        def get(self, key, default=None):
            return self.data.get(key, default)

    mock_result = MockWhoisResult(mock_whois_result)

    def mock_whois(domain):
        return mock_result

    monkeypatch.setattr("saq.modules.whois.whois.whois", mock_whois)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.org")

    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(WhoisAnalysis)
    assert analysis is not None
    assert analysis.error is None
    assert analysis.age_created_in_days is not None
    assert analysis.age_created_in_days.isdigit()
    assert analysis.age_last_updated_in_days is not None
    assert analysis.age_last_updated_in_days.isdigit()


@pytest.mark.unit
def test_whois_analyzer_no_dates(test_context, monkeypatch):
    """Test whois analysis when no date information is available."""
    
    mock_whois_result = {
        "domain_name": "NODATE.COM",
        "registrar": "No Date Registrar",
        "creation_date": None,
        "updated_date": None,
        "name_servers": ["ns1.nodate.com"],
        "text": "mock whois text"
    }
    
    class MockWhoisResult:
        def __init__(self, data):
            self.data = data
            self.text = data.get("text", "mock whois text")
        
        def get(self, key, default=None):
            return self.data.get(key, default)
    
    mock_result = MockWhoisResult(mock_whois_result)
    
    def mock_whois(domain):
        return mock_result
    
    monkeypatch.setattr("saq.modules.whois.whois.whois", mock_whois)
    
    # Create test setup
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "nodate.com")
    
    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER))
    analyzer.root = root
    
    # Execute analysis
    result = analyzer.execute_analysis(observable)
    
    # Verify execution result
    assert result == AnalysisExecutionResult.COMPLETED
    
    # Get the analysis and verify handling of missing dates
    analysis = observable.get_analysis(WhoisAnalysis)
    assert analysis is not None
    assert analysis.error is None
    assert analysis.domain_name == "NODATE.COM"
    assert analysis.registrar == "No Date Registrar"
    
    # Date-related fields should remain None
    assert analysis.datetime_created is None
    assert analysis.datetime_of_last_update is None
    assert analysis.age_created_in_days is None
    assert analysis.age_last_updated_in_days is None
    
    # But analysis timestamp should be set
    assert analysis.datetime_of_analysis is not None
