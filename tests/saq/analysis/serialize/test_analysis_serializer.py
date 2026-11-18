import pytest

from saq.analysis.analysis import Analysis, SummaryDetail
from saq.analysis.pivot_link import PivotLink
from saq.analysis.serialize.analysis_serializer import AnalysisSerializer
from saq.constants import SUMMARY_DETAIL_FORMAT_PRE


class MockObservable:
    """Mock observable for testing."""
    def __init__(self, id_value):
        self.uuid = id_value


class TestAnalysis(Analysis):
    """Test Analysis class for serialization testing."""

    __test__ = False


@pytest.fixture
def sample_analysis():
    """Create a sample Analysis object for testing."""
    analysis = TestAnalysis()
    analysis.uuid = "test-uuid-12345"
    analysis.instance = "test-instance"
    analysis.summary = "test summary"
    analysis._completed = True
    analysis.delayed = False
    analysis.external_details_path = "/path/to/details"
    analysis.details_size = 1024
    analysis.llm_context_documents = ["doc1", "doc2"]
    
    # Add some tags via the tag manager
    analysis.add_tag("test-tag1")
    analysis.add_tag("test-tag2")
    
    # Add some detections via the detection manager
    analysis.add_detection_point("test-detection")
    
    # Set sort order via the sort manager
    analysis.sort_order = 50
    
    # Add some observables
    analysis._observables = [MockObservable("obs-1"), MockObservable("obs-2")]
    
    # Add some summary details
    detail1 = SummaryDetail("Header 1", "Content 1", SUMMARY_DETAIL_FORMAT_PRE)
    detail2 = SummaryDetail("Header 2", "Content 2", SUMMARY_DETAIL_FORMAT_PRE)
    analysis.summary_details = [detail1, detail2]
    
    # Add some pivot links
    link1 = PivotLink("http://example.com", "icon1", "Link 1")
    link2 = PivotLink("http://example2.com", "icon2", "Link 2")
    analysis.pivot_links = [link1, link2]
    
    return analysis


@pytest.mark.unit
def test_serialize_full_analysis(sample_analysis):
    """Serializing a fully populated Analysis object. The keys are the ones
    stored in root.json, written out so a renamed key fails here."""
    result = AnalysisSerializer.serialize(sample_analysis)
    
    # Check that result is a dictionary
    assert isinstance(result, dict)
    
    # Check component manager data is included
    assert 'tags' in result
    assert 'detections' in result
    assert 'sort_order' in result
    assert result['sort_order'] == 50
    
    # Check analysis-specific data
    assert result['uuid'] == "test-uuid-12345"
    assert result['instance'] == "test-instance"
    assert result['observables'] == ["obs-1", "obs-2"]
    assert result['summary'] == "test summary"
    assert result['completed'] is True
    assert result['delayed'] is False
    assert result['file_path'] == "/path/to/details"
    assert result['details_size'] == 1024
    assert result['llm_context_documents'] == ["doc1", "doc2"]
    
    # Check summary details
    assert len(result['summary_details']) == 2
    assert result['summary_details'][0]['header'] == "Header 1"
    assert result['summary_details'][1]['header'] == "Header 2"
    
    # Check pivot links
    assert len(result['pivot_links']) == 2
    assert result['pivot_links'][0]['url'] == "http://example.com"
    assert result['pivot_links'][1]['url'] == "http://example2.com"


@pytest.mark.unit
def test_deserialize_full_data():
    """Test deserializing a fully populated dictionary."""
    analysis = TestAnalysis()
    
    # Sample data dictionary
    data = {
        'tags': ['tag1', 'tag2'],
        'detections': ['detection1'],
        'sort_order': 75,
        'uuid': "test-uuid-67890",
        'instance': "deserialized-instance",
        'observables': ["obs-3", "obs-4", "obs-5"],
        'summary': "deserialized summary",
        'completed': False,
        'delayed': True,
        'summary_details': [
            {
                'id': 'detail-1',
                'header': 'Deserialized Header 1',
                'content': 'Deserialized Content 1',
                'format': SUMMARY_DETAIL_FORMAT_PRE
            },
            {
                'id': 'detail-2',
                'header': 'Deserialized Header 2',
                'content': 'Deserialized Content 2',
                'format': SUMMARY_DETAIL_FORMAT_PRE
            }
        ],
        'pivot_links': [
            {
                'url': 'http://deserialized1.com',
                'icon': 'deser-icon1',
                'text': 'Deserialized Link 1'
            },
            {
                'url': 'http://deserialized2.com',
                'icon': 'deser-icon2',
                'text': 'Deserialized Link 2'
            }
        ],
        'file_path': "/deserialized/path",
        'details_size': 2048,
        'llm_context_documents': ["deser-doc1", "deser-doc2", "deser-doc3"]
    }
    
    AnalysisSerializer.deserialize(analysis, data)
    
    # Verify component manager data was set
    assert analysis.sort_order == 75
    
    # Verify analysis properties were set
    assert analysis.uuid == "test-uuid-67890"
    assert analysis.instance == "deserialized-instance"
    assert analysis.observable_references == ["obs-3", "obs-4", "obs-5"]
    assert analysis.summary == "deserialized summary"
    assert analysis._completed is False
    assert analysis.delayed is True
    assert analysis.external_details_path == "/deserialized/path"
    assert analysis.details_size == 2048
    assert analysis.llm_context_documents == ["deser-doc1", "deser-doc2", "deser-doc3"]
    
    # Verify summary details
    assert len(analysis.summary_details) == 2
    assert analysis.summary_details[0].header == "Deserialized Header 1"
    assert analysis.summary_details[1].header == "Deserialized Header 2"
    
    # Verify pivot links
    assert len(analysis.pivot_links) == 2
    assert analysis.pivot_links[0].url == "http://deserialized1.com"
    assert analysis.pivot_links[1].url == "http://deserialized2.com"


@pytest.mark.unit
def test_deserialize_empty_data():
    """Test deserializing with empty dictionary."""
    analysis = TestAnalysis()
    
    # Store original values
    original_uuid = analysis.uuid
    original_instance = analysis.instance
    
    data = {}
    
    AnalysisSerializer.deserialize(analysis, data)
    
    # Verify properties retain original values
    assert analysis.uuid == original_uuid
    assert analysis.instance == original_instance


@pytest.mark.unit
def test_deserialize_non_dict_assertion():
    """Test that deserialize raises assertion error for non-dict input."""
    analysis = TestAnalysis()
    
    with pytest.raises(AssertionError):
        AnalysisSerializer.deserialize(analysis, "not a dict")
    
    with pytest.raises(AssertionError):
        AnalysisSerializer.deserialize(analysis, None)
    
    with pytest.raises(AssertionError):
        AnalysisSerializer.deserialize(analysis, [])


@pytest.mark.unit 
def test_round_trip_serialization(sample_analysis):
    """Test that serialize -> deserialize preserves data integrity."""
    # Serialize
    serialized_data = AnalysisSerializer.serialize(sample_analysis)
    
    # Create a new analysis for deserialization
    new_analysis = TestAnalysis()
    
    # Deserialize
    AnalysisSerializer.deserialize(new_analysis, serialized_data)
    
    # Verify key properties are preserved
    assert new_analysis.uuid == sample_analysis.uuid
    assert new_analysis.instance == sample_analysis.instance
    assert new_analysis.summary == sample_analysis.summary
    assert new_analysis._completed == sample_analysis._completed
    assert new_analysis.delayed == sample_analysis.delayed
    assert new_analysis.external_details_path == sample_analysis.external_details_path
    assert new_analysis.details_size == sample_analysis.details_size
    assert new_analysis.llm_context_documents == sample_analysis.llm_context_documents
    assert new_analysis.observable_references == ["obs-1", "obs-2"]
    
    # Verify component manager data is preserved
    assert new_analysis.sort_order == sample_analysis.sort_order
    
    # Verify summary details are preserved
    assert len(new_analysis.summary_details) == len(sample_analysis.summary_details)
    for i, detail in enumerate(new_analysis.summary_details):
        assert detail.header == sample_analysis.summary_details[i].header
        assert detail.content == sample_analysis.summary_details[i].content
        assert detail.format == sample_analysis.summary_details[i].format
    
    # Verify pivot links are preserved
    assert len(new_analysis.pivot_links) == len(sample_analysis.pivot_links)
    for i, link in enumerate(new_analysis.pivot_links):
        assert link.url == sample_analysis.pivot_links[i].url
        assert link.icon == sample_analysis.pivot_links[i].icon
        assert link.text == sample_analysis.pivot_links[i].text