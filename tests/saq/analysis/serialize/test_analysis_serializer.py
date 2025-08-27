import pytest
import uuid

from saq.analysis.analysis import Analysis, SummaryDetail
from saq.analysis.pivot_link import PivotLink
from saq.analysis.detectable import DetectionManager
from saq.analysis.taggable import TagManager
from saq.analysis.sortable import SortManager
from saq.analysis.serialize.analysis_serializer import (
    AnalysisSerializer,
    KEY_UUID,
    KEY_INSTANCE,
    KEY_OBSERVABLES,
    KEY_SUMMARY,
    KEY_SUMMARY_DETAILS,
    KEY_PIVOT_LINKS,
    KEY_COMPLETED,
    KEY_DELAYED,
    KEY_EXTERNAL_DETAILS_PATH,
    KEY_DETAILS_SIZE,
    KEY_LLM_CONTEXT_DOCUMENTS,
)
from saq.constants import SUMMARY_DETAIL_FORMAT_PRE


class MockObservable:
    """Mock observable for testing."""
    def __init__(self, id_value):
        self.id = id_value


class TestAnalysis(Analysis):
    """Test Analysis class for serialization testing."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Initialize component managers with real instances
        self._tag_manager = TagManager(self)
        self._detection_manager = DetectionManager(self)
        self._sort_manager = SortManager(self)


@pytest.fixture
def sample_analysis():
    """Create a sample Analysis object for testing."""
    analysis = TestAnalysis()
    analysis._uuid = "test-uuid-12345"
    analysis.instance = "test-instance"
    analysis.summary = "test summary"
    analysis._completed = True
    analysis.delayed = False
    analysis.external_details_path = "/path/to/details"
    analysis.details_size = 1024
    analysis.llm_context_documents = ["doc1", "doc2"]
    
    # Add some tags via the tag manager
    analysis._tag_manager.add_tag("test-tag1")
    analysis._tag_manager.add_tag("test-tag2")
    
    # Add some detections via the detection manager
    analysis.add_detection_point("test-detection")
    
    # Set sort order via the sort manager
    analysis._sort_manager.sort_order = 50
    
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


@pytest.fixture
def empty_analysis():
    """Create an empty Analysis object for testing."""
    return TestAnalysis()


@pytest.mark.unit
def test_analysis_serializer_constants():
    """Test that all required constants are defined."""
    assert KEY_UUID == 'uuid'
    assert KEY_INSTANCE == 'instance'
    assert KEY_OBSERVABLES == 'observables'
    assert KEY_SUMMARY == 'summary'
    assert KEY_SUMMARY_DETAILS == 'summary_details'
    assert KEY_PIVOT_LINKS == 'pivot_links'
    assert KEY_COMPLETED == 'completed'
    assert KEY_DELAYED == 'delayed'
    assert KEY_EXTERNAL_DETAILS_PATH == 'file_path'
    assert KEY_DETAILS_SIZE == 'details_size'
    assert KEY_LLM_CONTEXT_DOCUMENTS == 'llm_context_documents'


@pytest.mark.unit
def test_serialize_full_analysis(sample_analysis):
    """Test serializing a fully populated Analysis object."""
    result = AnalysisSerializer.serialize(sample_analysis)
    
    # Check that result is a dictionary
    assert isinstance(result, dict)
    
    # Check component manager data is included
    assert 'tags' in result  # from TagManager
    assert 'detections' in result  # from DetectionManager
    assert 'sort_order' in result  # from SortManager
    assert result['sort_order'] == 50
    
    # Check analysis-specific data
    assert result[KEY_UUID] == "test-uuid-12345"
    assert result[KEY_INSTANCE] == "test-instance"
    assert result[KEY_OBSERVABLES] == ["obs-1", "obs-2"]
    assert result[KEY_SUMMARY] == "test summary"
    assert result[KEY_COMPLETED] is True
    assert result[KEY_DELAYED] is False
    assert result[KEY_EXTERNAL_DETAILS_PATH] == "/path/to/details"
    assert result[KEY_DETAILS_SIZE] == 1024
    assert result[KEY_LLM_CONTEXT_DOCUMENTS] == ["doc1", "doc2"]
    
    # Check summary details
    assert len(result[KEY_SUMMARY_DETAILS]) == 2
    assert result[KEY_SUMMARY_DETAILS][0]['header'] == "Header 1"
    assert result[KEY_SUMMARY_DETAILS][1]['header'] == "Header 2"
    
    # Check pivot links
    assert len(result[KEY_PIVOT_LINKS]) == 2
    assert result[KEY_PIVOT_LINKS][0]['url'] == "http://example.com"
    assert result[KEY_PIVOT_LINKS][1]['url'] == "http://example2.com"


@pytest.mark.unit
def test_serialize_empty_analysis(empty_analysis):
    """Test serializing an empty Analysis object."""
    # Ensure properties have default values
    empty_analysis._observables = []
    empty_analysis.summary = None
    empty_analysis.summary_details = []
    empty_analysis.pivot_links = []
    empty_analysis.external_details_path = None
    empty_analysis.details_size = None
    empty_analysis.llm_context_documents = None
    
    result = AnalysisSerializer.serialize(empty_analysis)
    
    # Check that result is a dictionary
    assert isinstance(result, dict)
    
    # Check that all required keys are present
    assert KEY_UUID in result
    assert KEY_INSTANCE in result
    assert KEY_OBSERVABLES in result
    assert KEY_SUMMARY in result
    assert KEY_COMPLETED in result
    assert KEY_DELAYED in result
    assert KEY_SUMMARY_DETAILS in result
    assert KEY_PIVOT_LINKS in result
    assert KEY_EXTERNAL_DETAILS_PATH in result
    assert KEY_DETAILS_SIZE in result
    assert KEY_LLM_CONTEXT_DOCUMENTS in result
    
    # Check default values
    assert result[KEY_OBSERVABLES] == []
    assert result[KEY_SUMMARY_DETAILS] == []
    assert result[KEY_PIVOT_LINKS] == []


@pytest.mark.unit
def test_deserialize_full_data():
    """Test deserializing a fully populated dictionary."""
    analysis = TestAnalysis()
    
    # Sample data dictionary
    data = {
        'tags': ['tag1', 'tag2'],
        'detections': ['detection1'],
        'sort_order': 75,
        KEY_UUID: "test-uuid-67890",
        KEY_INSTANCE: "deserialized-instance",
        KEY_OBSERVABLES: ["obs-3", "obs-4", "obs-5"],
        KEY_SUMMARY: "deserialized summary",
        KEY_COMPLETED: False,
        KEY_DELAYED: True,
        KEY_SUMMARY_DETAILS: [
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
        KEY_PIVOT_LINKS: [
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
        KEY_EXTERNAL_DETAILS_PATH: "/deserialized/path",
        KEY_DETAILS_SIZE: 2048,
        KEY_LLM_CONTEXT_DOCUMENTS: ["deser-doc1", "deser-doc2", "deser-doc3"]
    }
    
    AnalysisSerializer.deserialize(analysis, data)
    
    # Verify component manager data was set
    assert analysis._sort_manager.sort_order == 75
    
    # Verify analysis properties were set
    assert analysis._uuid == "test-uuid-67890"
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
def test_deserialize_partial_data():
    """Test deserializing with only some keys present."""
    analysis = TestAnalysis()
    
    # Store original values
    original_uuid = analysis._uuid
    original_instance = analysis.instance
    
    # Partial data dictionary
    data = {
        KEY_UUID: "partial-uuid",
        KEY_SUMMARY: "partial summary",
        KEY_COMPLETED: True
    }
    
    AnalysisSerializer.deserialize(analysis, data)
    
    # Verify only provided properties were set
    assert analysis._uuid == "partial-uuid"
    assert analysis.summary == "partial summary"
    assert analysis._completed is True
    
    # Verify unspecified properties retain original values or defaults
    assert analysis.instance == original_instance  # Should remain unchanged


@pytest.mark.unit
def test_deserialize_empty_data():
    """Test deserializing with empty dictionary."""
    analysis = TestAnalysis()
    
    # Store original values
    original_uuid = analysis._uuid
    original_instance = analysis.instance
    
    data = {}
    
    AnalysisSerializer.deserialize(analysis, data)
    
    # Verify properties retain original values
    assert analysis._uuid == original_uuid
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
    assert new_analysis._uuid == sample_analysis._uuid
    assert new_analysis.instance == sample_analysis.instance
    assert new_analysis.summary == sample_analysis.summary
    assert new_analysis._completed == sample_analysis._completed
    assert new_analysis.delayed == sample_analysis.delayed
    assert new_analysis.external_details_path == sample_analysis.external_details_path
    assert new_analysis.details_size == sample_analysis.details_size
    assert new_analysis.llm_context_documents == sample_analysis.llm_context_documents
    assert new_analysis.observable_references == ["obs-1", "obs-2"]
    
    # Verify component manager data is preserved
    assert new_analysis._sort_manager.sort_order == sample_analysis._sort_manager.sort_order
    
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