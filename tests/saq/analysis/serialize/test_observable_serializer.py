import pytest
from datetime import datetime, timezone
import uuid

from saq.analysis.observable import Observable
from saq.analysis.relationship import Relationship
from saq.analysis.detectable import DetectionManager
from saq.analysis.taggable import TagManager
from saq.analysis.sortable import SortManager
from saq.analysis.serialize.observable_serializer import (
    ObservableSerializer,
    KEY_ID,
    KEY_TYPE,
    KEY_VALUE,
    KEY_TIME,
    KEY_ANALYSIS,
    KEY_DIRECTIVES,
    KEY_REDIRECTION,
    KEY_LINKS,
    KEY_LIMITED_ANALYSIS,
    KEY_EXCLUDED_ANALYSIS,
    KEY_RELATIONSHIPS,
    KEY_GROUPING_TARGET,
    KEY_VOLATILE,
    KEY_LLM_CONTEXT_DOCUMENTS,
)
from saq.constants import F_TEST, VALID_RELATIONSHIP_TYPES


class MockObservable(Observable):
    """Mock Observable class for serialization testing."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@pytest.fixture
def sample_observable():
    """Create a sample Observable object for testing."""
    observable = MockObservable(type=F_TEST, value="test-value", volatile=True)
    
    # Set observable ID to a known value for testing
    observable._id = "test-observable-12345"
    
    # Set time to a specific datetime
    test_time = datetime(2023, 12, 25, 12, 30, 45, tzinfo=timezone.utc)
    observable._time = test_time
    
    # Add analysis data
    observable._analysis = {"module1": "analysis1", "module2": "analysis2"}
    
    # Add directives
    observable._directives = ["directive1", "directive2"]
    
    # Set redirection
    observable._redirection = "redirect-target"
    
    # Add links
    observable._links = ["link1", "link2", "link3"]
    
    # Add limited analysis
    observable._limited_analysis = ["limited_module1", "limited_module2"]
    
    # Add excluded analysis
    observable._excluded_analysis = ["excluded_module1"]
    
    # Add relationships
    relationship1 = Relationship("contains", "related-observable-1")
    relationship2 = Relationship("extracted_from", "related-observable-2")
    observable._relationships = [relationship1, relationship2]
    
    # Set grouping target
    observable._grouping_target = True
    
    # Add LLM context documents
    observable.llm_context_documents = ["doc1", "doc2", "doc3"]
    
    # Add some tags via the tag manager
    observable._tag_manager.add_tag("test-tag1")
    observable._tag_manager.add_tag("test-tag2")
    
    # Add some detections via the detection manager
    observable.add_detection_point("test-detection")
    
    # Set sort order via the sort manager
    observable._sort_manager.sort_order = 75
    
    return observable


@pytest.fixture
def empty_observable():
    """Create an empty Observable object for testing."""
    return MockObservable()


@pytest.mark.unit
def test_observable_serializer_constants():
    """Test that all required constants are defined."""
    assert KEY_ID == 'id'
    assert KEY_TYPE == 'type'
    assert KEY_VALUE == 'value'
    assert KEY_TIME == 'time'
    assert KEY_ANALYSIS == 'analysis'
    assert KEY_DIRECTIVES == 'directives'
    assert KEY_REDIRECTION == 'redirection'
    assert KEY_LINKS == 'links'
    assert KEY_LIMITED_ANALYSIS == 'limited_analysis'
    assert KEY_EXCLUDED_ANALYSIS == 'excluded_analysis'
    assert KEY_RELATIONSHIPS == 'relationships'
    assert KEY_GROUPING_TARGET == 'grouping_target'
    assert KEY_VOLATILE == 'volatile'
    assert KEY_LLM_CONTEXT_DOCUMENTS == 'llm_context_documents'


@pytest.mark.unit
def test_serialize_full_observable(sample_observable):
    """Test serializing a fully populated Observable object."""
    result = ObservableSerializer.serialize(sample_observable)
    
    # Check that result is a dictionary
    assert isinstance(result, dict)
    
    # Check component manager data is included
    assert 'tags' in result  # from TagManager
    assert 'detections' in result  # from DetectionManager
    assert 'sort_order' in result  # from SortManager
    assert result['sort_order'] == 75
    
    # Check observable-specific data
    assert result[KEY_ID] == "test-observable-12345"
    assert result[KEY_TYPE] == F_TEST
    assert result[KEY_VALUE] == "test-value"
    assert result[KEY_TIME] == sample_observable._time
    assert result[KEY_ANALYSIS] == {"module1": "analysis1", "module2": "analysis2"}
    assert result[KEY_DIRECTIVES] == ["directive1", "directive2"]
    assert result[KEY_REDIRECTION] == "redirect-target"
    assert result[KEY_LINKS] == ["link1", "link2", "link3"]
    assert result[KEY_LIMITED_ANALYSIS] == ["limited_module1", "limited_module2"]
    assert result[KEY_EXCLUDED_ANALYSIS] == ["excluded_module1"]
    assert result[KEY_GROUPING_TARGET] is True
    assert result[KEY_VOLATILE] is True
    assert result[KEY_LLM_CONTEXT_DOCUMENTS] == ["doc1", "doc2", "doc3"]
    
    # Check relationships (should be a list of relationship objects)
    assert len(result[KEY_RELATIONSHIPS]) == 2
    assert result[KEY_RELATIONSHIPS][0].target == "related-observable-1"
    assert result[KEY_RELATIONSHIPS][0].r_type == "contains"
    assert result[KEY_RELATIONSHIPS][1].target == "related-observable-2"
    assert result[KEY_RELATIONSHIPS][1].r_type == "extracted_from"


@pytest.mark.unit
def test_serialize_empty_observable(empty_observable):
    """Test serializing an empty Observable object."""
    result = ObservableSerializer.serialize(empty_observable)
    
    # Check that result is a dictionary
    assert isinstance(result, dict)
    
    # Check that all required keys are present
    assert KEY_ID in result
    assert KEY_TYPE in result
    assert KEY_VALUE in result
    assert KEY_TIME in result
    assert KEY_ANALYSIS in result
    assert KEY_DIRECTIVES in result
    assert KEY_REDIRECTION in result
    assert KEY_LINKS in result
    assert KEY_LIMITED_ANALYSIS in result
    assert KEY_EXCLUDED_ANALYSIS in result
    assert KEY_RELATIONSHIPS in result
    assert KEY_GROUPING_TARGET in result
    assert KEY_VOLATILE in result
    assert KEY_LLM_CONTEXT_DOCUMENTS in result
    
    # Check default values
    assert result[KEY_ANALYSIS] == {}
    assert result[KEY_DIRECTIVES] == []
    assert result[KEY_REDIRECTION] is None
    assert result[KEY_LINKS] == []
    assert result[KEY_LIMITED_ANALYSIS] == []
    assert result[KEY_EXCLUDED_ANALYSIS] == []
    assert result[KEY_RELATIONSHIPS] == []
    assert result[KEY_GROUPING_TARGET] is False
    assert result[KEY_VOLATILE] is False
    assert result[KEY_LLM_CONTEXT_DOCUMENTS] == []


@pytest.mark.unit
def test_serialize_observable_with_string_time():
    """Test serializing an observable with string time value."""
    observable = MockObservable(type=F_TEST, value="test", time="2023-12-25 12:30:45")
    result = ObservableSerializer.serialize(observable)
    
    assert result[KEY_TIME] == "2023-12-25 12:30:45"


@pytest.mark.unit
def test_serialize_observable_with_none_values():
    """Test serializing an observable with None values for optional fields."""
    observable = MockObservable()
    observable._time = None
    observable._redirection = None
    observable.llm_context_documents = None
    
    result = ObservableSerializer.serialize(observable)
    
    assert result[KEY_TIME] is None
    assert result[KEY_REDIRECTION] is None
    assert result[KEY_LLM_CONTEXT_DOCUMENTS] is None


@pytest.mark.unit
def test_deserialize_full_data():
    """Test deserializing a fully populated dictionary."""
    observable = MockObservable()
    
    # Create relationships for test data
    test_relationship1 = Relationship("contains", "rel-obs-1")
    test_relationship2 = Relationship("extracted_from", "rel-obs-2")
    
    # Sample data dictionary
    data = {
        'tags': ['deserialized-tag1', 'deserialized-tag2'],
        'detections': ['deserialized-detection'],
        'sort_order': 150,
        KEY_ID: "deserialized-id-67890",
        KEY_TYPE: "deserialized-type",
        KEY_VALUE: "deserialized-value",
        KEY_TIME: datetime(2023, 11, 15, 10, 20, 30, tzinfo=timezone.utc),
        KEY_ANALYSIS: {"deser_module1": "deser_analysis1", "deser_module2": "deser_analysis2"},
        KEY_DIRECTIVES: ["deser_directive1", "deser_directive2", "deser_directive3"],
        KEY_REDIRECTION: "deser-redirect-target",
        KEY_LINKS: ["deser_link1", "deser_link2"],
        KEY_LIMITED_ANALYSIS: ["deser_limited1", "deser_limited2"],
        KEY_EXCLUDED_ANALYSIS: ["deser_excluded1"],
        KEY_RELATIONSHIPS: [test_relationship1, test_relationship2],
        KEY_GROUPING_TARGET: True,
        KEY_VOLATILE: True,
        KEY_LLM_CONTEXT_DOCUMENTS: ["deser_doc1", "deser_doc2"]
    }
    
    ObservableSerializer.deserialize(observable, data)
    
    # Verify component manager data was set
    assert observable._sort_manager.sort_order == 150
    
    # Verify observable properties were set
    assert observable.id == "deserialized-id-67890"
    assert observable.type == "deserialized-type"
    assert observable._value == "deserialized-value"
    assert observable.time == datetime(2023, 11, 15, 10, 20, 30, tzinfo=timezone.utc)
    assert observable.analysis == {"deser_module1": "deser_analysis1", "deser_module2": "deser_analysis2"}
    assert observable.directives == ["deser_directive1", "deser_directive2", "deser_directive3"]
    assert observable._redirection == "deser-redirect-target"
    assert observable._links == ["deser_link1", "deser_link2"]
    assert observable._limited_analysis == ["deser_limited1", "deser_limited2"]
    assert observable._excluded_analysis == ["deser_excluded1"]
    assert observable._relationships == [test_relationship1, test_relationship2]
    assert observable._grouping_target is True
    assert observable._volatile is True
    assert observable.llm_context_documents == ["deser_doc1", "deser_doc2"]


@pytest.mark.unit
def test_deserialize_partial_data():
    """Test deserializing with only some keys present."""
    observable = MockObservable()
    
    # Store original values
    original_id = observable.id
    original_type = observable.type
    original_value = observable._value
    
    # Partial data dictionary
    data = {
        KEY_ID: "partial-id",
        KEY_ANALYSIS: {"partial_module": "partial_analysis"},
        KEY_VOLATILE: True
    }
    
    ObservableSerializer.deserialize(observable, data)
    
    # Verify only provided properties were set
    assert observable.id == "partial-id"
    assert observable.analysis == {"partial_module": "partial_analysis"}
    assert observable._volatile is True
    
    # Verify unspecified properties retain original values
    assert observable.type == original_type
    assert observable._value == original_value


@pytest.mark.unit
def test_deserialize_empty_data():
    """Test deserializing with empty dictionary."""
    observable = MockObservable()
    
    # Store original values
    original_id = observable.id
    original_type = observable.type
    original_value = observable._value
    
    data = {}
    
    ObservableSerializer.deserialize(observable, data)
    
    # Verify properties retain original values
    assert observable.id == original_id
    assert observable.type == original_type
    assert observable._value == original_value


@pytest.mark.unit
def test_deserialize_non_dict_assertion():
    """Test that deserialize raises assertion error for non-dict input."""
    observable = MockObservable()
    
    with pytest.raises(AssertionError):
        ObservableSerializer.deserialize(observable, "not a dict")
    
    with pytest.raises(AssertionError):
        ObservableSerializer.deserialize(observable, None)
    
    with pytest.raises(AssertionError):
        ObservableSerializer.deserialize(observable, [])


@pytest.mark.unit
def test_deserialize_none_values():
    """Test deserializing with None values for optional fields."""
    observable = MockObservable()
    
    data = {
        KEY_TIME: None,
        KEY_REDIRECTION: None,
        KEY_LLM_CONTEXT_DOCUMENTS: None
    }
    
    ObservableSerializer.deserialize(observable, data)
    
    assert observable.time is None
    assert observable._redirection is None
    assert observable.llm_context_documents is None


@pytest.mark.unit
def test_round_trip_serialization(sample_observable):
    """Test that serialize -> deserialize preserves data integrity."""
    # Serialize
    serialized_data = ObservableSerializer.serialize(sample_observable)
    
    # Create a new observable for deserialization
    new_observable = MockObservable()
    
    # Deserialize
    ObservableSerializer.deserialize(new_observable, serialized_data)
    
    # Verify key properties are preserved
    assert new_observable.id == sample_observable.id
    assert new_observable.type == sample_observable.type
    assert new_observable._value == sample_observable._value
    assert new_observable.time == sample_observable.time
    assert new_observable.analysis == sample_observable.analysis
    assert new_observable.directives == sample_observable.directives
    assert new_observable._redirection == sample_observable._redirection
    assert new_observable._links == sample_observable._links
    assert new_observable._limited_analysis == sample_observable._limited_analysis
    assert new_observable._excluded_analysis == sample_observable._excluded_analysis
    assert new_observable._grouping_target == sample_observable._grouping_target
    assert new_observable._volatile == sample_observable._volatile
    assert new_observable.llm_context_documents == sample_observable.llm_context_documents
    
    # Verify relationships are preserved
    assert len(new_observable._relationships) == len(sample_observable._relationships)
    for i, rel in enumerate(new_observable._relationships):
        assert rel.target == sample_observable._relationships[i].target
        assert rel.r_type == sample_observable._relationships[i].r_type
    
    # Verify component manager data is preserved
    assert new_observable._sort_manager.sort_order == sample_observable._sort_manager.sort_order


@pytest.mark.unit
def test_serialize_preserves_original_observable():
    """Test that serialization doesn't modify the original observable."""
    observable = MockObservable(type=F_TEST, value="original-value")
    original_id = observable.id
    original_type = observable.type
    original_value = observable._value
    
    # Serialize
    result = ObservableSerializer.serialize(observable)
    
    # Verify original observable is unchanged
    assert observable.id == original_id
    assert observable.type == original_type
    assert observable._value == original_value
    
    # Verify result contains correct data
    assert result[KEY_ID] == original_id
    assert result[KEY_TYPE] == original_type
    assert result[KEY_VALUE] == original_value


@pytest.mark.unit
def test_deserialize_with_string_time():
    """Test deserializing with string time value."""
    observable = MockObservable()
    
    data = {
        KEY_TIME: "2023-01-01 12:00:00"
    }
    
    ObservableSerializer.deserialize(observable, data)
    
    # The Observable.time setter parses string times to datetime objects
    from saq.util import parse_event_time
    expected_time = parse_event_time("2023-01-01 12:00:00")
    assert observable.time == expected_time


@pytest.mark.unit
def test_serialize_observable_with_complex_analysis():
    """Test serializing an observable with complex analysis data."""
    observable = MockObservable(type=F_TEST, value="complex-test")
    
    # Complex analysis data with nested structures
    complex_analysis = {
        "module1": {
            "results": ["result1", "result2"],
            "metadata": {"score": 85, "confidence": "high"}
        },
        "module2": "simple_result"
    }
    observable._analysis = complex_analysis
    
    result = ObservableSerializer.serialize(observable)
    
    assert result[KEY_ANALYSIS] == complex_analysis
    assert result[KEY_ANALYSIS]["module1"]["results"] == ["result1", "result2"]
    assert result[KEY_ANALYSIS]["module1"]["metadata"]["score"] == 85


@pytest.mark.unit
def test_deserialize_with_complex_analysis():
    """Test deserializing with complex analysis data."""
    observable = MockObservable()
    
    complex_analysis = {
        "scanner": {
            "threats": ["malware1", "malware2"],
            "scan_time": "2023-12-01 10:00:00"
        },
        "enrichment": {
            "reputation": {"score": 90, "vendor": "test_vendor"},
            "categories": ["suspicious", "analysis"]
        }
    }
    
    data = {
        KEY_ANALYSIS: complex_analysis
    }
    
    ObservableSerializer.deserialize(observable, data)
    
    assert observable.analysis == complex_analysis
    assert observable.analysis["scanner"]["threats"] == ["malware1", "malware2"]
    assert observable.analysis["enrichment"]["reputation"]["score"] == 90