import pytest
from datetime import datetime, timezone

from saq.analysis.observable import Observable
from saq.analysis.relationship import Relationship
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
from saq.constants import F_TEST


class MockObservable(Observable):
    """Mock Observable class for serialization testing."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@pytest.fixture
def sample_observable():
    """Create a sample Observable object for testing."""
    observable = MockObservable(type=F_TEST, value="test-value", volatile=True)
    
    # Set observable ID to a known value for testing
    observable.uuid = "test-observable-12345"
    
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
    from saq.constants import R_EXTRACTED_FROM, R_DOWNLOADED_FROM
    relationship1 = Relationship(R_DOWNLOADED_FROM, "related-observable-1")
    relationship2 = Relationship(R_EXTRACTED_FROM, "related-observable-2")
    observable._relationships = [relationship1, relationship2]
    
    # Set grouping target
    observable._grouping_target = True
    
    # Add LLM context documents
    observable.llm_context_documents = ["doc1", "doc2", "doc3"]
    
    # Add some tags via the tag manager
    observable.add_tag("test-tag1")
    observable.add_tag("test-tag2")
    
    # Add some detections via the detection manager
    observable.add_detection_point("test-detection")
    
    # Set sort order via the sort manager
    observable.sort_order = 75
    
    return observable


@pytest.fixture
def empty_observable():
    """Create an empty Observable object for testing."""
    return MockObservable()


@pytest.mark.unit
def test_observable_serializer_constants():
    """Test that all required constants are defined."""
    assert KEY_ID == 'uuid'
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
    
    # Check relationships (should be a list of relationship dicts)
    assert len(result[KEY_RELATIONSHIPS]) == 2
    # Verify relationships are dicts, not objects
    assert isinstance(result[KEY_RELATIONSHIPS][0], dict)
    assert isinstance(result[KEY_RELATIONSHIPS][1], dict)
    # Verify dict structure
    from saq.constants import R_EXTRACTED_FROM, R_DOWNLOADED_FROM
    assert result[KEY_RELATIONSHIPS][0]['target'] == "related-observable-1"
    assert result[KEY_RELATIONSHIPS][0]['type'] == R_DOWNLOADED_FROM
    assert result[KEY_RELATIONSHIPS][1]['target'] == "related-observable-2"
    assert result[KEY_RELATIONSHIPS][1]['type'] == R_EXTRACTED_FROM


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
    from saq.constants import R_EXTRACTED_FROM, R_DOWNLOADED_FROM
    test_relationship1 = Relationship(R_DOWNLOADED_FROM, "rel-obs-1")
    test_relationship2 = Relationship(R_EXTRACTED_FROM, "rel-obs-2")
    
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
    assert observable.sort_order == 150
    
    # Verify observable properties were set
    assert observable.uuid == "deserialized-id-67890"
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
    original_id = observable.uuid
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
    assert observable.uuid == "partial-id"
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
    original_id = observable.uuid
    original_type = observable.type
    original_value = observable._value
    
    data = {}
    
    ObservableSerializer.deserialize(observable, data)
    
    # Verify properties retain original values
    assert observable.uuid == original_id
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
    assert new_observable.uuid == sample_observable.uuid
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
    assert new_observable.sort_order == sample_observable.sort_order


@pytest.mark.unit
def test_serialize_preserves_original_observable():
    """Test that serialization doesn't modify the original observable."""
    observable = MockObservable(type=F_TEST, value="original-value")
    original_id = observable.uuid
    original_type = observable.type
    original_value = observable._value
    
    # Serialize
    result = ObservableSerializer.serialize(observable)
    
    # Verify original observable is unchanged
    assert observable.uuid == original_id
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


@pytest.mark.unit
def test_serialize_relationships_as_dicts():
    """Test that relationships are serialized as dicts, not Relationship objects."""
    import json
    from saq.analysis.root import RootAnalysis
    from saq.constants import R_EXTRACTED_FROM

    # Create RootAnalysis with initialized storage
    root = RootAnalysis()
    root.initialize_storage()

    # Add two observables
    o1 = root.add_observable_by_spec(F_TEST, "observable1")
    o2 = root.add_observable_by_spec(F_TEST, "observable2")

    # Add relationship from o1 to o2
    o1.add_relationship(R_EXTRACTED_FROM, o2)

    # Serialize o1
    result = ObservableSerializer.serialize(o1)

    # Assert relationships is a list
    assert isinstance(result[KEY_RELATIONSHIPS], list)
    assert len(result[KEY_RELATIONSHIPS]) == 1

    # Assert each item is a dict, not a Relationship object
    rel = result[KEY_RELATIONSHIPS][0]
    assert isinstance(rel, dict), f"Expected dict, got {type(rel)}"

    # Assert dict has correct keys
    assert "type" in rel
    assert "target" in rel

    # Assert target is a UUID string, not an Observable object
    assert isinstance(rel["target"], str), f"Expected string UUID, got {type(rel['target'])}"
    assert rel["target"] == o2.uuid


@pytest.mark.unit
def test_observable_json_is_json_serializable():
    """Test that Observable.json returns data that can be JSON encoded without custom encoder."""
    import json
    from saq.analysis.root import RootAnalysis
    from saq.constants import R_DOWNLOADED_FROM

    # Create RootAnalysis with initialized storage
    root = RootAnalysis()
    root.initialize_storage()

    # Add two observables with relationship
    o1 = root.add_observable_by_spec(F_TEST, "observable1")
    o2 = root.add_observable_by_spec(F_TEST, "observable2")
    o1.add_relationship(R_DOWNLOADED_FROM, o2)

    # Get o1's JSON
    o1_json = o1.json

    # Attempt standard JSON encoding (NO custom encoder)
    json_str = json.dumps(o1_json)

    # Parse back
    parsed = json.loads(json_str)

    # Verify relationships are dicts with correct keys
    assert "relationships" in parsed
    assert isinstance(parsed["relationships"], list)
    assert len(parsed["relationships"]) == 1
    assert isinstance(parsed["relationships"][0], dict)
    assert "type" in parsed["relationships"][0]
    assert "target" in parsed["relationships"][0]


@pytest.mark.unit
def test_relationship_dict_structure_after_serialization():
    """Test that relationship dict structure matches expected format with correct types."""
    from saq.analysis.root import RootAnalysis
    from saq.constants import R_DOWNLOADED_FROM, R_EXTRACTED_FROM, VALID_RELATIONSHIP_TYPES

    # Create RootAnalysis
    root = RootAnalysis()
    root.initialize_storage()

    # Add observables
    o1 = root.add_observable_by_spec(F_TEST, "observable1")
    o2 = root.add_observable_by_spec(F_TEST, "observable2")
    o3 = root.add_observable_by_spec(F_TEST, "observable3")

    # Add multiple relationships
    o1.add_relationship(R_DOWNLOADED_FROM, o2)
    o1.add_relationship(R_EXTRACTED_FROM, o3)

    # Serialize
    result = o1.json

    # Assert relationships is a list of 2 dicts
    assert isinstance(result["relationships"], list)
    assert len(result["relationships"]) == 2

    # Check each relationship dict
    for rel in result["relationships"]:
        # Assert it's a dict, not a Relationship object
        assert isinstance(rel, dict), f"Expected dict, got {type(rel)}"

        # Assert it has the correct keys
        assert "type" in rel
        assert "target" in rel

        # Assert type is a valid relationship type string
        assert rel["type"] in VALID_RELATIONSHIP_TYPES

        # Assert target is a string (UUID), not an Observable object
        assert isinstance(rel["target"], str), f"Expected string UUID, got {type(rel['target'])}"

        # Assert target matches one of the observable UUIDs
        assert rel["target"] in [o2.uuid, o3.uuid]


@pytest.mark.unit
def test_observable_serialization_round_trip_with_json_encoding():
    """Test full round-trip through actual JSON encoding/decoding."""
    import json
    from saq.analysis.root import RootAnalysis
    from saq.constants import R_EXTRACTED_FROM, R_DOWNLOADED_FROM

    # Create RootAnalysis with multiple observables and relationships
    root = RootAnalysis()
    root.initialize_storage()

    o1 = root.add_observable_by_spec(F_TEST, "observable1")
    o2 = root.add_observable_by_spec(F_TEST, "observable2")
    o3 = root.add_observable_by_spec(F_TEST, "observable3")

    o1.add_relationship(R_EXTRACTED_FROM, o2)
    o1.add_relationship(R_DOWNLOADED_FROM, o3)

    # Serialize observable
    serialized = o1.json

    # Encode to JSON string (NO custom encoder)
    json_str = json.dumps(serialized)

    # Decode back
    parsed = json.loads(json_str)

    # Verify relationships structure is preserved
    assert "relationships" in parsed
    assert len(parsed["relationships"]) == 2

    # Verify all relationship data is correct
    rel_types = {rel["type"] for rel in parsed["relationships"]}
    assert R_EXTRACTED_FROM in rel_types
    assert R_DOWNLOADED_FROM in rel_types

    # Verify targets are preserved as UUID strings
    rel_targets = {rel["target"] for rel in parsed["relationships"]}
    assert o2.uuid in rel_targets
    assert o3.uuid in rel_targets