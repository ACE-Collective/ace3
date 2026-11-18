import pytest
from datetime import datetime, timezone

from saq.analysis.observable import Observable
from saq.analysis.relationship import Relationship
from saq.analysis.serialize.observable_serializer import ObservableSerializer
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

    observable._ignored = True
    observable._display_value = "shown value"
    observable._display_type = "shown type"
    observable._added_by = "analyst1"
    observable._added_time = datetime(2026, 6, 11, 9, 30, 0, tzinfo=timezone.utc)

    return observable


@pytest.mark.unit
def test_serialize_full_observable(sample_observable):
    """Serializing a fully populated Observable object. The keys are the ones
    stored in root.json, written out so a renamed key fails here."""
    result = ObservableSerializer.serialize(sample_observable)
    
    # Check that result is a dictionary
    assert isinstance(result, dict)
    
    # Check component manager data is included
    assert 'tags' in result
    assert 'detections' in result
    assert 'sort_order' in result
    assert result['sort_order'] == 75
    
    # Check observable-specific data
    assert result['uuid'] == "test-observable-12345"
    assert result['type'] == F_TEST
    assert result['value'] == "test-value"
    assert result['time'] == sample_observable._time
    assert result['analysis'] == {"module1": "analysis1", "module2": "analysis2"}
    assert result['directives'] == ["directive1", "directive2"]
    assert result['redirection'] == "redirect-target"
    assert result['links'] == ["link1", "link2", "link3"]
    assert result['limited_analysis'] == ["limited_module1", "limited_module2"]
    assert result['excluded_analysis'] == ["excluded_module1"]
    assert result['grouping_target'] is True
    assert result['volatile'] is True
    assert result['llm_context_documents'] == ["doc1", "doc2", "doc3"]
    assert result["ignored"] is True
    assert result["display_value"] == "shown value"
    assert result["display_type"] == "shown type"
    assert result['added_by'] == "analyst1"
    assert result['added_time'] == datetime(2026, 6, 11, 9, 30, 0, tzinfo=timezone.utc)

    # Check relationships (should be a list of relationship dicts)
    assert len(result['relationships']) == 2
    # Verify relationships are dicts, not objects
    assert isinstance(result['relationships'][0], dict)
    assert isinstance(result['relationships'][1], dict)
    # Verify dict structure
    from saq.constants import R_EXTRACTED_FROM, R_DOWNLOADED_FROM
    assert result['relationships'][0]['target'] == "related-observable-1"
    assert result['relationships'][0]['type'] == R_DOWNLOADED_FROM
    assert result['relationships'][1]['target'] == "related-observable-2"
    assert result['relationships'][1]['type'] == R_EXTRACTED_FROM


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
        'uuid': "deserialized-id-67890",
        'type': "deserialized-type",
        'value': "deserialized-value",
        'time': datetime(2023, 11, 15, 10, 20, 30, tzinfo=timezone.utc),
        'analysis': {"deser_module1": "deser_analysis1", "deser_module2": "deser_analysis2"},
        'directives': ["deser_directive1", "deser_directive2", "deser_directive3"],
        'redirection': "deser-redirect-target",
        'links': ["deser_link1", "deser_link2"],
        'limited_analysis': ["deser_limited1", "deser_limited2"],
        'excluded_analysis': ["deser_excluded1"],
        'relationships': [test_relationship1, test_relationship2],
        'grouping_target': True,
        'volatile': True,
        'llm_context_documents': ["deser_doc1", "deser_doc2"]
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
def test_deserialize_with_string_time():
    """Test deserializing with string time value."""
    observable = MockObservable()
    
    data = {
        'time': "2023-01-01 12:34:56 +0000"
    }

    ObservableSerializer.deserialize(observable, data)

    # the Observable.time setter parses string times to datetime objects
    assert observable.time == datetime(2023, 1, 1, 12, 34, 56, tzinfo=timezone.utc)


@pytest.mark.unit
def test_added_by_round_trip():
    """Test that added_by and added_time survive serialize -> deserialize."""
    observable = MockObservable(type=F_TEST, value="manually-added")
    observable.added_by = "analyst1"
    added_time = datetime(2026, 6, 11, 9, 30, 0, tzinfo=timezone.utc)
    observable.added_time = added_time

    serialized = ObservableSerializer.serialize(observable)
    assert serialized['added_by'] == "analyst1"
    assert serialized['added_time'] == added_time

    new_observable = MockObservable()
    ObservableSerializer.deserialize(new_observable, serialized)
    assert new_observable.added_by == "analyst1"
    assert new_observable.added_time == added_time


@pytest.mark.unit
def test_deserialize_added_time_from_string():
    """Test that added_time deserializes from a JSON string back to datetime."""
    observable = MockObservable()

    ObservableSerializer.deserialize(observable, {
        'added_by': "analyst1",
        'added_time': "2026-06-11 09:30:00 +0000",
    })

    assert observable.added_by == "analyst1"
    assert observable.added_time == datetime(2026, 6, 11, 9, 30, 0, tzinfo=timezone.utc)


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