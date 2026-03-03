import pytest

from saq.constants import F_FILE, F_HOSTNAME, F_IPV4
from saq.observables.mapping import (
    ObservableMapping,
    RelationshipMapping,
    RelationshipMappingTarget,
)
from saq.query.config import SummaryDetailConfig
from saq.query.decoder import DecoderType
from saq.query.extraction import (
    extract_observables_from_event,
    interpret_event_value,
    process_summary_details,
)


@pytest.mark.unit
def test_interpret_event_value_simple():
    """Test simple field extraction without interpolation."""
    mapping = ObservableMapping(field="src_ip", type=F_IPV4)
    event = {"src_ip": "1.2.3.4"}
    result = interpret_event_value(mapping, event)
    assert result == ["1.2.3.4"]


@pytest.mark.unit
def test_interpret_event_value_with_interpolation():
    """Test value interpolation from event fields."""
    mapping = ObservableMapping(field="host", type=F_HOSTNAME, value="${host}.${domain}")
    event = {"host": "workstation", "domain": "example.com"}
    result = interpret_event_value(mapping, event)
    assert result == ["workstation.example.com"]


@pytest.mark.unit
def test_interpret_event_value_field_override():
    """Test field_override parameter."""
    mapping = ObservableMapping(fields=["primary", "secondary"], type=F_IPV4)
    event = {"primary": "1.1.1.1", "secondary": "2.2.2.2"}
    result = interpret_event_value(mapping, event, field_override="secondary")
    assert result == ["2.2.2.2"]


@pytest.mark.unit
def test_extract_observables_basic():
    """Test basic observable extraction."""
    mappings = [
        ObservableMapping(field="src_ip", type=F_IPV4),
        ObservableMapping(field="hostname", type=F_HOSTNAME),
    ]
    event = {"src_ip": "10.0.0.1", "hostname": "web-server-01"}

    extracted, file_contents, relationships = extract_observables_from_event(event, mappings)

    assert len(extracted) == 2
    assert len(file_contents) == 0
    assert len(relationships) == 0

    types = {ext.observable.type for ext in extracted}
    assert F_IPV4 in types
    assert F_HOSTNAME in types


@pytest.mark.unit
def test_extract_observables_missing_field():
    """Test extraction when a mapped field is missing."""
    mappings = [
        ObservableMapping(field="src_ip", type=F_IPV4),
        ObservableMapping(field="missing_field", type=F_HOSTNAME),
    ]
    event = {"src_ip": "10.0.0.1"}

    extracted, file_contents, relationships = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == F_IPV4


@pytest.mark.unit
def test_extract_observables_with_tags_and_directives():
    """Test that tags and directives are applied to extracted observables."""
    mappings = [
        ObservableMapping(
            field="src_ip", type=F_IPV4,
            tags=["external", "suspicious"],
            directives=["analyze_ip"],
        ),
    ]
    event = {"src_ip": "10.0.0.1"}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    obs = extracted[0].observable
    assert "external" in obs.tags
    assert "suspicious" in obs.tags
    assert "analyze_ip" in obs.directives


@pytest.mark.unit
def test_extract_observables_with_ignored_values():
    """Test per-mapping ignored values."""
    mappings = [
        ObservableMapping(
            field="src_ip", type=F_IPV4,
            ignored_values=[r"0\.0\.0\.0"],
        ),
    ]

    event = {"src_ip": "0.0.0.0"}
    extracted, _, _ = extract_observables_from_event(event, mappings)
    assert len(extracted) == 0

    event = {"src_ip": "10.0.0.1"}
    extracted, _, _ = extract_observables_from_event(event, mappings)
    assert len(extracted) == 1


@pytest.mark.unit
def test_extract_observables_with_global_ignored_values():
    """Test global ignored value patterns."""
    import re
    mappings = [
        ObservableMapping(field="src_ip", type=F_IPV4),
    ]

    patterns = [re.compile(r"0\.0\.0\.0")]

    event = {"src_ip": "0.0.0.0"}
    extracted, _, _ = extract_observables_from_event(event, mappings, global_ignored_patterns=patterns)
    assert len(extracted) == 0


@pytest.mark.unit
def test_extract_observables_with_value_filter():
    """Test value_filter callback."""
    mappings = [
        ObservableMapping(field="src_ip", type=F_IPV4),
    ]
    event = {"src_ip": "  10.0.0.1  "}

    def strip_filter(field, obs_type, value):
        return value.strip()

    extracted, _, _ = extract_observables_from_event(
        event, mappings, value_filter=strip_filter
    )
    assert len(extracted) == 1
    assert extracted[0].observable.value == "10.0.0.1"


@pytest.mark.unit
def test_extract_observables_with_relationships():
    """Test relationship tracking."""
    mappings = [
        ObservableMapping(
            field="src_ip", type=F_IPV4,
            relationships=[
                RelationshipMapping(
                    type="connected_to",
                    target=RelationshipMappingTarget(type=F_HOSTNAME, value="${hostname}"),
                ),
            ],
        ),
    ]
    event = {"src_ip": "10.0.0.1", "hostname": "web-server"}

    extracted, _, relationships = extract_observables_from_event(event, mappings)
    assert len(extracted) == 1
    assert len(relationships) == 1
    obs = extracted[0].observable
    assert obs in relationships
    assert relationships[obs][0].type == "connected_to"


@pytest.mark.unit
def test_extract_observables_volatile():
    """Test volatile flag on observables."""
    mappings = [
        ObservableMapping(field="src_ip", type=F_IPV4, volatile=True),
    ]
    event = {"src_ip": "10.0.0.1"}

    extracted, _, _ = extract_observables_from_event(event, mappings)
    assert len(extracted) == 1
    assert extracted[0].observable.volatile is True


@pytest.mark.unit
def test_extract_observables_file_type():
    """Test file type observable extraction."""
    import base64
    content = b"malware content"
    encoded = base64.b64encode(content).decode()

    mappings = [
        ObservableMapping(
            field="file_data", type=F_FILE,
            file_name="malware.exe",
            file_decoder=DecoderType.BASE64,
        ),
    ]
    event = {"file_data": encoded}

    extracted, file_contents, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 0  # file observables go to file_contents, not extracted
    assert len(file_contents) == 1
    assert file_contents[0].file_name == "malware.exe"
    assert file_contents[0].content == content


@pytest.mark.unit
def test_extract_observables_empty_value_skipped():
    """Test that empty values are skipped."""
    mappings = [
        ObservableMapping(field="src_ip", type=F_IPV4),
    ]
    event = {"src_ip": ""}

    extracted, _, _ = extract_observables_from_event(event, mappings)
    assert len(extracted) == 0


@pytest.mark.unit
def test_process_summary_details_basic():
    """Test basic summary detail processing."""
    configs = [
        SummaryDetailConfig(content="IP: ${src_ip}"),
    ]
    results = [
        {"src_ip": "10.0.0.1"},
        {"src_ip": "10.0.0.2"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append({"content": content, "header": header, "format": fmt})

    process_summary_details(configs, results, add_detail)

    assert len(details) == 2
    assert details[0]["content"] == "IP: 10.0.0.1"
    assert details[1]["content"] == "IP: 10.0.0.2"


@pytest.mark.unit
def test_process_summary_details_with_header():
    """Test summary details with header."""
    configs = [
        SummaryDetailConfig(content="${value}", header="Header: ${label}"),
    ]
    results = [{"value": "test", "label": "Test Label"}]

    details = []
    def add_detail(content, header, fmt):
        details.append({"content": content, "header": header, "format": fmt})

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0]["header"] == "Header: Test Label"


@pytest.mark.unit
def test_process_summary_details_limit():
    """Test summary detail limit enforcement."""
    configs = [
        SummaryDetailConfig(content="${value}", limit=2),
    ]
    results = [{"value": f"item-{i}"} for i in range(5)]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 2


@pytest.mark.unit
def test_process_summary_details_unresolved_placeholders_skipped():
    """Test that events with unresolved placeholders are skipped."""
    configs = [
        SummaryDetailConfig(content="${missing_field}"),
    ]
    results = [{"other_field": "value"}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 0
