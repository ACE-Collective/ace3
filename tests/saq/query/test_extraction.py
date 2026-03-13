import pytest

from saq.constants import F_FILE, F_HOSTNAME, F_IPV4, SUMMARY_DETAIL_FORMAT_JINJA
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


@pytest.mark.unit
def test_process_summary_details_grouped_basic():
    """Test grouped summary details combine multiple events into one detail."""
    configs = [
        SummaryDetailConfig(content="[Link](${url})", header="Links", grouped=True),
    ]
    results = [
        {"url": "https://example.com/1"},
        {"url": "https://example.com/2"},
        {"url": "https://example.com/3"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append({"content": content, "header": header, "format": fmt})

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0]["header"] == "Links"
    lines = details[0]["content"].split("\n")
    assert len(lines) == 3
    assert lines[0] == "[Link](https://example.com/1)"
    assert lines[2] == "[Link](https://example.com/3)"


@pytest.mark.unit
def test_process_summary_details_grouped_limit(caplog):
    """Test grouped summary details respect limit and log a warning."""
    configs = [
        SummaryDetailConfig(content="${value}", grouped=True, limit=2),
    ]
    results = [{"value": f"item-{i}"} for i in range(5)]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    import logging
    with caplog.at_level(logging.WARNING):
        process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    lines = details[0].split("\n")
    assert len(lines) == 2
    assert lines == ["item-0", "item-1"]
    assert "summary detail limit (2) reached" in caplog.text


@pytest.mark.unit
def test_process_summary_details_grouped_no_matching_events():
    """Test grouped summary details produce no detail when all events fail interpolation."""
    configs = [
        SummaryDetailConfig(content="${missing}", grouped=True),
    ]
    results = [{"other": "value"}, {"other": "value2"}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 0


@pytest.mark.unit
def test_process_summary_details_mixed_grouped_and_ungrouped():
    """Test both grouped and ungrouped configs in a single call."""
    configs = [
        SummaryDetailConfig(content="[Link](${url})", header="Links", grouped=True),
        SummaryDetailConfig(content="IP: ${ip}"),
    ]
    results = [
        {"url": "https://example.com/1", "ip": "10.0.0.1"},
        {"url": "https://example.com/2", "ip": "10.0.0.2"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append({"content": content, "header": header})

    process_summary_details(configs, results, add_detail)

    # 1 grouped detail + 2 ungrouped details = 3 total
    assert len(details) == 3
    # first detail is the grouped one
    assert details[0]["header"] == "Links"
    assert "\n" in details[0]["content"]
    # next two are ungrouped
    assert details[1]["content"] == "IP: 10.0.0.1"
    assert details[2]["content"] == "IP: 10.0.0.2"


# --- Jinja format tests ---


@pytest.mark.unit
def test_process_summary_details_jinja_basic():
    """Test basic Jinja template rendering."""
    configs = [
        SummaryDetailConfig(content="IP: {{ src_ip }}", format=SUMMARY_DETAIL_FORMAT_JINJA),
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
    assert details[0]["format"] == SUMMARY_DETAIL_FORMAT_JINJA
    assert details[1]["content"] == "IP: 10.0.0.2"


@pytest.mark.unit
def test_process_summary_details_jinja_loop_conditional():
    """Test Jinja format with loop and conditional."""
    configs = [
        SummaryDetailConfig(
            content="{% for ip in ips %}{% if ip != '0.0.0.0' %}{{ ip }} {% endif %}{% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
        ),
    ]
    results = [{"ips": ["10.0.0.1", "0.0.0.0", "10.0.0.2"]}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0] == "10.0.0.1 10.0.0.2 "


@pytest.mark.unit
def test_process_summary_details_jinja_missing_field_strict_skipped():
    """Test Jinja format with missing field in strict mode — event is skipped."""
    configs = [
        SummaryDetailConfig(content="{{ missing_field }}", format=SUMMARY_DETAIL_FORMAT_JINJA),
    ]
    results = [{"other": "value"}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 0


@pytest.mark.unit
def test_process_summary_details_jinja_with_required_fields_permissive():
    """Test Jinja format with required_fields set — permissive mode renders missing as empty."""
    configs = [
        SummaryDetailConfig(
            content="IP: {{ src_ip }}, Host: {{ hostname }}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            required_fields=["src_ip"],
        ),
    ]
    results = [{"src_ip": "10.0.0.1"}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0] == "IP: 10.0.0.1, Host: "


@pytest.mark.unit
def test_process_summary_details_jinja_required_fields_missing():
    """Test Jinja format with required_fields — event skipped when required field missing."""
    configs = [
        SummaryDetailConfig(
            content="IP: {{ src_ip }}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            required_fields=["src_ip"],
        ),
    ]
    results = [{"other": "value"}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 0


# --- Dedup fields tests ---


@pytest.mark.unit
def test_process_summary_details_dedup_basic():
    """Test basic deduplication of events."""
    configs = [
        SummaryDetailConfig(content="${src_ip}", dedup_fields=["src_ip"]),
    ]
    results = [
        {"src_ip": "10.0.0.1"},
        {"src_ip": "10.0.0.1"},
        {"src_ip": "10.0.0.2"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 2
    assert details[0] == "10.0.0.1"
    assert details[1] == "10.0.0.2"


@pytest.mark.unit
def test_process_summary_details_dedup_dot_syntax():
    """Test dedup with $dot{} syntax."""
    configs = [
        SummaryDetailConfig(content="$dot{host.name}", dedup_fields=["$dot{host.name}"]),
    ]
    results = [
        {"host": {"name": "server1"}},
        {"host": {"name": "server1"}},
        {"host": {"name": "server2"}},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 2
    assert details[0] == "server1"
    assert details[1] == "server2"


@pytest.mark.unit
def test_process_summary_details_dedup_grouped():
    """Test dedup with grouped mode."""
    configs = [
        SummaryDetailConfig(
            content="${host}", grouped=True, dedup_fields=["host"],
        ),
    ]
    results = [
        {"host": "server1"},
        {"host": "server1"},
        {"host": "server2"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    lines = details[0].split("\n")
    assert lines == ["server1", "server2"]


# --- Required fields tests (non-jinja) ---


@pytest.mark.unit
def test_process_summary_details_required_fields_partial_resolution():
    """Test required_fields with ${field} format allows partial resolution."""
    configs = [
        SummaryDetailConfig(
            content="IP: ${src_ip}, Host: ${hostname}",
            required_fields=["src_ip"],
        ),
    ]
    results = [{"src_ip": "10.0.0.1"}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0] == "IP: 10.0.0.1, Host: "


@pytest.mark.unit
def test_process_summary_details_required_fields_dot_syntax():
    """Test required_fields with $dot{} syntax."""
    configs = [
        SummaryDetailConfig(
            content="$dot{device.ip}",
            required_fields=["$dot{device.ip}"],
        ),
    ]
    results = [
        {"device": {"ip": "10.0.0.1"}},
        {"other": "value"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0] == "10.0.0.1"


@pytest.mark.unit
def test_process_summary_details_required_fields_missing_skips():
    """Test that events missing required fields are skipped."""
    configs = [
        SummaryDetailConfig(
            content="${src_ip}",
            required_fields=["src_ip", "hostname"],
        ),
    ]
    results = [
        {"src_ip": "10.0.0.1"},  # missing hostname
        {"src_ip": "10.0.0.2", "hostname": "web-01"},  # has both
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0] == "10.0.0.2"


@pytest.mark.unit
def test_process_summary_details_default_behavior_unchanged():
    """Test that default behavior (no required_fields) is unchanged — unresolved skips."""
    configs = [
        SummaryDetailConfig(content="${src_ip}, ${hostname}"),
    ]
    results = [
        {"src_ip": "10.0.0.1"},  # missing hostname
        {"src_ip": "10.0.0.2", "hostname": "web-01"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0] == "10.0.0.2, web-01"


# --- Grouped + Jinja tests ---


@pytest.mark.unit
def test_process_summary_details_grouped_jinja_renders_once_with_events():
    """Test grouped + Jinja renders template once with events list context."""
    configs = [
        SummaryDetailConfig(
            content="{% for event in events %}{{ event.host }}\n{% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
            required_fields=["host"],
        ),
    ]
    results = [
        {"host": "server1"},
        {"host": "server2"},
        {"host": "server3"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append({"content": content, "header": header, "format": fmt})

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0]["format"] == SUMMARY_DETAIL_FORMAT_JINJA
    assert "server1" in details[0]["content"]
    assert "server2" in details[0]["content"]
    assert "server3" in details[0]["content"]


@pytest.mark.unit
def test_process_summary_details_grouped_jinja_dedup():
    """Test grouped + Jinja with dedup_fields filters events before rendering."""
    configs = [
        SummaryDetailConfig(
            content="{% for event in events %}{{ event.host }}\n{% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
            dedup_fields=["host"],
            required_fields=["host"],
        ),
    ]
    results = [
        {"host": "server1"},
        {"host": "server1"},
        {"host": "server2"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    # server1 should appear only once due to dedup
    assert details[0].count("server1") == 1
    assert "server2" in details[0]


@pytest.mark.unit
def test_process_summary_details_grouped_jinja_required_fields():
    """Test grouped + Jinja with required_fields filters events before rendering."""
    configs = [
        SummaryDetailConfig(
            content="{% for event in events %}{{ event.host }}\n{% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
            required_fields=["host"],
        ),
    ]
    results = [
        {"host": "server1"},
        {"other": "value"},
        {"host": "server3"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert "server1" in details[0]
    assert "server3" in details[0]
    # event without "host" should not appear
    assert "value" not in details[0]


@pytest.mark.unit
def test_process_summary_details_grouped_jinja_limit(caplog):
    """Test grouped + Jinja with limit caps the events list."""
    configs = [
        SummaryDetailConfig(
            content="{% for event in events %}{{ event.val }}\n{% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
            limit=2,
            required_fields=["val"],
        ),
    ]
    results = [{"val": f"item-{i}"} for i in range(5)]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    import logging
    with caplog.at_level(logging.WARNING):
        process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert "item-0" in details[0]
    assert "item-1" in details[0]
    assert "item-2" not in details[0]
    assert "summary detail limit (2) reached" in caplog.text


@pytest.mark.unit
def test_process_summary_details_grouped_jinja_empty_result():
    """Test grouped + Jinja with empty/whitespace result produces no detail."""
    configs = [
        SummaryDetailConfig(
            content="{% for event in events %}{% if event.missing %}{{ event.missing }}{% endif %}{% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
            required_fields=["host"],
        ),
    ]
    results = [{"host": "server1"}, {"host": "server2"}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 0


@pytest.mark.unit
def test_process_summary_details_grouped_non_jinja_unchanged():
    """Test grouped + non-Jinja behavior is unchanged (per-event render + join)."""
    configs = [
        SummaryDetailConfig(content="${host}", grouped=True),
    ]
    results = [
        {"host": "server1"},
        {"host": "server2"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0] == "server1\nserver2"


@pytest.mark.unit
def test_process_summary_details_grouped_jinja_no_qualifying_events():
    """Test grouped + Jinja with no qualifying events produces no detail."""
    configs = [
        SummaryDetailConfig(
            content="{% for event in events %}{{ event.host }}{% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
            required_fields=["host"],
        ),
    ]
    results = [{"other": "value1"}, {"other": "value2"}]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert len(details) == 0


@pytest.mark.unit
def test_process_summary_details_grouped_jinja_with_header():
    """Test grouped + Jinja renders header from first qualifying event."""
    configs = [
        SummaryDetailConfig(
            content="{% for event in events %}{{ event.host }}\n{% endfor %}",
            header="Hosts for {{ group }}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
            required_fields=["host"],
        ),
    ]
    results = [
        {"host": "server1", "group": "web"},
        {"host": "server2", "group": "web"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append({"content": content, "header": header})

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0]["header"] == "Hosts for web"
