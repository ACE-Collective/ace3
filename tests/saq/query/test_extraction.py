import logging

import pytest
from pydantic import ValidationError

from saq.constants import F_FILE, F_FILE_LOCATION, F_HOSTNAME, F_IP, F_USER, SUMMARY_DETAIL_FORMAT_JINJA
from saq.observables.mapping import (
    ObservableMapping,
    RelationshipMapping,
    RelationshipMappingTarget,
)
from saq.observables.type_hierarchy import get_type_hierarchy
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
    mapping = ObservableMapping(field="src_ip", type=F_IP)
    event = {"src_ip": "1.2.3.4"}
    result = interpret_event_value(mapping, event)
    assert result == ["1.2.3.4"]


@pytest.mark.unit
def test_interpret_event_value_with_interpolation():
    """Test value interpolation from event fields."""
    mapping = ObservableMapping(field="host", type=F_HOSTNAME, value="{{ host }}.{{ domain }}")
    event = {"host": "workstation", "domain": "example.com"}
    result = interpret_event_value(mapping, event)
    assert result == ["workstation.example.com"]


@pytest.mark.unit
def test_interpret_event_value_field_override():
    """Test field_override parameter."""
    mapping = ObservableMapping(fields=["primary", "secondary"], type=F_IP)
    event = {"primary": "1.1.1.1", "secondary": "2.2.2.2"}
    result = interpret_event_value(mapping, event, field_override="secondary")
    assert result == ["2.2.2.2"]


@pytest.mark.unit
def test_interpret_event_value_dot_lookup():
    """Dot-path lookup must walk nested dicts and list indices (glom)."""
    mapping = ObservableMapping(
        fields=["share_info.0.message_id"],
        field_lookup_type="dot",
        type=F_HOSTNAME,
    )
    event = {"share_info": [{"message_id": "abc123"}]}
    result = interpret_event_value(mapping, event, field_override="share_info.0.message_id")
    assert result == ["abc123"]


@pytest.mark.unit
def test_extract_observables_dot_lookup():
    """Observables declared with field_lookup_type=dot resolve through nested structures."""
    mappings = [
        ObservableMapping(
            fields=["share_info.0.sender"],
            field_lookup_type="dot",
            type=F_HOSTNAME,
        )
    ]
    event = {"share_info": [{"sender": "alice.example.com"}]}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.value == "alice.example.com"


@pytest.mark.unit
def test_interpret_event_value_wildcard_plucks_each_item():
    """A '*' wildcard segment plucks the sub-key from every item in a list field."""
    mapping = ObservableMapping(
        fields=["logs.*.cid"],
        field_lookup_type="dot",
        type=F_HOSTNAME,
    )
    event = {"logs": [{"cid": "a"}, {"cid": "b"}, {"cid": "c"}]}
    result = interpret_event_value(mapping, event, field_override="logs.*.cid")
    assert result == ["a", "b", "c"]


@pytest.mark.unit
def test_interpret_event_value_wildcard_with_limit():
    """limit caps how many observables a wildcard expansion emits."""
    mapping = ObservableMapping(
        fields=["logs.*.cid"],
        field_lookup_type="dot",
        type=F_HOSTNAME,
        limit=2,
    )
    event = {"logs": [{"cid": "a"}, {"cid": "b"}, {"cid": "c"}, {"cid": "d"}, {"cid": "e"}]}
    result = interpret_event_value(mapping, event, field_override="logs.*.cid")
    assert result == ["a", "b"]


@pytest.mark.unit
def test_interpret_event_value_wildcard_skips_items_missing_subkey():
    """Items missing the trailing sub-key are dropped, the rest are kept."""
    mapping = ObservableMapping(
        fields=["logs.*.cid"],
        field_lookup_type="dot",
        type=F_HOSTNAME,
    )
    event = {"logs": [{"cid": "a"}, {"other": "x"}, {"cid": "c"}]}
    result = interpret_event_value(mapping, event, field_override="logs.*.cid")
    assert result == ["a", "c"]


@pytest.mark.unit
def test_interpret_event_value_wildcard_empty_list():
    """A wildcard over an empty list yields no values (and does not raise)."""
    mapping = ObservableMapping(
        fields=["logs.*.cid"],
        field_lookup_type="dot",
        type=F_HOSTNAME,
    )
    event = {"logs": []}
    result = interpret_event_value(mapping, event, field_override="logs.*.cid")
    assert result == []


@pytest.mark.unit
def test_interpret_event_value_trailing_wildcard_returns_each_item():
    """A trailing '*' returns each list item as-is."""
    mapping = ObservableMapping(
        fields=["ips.*"],
        field_lookup_type="dot",
        type=F_IP,
    )
    event = {"ips": ["1.1.1.1", "2.2.2.2"]}
    result = interpret_event_value(mapping, event, field_override="ips.*")
    assert result == ["1.1.1.1", "2.2.2.2"]


@pytest.mark.unit
def test_extract_observables_wildcard_creates_one_per_item():
    """End-to-end: a wildcard mapping creates one observable per list item."""
    mappings = [
        ObservableMapping(
            fields=["logs.*.ip"],
            field_lookup_type="dot",
            type=F_IP,
            limit=2,
        )
    ]
    event = {"logs": [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}, {"ip": "3.3.3.3"}]}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert [e.observable.value for e in extracted] == ["1.1.1.1", "2.2.2.2"]


@pytest.mark.unit
def test_extract_observables_wildcard_missing_top_key_skipped():
    """A wildcard whose top-level list key is absent produces nothing (fields_mode=all)."""
    mappings = [
        ObservableMapping(
            fields=["logs.*.ip"],
            field_lookup_type="dot",
            type=F_IP,
        )
    ]
    event = {"unrelated": "value"}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert extracted == []


@pytest.mark.unit
def test_extract_observables_multivalue_user_field_strips_domain():
    """A multivalue (Splunk-style list) user field maps each element to a non-empty
    user observable, even when the domain separator is a double backslash.

    Regression for an analyst-reported hunt that produced empty `user` observables:
    the list is expanded element-by-element (so the whole list is never stringified)
    and UserObservable drops the domain to the bare account name rather than the
    empty segment between the two backslashes.
    """
    mappings = [ObservableMapping(fields=["process_username"], type=F_USER)]
    event = {"process_username": ["DOMAIN\\\\user", "DOMAIN\\\\user"]}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    values = [e.observable.value for e in extracted]
    assert "" not in values
    assert values == ["user", "user"]


@pytest.mark.unit
def test_interpret_event_value_limit_caps_list_valued_field():
    """limit also caps a plain list-valued field (not just wildcards)."""
    mapping = ObservableMapping(fields=["ips"], type=F_IP, limit=2)
    event = {"ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]}
    result = interpret_event_value(mapping, event)
    assert result == ["1.1.1.1", "2.2.2.2"]


@pytest.mark.unit
def test_extract_observables_basic():
    """Test basic observable extraction."""
    mappings = [
        ObservableMapping(field="src_ip", type=F_IP),
        ObservableMapping(field="hostname", type=F_HOSTNAME),
    ]
    event = {"src_ip": "10.0.0.1", "hostname": "web-server-01"}

    extracted, file_contents, relationships = extract_observables_from_event(event, mappings)

    assert len(extracted) == 2
    assert len(file_contents) == 0
    assert len(relationships) == 0

    types = {ext.observable.type for ext in extracted}
    assert F_IP in types
    assert F_HOSTNAME in types


@pytest.mark.unit
def test_extract_observables_missing_field():
    """Test extraction when a mapped field is missing."""
    mappings = [
        ObservableMapping(field="src_ip", type=F_IP),
        ObservableMapping(field="missing_field", type=F_HOSTNAME),
    ]
    event = {"src_ip": "10.0.0.1"}

    extracted, file_contents, relationships = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == F_IP


@pytest.mark.unit
def test_extract_observables_with_tags_and_directives():
    """Test that tags and directives are applied to extracted observables."""
    mappings = [
        ObservableMapping(
            field="src_ip", type=F_IP,
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
            field="src_ip", type=F_IP,
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
        ObservableMapping(field="src_ip", type=F_IP),
    ]

    patterns = [re.compile(r"0\.0\.0\.0")]

    event = {"src_ip": "0.0.0.0"}
    extracted, _, _ = extract_observables_from_event(event, mappings, global_ignored_patterns=patterns)
    assert len(extracted) == 0


@pytest.mark.unit
def test_extract_observables_with_value_filter():
    """Test value_filter callback."""
    mappings = [
        ObservableMapping(field="src_ip", type=F_IP),
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
            field="src_ip", type=F_IP,
            relationships=[
                RelationshipMapping(
                    type="connected_to",
                    target=RelationshipMappingTarget(type=F_HOSTNAME, value="{{ hostname }}"),
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
        ObservableMapping(field="src_ip", type=F_IP, volatile=True),
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
        ObservableMapping(field="src_ip", type=F_IP),
    ]
    event = {"src_ip": ""}

    extracted, _, _ = extract_observables_from_event(event, mappings)
    assert len(extracted) == 0


@pytest.mark.unit
def test_interpret_event_value_skips_unresolved_interpolation():
    """interpolated value templates with any missing field produce no values."""
    mapping = ObservableMapping(field="host", type=F_HOSTNAME, value="{{ host }}.{{ domain }}")
    # 'domain' is missing — strict-mode render raises UndefinedError, caught
    # and converted to []
    result = interpret_event_value(mapping, {"host": "workstation"})
    assert result == []


@pytest.mark.unit
def test_extract_observables_skips_unresolved_value():
    """observable mappings with unresolved value templates produce no observable."""
    mappings = [
        ObservableMapping(field="host", type=F_HOSTNAME, value="{{ host }}.{{ domain }}"),
    ]
    extracted, _, _ = extract_observables_from_event(
        {"host": "workstation"}, mappings,
    )
    assert len(extracted) == 0

    extracted, _, _ = extract_observables_from_event(
        {"host": "workstation", "domain": "example.com"}, mappings,
    )
    assert len(extracted) == 1
    assert extracted[0].observable.value == "workstation.example.com"


@pytest.mark.unit
def test_extract_observables_skips_blank_field_in_value_template():
    """A present-but-empty field in an ALL-mode value template skips the mapping (the
    coalesce-to-"" case that produced 'HOST@' file_location observables)."""
    mappings = [
        ObservableMapping(fields=["hostname", "file_path"], type=F_FILE_LOCATION,
                          value="{{ hostname }}@{{ file_path }}"),
    ]
    # file_path present but empty -> skipped
    extracted, _, _ = extract_observables_from_event(
        {"hostname": "PCN31337", "file_path": ""}, mappings)
    assert len(extracted) == 0

    # both present -> one valid observable
    extracted, _, _ = extract_observables_from_event(
        {"hostname": "PCN31337", "file_path": r"C:\users\lol.txt"}, mappings)
    assert len(extracted) == 1
    assert extracted[0].observable.value == r"PCN31337@C:\users\lol.txt"


@pytest.mark.unit
def test_extract_observables_skips_unresolved_tags_directives():
    """observable mapping tags/directives with any missing field are skipped entirely."""
    mappings = [
        ObservableMapping(
            field="src_ip", type=F_IP,
            tags=["mitre:{{ technique }}", "static_tag"],
            directives=["{{ missing_directive }}", "analyze_ip"],
        ),
    ]
    extracted, _, _ = extract_observables_from_event({"src_ip": "10.0.0.1"}, mappings)
    assert len(extracted) == 1
    obs = extracted[0].observable
    # The unresolved tag template is rejected entirely; only the static sibling remains.
    assert "static_tag" in obs.tags
    assert not any(t.startswith("mitre:") for t in obs.tags)
    # Same for directives: unresolved one is rejected, sibling kept.
    assert "analyze_ip" in obs.directives
    assert all(d == "analyze_ip" for d in obs.directives)


@pytest.mark.unit
def test_extract_observables_file_type_skips_unresolved_file_name():
    """F_FILE mappings with unresolved file_name templates produce no FileContent."""
    import base64
    content = b"data"
    encoded = base64.b64encode(content).decode()

    mappings = [
        ObservableMapping(
            field="file_data", type=F_FILE,
            file_name="{{ prefix }}-malware.exe",
            file_decoder=DecoderType.BASE64,
        ),
    ]
    # 'prefix' missing — no FileContent emitted
    _, file_contents, _ = extract_observables_from_event(
        {"file_data": encoded}, mappings,
    )
    assert len(file_contents) == 0

    # 'prefix' present — FileContent emitted with interpolated name
    _, file_contents, _ = extract_observables_from_event(
        {"file_data": encoded, "prefix": "sample"}, mappings,
    )
    assert len(file_contents) == 1
    assert file_contents[0].file_name == "sample-malware.exe"


@pytest.mark.unit
def test_extract_observables_file_type_skips_unresolved_tags_directives():
    """F_FILE per-file tags/directives with any missing field are rejected; siblings kept."""
    import base64
    content = b"data"
    encoded = base64.b64encode(content).decode()

    mappings = [
        ObservableMapping(
            field="file_data", type=F_FILE,
            file_name="dump.bin",
            file_decoder=DecoderType.BASE64,
            tags=["origin:{{ source }}", "static_tag"],
            directives=["{{ missing_directive }}", "analyze_file"],
        ),
    ]
    _, file_contents, _ = extract_observables_from_event(
        {"file_data": encoded}, mappings,
    )
    assert len(file_contents) == 1
    fc = file_contents[0]
    assert "static_tag" in fc.tags
    assert not any(t.startswith("origin:") for t in fc.tags)
    assert "analyze_file" in fc.directives
    assert all(d == "analyze_file" for d in fc.directives)


# --- Jinja-templated observable type tests ---


@pytest.fixture
def declare_yaml_types():
    """Temporarily add YAML-declared observable types to the global registry."""
    hierarchy = get_type_hierarchy()
    snapshot = set(hierarchy._yaml_declared_types)

    def _declare(*names: str):
        hierarchy._yaml_declared_types.update(names)

    yield _declare
    hierarchy._yaml_declared_types = snapshot


def _error_records(caplog):
    return [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.unit
def test_extract_observables_templated_type_resolves():
    """A Jinja-templated type renders against the event before observable creation."""
    mappings = [ObservableMapping(field="src", type="{{ obs_type }}")]
    event = {"src": "1.2.3.4", "obs_type": "ip"}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == F_IP
    assert extracted[0].observable.value == "1.2.3.4"


@pytest.mark.unit
def test_extract_observables_templated_type_lowercased():
    """The rendered type is lowercased before validation/creation."""
    mappings = [ObservableMapping(field="src", type="{{ obs_type }}")]
    event = {"src": "1.2.3.4", "obs_type": "IP"}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == F_IP


@pytest.mark.unit
def test_extract_observables_templated_type_dotted_event_key(declare_yaml_types):
    """The motivating shape: a platform-specific type from a flat dotted event key."""
    declare_yaml_types("azure_user_id")
    mappings = [
        ObservableMapping(
            fields=["event.subjectResource.providerUniqueId"],
            type="{{ event.cloudPlatform }}_user_id",
        )
    ]
    event = {
        "event.cloudPlatform": "Azure",
        "event.subjectResource.providerUniqueId": "f10fa516-dc68-4497-88c5-23e4904bcae3",
    }

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == "azure_user_id"
    assert extracted[0].observable.value == "f10fa516-dc68-4497-88c5-23e4904bcae3"


@pytest.mark.unit
def test_extract_observables_templated_type_unknown_skips_with_error(caplog):
    """An unknown resolved type with no fallback_type skips the observable and logs an error."""
    mappings = [ObservableMapping(field="src", type="{{ platform }}_user_id")]
    event = {"src": "some-id", "platform": "gcp"}

    with caplog.at_level(logging.ERROR):
        extracted, _, _ = extract_observables_from_event(event, mappings)

    assert extracted == []
    assert "{{ platform }}_user_id" in caplog.text
    assert "gcp_user_id" in caplog.text


@pytest.mark.unit
def test_extract_observables_templated_type_unknown_uses_fallback(caplog):
    """An unknown resolved type falls back to fallback_type and still logs an error."""
    mappings = [
        ObservableMapping(field="src", type="{{ platform }}_user_id", fallback_type=F_IP)
    ]
    event = {"src": "1.2.3.4", "platform": "gcp"}

    with caplog.at_level(logging.ERROR):
        extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == F_IP
    assert "gcp_user_id" in caplog.text
    assert "fallback_type" in caplog.text


@pytest.mark.unit
def test_extract_observables_templated_type_valid_ignores_fallback(caplog):
    """A valid resolved type is used directly; fallback_type stays unused and nothing is logged."""
    mappings = [ObservableMapping(field="src", type="{{ kind }}", fallback_type=F_HOSTNAME)]
    event = {"src": "1.2.3.4", "kind": "ip"}

    with caplog.at_level(logging.ERROR):
        extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == F_IP
    assert _error_records(caplog) == []


@pytest.mark.unit
def test_extract_observables_templated_type_unknown_fallback_skips(caplog):
    """A fallback_type that is itself unknown skips the observable and logs an error."""
    mappings = [
        ObservableMapping(
            field="src", type="{{ platform }}_user_id", fallback_type="zz_also_unknown"
        )
    ]
    event = {"src": "some-id", "platform": "gcp"}

    with caplog.at_level(logging.ERROR):
        extracted, _, _ = extract_observables_from_event(event, mappings)

    assert extracted == []
    assert "zz_also_unknown" in caplog.text


@pytest.mark.unit
def test_extract_observables_templated_type_missing_field_skips_silently(caplog):
    """A type template referencing a missing field skips silently — fallback does not apply."""
    event = {"src": "some-id"}  # no 'platform'

    for mapping in [
        ObservableMapping(field="src", type="{{ platform }}_user_id"),
        ObservableMapping(field="src", type="{{ platform }}_user_id", fallback_type=F_IP),
    ]:
        with caplog.at_level(logging.ERROR):
            extracted, _, _ = extract_observables_from_event(event, [mapping])
        assert extracted == []
        assert _error_records(caplog) == []


@pytest.mark.unit
def test_extract_observables_templated_type_empty_field(caplog):
    """A present-but-empty field resolves to an unknown type and takes the fallback path."""
    event = {"src": "1.2.3.4", "platform": ""}

    mappings = [ObservableMapping(field="src", type="{{ platform }}_user_id")]
    with caplog.at_level(logging.ERROR):
        extracted, _, _ = extract_observables_from_event(event, mappings)
    assert extracted == []
    assert "_user_id" in caplog.text

    mappings = [
        ObservableMapping(field="src", type="{{ platform }}_user_id", fallback_type=F_IP)
    ]
    with caplog.at_level(logging.ERROR):
        extracted, _, _ = extract_observables_from_event(event, mappings)
    assert len(extracted) == 1
    assert extracted[0].observable.type == F_IP


@pytest.mark.unit
def test_extract_observables_templated_type_resolving_to_file_rejected(caplog):
    """A templated type resolving to 'file' is unusable (no file_name handling)."""
    mappings = [ObservableMapping(field="src", type="{{ t }}")]
    event = {"src": "content", "t": "FILE"}

    with caplog.at_level(logging.ERROR):
        extracted, file_contents, _ = extract_observables_from_event(event, mappings)

    assert extracted == []
    assert file_contents == []
    assert len(_error_records(caplog)) == 1


@pytest.mark.unit
def test_extract_observables_templated_type_syntax_error_skips(caplog):
    """A malformed type template skips the mapping; the rendering layer logs the error."""
    mappings = [ObservableMapping(field="src", type="{{ unclosed")]
    event = {"src": "1.2.3.4", "unclosed": "ipv4"}

    with caplog.at_level(logging.ERROR):
        extracted, _, _ = extract_observables_from_event(event, mappings)

    assert extracted == []
    assert len(_error_records(caplog)) >= 1


@pytest.mark.unit
def test_extract_observables_static_unknown_type_unchanged():
    """Regression guard: a static unknown type still creates an observable (no validation)."""
    mappings = [ObservableMapping(field="src", type="zz_pytest_unknown_type")]
    event = {"src": "some-value"}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == "zz_pytest_unknown_type"
    assert extracted[0].observable.value == "some-value"


@pytest.mark.unit
def test_templated_type_parse_time_constraints():
    """Pydantic validators reject invalid templated-type / fallback_type combinations."""
    with pytest.raises(ValidationError):
        ObservableMapping(field="x", type="{{ t }}", file_name="dump.bin")
    with pytest.raises(ValidationError):
        ObservableMapping(field="x", type="{{ t }}", file_decoder=DecoderType.BASE64)
    with pytest.raises(ValidationError):
        ObservableMapping(field="x", type=F_IP, fallback_type=F_HOSTNAME)
    with pytest.raises(ValidationError):
        ObservableMapping(field="x", type="{{ t }}", fallback_type="{{ u }}")
    with pytest.raises(ValidationError):
        ObservableMapping(field="x", type="{{ t }}", fallback_type=F_FILE)


@pytest.mark.unit
def test_extract_observables_templated_type_with_value_template():
    """A templated type and a templated value resolve from the same event."""
    mappings = [
        ObservableMapping(
            fields=["host", "domain"], type="{{ kind }}", value="{{ host }}.{{ domain }}"
        )
    ]
    event = {"host": "workstation", "domain": "example.com", "kind": "HOSTNAME"}

    extracted, _, _ = extract_observables_from_event(event, mappings)

    assert len(extracted) == 1
    assert extracted[0].observable.type == F_HOSTNAME
    assert extracted[0].observable.value == "workstation.example.com"


@pytest.mark.unit
def test_process_summary_details_basic():
    """Test basic summary detail processing."""
    configs = [
        SummaryDetailConfig(content="IP: {{ src_ip }}"),
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
        SummaryDetailConfig(content="{{ value }}", header="Header: {{ label }}"),
    ]
    results = [{"value": "test", "label": "Test Label"}]

    details = []
    def add_detail(content, header, fmt):
        details.append({"content": content, "header": header, "format": fmt})

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0]["header"] == "Header: Test Label"


@pytest.mark.unit
def test_process_summary_details_unrenderable_header_keeps_content():
    """A header that cannot render must not cost content that rendered fine."""
    configs = [
        SummaryDetailConfig(content="{{ value }}", header="Seen by {{ missing }}"),
    ]
    results = [{"value": "test"}]

    details = []
    def add_detail(content, header, fmt):
        details.append({"content": content, "header": header})

    process_summary_details(configs, results, add_detail)

    assert len(details) == 1
    assert details[0]["content"] == "test"
    assert details[0]["header"] is None


@pytest.mark.unit
def test_process_summary_details_limit():
    """Test summary detail limit enforcement."""
    configs = [
        SummaryDetailConfig(content="{{ value }}", limit=2),
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
        SummaryDetailConfig(content="{{ missing_field }}"),
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
        SummaryDetailConfig(content="[Link]({{ url }})", header="Links", grouped=True),
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
        SummaryDetailConfig(content="{{ value }}", grouped=True, limit=2),
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
        SummaryDetailConfig(content="{{ missing }}", grouped=True),
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
        SummaryDetailConfig(content="[Link]({{ url }})", header="Links", grouped=True),
        SummaryDetailConfig(content="IP: {{ ip }}"),
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
def test_process_summary_details_grouped_jinja_missing_field_skipped():
    """Grouped Jinja with a missing field under strict mode skips the block, does not raise.

    Regression: previously the grouped-Jinja path did not catch UndefinedError, so a missing
    dict key (e.g. an event lacking a referenced field) raised out of process_summary_details
    and killed the whole hunt/alert instead of dropping just this summary detail.
    """
    configs = [
        SummaryDetailConfig(
            content="{% for e in events %}{{ e.always }}/{{ e.sometimes }} {% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
        ),
    ]
    # second event is missing 'sometimes' -> UndefinedError in strict mode
    results = [
        {"always": "a", "sometimes": "x"},
        {"always": "b"},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    # must not raise
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
        SummaryDetailConfig(content="{{ src_ip }}", dedup_fields=["src_ip"]),
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
def test_process_summary_details_dedup_grouped():
    """Test dedup with grouped mode."""
    configs = [
        SummaryDetailConfig(
            content="{{ host }}", grouped=True, dedup_fields=["host"],
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
    """Test required_fields with {{ field }} format allows partial resolution."""
    configs = [
        SummaryDetailConfig(
            content="IP: {{ src_ip }}, Host: {{ hostname }}",
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
def test_process_summary_details_required_fields_missing_skips():
    """Test that events missing required fields are skipped."""
    configs = [
        SummaryDetailConfig(
            content="{{ src_ip }}",
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
def test_process_summary_details_required_fields_empty_value_skips():
    """Test that a present-but-empty required field skips the event (empty list/str/dict)."""
    configs = [
        SummaryDetailConfig(
            content="{{ name }}",
            required_fields=["correlate"],
        ),
    ]
    results = [
        {"name": "empty-list", "correlate": []},       # present but empty -> skip
        {"name": "empty-str", "correlate": ""},        # present but empty -> skip
        {"name": "whitespace", "correlate": "   "},    # whitespace-only -> skip
        {"name": "empty-dict", "correlate": {}},       # present but empty -> skip
        {"name": "none", "correlate": None},           # None -> skip
        {"name": "has-data", "correlate": [{"x": 1}]}, # non-empty -> keep
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert details == ["has-data"]


@pytest.mark.unit
def test_process_summary_details_required_fields_zero_and_false_are_present():
    """Test that numeric 0 and boolean False count as present (real values, not empty)."""
    configs = [
        SummaryDetailConfig(
            content="{{ name }}",
            required_fields=["flag"],
        ),
    ]
    results = [
        {"name": "zero", "flag": 0},
        {"name": "false", "flag": False},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    assert details == ["zero", "false"]


@pytest.mark.unit
def test_process_summary_details_grouped_jinja_required_fields_all_empty_suppresses_pane():
    """Test grouped + Jinja: when every event's required field is empty, no pane is emitted."""
    configs = [
        SummaryDetailConfig(
            content="{% for event in events %}{{ event.host }}\n{% endfor %}",
            format=SUMMARY_DETAIL_FORMAT_JINJA,
            grouped=True,
            required_fields=["correlate"],
        ),
    ]
    results = [
        {"host": "server1", "correlate": []},
        {"host": "server2", "correlate": []},
    ]

    details = []
    def add_detail(content, header, fmt):
        details.append(content)

    process_summary_details(configs, results, add_detail)

    # all events filtered out -> grouped Jinja returns early, no detail added
    assert details == []


@pytest.mark.unit
def test_process_summary_details_default_behavior_unchanged():
    """Test that default behavior (no required_fields) is unchanged — unresolved skips."""
    configs = [
        SummaryDetailConfig(content="{{ src_ip }}, {{ hostname }}"),
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
        SummaryDetailConfig(content="{{ host }}", grouped=True),
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
