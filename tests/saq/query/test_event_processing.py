import pytest

from saq.query.event_processing import (
    FIELD_LOOKUP_TYPE_DOT,
    FIELD_LOOKUP_TYPE_KEY,
    parse_field_reference,
    strip_unresolved_placeholders,
)


@pytest.mark.unit
def test_parse_field_reference_plain_name():
    """Test parsing a plain field name."""
    lookup_type, field_path = parse_field_reference("hostname")
    assert lookup_type == FIELD_LOOKUP_TYPE_KEY
    assert field_path == "hostname"


@pytest.mark.unit
def test_parse_field_reference_key_syntax():
    """Test parsing $key{name} syntax."""
    lookup_type, field_path = parse_field_reference("$key{hostname}")
    assert lookup_type == FIELD_LOOKUP_TYPE_KEY
    assert field_path == "hostname"


@pytest.mark.unit
def test_parse_field_reference_dot_syntax():
    """Test parsing $dot{path} syntax."""
    lookup_type, field_path = parse_field_reference("$dot{device.hostname}")
    assert lookup_type == FIELD_LOOKUP_TYPE_DOT
    assert field_path == "device.hostname"


@pytest.mark.unit
def test_parse_field_reference_default_key_syntax():
    """Test parsing ${name} syntax (no explicit type defaults to key)."""
    lookup_type, field_path = parse_field_reference("${hostname}")
    assert lookup_type == FIELD_LOOKUP_TYPE_KEY
    assert field_path == "hostname"


@pytest.mark.unit
def test_parse_field_reference_with_escaped_braces():
    """Test parsing with escaped braces in the field path."""
    lookup_type, field_path = parse_field_reference("$key{field\\{with\\}braces}")
    assert lookup_type == FIELD_LOOKUP_TYPE_KEY
    assert field_path == "field{with}braces"


@pytest.mark.unit
def test_strip_unresolved_placeholders_basic():
    """Test stripping unresolved placeholders."""
    result = strip_unresolved_placeholders("IP: ${src_ip} Host: ${hostname}")
    assert result == "IP:  Host: "


@pytest.mark.unit
def test_strip_unresolved_placeholders_no_placeholders():
    """Test that strings without placeholders are unchanged."""
    result = strip_unresolved_placeholders("Hello World")
    assert result == "Hello World"


@pytest.mark.unit
def test_strip_unresolved_placeholders_mixed():
    """Test stripping only unresolved placeholders from a partially resolved string."""
    # After interpolation, resolved values are already substituted.
    # This tests the raw pattern removal.
    result = strip_unresolved_placeholders("Resolved: 10.0.0.1, Missing: ${missing}")
    assert result == "Resolved: 10.0.0.1, Missing: "


@pytest.mark.unit
def test_strip_unresolved_placeholders_dot_syntax():
    """Test stripping $dot{} placeholders."""
    result = strip_unresolved_placeholders("Value: $dot{some.path}")
    assert result == "Value: "
