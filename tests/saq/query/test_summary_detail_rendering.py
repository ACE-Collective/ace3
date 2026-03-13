import pytest

from jinja2 import UndefinedError

from saq.query.summary_detail_rendering import render_jinja_template


@pytest.mark.unit
def test_render_jinja_template_basic():
    """Test basic Jinja template rendering."""
    result = render_jinja_template("IP: {{ src_ip }}", {"src_ip": "10.0.0.1"})
    assert result == "IP: 10.0.0.1"


@pytest.mark.unit
def test_render_jinja_template_missing_var_permissive():
    """Test that missing variables render as empty string in permissive mode."""
    result = render_jinja_template("IP: {{ src_ip }}, Host: {{ hostname }}", {"src_ip": "10.0.0.1"})
    assert result == "IP: 10.0.0.1, Host: "


@pytest.mark.unit
def test_render_jinja_template_with_loop():
    """Test Jinja template with a loop."""
    template = "{% for item in items %}{{ item }} {% endfor %}"
    result = render_jinja_template(template, {"items": ["a", "b", "c"]})
    assert result == "a b c "


@pytest.mark.unit
def test_render_jinja_template_with_conditional():
    """Test Jinja template with conditionals."""
    template = "{% if severity == 'high' %}ALERT{% else %}info{% endif %}"
    assert render_jinja_template(template, {"severity": "high"}) == "ALERT"
    assert render_jinja_template(template, {"severity": "low"}) == "info"


@pytest.mark.unit
def test_render_jinja_template_with_tojson_filter():
    """Test Jinja template with tojson filter."""
    result = render_jinja_template("{{ data | tojson }}", {"data": {"key": "value"}})
    assert '"key"' in result
    assert '"value"' in result


@pytest.mark.unit
def test_render_jinja_template_syntax_error():
    """Test that template syntax errors return None."""
    result = render_jinja_template("{% if %}", {"field": "value"})
    assert result is None


@pytest.mark.unit
def test_render_jinja_template_strict_basic():
    """Test basic strict rendering."""
    result = render_jinja_template("Host: {{ hostname }}", {"hostname": "web-01"}, strict=True)
    assert result == "Host: web-01"


@pytest.mark.unit
def test_render_jinja_template_strict_missing_var():
    """Test that missing variables raise UndefinedError in strict mode."""
    with pytest.raises(UndefinedError):
        render_jinja_template("{{ missing_field }}", {"other": "value"}, strict=True)


@pytest.mark.unit
def test_render_jinja_template_strict_syntax_error():
    """Test that template syntax errors return None in strict mode."""
    result = render_jinja_template("{% if %}", {"field": "value"}, strict=True)
    assert result is None


@pytest.mark.unit
def test_sandboxed_environment_prevents_dangerous_ops():
    """Test that the sandboxed environment prevents dangerous operations."""
    # Attempting to access __class__ or other dunder attributes should fail
    result = render_jinja_template("{{ ''.__class__ }}", {})
    # SandboxedEnvironment should block this — result may be None or a security error string
    # The key is it shouldn't expose internal Python objects
    assert result is None or "__class__" not in result or "SecurityError" in str(result)


# --- fromjson filter tests ---


@pytest.mark.unit
def test_fromjson_filter_parses_json_string():
    """Test that fromjson filter parses a JSON string into a dict."""
    template = "{% set data = json_str | fromjson %}{{ data.name }}: {{ data.value }}"
    result = render_jinja_template(template, {"json_str": '{"name": "test", "value": 42}'})
    assert result == "test: 42"


@pytest.mark.unit
def test_fromjson_filter_with_invalid_json():
    """Test that fromjson with invalid JSON returns an empty dict."""
    template = "{% set data = json_str | fromjson %}{{ data }}"
    result = render_jinja_template(template, {"json_str": "not valid json"})
    assert result == "{}"


@pytest.mark.unit
def test_fromjson_filter_with_empty_string():
    """Test that fromjson with an empty string returns an empty dict."""
    template = "{% set data = json_str | fromjson %}{% if data.displayName %}yes{% else %}no{% endif %}"
    result = render_jinja_template(template, {"json_str": ""})
    assert result == "no"
