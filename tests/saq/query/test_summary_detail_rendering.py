import logging

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
def test_sandboxed_environment_prevents_dangerous_ops():
    """A hunt author's template cannot reach Python internals: the sandbox renders an unsafe
    attribute as nothing, where plain Jinja would render "<class 'str'>"."""
    assert render_jinja_template("{{ ''.__class__ }}", {}) == ""


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
def test_render_jinja_template_render_error_is_a_warning(caplog):
    """An exception raised while rendering returns None and is the template author's to fix."""
    with caplog.at_level(logging.WARNING):
        assert render_jinja_template("{{ 1 / 0 }}", {}) is None

    records = [r for r in caplog.records if "unexpected error rendering jinja template" in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
