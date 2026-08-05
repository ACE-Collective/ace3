import pytest

from saq.collectors.hunter.correlation.expressions import (
    build_jinja_context,
    evaluate_expression,
)
from saq.collectors.hunter.correlation.schema import ExpressionConfig


@pytest.mark.unit
class TestBuildJinjaContext:

    def test_context_contains_event_and_events(self):
        event = {"field1": "value1", "field2": 42}
        events = [event]
        ctx = build_jinja_context(event, events)
        assert ctx["_event"] is event
        assert ctx["_events"] is events
        assert "field1" not in ctx
        assert "field2" not in ctx

    def test_context_without_secrets_and_config(self):
        ctx = build_jinja_context({}, [])
        assert "_secrets" not in ctx
        assert "_config" not in ctx

    def test_context_never_binds_secrets(self):
        """The credential store must not be reachable from a correlation template.

        A template is rendered into query text, command arguments and command environment
        variables that are handed to third parties, so a bound name is a value the hunt can
        transmit off-box.
        """
        assert "_secrets" not in build_jinja_context({}, [], {"global": {"key": "value"}})
        with pytest.raises(TypeError):
            build_jinja_context({}, [], secrets={"api_key": "secret123"})

    def test_context_with_config(self):
        config = {"global": {"key": "value"}}
        ctx = build_jinja_context({}, [], config=config)
        assert ctx["_config"] is config

    def test_context_keys_are_event_data_and_config_only(self):
        ctx = build_jinja_context({}, [], {"global": {"key": "value"}})
        assert set(ctx) == {"_event", "_events", "_config"}


@pytest.mark.unit
class TestEvaluateExpression:

    def test_jinja_truthy(self):
        expr = ExpressionConfig(type="jinja", value="{{ _event.field1 }}")
        assert evaluate_expression(expr, {"field1": "hello"}, []) is True

    def test_jinja_falsy(self):
        expr = ExpressionConfig(type="jinja", value="{{ _event.field1 }}")
        assert evaluate_expression(expr, {"field1": ""}, []) is False

    def test_jinja_missing_field(self):
        expr = ExpressionConfig(type="jinja", value="{{ _event.missing }}")
        assert evaluate_expression(expr, {}, []) is False

    def test_jinja_string_shorthand(self):
        expr = ExpressionConfig.model_validate("{{ _event.x }}")
        assert evaluate_expression(expr, {"x": "yes"}, []) is True

    @pytest.mark.parametrize("event_value,expr_value,expected", [
        ("admin", "admin", True),
        ("admin", "user", False),
        ("Admin", "admin", False),
    ])
    def test_equals(self, event_value, expr_value, expected):
        expr = ExpressionConfig(type="equals", value=expr_value, property="user")
        assert evaluate_expression(expr, {"user": event_value}, []) is expected

    def test_equals_case_insensitive(self):
        expr = ExpressionConfig(type="equals", value="ADMIN", property="user", case_sensitive=False)
        assert evaluate_expression(expr, {"user": "admin"}, []) is True

    def test_equals_missing_property(self):
        expr = ExpressionConfig(type="equals", value="x", property="missing")
        assert evaluate_expression(expr, {}, []) is False

    @pytest.mark.parametrize("event_value,pattern,expected", [
        ("admin_user", "admin*", True),
        ("admin_user", "user*", False),
        ("file.txt", "*.txt", True),
    ])
    def test_glob(self, event_value, pattern, expected):
        expr = ExpressionConfig(type="glob", value=pattern, property="name")
        assert evaluate_expression(expr, {"name": event_value}, []) is expected

    def test_glob_case_insensitive(self):
        expr = ExpressionConfig(type="glob", value="ADMIN*", property="name", case_sensitive=False)
        assert evaluate_expression(expr, {"name": "admin_user"}, []) is True

    @pytest.mark.parametrize("event_value,pattern,expected", [
        ("admin123", r"admin\d+", True),
        ("user123", r"admin\d+", False),
        ("test@example.com", r".*@example\.com", True),
    ])
    def test_regex(self, event_value, pattern, expected):
        expr = ExpressionConfig(type="regex", value=pattern, property="field")
        assert evaluate_expression(expr, {"field": event_value}, []) is expected

    def test_regex_case_insensitive(self):
        expr = ExpressionConfig(type="regex", value="ADMIN", property="field", case_sensitive=False)
        assert evaluate_expression(expr, {"field": "admin"}, []) is True

    def test_and_all_true(self):
        expr = ExpressionConfig(type="and", value=[
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "active", "property": "status"},
        ])
        assert evaluate_expression(expr, {"user": "admin", "status": "active"}, []) is True

    def test_and_one_false(self):
        expr = ExpressionConfig(type="and", value=[
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "inactive", "property": "status"},
        ])
        assert evaluate_expression(expr, {"user": "admin", "status": "active"}, []) is False

    def test_or_one_true(self):
        expr = ExpressionConfig(type="or", value=[
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "root", "property": "user"},
        ])
        assert evaluate_expression(expr, {"user": "root"}, []) is True

    def test_or_none_true(self):
        expr = ExpressionConfig(type="or", value=[
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "root", "property": "user"},
        ])
        assert evaluate_expression(expr, {"user": "guest"}, []) is False

    def test_not_inverts(self):
        expr = ExpressionConfig(type="not", value={"type": "equals", "value": "admin", "property": "user"})
        assert evaluate_expression(expr, {"user": "guest"}, []) is True
        assert evaluate_expression(expr, {"user": "admin"}, []) is False

    def test_nested_logic(self):
        expr = ExpressionConfig(type="and", value=[
            {"type": "not", "value": {"type": "equals", "value": "guest", "property": "user"}},
            {"type": "or", "value": [
                {"type": "equals", "value": "active", "property": "status"},
                {"type": "equals", "value": "pending", "property": "status"},
            ]},
        ])
        assert evaluate_expression(expr, {"user": "admin", "status": "active"}, []) is True
        assert evaluate_expression(expr, {"user": "guest", "status": "active"}, []) is False

    def test_jinja_cannot_access_secrets(self):
        expr = ExpressionConfig(type="jinja", value="{{ _secrets is undefined }}")
        assert evaluate_expression(expr, {}, []) is True

    def test_jinja_accesses_config(self):
        expr = ExpressionConfig(type="jinja", value="{{ _config.global.setting }}")
        assert evaluate_expression(expr, {}, [], config={"global": {"setting": "value"}}) is True

    def test_unknown_type_raises(self):
        expr = ExpressionConfig(type="jinja", value="x")
        expr.type = "bogus"
        with pytest.raises(ValueError, match="unknown expression type"):
            evaluate_expression(expr, {}, [])
