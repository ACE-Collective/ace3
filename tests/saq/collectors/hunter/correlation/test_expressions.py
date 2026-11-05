
import pytest

from saq.collectors.hunter.correlation.expressions import (
    build_jinja_context,
    evaluate_expression,
)
from saq.collectors.hunter.correlation.schema import ExpressionConfig


@pytest.mark.unit
class TestBuildJinjaContext:

    def test_context_is_event_data_only(self):
        """A hunt template sees the event and the stream, and has no path to configuration or credentials."""
        event = {"field1": "value1", "field2": 42}
        events = [event]
        ctx = build_jinja_context(event, events)
        assert ctx["_event"] is event
        assert ctx["_events"] is events
        assert set(ctx) == {"_event", "_events"}


@pytest.mark.unit
class TestEvaluateExpression:

    @pytest.mark.parametrize("event_value,expr_value,expected", [
        ("admin", "admin", True),
        ("admin", "user", False),
        ("Admin", "admin", False),
    ])
    def test_equals(self, event_value, expr_value, expected):
        expr = ExpressionConfig(type="equals", value=expr_value, property="user")
        assert evaluate_expression(expr, {"user": event_value}, []) is expected

    def test_equals_case_insensitive(self):
        # mixed case on both sides, so both the property and the value must be lowered
        expr = ExpressionConfig(type="equals", value="ADMIN", property="user", case_sensitive=False)
        assert evaluate_expression(expr, {"user": "Admin"}, []) is True

    def test_equals_missing_property(self):
        # "None" is what a missing value would become if it were stringified rather than skipped
        expr = ExpressionConfig(type="equals", value="None", property="missing")
        assert evaluate_expression(expr, {}, []) is False

    @pytest.mark.parametrize("event_value,pattern,expected", [
        ("admin_user", "admin*", True),
        ("admin_user", "user*", False),
    ])
    def test_glob(self, event_value, pattern, expected):
        expr = ExpressionConfig(type="glob", value=pattern, property="name")
        assert evaluate_expression(expr, {"name": event_value}, []) is expected

    def test_glob_case_insensitive(self):
        expr = ExpressionConfig(type="glob", value="ADMIN*", property="name", case_sensitive=False)
        assert evaluate_expression(expr, {"name": "Admin_User"}, []) is True

    @pytest.mark.parametrize("event_value,pattern,expected", [
        ("admin123", r"admin\d+", True),
        ("user123", r"admin\d+", False),
        # a match anywhere in the value, not only at its start
        ("login by admin123", r"admin\d+", True),
    ])
    def test_regex(self, event_value, pattern, expected):
        expr = ExpressionConfig(type="regex", value=pattern, property="field")
        assert evaluate_expression(expr, {"field": event_value}, []) is expected

    def test_regex_case_insensitive(self):
        expr = ExpressionConfig(type="regex", value="ADMIN", property="field", case_sensitive=False)
        assert evaluate_expression(expr, {"field": "admin"}, []) is True
