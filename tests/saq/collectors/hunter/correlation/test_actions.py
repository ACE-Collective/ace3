import logging

import pytest

from saq.collectors.hunter.correlation.actions import ActionResult, execute_action
from saq.collectors.hunter.correlation.schema import ActionConfig


@pytest.mark.unit
class TestActionResult:

    @pytest.mark.parametrize("action_type,expected", [
        ("filter", True),
        ("stop", True),
        ("discard", True),
        ("alert", True),
        ("log", False),
    ])
    def test_is_interrupt(self, action_type, expected):
        result = ActionResult(action_type=action_type)
        assert result.is_interrupt is expected

    @pytest.mark.parametrize("action_type,expected", [
        ("stop", True),
        ("discard", True),
        ("filter", False),
        ("alert", False),
        ("log", False),
    ])
    def test_is_stream_interrupt(self, action_type, expected):
        result = ActionResult(action_type=action_type)
        assert result.is_stream_interrupt is expected


@pytest.mark.unit
class TestExecuteAction:

    def test_filter(self):
        action = ActionConfig(type="filter")
        result = execute_action(action, {}, [])
        assert result.action_type == "filter"

    def test_stop(self):
        action = ActionConfig(type="stop")
        result = execute_action(action, {}, [])
        assert result.action_type == "stop"

    def test_discard(self):
        action = ActionConfig(type="discard")
        result = execute_action(action, {}, [])
        assert result.action_type == "discard"

    def test_alert_with_overrides(self):
        action = ActionConfig(type="alert", queue="my_queue", analysis_mode="deep")
        result = execute_action(action, {}, [])
        assert result.action_type == "alert"
        assert result.queue_override == "my_queue"
        assert result.analysis_mode_override == "deep"

    def test_alert_no_overrides(self):
        action = ActionConfig(type="alert")
        result = execute_action(action, {}, [])
        assert result.queue_override is None
        assert result.analysis_mode_override is None

    def test_log(self, caplog):
        action = ActionConfig(type="log", log_message="user={{ _event.user }}", log_level="WARNING")
        event = {"user": "admin"}
        with caplog.at_level(logging.WARNING):
            result = execute_action(action, event, [event])
        assert result.action_type == "log"
        assert "user=admin" in caplog.text

    def test_log_default_level(self, caplog):
        action = ActionConfig(type="log", log_message="test message")
        with caplog.at_level(logging.INFO):
            result = execute_action(action, {}, [])
        assert result.action_type == "log"
        assert "test message" in caplog.text


@pytest.mark.unit
class TestUniversalActionLogging:

    @pytest.mark.parametrize("action_type", ["filter", "stop", "discard", "alert", "log"])
    def test_default_log_message(self, action_type, caplog):
        """All action types log a default message when log_message is not set."""
        action = ActionConfig(type=action_type)
        with caplog.at_level(logging.INFO):
            execute_action(action, {}, [])
        assert f"executed {action_type} action" in caplog.text

    def test_custom_log_message_on_non_log_action(self, caplog):
        """Non-log action types support custom log_message."""
        action = ActionConfig(type="filter", log_message="filtering event {{ _event.id }}")
        event = {"id": 42}
        with caplog.at_level(logging.INFO):
            execute_action(action, event, [event])
        assert "filtering event 42" in caplog.text

    def test_custom_log_level_on_non_log_action(self, caplog):
        """Non-log action types support custom log_level."""
        action = ActionConfig(type="stop", log_level="WARNING", log_message="stopping")
        with caplog.at_level(logging.WARNING):
            result = execute_action(action, {}, [])
        assert result.action_type == "stop"
        assert "stopping" in caplog.text

    def test_log_message_render_error(self, caplog):
        """A render error in log_message should not prevent the action from returning."""
        action = ActionConfig(type="filter", log_message="{{ invalid | bad_filter }}")
        with caplog.at_level(logging.WARNING):
            result = execute_action(action, {}, [])
        assert result.action_type == "filter"
        records = [r for r in caplog.records if "failed to render log message template" in r.getMessage()]
        assert len(records) == 1
        # a broken template is the hunt author's to fix, not an ACE error to report
        assert records[0].levelno == logging.WARNING
