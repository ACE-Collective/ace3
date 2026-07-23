from datetime import timedelta

import pytest
from pydantic import ValidationError

from saq.collectors.hunter.correlation.timespec import parse_timespec
from saq.collectors.hunter.correlation.schema import (
    ActionConfig,
    CommandConfig,
    ConditionConfig,
    CorrelateConfig,
    ExpressionConfig,
    MergeTimeSpecConfig,
    PredefinedCommandConfig,
    StepConfig,
    TimeRangeConfig,
    TransformConfig,
)


@pytest.mark.unit
class TestExpressionConfig:

    def test_string_shorthand(self):
        expr = ExpressionConfig.model_validate("{{ field1 }}")
        assert expr.type == "jinja"
        assert expr.value == "{{ field1 }}"

    def test_explicit_jinja(self):
        expr = ExpressionConfig(type="jinja", value="{{ x }}")
        assert expr.type == "jinja"

    @pytest.mark.parametrize("expr_type", ["equals", "glob", "regex"])
    def test_comparison_requires_property(self, expr_type):
        with pytest.raises(ValidationError):
            ExpressionConfig(type=expr_type, value="test")

    @pytest.mark.parametrize("expr_type", ["equals", "glob", "regex"])
    def test_comparison_with_property(self, expr_type):
        expr = ExpressionConfig(type=expr_type, value="test", property="field1")
        assert expr.property == "field1"

    def test_not_rejects_list(self):
        with pytest.raises(ValidationError):
            ExpressionConfig(type="not", value=["a", "b"])

    @pytest.mark.parametrize("expr_type", ["and", "or"])
    def test_logical_requires_list(self, expr_type):
        with pytest.raises(ValidationError):
            ExpressionConfig(type=expr_type, value="single")

    def test_and_with_list(self):
        expr = ExpressionConfig(type="and", value=["{{ a }}", "{{ b }}"])
        assert len(expr.value) == 2

    def test_case_sensitive_default(self):
        expr = ExpressionConfig(type="equals", value="x", property="f")
        assert expr.case_sensitive is True


@pytest.mark.unit
class TestCommandConfig:

    def test_query_requires_source(self):
        with pytest.raises(ValidationError):
            CommandConfig(type="query", query="search index=main")

    def test_query_valid(self):
        cmd = CommandConfig(type="query", source="splunk", query="search index=main")
        assert cmd.source == "splunk"

    def test_executable_requires_path(self):
        with pytest.raises(ValidationError):
            CommandConfig(type="executable")

    def test_executable_valid(self):
        cmd = CommandConfig(type="executable", path="/usr/bin/script.py")
        assert cmd.path == "/usr/bin/script.py"

    def test_defined_requires_name(self):
        with pytest.raises(ValidationError):
            CommandConfig(type="defined")

    def test_defined_valid(self):
        cmd = CommandConfig(type="defined", name="my_command")
        assert cmd.name == "my_command"

    def test_default_timeout_is_a_backstop(self):
        """The default has to clear real correlate query durations (p99 ~400s).

        A command error makes the event fall through to an alert, so a default that fires during
        normal operation manufactures false positives rather than protecting anything.
        """
        cmd = CommandConfig(type="query", source="splunk", query="search index=main")
        assert parse_timespec(cmd.timeout) >= timedelta(minutes=10)

    def test_explicit_timeout_wins(self):
        cmd = CommandConfig(type="query", source="splunk", query="search index=main", timeout="45s")
        assert parse_timespec(cmd.timeout) == timedelta(seconds=45)

    def test_executable_with_env(self):
        cmd = CommandConfig(type="executable", path="/usr/bin/test", env={"KEY": "value"})
        assert cmd.env == {"KEY": "value"}

    def test_executable_env_defaults_none(self):
        cmd = CommandConfig(type="executable", path="/usr/bin/test")
        assert cmd.env is None

    def test_source_options_defaults_to_empty_dict(self):
        cmd = CommandConfig(type="query", source="splunk", query="search index=main")
        assert cmd.source_options == {}

    def test_source_options_accepts_dict(self):
        cmd = CommandConfig(
            type="query",
            source="rapid7",
            query="where(...)",
            source_options={"log_names": ["Firewall Activity"], "ingestion_lag_buffer": "1h"},
        )
        assert cmd.source_options == {"log_names": ["Firewall Activity"], "ingestion_lag_buffer": "1h"}

    def test_predefined_command_source_options_round_trip(self):
        predef = PredefinedCommandConfig(
            name="rapid7_default",
            type="query",
            source="rapid7",
            query="where(...)",
            source_options={"log_names": ["Authentication"]},
        )
        cmd = predef.to_command_config()
        assert cmd.source_options == {"log_names": ["Authentication"]}

    def test_predefined_command_source_options_overridable(self):
        predef = PredefinedCommandConfig(
            name="rapid7_default",
            type="query",
            source="rapid7",
            query="where(...)",
            source_options={"log_names": ["Authentication"]},
        )
        cmd = predef.to_command_config({"source_options": {"log_names": ["Firewall Activity"]}})
        assert cmd.source_options == {"log_names": ["Firewall Activity"]}


@pytest.mark.unit
class TestTransformConfig:

    def test_property_method_requires_event_type(self):
        with pytest.raises(ValidationError):
            TransformConfig(
                type="stream",
                method="property",
                property_name="x",
                command=CommandConfig(type="defined", name="test"),
            )

    def test_merge_requires_stream_type(self):
        with pytest.raises(ValidationError):
            TransformConfig(
                type="event",
                method="merge",
                merge_time_spec=MergeTimeSpecConfig(l_field="t1", l_format="epoch", r_field="t2", r_format="epoch"),
                command=CommandConfig(type="defined", name="test"),
            )

    def test_property_requires_name(self):
        with pytest.raises(ValidationError):
            TransformConfig(
                type="event",
                method="property",
                command=CommandConfig(type="defined", name="test"),
            )

    def test_merge_requires_time_spec(self):
        with pytest.raises(ValidationError):
            TransformConfig(
                type="stream",
                method="merge",
                command=CommandConfig(type="defined", name="test"),
            )

    def test_valid_property_transform(self):
        t = TransformConfig(
            type="event",
            method="property",
            property_name="result",
            command=CommandConfig(type="defined", name="test"),
        )
        assert t.property_name == "result"

    def test_valid_mutate_transform(self):
        t = TransformConfig(
            type="stream",
            method="mutate",
            command=CommandConfig(type="defined", name="test"),
        )
        assert t.method == "mutate"


@pytest.mark.unit
class TestActionConfig:

    @pytest.mark.parametrize("action_type", ["filter", "stop", "discard", "alert"])
    def test_valid_short_form(self, action_type):
        action = ActionConfig.model_validate(action_type)
        assert action.type == action_type

    def test_string_shorthand(self):
        action = ActionConfig.model_validate("filter")
        assert action.type == "filter"

    def test_log_without_message_valid(self):
        action = ActionConfig(type="log")
        assert action.log_message is None

    def test_log_valid(self):
        action = ActionConfig(type="log", log_message="hello {{ name }}")
        assert action.log_message == "hello {{ name }}"

    def test_log_fields_on_non_log_action(self):
        action = ActionConfig(type="filter", log_level="WARNING", log_message="filtering event")
        assert action.log_level == "WARNING"
        assert action.log_message == "filtering event"

    def test_invalid_type(self):
        with pytest.raises(ValidationError):
            ActionConfig(type="bogus")

    def test_alert_with_overrides(self):
        action = ActionConfig(type="alert", queue="my_queue", analysis_mode="analysis")
        assert action.queue == "my_queue"
        assert action.analysis_mode == "analysis"


@pytest.mark.unit
class TestStepConfig:

    def test_dispatch_condition(self):
        step = StepConfig.model_validate({
            "when": "{{ x }}",
            "execute": [{"action": "filter"}],
        })
        assert isinstance(step.step, ConditionConfig)

    def test_dispatch_transform(self):
        step = StepConfig.model_validate({
            "transform": {
                "type": "event",
                "method": "property",
                "property_name": "result",
                "command": {"type": "defined", "name": "test"},
            },
        })
        assert isinstance(step.step, TransformConfig)

    def test_dispatch_action(self):
        step = StepConfig.model_validate({"action": "filter"})
        assert isinstance(step.step, ActionConfig)

    def test_missing_key_raises(self):
        with pytest.raises(ValidationError):
            StepConfig.model_validate({"bogus": "value"})

    def test_description_and_debug(self):
        step = StepConfig.model_validate({
            "action": "filter",
            "description": "test desc",
            "debug": "{{ x }}",
        })
        assert step.description == "test desc"
        assert step.debug == "{{ x }}"

    def test_condition_with_else(self):
        step = StepConfig.model_validate({
            "when": "{{ x }}",
            "execute": [{"action": "filter"}],
            "else": [{"action": "alert"}],
        })
        assert isinstance(step.step, ConditionConfig)
        assert step.step.else_ is not None
        assert len(step.step.else_) == 1


@pytest.mark.unit
class TestCorrelateConfig:

    def test_valid_minimal(self):
        config = CorrelateConfig(logic=[
            StepConfig.model_validate({"action": "alert"}),
        ])
        assert config.timeout == "15m"

    def test_custom_timeout(self):
        config = CorrelateConfig(timeout="1h", logic=[
            StepConfig.model_validate({"action": "alert"}),
        ])
        assert config.timeout == "1h"

    def test_invalid_timeout(self):
        with pytest.raises(ValidationError):
            CorrelateConfig(timeout="invalid", logic=[
                StepConfig.model_validate({"action": "alert"}),
            ])

    def test_full_correlate_yaml(self):
        """Test parsing a complete correlate block from dict (simulating YAML)."""
        data = {
            "timeout": "5m",
            "logic": [
                {
                    "when": {"type": "equals", "value": "admin", "property": "username"},
                    "execute": [{"action": "alert"}],
                    "else": [{"action": "filter"}],
                },
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "enrichment",
                        "property_type": "dict",
                        "command": {
                            "type": "executable",
                            "path": "/usr/bin/lookup.sh",
                            "args": ["{{ userId }}"],
                        },
                    },
                },
                {"action": "alert"},
            ],
        }
        config = CorrelateConfig.model_validate(data)
        assert config.timeout == "5m"
        assert len(config.logic) == 3


@pytest.mark.unit
class TestPredefinedCommandConfig:

    def test_default_timeout_matches_command_config(self):
        """PredefinedCommandConfig declares its own copy of the timeout default; if the two drift,
        whether a command is inlined or predefined silently changes its timeout."""
        predef = PredefinedCommandConfig(name="lookup", type="query", source="splunk", query="x")
        inline = CommandConfig(type="query", source="splunk", query="x")
        assert parse_timespec(predef.timeout) == parse_timespec(inline.timeout)

    def test_to_command_config(self):
        predef = PredefinedCommandConfig(
            name="lookup",
            type="executable",
            path="/usr/bin/lookup.sh",
            args=[],
        )
        cmd = predef.to_command_config(overrides={"args": ["arg1"]})
        assert cmd.type == "executable"
        assert cmd.args == ["arg1"]

    def test_to_command_config_no_overrides(self):
        predef = PredefinedCommandConfig(
            name="lookup",
            type="executable",
            path="/usr/bin/lookup.sh",
        )
        cmd = predef.to_command_config()
        assert cmd.path == "/usr/bin/lookup.sh"

    def test_env_field(self):
        predef = PredefinedCommandConfig(
            name="lookup",
            type="executable",
            path="/usr/bin/lookup.sh",
            env={"API_KEY": "{{ _secrets.key }}"},
        )
        assert predef.env == {"API_KEY": "{{ _secrets.key }}"}

    def test_env_carried_to_command_config(self):
        predef = PredefinedCommandConfig(
            name="lookup",
            type="executable",
            path="/usr/bin/lookup.sh",
            env={"KEY": "value"},
        )
        cmd = predef.to_command_config()
        assert cmd.env == {"KEY": "value"}


# Minimal payloads that satisfy each config's required fields. Used to prove
# that a typo next to known-good fields raises a ValidationError naming the
# extra field, not a "missing field" error.
_STRICT_PAYLOADS: list[tuple[type, dict]] = [
    (ExpressionConfig, {"type": "jinja", "value": "{{ x }}"}),
    (TimeRangeConfig, {"before": "1h"}),
    (CommandConfig, {"type": "query", "source": "splunk", "query": "search"}),
    (MergeTimeSpecConfig, {"l_field": "a", "l_format": "x", "r_field": "b", "r_format": "y"}),
    (TransformConfig, {
        "type": "event", "method": "property", "property_name": "p",
        "command": {"type": "query", "source": "splunk", "query": "q"},
    }),
    (ActionConfig, {"type": "filter"}),
    (ConditionConfig, {"when": "{{ true }}", "execute": []}),
    (PredefinedCommandConfig, {"name": "c", "type": "executable", "path": "/bin/true"}),
    (CorrelateConfig, {"logic": []}),
]


@pytest.mark.unit
@pytest.mark.parametrize("cls,payload", _STRICT_PAYLOADS, ids=lambda x: getattr(x, "__name__", str(x)))
def test_extra_field_rejected(cls, payload):
    """Every correlation config must reject unknown fields with a clear error."""
    bad = {**payload, "not_a_real_field": "oops"}
    with pytest.raises(ValidationError) as exc_info:
        cls.model_validate(bad)
    assert "not_a_real_field" in str(exc_info.value)


@pytest.mark.unit
def test_step_config_rejects_extra_at_step_level():
    with pytest.raises(ValidationError) as exc_info:
        StepConfig.model_validate({
            "when": "{{ true }}",
            "execute": [],
            "typo_field": "x",
        })
    assert "typo_field" in str(exc_info.value)


@pytest.mark.unit
def test_step_config_rejects_extra_next_to_transform():
    with pytest.raises(ValidationError) as exc_info:
        StepConfig.model_validate({
            "transform": {
                "type": "event", "method": "property", "property_name": "p",
                "command": {"type": "query", "source": "splunk", "query": "q"},
            },
            "typo_field": "x",
        })
    assert "typo_field" in str(exc_info.value)


@pytest.mark.unit
@pytest.mark.parametrize("keys", [
    {"when": "{{ true }}", "transform": {}},
    {"when": "{{ true }}", "action": "log"},
    {"transform": {}, "action": "log"},
    {"when": "{{ true }}", "transform": {}, "action": "log"},
])
def test_step_config_rejects_multiple_step_keys(keys):
    """Silent-dispatch bug guard: a step with more than one of when/transform/action must fail loud."""
    with pytest.raises(ValidationError) as exc_info:
        StepConfig.model_validate(keys)
    msg = str(exc_info.value)
    assert "exactly one" in msg
