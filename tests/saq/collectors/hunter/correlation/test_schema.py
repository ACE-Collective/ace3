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

    @pytest.mark.parametrize("expr_type", ["equals", "glob", "regex"])
    def test_comparison_requires_property(self, expr_type):
        with pytest.raises(ValidationError):
            ExpressionConfig(type=expr_type, value="test")

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


@pytest.mark.unit
class TestCommandConfig:

    def test_query_requires_source(self):
        with pytest.raises(ValidationError):
            CommandConfig(type="query", query="search index=main")

    def test_executable_requires_path(self):
        with pytest.raises(ValidationError):
            CommandConfig(type="executable")

    def test_defined_requires_name(self):
        with pytest.raises(ValidationError):
            CommandConfig(type="defined")

    def test_default_timeout_is_a_backstop(self):
        """The default has to clear real correlate query durations (p99 ~400s).

        A command error makes the event fall through to an alert, so a default that fires during
        normal operation manufactures false positives rather than protecting anything.
        """
        cmd = CommandConfig(type="query", source="splunk", query="search index=main")
        assert parse_timespec(cmd.timeout) >= timedelta(minutes=10)

    def test_executable_env_defaults_none(self):
        cmd = CommandConfig(type="executable", path="/usr/bin/test")
        assert cmd.env is None

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


@pytest.mark.unit
class TestActionConfig:

    @pytest.mark.parametrize("action_type", ["filter", "stop", "discard", "alert"])
    def test_valid_short_form(self, action_type):
        action = ActionConfig.model_validate(action_type)
        assert action.type == action_type

    def test_invalid_type(self):
        with pytest.raises(ValidationError):
            ActionConfig(type="bogus")


@pytest.mark.unit
class TestStepConfig:

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

    def test_env_carried_to_command_config(self):
        predef = PredefinedCommandConfig(
            name="lookup",
            type="executable",
            path="/usr/bin/lookup.sh",
            env={"KEY": "value"},
        )
        cmd = predef.to_command_config()
        assert cmd.env == {"KEY": "value"}


@pytest.mark.unit
class TestCustomCommandTypeSchema:

    def test_minimal_custom_command_accepted(self):
        cmd = CommandConfig.model_validate({
            "type": "wiz_lookup", "timeout": "2m", "cache": "1d",
            "options": {"ip": "{{ _event.ip }}", "nested": {"a": [1, 2]}},
        })
        assert cmd.type == "wiz_lookup"
        assert cmd.options == {"ip": "{{ _event.ip }}", "nested": {"a": [1, 2]}}

    def test_custom_command_without_options_accepted(self):
        assert CommandConfig.model_validate({"type": "wiz_lookup"}).options == {}

    # query has a test of its own below, which also checks the hint
    @pytest.mark.parametrize("builtin", [
        {"type": "executable", "path": "/bin/true"},
        {"type": "defined", "name": "c"},
    ])
    def test_options_rejected_on_builtin_types(self, builtin):
        with pytest.raises(ValidationError, match="only valid for custom command types"):
            CommandConfig.model_validate({**builtin, "options": {"x": 1}})

    def test_options_on_query_points_at_source_options(self):
        with pytest.raises(ValidationError, match="did you mean 'source_options'"):
            CommandConfig.model_validate({"type": "query", "source": "splunk", "query": "q", "options": {"x": 1}})

    @pytest.mark.parametrize("field,value", [
        ("source", "splunk"),
        ("query", "search"),
        ("time_range", {"before": "1h"}),
        ("source_options", {"log_names": ["x"]}),
        ("path", "/bin/true"),
        ("stdin", False),
        ("args", ["a"]),
        ("env", {"K": "v"}),
        ("files", ["f"]),
        ("name", "c"),
        ("arguments", {"x": 1}),
    ])
    def test_builtin_fields_rejected_on_custom_type(self, field, value):
        with pytest.raises(ValidationError, match=f"does not accept \\['{field}'\\]"):
            CommandConfig.model_validate({"type": "wiz_lookup", field: value})

    def test_builtin_fields_rejected_on_custom_predefined(self):
        """PredefinedCommandConfig runs the same placement check; the cases above cover each field."""
        with pytest.raises(ValidationError, match="does not accept \\['source'\\]"):
            PredefinedCommandConfig.model_validate({"name": "c", "type": "wiz_lookup", "source": "splunk"})

    def test_predefined_custom_command_round_trips(self):
        predef = PredefinedCommandConfig.model_validate({
            "name": "c", "type": "wiz_lookup", "cache": "1d", "options": {"ip": "1.2.3.4"},
        })
        cmd = predef.to_command_config({"options": {"ip": "5.6.7.8"}})
        assert cmd.type == "wiz_lookup"
        assert cmd.cache == "1d"
        assert cmd.options == {"ip": "5.6.7.8"}


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
    {"when": "{{ true }}", "action": "log"},
    {"when": "{{ true }}", "transform": {}, "action": "log"},
])
def test_step_config_rejects_multiple_step_keys(keys):
    """Silent-dispatch bug guard: a step with more than one of when/transform/action must fail loud."""
    with pytest.raises(ValidationError) as exc_info:
        StepConfig.model_validate(keys)
    msg = str(exc_info.value)
    assert "exactly one" in msg
