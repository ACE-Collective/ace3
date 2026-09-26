import datetime
import json
import logging
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError

from saq.collectors.hunter.correlation.command_types import (
    CommandContext,
    CorrelationCommand,
    clear_command_types,
    get_command_type,
    get_command_type_load_errors,
    get_registered_command_types,
    load_command_types_from_config,
    register_command_type,
    reset_command_types_loaded_flag,
)
from saq.collectors.hunter.correlation.commands import execute_command
from saq.collectors.hunter.correlation.engine import CorrelationEngine
from saq.collectors.hunter.correlation.schema import CommandConfig, CorrelateConfig, PredefinedCommandConfig
from saq.configuration import get_config
from saq.configuration.schema import CommandTypeConfig, CorrelationConfig, HunterConfig
from saq.util import local_time

THIS_MODULE = "tests.saq.collectors.hunter.correlation.test_command_types"


class _EchoOptions(BaseModel):
    model_config = {"extra": "forbid"}

    message: str
    count: int = 1


class _EchoCommand(CorrelationCommand):
    """Records every call and returns one JSONL row per `count`."""

    config_class = _EchoOptions

    def __init__(self, prefix: str = ""):
        self.prefix = prefix
        self.calls: list[tuple[CommandContext, _EchoOptions]] = []

    def execute(self, context, options):
        self.calls.append((context, options))
        return "\n".join(json.dumps({"message": self.prefix + options.message}) for _ in range(options.count))


class _NarrowKeyCommand(_EchoCommand):
    def cache_key(self, context, options):
        return {"message": options.message}


class _NoOptionsCommand(CorrelationCommand):
    def execute(self, context, options):
        return json.dumps({"event_id": context.event.get("id")})


class _UncacheableCommand(_EchoCommand):
    cacheable = False


class _LiteralCommand(_EchoCommand):
    render_options = False


class _BadReturnCommand(CorrelationCommand):
    def execute(self, context, options):
        return [{"not": "a string"}]


class _BoomCommand(CorrelationCommand):
    def __init__(self):
        raise RuntimeError("constructor boom")

    def execute(self, context, options):
        return ""


@pytest.fixture(autouse=True)
def _clean_command_types():
    clear_command_types()
    reset_command_types_loaded_flag()
    yield
    clear_command_types()
    reset_command_types_loaded_flag()


@pytest.fixture
def no_cache():
    with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None) as get_cached, \
         patch("saq.collectors.hunter.correlation.commands.set_cached_result") as set_cached:
        yield get_cached, set_cached


def _run(command: CommandConfig, tmpdir, event=None, events=None, transform_type="event", secrets=None, predefined=None):
    event = event if event is not None else {}
    events = events if events is not None else [event]
    return execute_command(
        command, event, events, transform_type, predefined or [], local_time(), str(tmpdir),
        secrets=secrets, config={"vendor": {"region": "us"}},
    )


@pytest.mark.unit
class TestRegistry:

    def test_register_and_get(self):
        handler = _EchoCommand()
        register_command_type("echo", handler)
        assert get_command_type("echo") is handler
        assert get_registered_command_types() == {"echo": handler}

    @pytest.mark.parametrize("name", ["query", "executable", "defined"])
    def test_builtin_names_are_reserved(self, name):
        with pytest.raises(ValueError, match="built-in"):
            register_command_type(name, _EchoCommand())

    @pytest.mark.parametrize("name", ["Echo", "1echo", "echo-lookup", "echo lookup", ""])
    def test_invalid_names_rejected(self, name):
        with pytest.raises(ValueError, match="invalid correlation command type name"):
            register_command_type(name, _EchoCommand())

    def test_handler_must_be_a_correlation_command(self):
        with pytest.raises(TypeError):
            register_command_type("echo", object())

    def test_overwrite_warns(self, caplog):
        register_command_type("echo", _EchoCommand())
        replacement = _EchoCommand()
        with caplog.at_level(logging.WARNING):
            register_command_type("echo", replacement)
        assert get_command_type("echo") is replacement
        assert "overwriting existing correlation command type registration: echo" in caplog.text

    def test_clear(self):
        register_command_type("echo", _EchoCommand())
        clear_command_types()
        assert get_registered_command_types() == {}

    def test_unknown_type(self):
        with pytest.raises(ValueError, match="unknown command type: 'nope'"):
            get_command_type("nope")


def _set_command_types(monkeypatch, command_types: list[CommandTypeConfig]):
    monkeypatch.setattr(
        get_config(),
        "hunter",
        HunterConfig(correlation=CorrelationConfig(command_types=command_types)),
    )


@pytest.mark.unit
class TestLoadCommandTypesFromConfig:

    def test_registers_configured_type_with_kwargs(self, monkeypatch):
        _set_command_types(monkeypatch, [
            CommandTypeConfig(name="echo", python_module=THIS_MODULE, python_class="_EchoCommand",
                              kwargs={"prefix": ">> "}),
        ])

        load_command_types_from_config()

        handler = get_command_type("echo")
        assert isinstance(handler, _EchoCommand)
        assert handler.prefix == ">> "

    def test_loaded_flag_prevents_reload(self, monkeypatch):
        _set_command_types(monkeypatch, [
            CommandTypeConfig(name="echo", python_module=THIS_MODULE, python_class="_EchoCommand"),
        ])
        load_command_types_from_config()
        first = get_command_type("echo")
        load_command_types_from_config()
        assert get_command_type("echo") is first
        load_command_types_from_config(force=True)
        assert get_command_type("echo") is not first

    def test_failing_type_does_not_abort_others(self, monkeypatch, caplog):
        _set_command_types(monkeypatch, [
            CommandTypeConfig(name="boom", python_module=THIS_MODULE, python_class="_BoomCommand"),
            CommandTypeConfig(name="echo", python_module=THIS_MODULE, python_class="_EchoCommand"),
        ])

        with caplog.at_level(logging.ERROR):
            load_command_types_from_config()

        assert isinstance(get_command_type("echo"), _EchoCommand)
        assert "failed to load correlation command type boom" in caplog.text
        assert "constructor boom" in get_command_type_load_errors()["boom"]
        # the load failure, not a bare "unknown type", is what a hunt using it gets told
        with pytest.raises(ValueError, match="failed to load: RuntimeError: constructor boom"):
            get_command_type("boom")

    def test_no_op_when_hunter_config_absent(self, monkeypatch):
        monkeypatch.setattr(get_config(), "hunter", None)
        load_command_types_from_config()
        assert get_registered_command_types() == {}

    def test_config_entry_rejects_unknown_keys(self):
        with pytest.raises(ValidationError, match="python_clas"):
            CommandTypeConfig.model_validate({
                "name": "echo", "python_module": THIS_MODULE, "python_clas": "_EchoCommand",
            })

    def test_default_config_declares_no_command_types(self):
        assert isinstance(get_config().hunter.correlation.command_types, list)


@pytest.mark.unit
class TestExecuteCustomCommand:

    def test_options_rendered_then_validated(self, tmpdir, no_cache):
        handler = _EchoCommand()
        register_command_type("echo", handler)
        cmd = CommandConfig(type="echo", options={
            "message": "hi {{ _event.user }}",
            "count": "{{ _event.n }}",
        })

        output = _run(cmd, tmpdir, event={"user": "alice", "n": 2})

        assert output.splitlines() == [json.dumps({"message": "hi alice"})] * 2
        context, options = handler.calls[0]
        # the rendered "2" was coerced by the config_class
        assert isinstance(options, _EchoOptions) and options.count == 2
        assert context.command_type == "echo"
        assert context.event == {"user": "alice", "n": 2}
        assert context.transform_type == "event"
        assert context.timeout == datetime.timedelta(minutes=10)
        assert context.temp_dir == str(tmpdir)
        # the handler, being integration code, still sees the configuration
        assert context.config == {"vendor": {"region": "us"}}

    def test_nested_options_rendered(self, tmpdir, no_cache):
        class _Nested(BaseModel):
            items: list[str]
            meta: dict[str, str]

        class _NestedCommand(CorrelationCommand):
            config_class = _Nested

            def execute(self, context, options):
                return json.dumps(options.model_dump())

        register_command_type("nested", _NestedCommand())
        cmd = CommandConfig(type="nested", options={
            "items": ["{{ _event.a }}", "literal"], "meta": {"k": "{{ _event.b }}"},
        })

        assert json.loads(_run(cmd, tmpdir, event={"a": "x", "b": "y"})) == {
            "items": ["x", "literal"], "meta": {"k": "y"},
        }

    def test_timeout_passed_to_context(self, tmpdir, no_cache):
        handler = _EchoCommand()
        register_command_type("echo", handler)
        _run(CommandConfig(type="echo", timeout="45s", options={"message": "m"}), tmpdir)
        assert handler.calls[0][0].timeout == datetime.timedelta(seconds=45)

    def test_invalid_options_raise(self, tmpdir, no_cache):
        register_command_type("echo", _EchoCommand())
        with pytest.raises(ValidationError, match="mesage"):
            _run(CommandConfig(type="echo", options={"mesage": "typo"}), tmpdir)

    def test_rendered_value_that_fails_validation_raises(self, tmpdir, no_cache):
        register_command_type("echo", _EchoCommand())
        cmd = CommandConfig(type="echo", options={"message": "m", "count": "{{ _event.n }}"})
        with pytest.raises(ValidationError):
            _run(cmd, tmpdir, event={"n": "many"})

    def test_options_on_type_without_config_class_raise(self, tmpdir, no_cache):
        register_command_type("plain", _NoOptionsCommand())
        with pytest.raises(ValueError, match="does not take options"):
            _run(CommandConfig(type="plain", options={"x": 1}), tmpdir)

    def test_type_without_options(self, tmpdir, no_cache):
        register_command_type("plain", _NoOptionsCommand())
        assert _run(CommandConfig(type="plain"), tmpdir, event={"id": 7}) == '{"event_id": 7}'

    def test_unregistered_type_raises(self, tmpdir):
        with pytest.raises(ValueError, match="unknown command type: 'nope'"):
            _run(CommandConfig(type="nope"), tmpdir)

    def test_non_string_return_raises(self, tmpdir, no_cache):
        register_command_type("bad", _BadReturnCommand())
        with pytest.raises(TypeError, match="returned list, expected str"):
            _run(CommandConfig(type="bad"), tmpdir)

    def test_output_is_sanitized(self, tmpdir, no_cache):
        register_command_type("echo", _EchoCommand(prefix="token=hunter2 "))
        output = _run(CommandConfig(type="echo", options={"message": "m"}), tmpdir,
                      secrets={"vendor.api_key": "hunter2"})
        assert "hunter2" not in output
        assert "***" in output

    @pytest.mark.parametrize("name", ["_secrets", "_config"])
    def test_secrets_and_config_not_bound_in_options(self, tmpdir, no_cache, name):
        register_command_type("echo", _EchoCommand())
        cmd = CommandConfig(type="echo", options={"message": f"[{{{{ {name} is defined }}}}]"})
        output = _run(cmd, tmpdir, secrets={"vendor.api_key": "hunter2"})
        assert json.loads(output) == {"message": "[False]"}

    def test_render_options_false_passes_templates_through(self, tmpdir, no_cache):
        handler = _LiteralCommand()
        register_command_type("literal", handler)
        _run(CommandConfig(type="literal", options={"message": "{{ _event.user }}"}), tmpdir,
             event={"user": "alice"})
        assert handler.calls[0][1].message == "{{ _event.user }}"

    def test_stream_transform_context(self, tmpdir, no_cache):
        handler = _EchoCommand()
        register_command_type("echo", handler)
        events = [{"id": 1}, {"id": 2}]
        _run(CommandConfig(type="echo", options={"message": "{{ _events | length }}"}), tmpdir,
             event=events[0], events=events, transform_type="stream")
        context, options = handler.calls[0]
        assert context.transform_type == "stream"
        assert context.events == events
        assert options.message == "2"


@pytest.mark.unit
class TestCustomCommandCache:

    def test_cache_hit_skips_execution(self, tmpdir):
        handler = _EchoCommand()
        register_command_type("echo", handler)
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value="cached") as get_cached, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result") as set_cached:
            output = _run(CommandConfig(type="echo", cache="1h", options={"message": "m"}), tmpdir)
        assert output == "cached"
        assert handler.calls == []
        assert get_cached.call_args[0][0]["type"] == "echo"
        set_cached.assert_not_called()

    def test_cache_miss_stores_result(self, tmpdir, no_cache):
        _, set_cached = no_cache
        register_command_type("echo", _EchoCommand())
        output = _run(CommandConfig(type="echo", cache="1h", options={"message": "m"}), tmpdir,
                      event={"id": 1})
        key, value, ttl = set_cached.call_args[0][:3]
        assert key == {"type": "echo", "options": {"message": "m", "count": 1}, "input": {"id": 1}}
        assert value == output
        assert ttl == 3600

    def test_no_cache_setting_skips_cache(self, tmpdir, no_cache):
        get_cached, set_cached = no_cache
        register_command_type("echo", _EchoCommand())
        _run(CommandConfig(type="echo", options={"message": "m"}), tmpdir)
        get_cached.assert_not_called()
        set_cached.assert_not_called()

    def test_default_key_differs_per_event(self, tmpdir, no_cache):
        """The default key includes the input: a handler may read the event directly, so two
        events rendering identical options must not share a cached result."""
        get_cached, _ = no_cache
        register_command_type("echo", _EchoCommand())
        cmd = CommandConfig(type="echo", cache="1h", options={"message": "same"})
        _run(cmd, tmpdir, event={"id": 1})
        _run(cmd, tmpdir, event={"id": 2})
        first, second = (c[0][0] for c in get_cached.call_args_list)
        assert first != second

    def test_default_key_for_stream_uses_whole_stream(self, tmpdir, no_cache):
        get_cached, _ = no_cache
        register_command_type("echo", _EchoCommand())
        events = [{"id": 1}, {"id": 2}]
        _run(CommandConfig(type="echo", cache="1h", options={"message": "m"}), tmpdir,
             event=events[0], events=events, transform_type="stream")
        assert get_cached.call_args[0][0]["input"] == events

    def test_narrowed_key_shared_across_events(self, tmpdir, no_cache):
        get_cached, _ = no_cache
        register_command_type("narrow", _NarrowKeyCommand())
        cmd = CommandConfig(type="narrow", cache="1h", options={"message": "same"})
        _run(cmd, tmpdir, event={"id": 1})
        _run(cmd, tmpdir, event={"id": 2})
        first, second = (c[0][0] for c in get_cached.call_args_list)
        assert first == second == {"type": "narrow", "message": "same"}

    def test_handler_cannot_override_type_in_key(self, tmpdir, no_cache):
        class _Sneaky(_EchoCommand):
            def cache_key(self, context, options):
                return {"type": "query", "query": "x"}

        get_cached, _ = no_cache
        register_command_type("sneaky", _Sneaky())
        _run(CommandConfig(type="sneaky", cache="1h", options={"message": "m"}), tmpdir)
        assert get_cached.call_args[0][0]["type"] == "sneaky"

    def test_uncacheable_type_ignores_cache(self, tmpdir, no_cache):
        get_cached, set_cached = no_cache
        handler = _UncacheableCommand()
        register_command_type("live", handler)
        _run(CommandConfig(type="live", cache="1h", options={"message": "m"}), tmpdir)
        get_cached.assert_not_called()
        set_cached.assert_not_called()
        assert len(handler.calls) == 1


@pytest.mark.unit
class TestDefinedCustomCommand:

    def test_defined_resolves_to_custom_type_with_option_override(self, tmpdir, no_cache):
        handler = _EchoCommand()
        register_command_type("echo", handler)
        predefined = [PredefinedCommandConfig(
            name="greet", type="echo", cache="1d", options={"message": "default", "count": 3},
        )]
        cmd = CommandConfig(type="defined", name="greet",
                            arguments={"options": {"message": "hi {{ _event.user }}"}})

        output = _run(cmd, tmpdir, event={"user": "bob"}, predefined=predefined)

        # `arguments.options` replaces the predefined options as a whole, so count is back to 1
        assert output.splitlines() == [json.dumps({"message": "hi bob"})]
        assert handler.calls[0][1].count == 1

    def test_predefined_round_trip_does_not_trip_builtin_field_check(self):
        """to_command_config() dumps every field (source_options={}, time_range=None, ...); the
        custom-type check must judge values, not which fields were set."""
        predef = PredefinedCommandConfig(name="greet", type="echo", options={"message": "m"})
        cmd = predef.to_command_config()
        assert cmd.type == "echo"
        assert cmd.options == {"message": "m"}


def _config(logic) -> CorrelateConfig:
    return CorrelateConfig.model_validate({"logic": logic})


@pytest.fixture
def _mock_secrets_and_config():
    mock_raw = MagicMock()
    mock_raw._data = {}
    with patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords", return_value={}), \
         patch("saq.collectors.hunter.correlation.engine.get_config", return_value=MagicMock(raw=mock_raw)):
        yield


@pytest.mark.unit
class TestEngineWithCustomCommand:

    def test_property_transform_enriches_and_filters(self, _mock_secrets_and_config, no_cache):
        register_command_type("echo", _EchoCommand())
        config = _config([
            {"transform": {
                "type": "event", "method": "property",
                "property_name": "echoed", "property_type": "list",
                "command": {"type": "echo", "options": {"message": "{{ _event.user }}"}},
            }},
            {"when": "{{ _event.echoed[0].message == 'noise' }}",
             "execute": [{"action": "filter"}]},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))

        result = engine.execute([{"user": "noise"}, {"user": "alice"}])

        assert [e["user"] for e in result.events] == ["alice"]
        assert result.events[0]["echoed"] == [{"message": "alice"}]

        transform = result.trace.event_traces[1].steps[0].step
        assert transform.trace_type == "transform"
        assert transform.command_type == "echo"
        assert transform.rendered_command == 'echo {"count": 1, "message": "alice"}'
        assert transform.result_count == 1
        # not a query: no time window on the trace
        assert transform.query_start_time is None

    def test_custom_render_summary_is_used(self, _mock_secrets_and_config, no_cache):
        class _Summarized(_EchoCommand):
            def render_summary(self, context, options):
                return f"lookup {options.message}"

        register_command_type("summarized", _Summarized())
        config = _config([{"transform": {
            "method": "property", "property_name": "p",
            "command": {"type": "summarized", "options": {"message": "{{ _event.user }}"}},
        }}])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))

        result = engine.execute([{"user": "alice"}])

        assert result.trace.event_traces[0].steps[0].step.rendered_command == "lookup alice"

    def test_unregistered_type_errors_and_alerts(self, _mock_secrets_and_config):
        config = _config([{"transform": {
            "method": "property", "property_name": "p",
            "command": {"type": "missing_type"},
        }}])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))

        result = engine.execute([{"id": 1}])

        # fail-safe: the event still alerts, with the error on its trace
        assert len(result.events) == 1
        event_trace = result.trace.event_traces[0]
        assert event_trace.outcome == "error"
        assert "unknown command type: 'missing_type'" in event_trace.steps[0].step.error
