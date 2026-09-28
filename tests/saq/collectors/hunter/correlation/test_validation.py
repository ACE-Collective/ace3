from unittest.mock import MagicMock, patch

import pytest

from pydantic import BaseModel

from saq.collectors.hunter.correlation.command_types import (
    CorrelationCommand,
    clear_command_types,
    register_command_type,
)
from saq.collectors.hunter.correlation.schema import CorrelateConfig, PredefinedCommandConfig
from saq.collectors.hunter.correlation.validation import (
    check_custom_command_types,
    check_templates_for_removed_names,
    iter_correlate_commands,
)

def _correlate(*commands) -> CorrelateConfig:
    return CorrelateConfig.model_validate({
        "logic": [
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": f"p{i}",
                    "command": command,
                },
            }
            for i, command in enumerate(commands)
        ],
    })


@pytest.mark.unit
class TestIterCorrelateCommands:

    def test_walks_nested_conditions(self):
        config = CorrelateConfig.model_validate({
            "logic": [
                {
                    "when": "{{ _event.x }}",
                    "execute": [
                        {"transform": {"method": "property", "property_name": "a",
                                       "command": {"type": "defined", "name": "cmd_a"}}},
                    ],
                    "else": [
                        {"transform": {"method": "property", "property_name": "b",
                                       "command": {"type": "defined", "name": "cmd_b"}}},
                    ],
                },
                {"transform": {"method": "property", "property_name": "c",
                               "command": {"type": "defined", "name": "cmd_c"}}},
            ],
        })
        assert [c.name for c in iter_correlate_commands(config.logic)] == ["cmd_a", "cmd_b", "cmd_c"]


@pytest.mark.unit
class TestCheckTemplatesForRemovedNames:

    @pytest.mark.parametrize("name", ["_secrets", "_config"])
    @pytest.mark.parametrize("command", [
        {"type": "executable", "path": "/x/a.py", "env": {"API_KEY": "{{ NAME['vendor.api_key'] }}"}},
        {"type": "executable", "path": "/x/a.py", "args": ["--key", "{{ NAME.vendor.api_key }}"]},
        {"type": "query", "source": "splunk", "query": "search key={{ NAME['vendor'] }}"},
        {"type": "lookup", "options": {"nested": {"deep": ["{{ NAME }}"]}}},
        {"type": "defined", "name": "cmd", "arguments": {"args": ["{% if NAME %}x{% endif %}"]}},
    ], ids=["env", "args", "query", "options", "defined_arguments"])
    def test_command_templates_are_rejected(self, name, command):
        command = {k: _substitute(v, name) for k, v in command.items()}
        errors = check_templates_for_removed_names(_correlate(command), None)
        assert len(errors) == 1
        assert name in errors[0]
        assert "custom command type" in errors[0]

    @pytest.mark.parametrize("name", ["_secrets", "_config"])
    def test_condition_action_and_debug_templates_are_rejected(self, name):
        correlate = CorrelateConfig.model_validate({
            "logic": [
                {
                    "when": {"type": "and", "value": [
                        "{{ _event.x }}",
                        {"type": "not", "value": f"{{{{ {name}.a }}}}"},
                    ]},
                    "execute": [{"action": {"type": "log", "log_message": "ok"}}],
                    "else": [
                        {
                            "action": {"type": "log", "log_message": f"{{{{ {name}.b }}}}"},
                            "debug": f"{{{{ {name}.c }}}}",
                        },
                    ],
                },
            ],
        })
        errors = check_templates_for_removed_names(correlate, None)
        assert len(errors) == 3
        assert all(name in e for e in errors)

    def test_predefined_command_is_checked(self):
        """Commands shared through an include file are checked under their own name."""
        predefined = [PredefinedCommandConfig.model_validate({
            "name": "get_r7_investigation_comments",
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _secrets['rapid7.api_key'] }}"},
        })]
        errors = check_templates_for_removed_names(None, predefined)
        assert len(errors) == 1
        assert "get_r7_investigation_comments" in errors[0]
        assert "_secrets" in errors[0]

    def test_event_templates_are_accepted(self):
        correlate = _correlate(
            {"type": "executable", "path": "/x/a.py", "args": ["{{ _event.domain }}"],
             "env": {"USER": "{{ _event['properties.userId'] }}", "MODE": "fast"}},
            {"type": "query", "source": "splunk", "query": "search host={{ _event.host }} | stats count by {{ _events|length }}"},
        )
        assert check_templates_for_removed_names(correlate, None) == []

    def test_a_locally_assigned_name_is_not_a_reference(self):
        correlate = _correlate({
            "type": "executable", "path": "/x/a.py",
            "args": ["{% set _config = _event.x %}{{ _config }}"],
        })
        assert check_templates_for_removed_names(correlate, None) == []

    def test_unrendered_fields_are_not_checked(self):
        """`description` and `source_options` are passed as written, never rendered."""
        predefined = [PredefinedCommandConfig.model_validate({
            "name": "cmd",
            "description": "do not use {{ _secrets }} here",
            "type": "query",
            "source": "splunk",
            "query": "search x",
            "source_options": {"note": "{{ _config }}"},
        })]
        assert check_templates_for_removed_names(None, predefined) == []

    def test_template_that_does_not_parse_is_skipped(self):
        correlate = _correlate({"type": "executable", "path": "/x/a.py", "args": ["{{ _secrets["]})
        assert check_templates_for_removed_names(correlate, None) == []

    def test_same_template_in_several_places_is_one_error(self):
        command = {"type": "executable", "path": "/x/a.py", "env": {"K": "{{ _secrets.k }}"}}
        assert len(check_templates_for_removed_names(_correlate(command, command), None)) == 1

    def test_non_correlate_hunt_is_a_no_op(self):
        assert check_templates_for_removed_names(None, None) == []

    def test_unparsed_config_objects_are_ignored(self):
        """A hunt type whose config exposes something other than the parsed models."""
        assert check_templates_for_removed_names(MagicMock(), MagicMock()) == []


def _substitute(value, name: str):
    """Replace the NAME placeholder in every string of a command fixture."""
    if isinstance(value, str):
        return value.replace("NAME", name)
    if isinstance(value, dict):
        return {k: _substitute(v, name) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, name) for v in value]
    return value


class _LookupOptions(BaseModel):
    model_config = {"extra": "forbid"}

    ip: str
    limit: int = 10


class _LookupCommand(CorrelationCommand):
    config_class = _LookupOptions

    def execute(self, context, options):
        return ""


class _LiveCommand(CorrelationCommand):
    cacheable = False

    def execute(self, context, options):
        return ""


@pytest.fixture
def custom_types():
    clear_command_types()
    register_command_type("lookup", _LookupCommand())
    register_command_type("live", _LiveCommand())
    yield
    clear_command_types()


@pytest.mark.unit
class TestCheckCustomCommandTypes:

    def test_valid_custom_command(self, custom_types):
        correlate = _correlate({"type": "lookup", "cache": "1d", "options": {"ip": "{{ _event.ip }}"}})
        assert check_custom_command_types(correlate) == []

    def test_builtin_commands_are_ignored(self, custom_types):
        correlate = _correlate(
            {"type": "query", "source": "not_even_registered", "query": "q"},
            {"type": "executable", "path": "/bin/true"},
        )
        assert check_custom_command_types(correlate) == []

    def test_unknown_type_is_reported_with_known_types(self, custom_types):
        errors = check_custom_command_types(_correlate({"type": "lookpu"}))
        assert len(errors) == 1
        assert "unknown command type 'lookpu'" in errors[0]
        assert "live, lookup" in errors[0]

    def test_load_failure_is_reported(self, custom_types):
        with patch("saq.collectors.hunter.correlation.validation.get_command_type_load_errors",
                   return_value={"broken": "RuntimeError: no api key"}):
            errors = check_custom_command_types(_correlate({"type": "broken"}))
        assert errors == ["command 'broken': command type 'broken' failed to load on this node: RuntimeError: no api key"]

    def test_bad_options_are_reported(self, custom_types):
        errors = check_custom_command_types(_correlate({"type": "lookup", "options": {"ipp": "1.2.3.4"}}))
        assert any("options.ip" in e and "Field required" in e for e in errors)
        assert any("options.ipp" in e for e in errors)

    def test_template_in_typed_field_is_tolerated(self, custom_types):
        """ "{{ _event.n }}" is not an int yet; it is judged after rendering, at run time."""
        correlate = _correlate({"type": "lookup", "options": {"ip": "x", "limit": "{{ _event.n }}"}})
        assert check_custom_command_types(correlate) == []

    def test_literal_bad_value_in_typed_field_is_reported(self, custom_types):
        correlate = _correlate({"type": "lookup", "options": {"ip": "x", "limit": "lots"}})
        errors = check_custom_command_types(correlate)
        assert len(errors) == 1
        assert "options.limit" in errors[0]

    def test_options_on_type_without_config_class_are_reported(self, custom_types):
        errors = check_custom_command_types(_correlate({"type": "live", "options": {"x": 1}}))
        assert errors == ["command 'live': command type 'live' takes no options, got ['x']"]

    def test_cache_on_uncacheable_type_is_reported(self, custom_types):
        errors = check_custom_command_types(_correlate({"type": "live", "cache": "1h"}))
        assert errors == ["command 'live': command type 'live' is not cacheable; remove 'cache'"]

    def test_predefined_custom_command_is_checked(self, custom_types):
        predefined = [PredefinedCommandConfig.model_validate({
            "name": "ip_lookup", "type": "lookup", "options": {"limit": 5},
        })]
        errors = check_custom_command_types(None, predefined)
        assert len(errors) == 1
        assert errors[0].startswith("predefined command 'ip_lookup': options.ip")

    def test_defined_arguments_are_applied_before_checking(self, custom_types):
        """A predefined command may leave a required option for each reference to supply."""
        predefined = [PredefinedCommandConfig.model_validate({
            "name": "ip_lookup", "type": "lookup", "options": {"ip": "placeholder"},
        })]
        correlate = _correlate({
            "type": "defined", "name": "ip_lookup",
            "arguments": {"options": {"limit": 5}},
        })
        errors = check_custom_command_types(correlate, predefined)
        # arguments.options replaced the whole dict, which dropped `ip`
        assert len(errors) == 1
        assert errors[0].startswith("defined command 'ip_lookup': options.ip")

    def test_unargumented_defined_reference_is_not_double_reported(self, custom_types):
        predefined = [PredefinedCommandConfig.model_validate({"name": "gone", "type": "lookpu"})]
        correlate = _correlate({"type": "defined", "name": "gone"}, {"type": "defined", "name": "gone"})
        assert len(check_custom_command_types(correlate, predefined)) == 1

    def test_nested_commands_are_checked(self, custom_types):
        correlate = CorrelateConfig.model_validate({"logic": [{
            "when": "{{ true }}",
            "execute": [{"transform": {"method": "property", "property_name": "a",
                                       "command": {"type": "nope"}}}],
        }]})
        assert len(check_custom_command_types(correlate)) == 1

    def test_non_correlate_hunt_is_a_no_op(self, custom_types):
        assert check_custom_command_types(None, None) == []
        assert check_custom_command_types(MagicMock(), MagicMock()) == []
