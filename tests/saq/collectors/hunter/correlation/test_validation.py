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
    check_env_for_encrypted_markers,
    iter_correlate_commands,
)

CONFIG = {
    "rapid7": {"api_key": "encrypted:rapid7.api_key"},
    "wiz": {"client_id": "abc123"},
}


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
class TestCheckEnvForEncryptedMarkers:

    def test_config_reference_to_encrypted_secret_is_rejected(self):
        """The reported rapid7 bug, caught before the hunt ever runs."""
        correlate = _correlate({
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _config['rapid7']['api_key'] }}"},
        })
        errors = check_env_for_encrypted_markers(correlate, None, CONFIG)
        assert len(errors) == 1
        assert "R7_API_KEY" in errors[0]
        assert "_secrets" in errors[0]

    def test_predefined_command_env_is_checked(self):
        """Every real secret consumer is a predefined command in a shared include file."""
        predefined = [PredefinedCommandConfig.model_validate({
            "name": "get_r7_investigation_comments",
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _config['rapid7']['api_key'] }}"},
        })]
        errors = check_env_for_encrypted_markers(None, predefined, CONFIG)
        assert len(errors) == 1
        assert "get_r7_investigation_comments" in errors[0]

    def test_secrets_reference_is_accepted(self):
        predefined = [PredefinedCommandConfig.model_validate({
            "name": "get_r7_investigation_comments",
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _secrets['rapid7.api_key'] }}"},
        })]
        assert check_env_for_encrypted_markers(None, predefined, CONFIG) == []

    def test_plaintext_config_reference_is_accepted(self):
        correlate = _correlate({
            "type": "executable",
            "path": "/x/wiz.py",
            "env": {"WIZ_CLIENT_ID": "{{ _config['wiz']['client_id']}}"},
        })
        assert check_env_for_encrypted_markers(correlate, None, CONFIG) == []

    def test_marker_composed_into_a_longer_value_is_rejected(self):
        correlate = _correlate({
            "type": "executable",
            "path": "/x/a.py",
            "env": {"CERT_PATH": "/opt/ace/{{ _config['rapid7']['api_key'] }}"},
        })
        assert len(check_env_for_encrypted_markers(correlate, None, CONFIG)) == 1

    def test_hardcoded_marker_is_rejected(self):
        correlate = _correlate({
            "type": "executable",
            "path": "/x/a.py",
            "env": {"R7_API_KEY": "encrypted:rapid7.api_key"},
        })
        assert len(check_env_for_encrypted_markers(correlate, None, CONFIG)) == 1

    def test_env_referencing_event_data_is_not_reported(self):
        """The probe context has no event data, so an unresolvable event field is not an error."""
        correlate = _correlate({
            "type": "executable",
            "path": "/x/a.py",
            "env": {"USER": "{{ _event['properties.userId'] }}"},
        })
        assert check_env_for_encrypted_markers(correlate, None, CONFIG) == []

    def test_commands_without_env_are_skipped(self):
        correlate = _correlate({"type": "defined", "name": "cmd"})
        assert check_env_for_encrypted_markers(correlate, None, CONFIG) == []

    def test_non_correlate_hunt_is_a_no_op(self):
        assert check_env_for_encrypted_markers(None, None, CONFIG) == []

    def test_unparsed_config_objects_are_ignored(self):
        """A hunt type whose config exposes something other than the parsed models."""
        assert check_env_for_encrypted_markers(MagicMock(), MagicMock(), CONFIG) == []

    def test_falls_back_to_live_config_when_none_supplied(self):
        correlate = _correlate({
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _config['rapid7']['api_key'] }}"},
        })
        mock_raw = MagicMock()
        mock_raw._data = CONFIG
        with patch("saq.collectors.hunter.correlation.validation.get_config",
                   return_value=MagicMock(raw=mock_raw)):
            assert len(check_env_for_encrypted_markers(correlate)) == 1


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
