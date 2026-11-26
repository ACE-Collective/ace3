"""Validation of alert automation rules: the rule block when the configuration loads, and the
trigger and action blocks when the service loads the rule."""

import logging

import pytest
from pydantic import ValidationError

from saq.alert_automation.rules import load_rule, load_rules
from saq.configuration.config import get_config
from saq.configuration.schema import AlertAutomationRuleConfig, AlertAutomationTypeConfig
from tests.saq.alert_automation.conftest import ACTIONS, RULE, rule_config
from tests.saq.helpers import the_error_with_traceback


def _load(config: dict):
    return load_rule(AlertAutomationRuleConfig.model_validate(config))


@pytest.mark.unit
def test_a_rule_rejects_an_unknown_key():
    with pytest.raises(ValidationError, match="extra_key"):
        AlertAutomationRuleConfig.model_validate({**rule_config(), "extra_key": 1})


@pytest.mark.unit
def test_a_rule_needs_an_action():
    with pytest.raises(ValidationError, match="actions"):
        AlertAutomationRuleConfig.model_validate(rule_config(actions=[]))


@pytest.mark.unit
def test_a_rule_defaults_to_disabled_and_dry_run():
    config = rule_config()
    del config["enabled"], config["mode"]
    rule = AlertAutomationRuleConfig.model_validate(config)
    assert (rule.enabled, rule.mode) == (False, "dry_run")


@pytest.mark.unit
@pytest.mark.parametrize("config, error", [
    (rule_config(extra_key=1), "extra_key"),
    (rule_config(probe="no_such_probe"), "no_such_probe"),
    (rule_config(max_age_hours=0), "max_age_hours"),
    (rule_config(actions=[{**ACTIONS[0], "extra_key": 1}]), "extra_key"),
    (rule_config(actions=[{**ACTIONS[0], "disposition": "NOT_A_DISPOSITION"}]), "not in the dispositions"),
    (rule_config(actions=[{**ACTIONS[0], "disposition": "SIMULATED"}]), "not analyst_selectable"),
    (rule_config(actions=[{"type": "remediate", "targets": "everything"}]), "targets"),
    (rule_config(actions=[{"type": "comment", "comment": "from {sender}"}]), "sender"),
    (rule_config(actions=[{**ACTIONS[0], "comment": "{probe.__class__}"}]), "probe.__class__"),
    (rule_config(actions=[{"type": "no_such_action"}]), "unknown action type no_such_action"),
    ({**rule_config(), "trigger": {"type": "no_such_trigger"}}, "unknown trigger type no_such_trigger"),
])
def test_a_trigger_or_action_block_that_does_not_validate_fails_the_rule(config, error):
    with pytest.raises(ValueError, match=error):
        _load(config)


@pytest.mark.unit
def test_a_type_must_be_a_trigger_or_action_class():
    get_config().alert_automation.action_types.append(AlertAutomationTypeConfig(
        name="not_an_action", python_module="saq.alert_automation.triggers",
        python_class="ExternalRemediationConfirmedTrigger"))

    with pytest.raises(ValueError, match="is not an AlertAutomationAction"):
        _load(rule_config(actions=[{"type": "not_an_action"}]))


@pytest.mark.unit
def test_the_configuration_rejects_two_rules_with_one_name():
    raw = get_config().raw._data
    raw["alert_automation_rule_one"] = rule_config()
    raw["alert_automation_rule_two"] = rule_config()

    with pytest.raises(ValueError, match=f"already named {RULE}"):
        get_config().load_alert_automation_rule_configs()


@pytest.mark.unit
def test_a_rule_that_fails_to_load_is_logged_and_the_others_still_load(caplog):
    raw = get_config().raw._data
    raw["alert_automation_rule_good"] = rule_config(name="good")
    raw["alert_automation_rule_broken"] = rule_config(name="broken", probe="no_such_probe")
    raw["alert_automation_rule_off"] = {**rule_config(name="off"), "enabled": False}
    get_config().load_alert_automation_rule_configs()

    assert [rule.name for rule in load_rules()] == ["good"]
    the_error_with_traceback(caplog, rule="broken")
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR and getattr(r, "rule", None) == "good"]
