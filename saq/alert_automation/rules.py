"""Alert automation rules: a trigger finds the alerts a rule applies to, and the rule's actions run
on each of them, at most once per (rule, alert, mode) and never on an alert a person owns
(docs/ALERT_AUTOMATION.md). The alert_automation service (saq/alert_automation/service.py) sweeps
the enabled rules with sweep_rule()."""

import importlib
import logging
import string
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from saq.alert_automation.runs import (
    ACTION_FAILED,
    ACTION_FINISHED,
    RUN_DONE,
    RUN_FAILED,
    RUN_LEASE_SECONDS,
    AlertState,
    Run,
    alert_states,
    alerts_with_runs,
    claim_run,
    delete_run,
    pending_runs,
    save_run,
    take_run,
)
from saq.auth import ApiAuthResult
from saq.configuration.config import get_config
from saq.configuration.schema import AlertAutomationRuleConfig, AlertAutomationStepConfig
from saq.constants import DISPOSITION_OPEN
from saq.database.pool import remove_all_sessions
from saq.error.reporting import log_loop_exception

MODE_DRY_RUN = "dry_run"
MODE_ENFORCE = "enforce"

# who the AUDIT records of an automated change name; the change itself is written as the
# automation user (global_settings.automation_user_id)
AUTOMATION_ACTOR = ApiAuthResult.system("alert_automation")

# the template fields every rule's comments may use, next to the trigger's own
COMMON_TEMPLATE_FIELDS = frozenset({"rule", "alert_uuid"})


class TriggerConfig(BaseModel):
    """The base of a trigger type's config_class: unknown keys are rejected."""
    model_config = ConfigDict(extra="forbid")
    type: str = Field(..., description="the trigger type's name")


class ActionConfig(BaseModel):
    """The base of an action type's config_class: unknown keys are rejected."""
    model_config = ConfigDict(extra="forbid")
    type: str = Field(..., description="the action type's name")


@dataclass(frozen=True)
class Candidate:
    """An alert a trigger found, with the evidence its actions are given and its run records."""
    alert_uuid: str
    # JSON-serializable
    evidence: dict


class AlertAutomationTrigger(ABC):
    """Finds the alerts a rule applies to. One instance per rule, built from its validated
    config_class."""

    config_class: type[TriggerConfig] = TriggerConfig
    # the fields a rule's comment templates may use from template_values()
    template_fields: frozenset[str] = frozenset()

    def __init__(self, config: TriggerConfig):
        self.config = config

    @abstractmethod
    def candidates(self, after: Optional[str], limit: int) -> list[Candidate]:
        """At most limit alerts the condition holds for, in alert uuid order, after the uuid after
        (from the start when None). Only alerts that have an alerts row."""

    @abstractmethod
    def still_holds(self, alert_uuids: list[str]) -> set[str]:
        """Those of the alerts the condition holds for now. The disposition action passes this to
        set_dispositions(eligible=...), which calls it under the alerts' row locks, so it reads on a
        connection of its own."""

    def template_values(self, evidence: dict) -> dict[str, str]:
        """The values of template_fields for a candidate's evidence."""
        return {}

    def evidence_observables(self, evidence: dict) -> list[tuple[str, str]]:
        """The (type, value) of each observable the evidence is about, for the remediate action."""
        return []


class ActionStatus(Enum):
    DONE = "done"
    SKIPPED = "skipped"
    # the action left the alert alone because it changed since the sweep chose it (an analyst took
    # it, or the trigger no longer holds): the rest of the rule does not run, and the alert is
    # considered again on a later sweep
    DEFERRED = "deferred"


@dataclass
class ActionOutcome:
    status: ActionStatus
    # JSON-serializable: what the action did, or in dry_run what it would have done
    detail: dict = field(default_factory=dict)
    reason: Optional[str] = None


@dataclass(frozen=True)
class ActionContext:
    rule_name: str
    alert_uuid: str
    mode: str
    evidence: dict
    trigger: AlertAutomationTrigger

    @property
    def dry_run(self) -> bool:
        return self.mode == MODE_DRY_RUN

    def render(self, template: str) -> str:
        """The template with the trigger's fields and the common ones filled in. check_template()
        made sure at load that it names no other field."""
        return template.format_map({**self.trigger.template_values(self.evidence),
                                    "rule": self.rule_name, "alert_uuid": self.alert_uuid})


class AlertAutomationAction(ABC):
    """Does one thing to one alert. One instance per rule and action, built from its validated
    config_class. Raising means the action failed and is retried on a later sweep."""

    config_class: type[ActionConfig] = ActionConfig

    def __init__(self, config: ActionConfig):
        self.config = config

    def check(self, trigger: AlertAutomationTrigger) -> None:
        """Raises ValueError when this action can't work with the rule's trigger."""

    @abstractmethod
    def run(self, context: ActionContext) -> ActionOutcome:
        """Does the action, or in dry_run records what it would do without changing anything."""


def check_template(template: str, trigger: AlertAutomationTrigger) -> None:
    """Raises ValueError when the template names a field the trigger does not provide, or is not a
    valid format string."""
    allowed = trigger.template_fields | COMMON_TEMPLATE_FIELDS
    for _, field_name, _, _ in string.Formatter().parse(template):
        if field_name is not None and field_name not in allowed:
            raise ValueError(f"template field {{{field_name}}} is not one of {', '.join(sorted(allowed))}")


#
# the trigger and action types
#

# type name -> class, loaded from alert_automation.trigger_types / action_types on first use
_TRIGGER_TYPES: dict[str, type[AlertAutomationTrigger]] = {}
_ACTION_TYPES: dict[str, type[AlertAutomationAction]] = {}


def reset_alert_automation_registry() -> None:
    _TRIGGER_TYPES.clear()
    _ACTION_TYPES.clear()


def _type_class(kind: str, name: str):
    registry, base, entries = {
        "trigger": (_TRIGGER_TYPES, AlertAutomationTrigger, get_config().alert_automation.trigger_types),
        "action": (_ACTION_TYPES, AlertAutomationAction, get_config().alert_automation.action_types),
    }[kind]
    if name in registry:
        return registry[name]

    for entry in entries:
        if entry.name == name:
            cls = getattr(importlib.import_module(entry.python_module), entry.python_class)
            if not (isinstance(cls, type) and issubclass(cls, base)):
                raise ValueError(f"{kind} type {name}: {entry.python_module}.{entry.python_class} "
                                 f"is not an {base.__name__}")
            registry[name] = cls
            return cls

    raise ValueError(f"unknown {kind} type {name}: alert_automation.{kind}_types does not list it")


def _build(kind: str, step: AlertAutomationStepConfig):
    cls = _type_class(kind, step.type)
    return cls(cls.config_class.model_validate(step.model_dump()))


@dataclass
class Rule:
    name: str
    mode: str
    trigger: AlertAutomationTrigger
    actions: list[AlertAutomationAction]


def load_rule(config: AlertAutomationRuleConfig) -> Rule:
    """Builds the rule's trigger and actions, validating their configuration. Raises when a type is
    unknown or fails to import, or a block does not validate."""
    trigger = _build("trigger", config.trigger)
    actions = [_build("action", step) for step in config.actions]
    for action in actions:
        action.check(trigger)

    return Rule(name=config.name, mode=config.mode, trigger=trigger, actions=actions)


def load_rules() -> list[Rule]:
    """The enabled rules. A rule that fails to load is logged at ERROR and left out; the others
    still run."""
    rules = []
    for config in get_config().alert_automation_rules:
        if not config.enabled:
            continue

        try:
            rules.append(load_rule(config))
        except Exception as e:
            logging.exception(f"alert automation rule {config.name} failed to load and does not run: {e}",
                              extra={"rule": config.name})
            continue

        logging.info("loaded alert automation rule %s (%s)", config.name, config.mode,
                     extra={"rule": config.name, "mode": config.mode})

    return rules


#
# the sweep
#

def _left_alone_because(state: Optional[AlertState], run: Optional[Run]) -> Optional[str]:
    """Why the guards leave the alert alone, or None when the rule may act on it. Rule authors
    can't turn these off."""
    if state is None:
        return "the alert does not exist"

    automation_user_id = get_config().global_settings.automation_user_id
    if state.owner_id is not None and state.owner_id != automation_user_id:
        return f"user {state.owner_id} owns the alert"

    # a run that has started put the alert in the state it is in (the disposition it set)
    if (run is None or not run.started) and state.disposition != DISPOSITION_OPEN:
        return f"the alert's disposition is {state.disposition}"

    return None


def _log_fields(rule: Rule, alert_uuid: str, action_type: Optional[str] = None) -> dict:
    fields = {"rule": rule.name, "alert_uuid": alert_uuid, "mode": rule.mode}
    if action_type is not None:
        fields["action"] = action_type
    return fields


def _log_error(message: str, extra: dict) -> None:
    # at ERROR with an exception, so an operator gets an error report, and one report per message
    logging.error(message, exc_info=RuntimeError(message), extra=extra)


def _saved(rule: Rule, run: Run, hold: bool = False) -> bool:
    """save_run(), logging at ERROR when another sweep has the run: it claimed the run after this
    sweep's lease ran out, so an action may run twice."""
    if save_run(run, hold):
        return True

    _log_error(f"alert automation rule {rule.name}: another sweep claimed the run on alert {run.alert_uuid} "
               f"while this one had it, after its {RUN_LEASE_SECONDS}s lease ran out; what this sweep did "
               f"since its last save is not recorded", _log_fields(rule, run.alert_uuid))
    return False


def process_alert(rule: Rule, alert_uuid: str, evidence: dict, state: Optional[AlertState],
                  run: Optional[Run], max_attempts: int) -> None:
    """Runs the rule's unfinished actions on the alert, in order, recording each outcome as it
    finishes. Stops at the first action that fails (retried on a later sweep, until max_attempts)
    or defers."""
    reason = _left_alone_because(state, run)
    if reason is not None:
        # a pending run left alone is retried on every sweep until the guard lets it through
        logging.log(logging.DEBUG if run is None else logging.INFO,
                    "alert automation rule %s leaves alert %s alone: %s", rule.name, alert_uuid, reason,
                    extra={**_log_fields(rule, alert_uuid), "reason": reason})
        return

    if run is None:
        run = claim_run(rule.name, alert_uuid, rule.mode, evidence,
                        [action.config.type for action in rule.actions])
        if run is None:
            return
    elif not take_run(run):
        logging.info("alert automation rule %s: another sweep has its run on alert %s", rule.name, alert_uuid,
                     extra=_log_fields(rule, alert_uuid))
        return

    recorded = [record["type"] for record in run.actions]
    configured = [action.config.type for action in rule.actions]
    if recorded != configured:
        # the rule was edited after the run started: which of its actions are done is not known
        run.status = RUN_FAILED
        _log_error(f"alert automation rule {rule.name}: its actions are now {', '.join(configured)}, but its "
                   f"run on alert {alert_uuid} was started for {', '.join(recorded)}; the run is marked "
                   f"failed and nothing more runs", _log_fields(rule, alert_uuid))
        _saved(rule, run)
        return

    context = ActionContext(rule_name=rule.name, alert_uuid=alert_uuid, mode=rule.mode, evidence=run.evidence,
                            trigger=rule.trigger)
    for action, record in zip(rule.actions, run.actions):
        if record["status"] in ACTION_FINISHED:
            continue

        extra = _log_fields(rule, alert_uuid, record["type"])
        try:
            outcome = action.run(context)
        except Exception as e:
            record["attempts"] += 1
            record["reason"] = f"{type(e).__name__}: {e}"
            extra["attempt"] = record["attempts"]
            message = (f"alert automation rule {rule.name}: action {record['type']} failed on alert {alert_uuid} "
                       f"(attempt {record['attempts']} of {max_attempts}): {e}")
            if record["attempts"] >= max_attempts:
                record["status"] = ACTION_FAILED
                run.status = RUN_FAILED
                message += f"; gave up after {record['attempts']} attempts, and the rule's later actions do not run"
            logging.exception(message, extra=extra)
            _saved(rule, run)
            return

        if outcome.status is ActionStatus.DEFERRED:
            logging.info("alert automation rule %s: action %s left alert %s alone: %s", rule.name, record["type"],
                         alert_uuid, outcome.reason, extra={**extra, "reason": outcome.reason})
            if run.started:
                _saved(rule, run)
            # nothing was done, so the run is deleted and the rule considers the alert again on a later sweep
            elif not delete_run(run):
                _log_error(f"alert automation rule {rule.name}: another sweep claimed the run on alert "
                           f"{alert_uuid} while this one had it, so it was not deleted", extra)
            return

        record["attempts"] += 1
        record["status"] = outcome.status.value
        record["detail"] = outcome.detail
        record["reason"] = outcome.reason
        logging.info("alert automation rule %s: action %s %s on alert %s (%s)", rule.name, record["type"],
                     outcome.status.value, alert_uuid, rule.mode,
                     extra={**extra, "status": outcome.status.value, "detail": outcome.detail,
                            "reason": outcome.reason})
        # recorded before the next action runs: a sweep that dies now must not leave the alert, which
        # this action may have taken out of OPEN, with a run that says nothing has started
        if not _saved(rule, run, hold=True):
            return

    run.status = RUN_DONE
    _saved(rule, run)


def _process_each(rule: Rule, items: list[tuple[str, dict, Optional[Run]]], max_attempts: int,
                  stopping: Callable[[], bool]) -> None:
    states = alert_states([alert_uuid for alert_uuid, _, _ in items])
    for alert_uuid, evidence, run in items:
        if stopping():
            return

        try:
            process_alert(rule, alert_uuid, evidence, states.get(alert_uuid), run, max_attempts)
        except Exception as e:
            # recording the run failed; the alert is considered again on the next sweep
            log_loop_exception(e, f"alert automation rule {rule.name} failed on alert {alert_uuid}",
                               extra=_log_fields(rule, alert_uuid))
        finally:
            # a write that failed in an action leaves the thread's get_db() session unusable (#852),
            # so each alert starts with a fresh one
            remove_all_sessions()


def sweep_rule(rule: Rule, batch_size: int, max_attempts: int, stopping: Callable[[], bool] = lambda: False) -> None:
    """Retries the rule's pending runs, then acts on the alerts its trigger finds that it has no
    run on yet, a batch at a time, until stopping() returns True."""
    after_id = 0
    while not stopping():
        runs = pending_runs(rule.name, rule.mode, after_id, batch_size)
        if not runs:
            break

        after_id = runs[-1].id
        _process_each(rule, [(run.alert_uuid, run.evidence, run) for run in runs], max_attempts, stopping)

    after: Optional[str] = None
    while not stopping():
        candidates = rule.trigger.candidates(after, batch_size)
        if not candidates:
            break

        after = candidates[-1].alert_uuid
        known = alerts_with_runs(rule.name, rule.mode, [candidate.alert_uuid for candidate in candidates])
        _process_each(rule, [(candidate.alert_uuid, candidate.evidence, None) for candidate in candidates
                             if candidate.alert_uuid not in known], max_attempts, stopping)
        if len(candidates) < batch_size:
            break
