"""The action types core ships (docs/ALERT_AUTOMATION.md, *Actions*)."""

import logging
from typing import Literal, Optional

from pydantic import Field, field_validator

from saq.alert_automation.rules import (
    AUTOMATION_ACTOR,
    ActionConfig,
    ActionContext,
    ActionOutcome,
    ActionStatus,
    AlertAutomationAction,
    AlertAutomationTrigger,
    check_template,
)
from saq.analysis.observable import Observable
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_OPEN, F_EMAIL_DELIVERY, parse_email_delivery
from saq.database.model import Comment, normalize_comment
from saq.database.pool import get_db
from saq.database.util.alert import get_alert_by_uuid, set_dispositions, touch_alerts
from saq.email import normalize_message_id
from saq.observables.type_hierarchy import get_type_hierarchy
from saq.remediation.database import removal_covers
from saq.remediation.target import RemediationTarget, get_observable_remediation_targets
from saq.remediation.types import RemediationAction
from saq.search.tasks import submit_index_task


class DispositionActionConfig(ActionConfig):
    disposition: str = Field(..., description="the disposition to set; one analysts may select")
    comment: Optional[str] = Field(default=None, description="a comment added with the disposition; a template of the trigger's fields")

    @field_validator("disposition")
    @classmethod
    def _analyst_selectable(cls, value: str) -> str:
        dispositions = get_config().dispositions
        if value not in dispositions:
            raise ValueError(f"disposition {value} is not in the dispositions: block")
        if not dispositions[value].analyst_selectable:
            raise ValueError(f"disposition {value} is not analyst_selectable; only ACE's own subsystems set it")
        return value


class DispositionAction(AlertAutomationAction):
    """Sets the alert's disposition as the automation user, but only while it is still OPEN, nobody
    else owns it and the trigger still holds, all read under the alert's row lock. Otherwise it
    defers: the rest of the rule does not run, and the alert is considered again later."""

    config_class = DispositionActionConfig

    def check(self, trigger: AlertAutomationTrigger) -> None:
        if self.config.comment:
            check_template(self.config.comment, trigger)

    def run(self, context: ActionContext) -> ActionOutcome:
        comment = context.render(self.config.comment) if self.config.comment else None
        detail = {"disposition": self.config.disposition, "comment": comment}
        if context.dry_run:
            return ActionOutcome(ActionStatus.DONE, detail)

        result = set_dispositions([context.alert_uuid], self.config.disposition, AUTOMATION_ACTOR,
                                  user_comment=comment, system=True, expected_dispositions={DISPOSITION_OPEN},
                                  eligible=context.trigger.still_holds)
        if context.alert_uuid in result.permitted:
            return ActionOutcome(ActionStatus.DONE, detail)

        if context.alert_uuid in result.skipped:
            reason = f"{result.skipped[context.alert_uuid]} owns the alert"
        elif context.alert_uuid in result.unexpected:
            reason = f"the alert's disposition is now {result.unexpected[context.alert_uuid]}"
        elif context.alert_uuid in result.ineligible:
            reason = "the trigger no longer holds"
        else:
            reason = "the alert was not dispositioned"

        return ActionOutcome(ActionStatus.DEFERRED, detail, reason)


class RemediateActionConfig(ActionConfig):
    targets: Literal["evidence", "same_message"] = Field(..., description="evidence: the observables the trigger's evidence names; same_message: every email_delivery in the alert whose message-id matches one of theirs")


def _message_id(email_delivery: str) -> Optional[str]:
    try:
        message_id, _ = parse_email_delivery(email_delivery)
    except ValueError:
        # not message-id|mailbox: there is no message to match, which is the answer
        return None

    return (normalize_message_id(message_id) or "").lower() or None


class RemediateAction(AlertAutomationAction):
    """Queues ACE's own removal of the observables it targets, as the automation user, skipping a
    target whose removal is already under way or found nothing to remove (removal_covers())."""

    config_class = RemediateActionConfig

    def _observables(self, context: ActionContext, observables: list[Observable]) -> list[Observable]:
        evidence = {(observable_type, value.lower())
                    for observable_type, value in context.trigger.evidence_observables(context.evidence)}
        if self.config.targets == "evidence":
            return [o for o in observables if (o.type, o.value.lower()) in evidence]

        hierarchy = get_type_hierarchy()
        message_ids = {_message_id(value) for observable_type, value in evidence
                       if hierarchy.is_subtype(observable_type, F_EMAIL_DELIVERY)} - {None}
        return [o for o in observables if o.is_a(F_EMAIL_DELIVERY) and _message_id(o.value) in message_ids]

    def run(self, context: ActionContext) -> ActionOutcome:
        alert = get_alert_by_uuid(context.alert_uuid)
        if alert is None:
            raise RuntimeError(f"alert {context.alert_uuid} does not exist")

        observables = self._observables(context, alert.root_analysis.all_observables)
        if not observables:
            return ActionOutcome(ActionStatus.SKIPPED, reason="the alert has no observable to remediate")

        targets: list[RemediationTarget] = []
        untargeted: list[str] = []
        for observable in observables:
            observable_targets = get_observable_remediation_targets(observable)
            if not observable_targets:
                # ACE's removal is the backstop for an external product's; without a target there is none
                untargeted.append(f"{observable.type}:{observable.value}")
                logging.error(f"alert automation rule {context.rule_name}: no remediation target for "
                              f"{observable.type} {observable.value} in alert {context.alert_uuid}, so ACE "
                              f"can't remove it; check the remediation configuration for {observable.type}",
                              extra={"rule": context.rule_name, "alert_uuid": context.alert_uuid,
                                     "action": self.config.type, "mode": context.mode,
                                     "observable": f"{observable.type}:{observable.value}"})
            targets.extend(t for t in observable_targets if t not in targets)

        queued: list[str] = []
        covered: list[str] = []
        automation_user_id = get_config().global_settings.automation_user_id
        for target in targets:
            name = f"{target.remediator_name}:{target.observable_type}:{target.observable_value}"
            if removal_covers(target):
                covered.append(name)
                continue

            if not context.dry_run:
                target.queue_remediation(RemediationAction.REMOVE, automation_user_id)
            queued.append(name)

        return ActionOutcome(ActionStatus.DONE, {"queued": queued, "covered": covered, "untargeted": untargeted})


class CommentActionConfig(ActionConfig):
    comment: str = Field(..., min_length=1, description="the comment; a template of the trigger's fields")


class CommentAction(AlertAutomationAction):
    """Adds a comment to the alert as the automation user."""

    config_class = CommentActionConfig

    def check(self, trigger: AlertAutomationTrigger) -> None:
        check_template(self.config.comment, trigger)

    def run(self, context: ActionContext) -> ActionOutcome:
        comment = normalize_comment(context.render(self.config.comment))
        if not context.dry_run:
            get_db().add(Comment(user_id=get_config().global_settings.automation_user_id, uuid=context.alert_uuid,
                                 comment=comment))
            touch_alerts([context.alert_uuid])
            get_db().commit()
            submit_index_task(context.alert_uuid)

        return ActionOutcome(ActionStatus.DONE, {"comment": comment})
