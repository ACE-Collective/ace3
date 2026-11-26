"""Shared fixtures for the alert automation tests: a probe, alerts holding email deliveries, the
probe's confirmations, and rules built from config the way the service loads them."""

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select, text, update

from saq.alert_automation.rules import Rule, load_rule, sweep_rule
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.configuration.schema import AlertAutomationRuleConfig, ExternalRemediationProbeConfig
from saq.constants import F_EMAIL_DELIVERY
from saq.database.model import Alert, AlertAutomationRun, Comment, ExternalRemediationCheck, Remediation, User
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.remediation.target import ObservableRemediationInterface, RemediationTarget, register_observable_remediation_interface
from tests.saq.helpers import create_root_analysis

PROBE = "unittest_probe"
RULE = "confirmed_removal"
MESSAGE_ID = "<automation-test@example.com>"
DELIVERY_ALICE = f"{MESSAGE_ID}|alice@example.com"
DELIVERY_BOB = f"{MESSAGE_ID}|bob@example.com"
OTHER_MESSAGE = "<another-message@example.com>|alice@example.com"

DISPOSITION_COMMENT = "{probe} confirmed removal of {observable} at {event_time}; ACE removal queued as a backstop"
ACTIONS = [
    {"type": "disposition", "disposition": "DELIVERY", "comment": DISPOSITION_COMMENT},
    {"type": "remediate", "targets": "same_message"},
]


@pytest.fixture(autouse=True)
def probe():
    get_config().add_external_remediation_probe_config(PROBE, ExternalRemediationProbeConfig(
        name=PROBE, observable_type=F_EMAIL_DELIVERY, python_module="unused", python_class="Unused"))


class _Targets(ObservableRemediationInterface):
    def get_remediation_targets(self, observable):
        return [RemediationTarget("test", observable.type, observable.value)]


@pytest.fixture
def remediable():
    """email_delivery observables have a remediation target."""
    register_observable_remediation_interface(F_EMAIL_DELIVERY, _Targets())


def rule_config(mode: str = "enforce", actions: list[dict] | None = None, name: str = RULE, **trigger) -> dict:
    return {"name": name, "enabled": True, "mode": mode,
            "trigger": {"type": "external_remediation_confirmed", "probe": PROBE, "max_age_hours": 120, **trigger},
            "actions": ACTIONS if actions is None else actions}


def make_rule(mode: str = "enforce", actions: list[dict] | None = None, **trigger) -> Rule:
    return load_rule(AlertAutomationRuleConfig.model_validate(rule_config(mode, actions, **trigger)))


def sweep(rule: Rule, max_attempts: int = 5) -> None:
    sweep_rule(rule, batch_size=100, max_attempts=max_attempts)


def make_root(*deliveries: str) -> RootAnalysis:
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now())
    root.initialize_storage()
    for delivery in deliveries:
        root.add_observable_by_spec(F_EMAIL_DELIVERY, delivery)
    root.save()
    return root


def make_alert(*deliveries: str) -> str:
    root = make_root(*deliveries)
    ALERT(root)
    return root.uuid


def confirm(alert_uuid: str, delivery: str, hours_ago: int = 0, probe_name: str = PROBE) -> None:
    """A check row of the probe, CONFIRMED hours_ago by the database's clock."""
    check = ExternalRemediationCheck(probe_name=probe_name, observable_type=F_EMAIL_DELIVERY, observable_value=delivery,
                                     alert_uuid=alert_uuid, status="COMPLETED", result="CONFIRMED", max_retries=1,
                                     deadline=datetime.now() + timedelta(days=1))
    db = get_db()
    db.add(check)
    db.flush()
    db.execute(update(ExternalRemediationCheck).where(ExternalRemediationCheck.id == check.id).values(
        update_time=func.DATE_SUB(func.NOW(), text(f"INTERVAL {int(hours_ago)} HOUR"))))
    db.commit()


def set_alert(alert_uuid: str, **values) -> None:
    db = get_db()
    db.execute(update(Alert).where(Alert.uuid == alert_uuid).values(**values))
    db.commit()


def analyst_id() -> int:
    return get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()


def runs(alert_uuid: str) -> list[AlertAutomationRun]:
    db = get_db()
    db.expire_all()
    return db.execute(select(AlertAutomationRun).where(AlertAutomationRun.alert_uuid == alert_uuid)
                      .order_by(AlertAutomationRun.id)).scalars().all()


def removals() -> dict[str, int]:
    """observable value -> user id, of every queued removal."""
    db = get_db()
    db.expire_all()
    return {key: user_id for key, user_id in db.execute(
        select(Remediation.key, Remediation.user_id).where(Remediation.action == "remove"))}


def comments(alert_uuid: str) -> list[tuple[int, str]]:
    db = get_db()
    db.expire_all()
    return [(user_id, comment) for user_id, comment in db.execute(
        select(Comment.user_id, Comment.comment).where(Comment.uuid == alert_uuid).order_by(Comment.comment_id))]
