"""The alert_automation_runs table: what each rule did, or would have done, to each alert
(docs/ALERT_AUTOMATION.md, *Runs and modes*). Each write is its own short private transaction, so
a run is recorded whatever the caller's get_db() session holds."""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

from sqlalchemy import delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError

from saq.configuration.config import get_config
from saq.constants import DISPOSITION_OPEN
from saq.database.model import Alert, AlertAutomationRun
from saq.database.private_session import private_transaction

RUN_PENDING = "pending"
RUN_DONE = "done"
RUN_FAILED = "failed"

# an action's status in a run; done and skipped are final, failed is final once its attempts ran out
ACTION_PENDING = "pending"
ACTION_DONE = "done"
ACTION_SKIPPED = "skipped"
ACTION_FAILED = "failed"
ACTION_FINISHED = (ACTION_DONE, ACTION_SKIPPED)

# how long a sweep has a run it claimed before another sweep may claim it: longer than a rule's
# actions take, so it only runs out when the sweep that had the run died
RUN_LEASE_SECONDS = 600


@dataclass
class Run:
    id: int
    rule_name: str
    alert_uuid: str
    mode: str
    status: str
    evidence: dict
    # one dict per action of the rule, in its order: type, status, attempts, detail, reason
    actions: list[dict]
    insert_date: Optional[datetime] = None
    # the version this sweep claimed, or read when it has not claimed the run
    version: int = 0

    @property
    def started(self) -> bool:
        """Whether an action of this run has finished: from then on the alert is in the state the
        run put it in, so the run goes on whatever its disposition is."""
        return any(action["status"] in ACTION_FINISHED for action in self.actions)


@dataclass(frozen=True)
class AlertState:
    disposition: Optional[str]
    owner_id: Optional[int]
    disposition_user_id: Optional[int] = None


def _run(row: AlertAutomationRun) -> Run:
    return Run(id=row.id, rule_name=row.rule_name, alert_uuid=row.alert_uuid, mode=row.mode, status=row.status,
               evidence=json.loads(row.evidence), actions=json.loads(row.actions), insert_date=row.insert_date,
               version=row.version)


def _lease_expires():
    return func.DATE_ADD(func.NOW(), text(f"INTERVAL {RUN_LEASE_SECONDS} SECOND"))


def _unclaimed():
    return or_(AlertAutomationRun.lease_expires.is_(None), AlertAutomationRun.lease_expires < func.NOW())


def claim_run(rule_name: str, alert_uuid: str, mode: str, evidence: dict, action_types: list[str]) -> Optional[Run]:
    """Records a new run, claimed by this sweep, before any of its actions runs. None when the alert
    already has a run of this rule and mode: another sweep got there first, and this one leaves the
    alert alone."""
    actions = [{"type": action_type, "status": ACTION_PENDING, "attempts": 0, "detail": {}, "reason": None}
               for action_type in action_types]
    try:
        with private_transaction() as session:
            row = AlertAutomationRun(rule_name=rule_name, alert_uuid=alert_uuid, mode=mode, status=RUN_PENDING,
                                     evidence=json.dumps(evidence), actions=json.dumps(actions), version=1,
                                     lease_expires=_lease_expires())
            session.add(row)
            session.flush()
            run_id = row.id
    except IntegrityError:
        # the unique key on (rule_name, alert_uuid, mode) is the backstop against two sweeps
        logging.info("alert automation rule %s already has a %s run on alert %s", rule_name, mode, alert_uuid,
                     extra={"rule": rule_name, "alert_uuid": alert_uuid, "mode": mode})
        return None

    return Run(id=run_id, rule_name=rule_name, alert_uuid=alert_uuid, mode=mode, status=RUN_PENDING,
               evidence=evidence, actions=actions, version=1)


def take_run(run: Run) -> bool:
    """Claims a pending run read by pending_runs() for this sweep. False when another sweep claimed
    or changed it since it was read: that sweep has it, and this one leaves it alone."""
    with private_transaction() as session:
        result = session.execute(
            update(AlertAutomationRun)
            .where(AlertAutomationRun.id == run.id, AlertAutomationRun.version == run.version,
                   AlertAutomationRun.status == RUN_PENDING, _unclaimed())
            .values(version=AlertAutomationRun.version + 1, lease_expires=_lease_expires()))
        if result.rowcount != 1:
            return False

    run.version += 1
    return True


def save_run(run: Run, hold: bool = False) -> bool:
    """Records the run as this sweep has it. hold keeps the claim, for a run whose next action runs
    now; otherwise the run is left to a later sweep. False when another sweep claimed the run since
    this one did, and nothing was written."""
    with private_transaction() as session:
        result = session.execute(
            update(AlertAutomationRun)
            .where(AlertAutomationRun.id == run.id, AlertAutomationRun.version == run.version)
            .values(status=run.status, actions=json.dumps(run.actions), update_time=func.now(),
                    lease_expires=_lease_expires() if hold else None))
        return result.rowcount == 1


def delete_run(run: Run) -> bool:
    """Removes a run none of whose actions finished, so the rule considers the alert again. False
    when another sweep claimed the run since this one did, and it was kept."""
    with private_transaction() as session:
        result = session.execute(delete(AlertAutomationRun).where(
            AlertAutomationRun.id == run.id, AlertAutomationRun.version == run.version))
        return result.rowcount == 1


def pending_runs(rule_name: str, mode: str, after_id: int, limit: int) -> list[Run]:
    """The rule's runs with an action still to be retried that no sweep has claimed, in id order
    after after_id."""
    with private_transaction() as session:
        rows = session.execute(
            select(AlertAutomationRun)
            .where(AlertAutomationRun.rule_name == rule_name, AlertAutomationRun.mode == mode,
                   AlertAutomationRun.status == RUN_PENDING, AlertAutomationRun.id > after_id, _unclaimed())
            .order_by(AlertAutomationRun.id).limit(limit)).scalars().all()
        return [_run(row) for row in rows]


def alerts_with_runs(rule_name: str, mode: str, alert_uuids: list[str]) -> set[str]:
    """Those of the alerts the rule already has a run on, in this mode."""
    if not alert_uuids:
        return set()

    with private_transaction() as session:
        return set(session.execute(
            select(AlertAutomationRun.alert_uuid)
            .where(AlertAutomationRun.rule_name == rule_name, AlertAutomationRun.mode == mode,
                   AlertAutomationRun.alert_uuid.in_(alert_uuids))).scalars())


def alert_states(alert_uuids: list[str]) -> dict[str, AlertState]:
    """alert uuid -> its disposition and owner, for those of the alerts that exist."""
    if not alert_uuids:
        return {}

    with private_transaction() as session:
        return {alert_uuid: AlertState(disposition, owner_id, disposition_user_id)
                for alert_uuid, disposition, owner_id, disposition_user_id in session.execute(
                    select(Alert.uuid, Alert.disposition, Alert.owner_id, Alert.disposition_user_id)
                    .where(Alert.uuid.in_(alert_uuids)))}


def list_runs(rule_name: Optional[str] = None, mode: Optional[str] = None, since: Optional[datetime] = None,
              limit: int = 100) -> list[Run]:
    """The most recent runs, newest first."""
    statement = select(AlertAutomationRun).order_by(AlertAutomationRun.id.desc()).limit(limit)
    if rule_name is not None:
        statement = statement.where(AlertAutomationRun.rule_name == rule_name)
    if mode is not None:
        statement = statement.where(AlertAutomationRun.mode == mode)
    if since is not None:
        statement = statement.where(AlertAutomationRun.insert_date >= since)

    with private_transaction() as session:
        return [_run(row) for row in session.execute(statement).scalars().all()]


def _dry_runs_with_alerts(rule_name: str, since: Optional[datetime],
                          batch_size: int = 1000) -> Iterator[tuple[Run, Optional[AlertState]]]:
    """The rule's dry runs, each with what its alert looks like now (None once it is deleted), in
    id order, a batch at a time."""
    after_id = 0
    while True:
        statement = (
            select(AlertAutomationRun, Alert.disposition, Alert.owner_id, Alert.disposition_user_id, Alert.id)
            .outerjoin(Alert, Alert.uuid == AlertAutomationRun.alert_uuid)
            .where(AlertAutomationRun.rule_name == rule_name, AlertAutomationRun.mode == "dry_run",
                   AlertAutomationRun.id > after_id)
            .order_by(AlertAutomationRun.id).limit(batch_size))
        if since is not None:
            statement = statement.where(AlertAutomationRun.insert_date >= since)

        with private_transaction() as session:
            rows = [(_run(row), disposition, owner_id, disposition_user_id, alert_id)
                    for row, disposition, owner_id, disposition_user_id, alert_id in session.execute(statement)]

        for run, disposition, owner_id, disposition_user_id, alert_id in rows:
            yield run, (AlertState(disposition, owner_id, disposition_user_id) if alert_id is not None else None)

        if len(rows) < batch_size:
            return

        after_id = rows[-1][0].id


@dataclass
class DryRunReport:
    """How a rule's dry-run decisions compare with what happened to each alert afterwards."""
    rule_name: str
    runs: int = 0
    # analysts gave the alert the disposition the dry run decided on
    same: int = 0
    # analysts gave it another one: (alert uuid, decided, actual)
    different: list[tuple[str, str, str]] = field(default_factory=list)
    still_open: int = 0
    # ACE itself dispositioned it (an enforce run of a rule, SVS)
    automated: int = 0
    # the alert was deleted
    missing: int = 0
    # the dry run recorded no disposition (the rule has no disposition action, or it did not get that far)
    undecided: int = 0


def _decided_disposition(run: Run) -> Optional[str]:
    for action in run.actions:
        if action["status"] == ACTION_DONE and action["detail"].get("disposition"):
            return action["detail"]["disposition"]

    return None


def dry_run_report(rule_name: str, since: Optional[datetime] = None) -> DryRunReport:
    report = DryRunReport(rule_name)
    automation_user_id = get_config().global_settings.automation_user_id
    for run, alert in _dry_runs_with_alerts(rule_name, since):
        report.runs += 1
        decided = _decided_disposition(run)
        if decided is None:
            report.undecided += 1
        elif alert is None:
            report.missing += 1
        elif alert.disposition in (None, DISPOSITION_OPEN):
            report.still_open += 1
        elif alert.disposition_user_id == automation_user_id:
            report.automated += 1
        elif alert.disposition == decided:
            report.same += 1
        else:
            report.different.append((run.alert_uuid, decided, alert.disposition))

    return report
