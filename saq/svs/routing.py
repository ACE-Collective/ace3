"""The SVS marker router (docs/SVS_RUNS.md, *Attribution*): routes an alert whose every detection is
attributed to a test run into the test queue (svs.queue).

It is an `alert_routers` entry (etc/saq.default.yaml) with a priority ahead of the built-in
detection-queue router, so a YARA rule with a `queue` meta that matched a dropped test file does not
take the alert before SVS sees it [FR-2]. A marker that agrees with its run is stronger evidence than
any configured queue, so it may override one.

At both stages it attributes the alert (saq/svs/attribution.py) and writes its svs_attributions rows,
in a transaction of its own. It never changes the tree: the svs_test and svs:marker_mismatch tags and
the mismatch detection come from the svs_alert_tagger module, which evaluates the alert the same way
[FR-3]. At POST_ANALYSIS an alert it routed that is no longer fully attributed goes back to the queue
it came from. The engine moves an existing alert only while it is OPEN and nobody has taken it.

A queue a person set through SVS (associating or disassociating the alert, recorded with the router
name svs_manual) is never overridden: while that is the alert's latest move, the router still
attributes it but holds it where it is, which also keeps any lower-priority router from moving it.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import select

from saq.alert_routing.router import AlertRouter, RouteDecision, RouteStage
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_OPEN
from saq.database.model import Alert, AlertQueueChange
from saq.database.private_session import private_transaction
from saq.svs.attribution import (
    Evaluation,
    alert_event_time,
    attribution_open,
    evaluate,
    log_sightings,
    write_attributions,
)
from saq.svs import maintenance
from saq.svs.constants import SVS_MANUAL_ROUTER, SVSStatus

REASON_ROUTED = "every detection is attributed to SVS test run {run}"
REASON_NO_LONGER_ATTRIBUTED = "no longer attributed to an SVS test run"
REASON_HELD = "queue set by hand in SVS"
REASON_MAINTENANCE = "in SVS maintenance window {window} on test host {host}"

DECISION_ROUTED = "routed"
DECISION_PARTIAL = "partial"
DECISION_MISMATCH = "mismatch"
DECISION_NONE = "none"
DECISION_MOVED_BACK = "moved back"
DECISION_HELD = "held (manual)"
DECISION_MAINTENANCE = "maintenance"


@dataclass(frozen=True)
class _AlertRow:
    id: int
    queue: str
    disposition: Optional[str]
    owner_id: Optional[int]
    insert_date: datetime
    # who put the alert in its queue, when this router did
    last_change: Optional[tuple[str, str, str]] = None   # (router, from_queue, to_queue)


def _alert_row(alert_uuid: str) -> Optional[_AlertRow]:
    with private_transaction() as session:
        alert = session.execute(
            select(Alert.id, Alert.queue, Alert.disposition, Alert.owner_id, Alert.insert_date)
            .where(Alert.uuid == alert_uuid)).first()
        if alert is None:
            return None
        change = session.execute(
            select(AlertQueueChange.router, AlertQueueChange.from_queue, AlertQueueChange.to_queue)
            .where(AlertQueueChange.alert_id == alert.id)
            .order_by(AlertQueueChange.id.desc()).limit(1)).first()
        return _AlertRow(alert.id, alert.queue, alert.disposition, alert.owner_id, alert.insert_date,
                         tuple(change) if change is not None else None)


class MarkerRouter(AlertRouter):

    def route(self, root, stage: RouteStage) -> Optional[RouteDecision]:
        if not attribution_open():
            return None

        alert = None
        if stage == RouteStage.POST_ANALYSIS:
            alert = _alert_row(root.uuid)
            if alert is None:
                return None

        evaluation = evaluate(root, alert_event_time(root, alert.insert_date if alert else datetime.now()))
        log_sightings(root.uuid, evaluation, stage.value)
        write_attributions(root.uuid, evaluation)
        # confirmed by the correlation pass that leaves no analysis delayed: until then a module may
        # still find a marker in the alert's analysis details
        maintenance.record_alert(root.uuid, evaluation.maintenance.id if evaluation.maintenance else None,
                                 confirmed=stage == RouteStage.POST_ANALYSIS and not root.delayed)

        queue = get_config().svs.queue
        if alert is not None and alert.last_change is not None and alert.last_change[0] == SVS_MANUAL_ROUTER:
            decision = RouteDecision(queue=alert.queue, reason=REASON_HELD)
            outcome = DECISION_HELD
        elif evaluation.routed:
            run = evaluation.runs[0].uuid if evaluation.runs else None
            decision = RouteDecision(queue=queue, reason=REASON_ROUTED.format(run=run))
            outcome = DECISION_ROUTED
        elif evaluation.maintenance is not None:
            decision = RouteDecision(queue=queue, reason=REASON_MAINTENANCE.format(
                window=evaluation.maintenance.uuid, host=evaluation.maintenance.target.host))
            outcome = DECISION_MAINTENANCE
        elif alert is not None and self._routed_here(alert, queue):
            decision = RouteDecision(queue=alert.last_change[1], reason=REASON_NO_LONGER_ATTRIBUTED)
            outcome = DECISION_MOVED_BACK
        else:
            decision = None
            outcome = {SVSStatus.PARTIAL: DECISION_PARTIAL, SVSStatus.MISMATCH: DECISION_MISMATCH}.get(
                evaluation.status, DECISION_NONE)

        self._log(root.uuid, stage, evaluation, outcome, decision, alert)
        return decision

    def _routed_here(self, alert: _AlertRow, queue: str) -> bool:
        """The alert is in the test queue because this router put it there."""
        return (alert.queue == queue and alert.last_change is not None
                and alert.last_change[0] == self.name and alert.last_change[2] == queue)

    def _log(self, alert_uuid: str, stage: RouteStage, evaluation: Evaluation, outcome: str,
             decision: Optional[RouteDecision], alert: Optional[_AlertRow]) -> None:
        if (outcome == DECISION_NONE and not evaluation.judgements and not evaluation.attributions
                and evaluation.maintenance is None):
            # nothing in this alert has to do with a run
            return

        if decision is not None and alert is not None and decision.queue != alert.queue:
            owned = (alert.owner_id is not None
                     and alert.owner_id != get_config().global_settings.automation_user_id)
            if owned or alert.disposition != DISPOSITION_OPEN:
                outcome = f"not moved because {'owned' if owned else 'closed'}"

        logging.info("svs router decision on alert %s at %s: %s", alert_uuid, stage.value, outcome,
                     extra={**self._run_fields(evaluation), "alert_uuid": alert_uuid, "stage": stage.value,
                            "decision": outcome, "queue": decision.queue if decision else None,
                            "confidence": evaluation.confidence.value if evaluation.confidence else None,
                            "status": evaluation.status.value if evaluation.status else None})

    @staticmethod
    def _run_fields(evaluation: Evaluation) -> dict:
        """The run a decision is about: the one it attributes to, or else the run of a marker in the
        alert (a mismatch on another host, say), or else just the marker; or the maintenance window."""
        if evaluation.maintenance is not None:
            return evaluation.maintenance.log_fields()
        if evaluation.runs:
            return evaluation.runs[0].log_fields()
        for judgement in evaluation.judgements:
            if judgement.run is not None:
                return judgement.run.log_fields()
        if evaluation.judgements:
            return {"svs_marker": evaluation.judgements[0].marker}
        return {}
