"""One alert's side of SVS for ACE API v2 (docs/SVS_RUNS.md, *Test alerts in the alert list and on
the alert page*).

Synchronous; the router runs each function through run_db_in_thread. saq.svs.alert_status derives
what SVS makes of the alert, and saq.svs.association gives it back to analysts.
"""

from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select

from aceapi_v2.svs.alerts.schemas import (
    AlertDisassociation,
    AlertDisassociationRequest,
    AlertSVS,
    AlertSVSDetection,
    AlertSVSMismatch,
    AlertSVSRun,
)
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.svs import association
from saq.svs.alert_status import RunRef, alert_svs_view
from saq.util.uuid import UUID_REGEX


def _alert_uuid(alert_uuid: str) -> str:
    alert_uuid = alert_uuid.lower()
    if not UUID_REGEX.fullmatch(alert_uuid):
        raise HTTPException(status_code=400, detail="invalid alert uuid")
    return alert_uuid


def _run(ref: Optional[RunRef]) -> Optional[AlertSVSRun]:
    if ref is None:
        return None
    return AlertSVSRun(run_id=ref.uuid, state=ref.state, test_guid=ref.test_guid, test_name=ref.test_name)


def get_alert_svs(alert_uuid: str) -> AlertSVS:
    """404 for an unknown alert; an alert SVS never touched has a null status."""
    alert_uuid = _alert_uuid(alert_uuid)
    alert_id = get_db().execute(select(Alert.id).where(Alert.uuid == alert_uuid)).scalar()
    if alert_id is None:
        raise HTTPException(status_code=404, detail=f"alert {alert_uuid} not found")

    view = alert_svs_view(alert_id, alert_uuid)
    if view is None:
        return AlertSVS(alert_uuid=alert_uuid)
    return AlertSVS(
        alert_uuid=alert_uuid,
        svs_status=view.status.value if view.status else None,
        runs=[_run(ref) for ref in view.runs],
        detections=[AlertSVSDetection(content_hash=content_hash, run_ids=list(run_ids))
                    for content_hash, run_ids in view.detections.items()],
        mismatches=[AlertSVSMismatch(marker=m.marker, result=m.result, run=_run(m.run)) for m in view.mismatches])


def disassociate_alert(alert_uuid: str, body: AlertDisassociationRequest | None, user_id: int | None, actor: str,
                       not_a_test: bool) -> AlertDisassociation:
    """422 for a config key (the change records who made it), 404 for an unknown alert, 409 when
    nothing holds it, or for not-a-test on an alert that isn't TEST?."""
    if user_id is None:
        raise HTTPException(status_code=422, detail="this action records who took it: it requires a user's API key or session")
    alert_uuid = _alert_uuid(alert_uuid)
    reason = body.reason if body is not None else None
    try:
        result = association.disassociate_alert(alert_uuid, user_id, actor, reason, not_a_test=not_a_test)
    except association.UnknownAlert as e:
        raise HTTPException(status_code=404, detail=str(e))
    except association.AssociationConflict as e:
        raise HTTPException(status_code=409, detail=str(e))

    return AlertDisassociation(alert_uuid=result.alert_uuid, run_ids=list(result.runs), svs_status=result.svs_status,
                               queue=result.queue, moved=result.moved, reopened=result.reopened)
