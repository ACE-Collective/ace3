"""One alert's side of SVS for ACE API v2 (docs/SVS_RUNS.md, *Test alerts in the alert list and on
the alert page*; docs/SVS_API.md), mounted under /alerts.

What SVS makes of the alert is read with alert:read. Giving a test alert back to analysts, by
disassociating it from every run that holds it or marking a TEST? alert not a test, needs
alert:write: it is the analyst's correction of an alert they triage, where the run-scoped
equivalents under /svs/runs need svs:run_manage.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.svs.alerts import service
from aceapi_v2.svs.alerts.schemas import AlertDisassociation, AlertDisassociationRequest, AlertSVS
from aceapi_v2.sync import run_db_in_thread

router = APIRouter(dependencies=[Security(get_current_auth)])

ReadAuth = Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))]
WriteAuth = Annotated[ApiAuthResult, Depends(require_permission("alert", "write"))]


@router.get("/{alert_uuid}/svs", response_model=AlertSVS)
async def get_alert_svs(alert_uuid: str, auth: ReadAuth) -> AlertSVS:
    """The alert's SVS status, the runs it is attributed to, which of its detections each holds,
    and the markers in it that disagree with their run. 404 for an unknown alert."""
    return await run_db_in_thread(service.get_alert_svs, alert_uuid)


@router.post("/{alert_uuid}/svs/disassociate", response_model=AlertDisassociation)
async def disassociate_alert(alert_uuid: str, auth: WriteAuth,
                             body: AlertDisassociationRequest | None = None) -> AlertDisassociation:
    """Disassociate the alert from every run that holds it: each run's attributions are removed by
    the caller and the router never attributes the alert to those runs again. The alert is given
    back: OPEN if it was SIMULATED, and back in the queue SVS took it from when it is OPEN and
    nobody else has taken it. 409 when no run holds it."""
    return await run_db_in_thread(service.disassociate_alert, alert_uuid, body, auth, False)


@router.post("/{alert_uuid}/svs/not-a-test", response_model=AlertDisassociation)
async def mark_not_a_test(alert_uuid: str, auth: WriteAuth,
                          body: AlertDisassociationRequest | None = None) -> AlertDisassociation:
    """Disassociate a TEST? alert, one its runs hold by context alone, as not a test (409 otherwise)."""
    return await run_db_in_thread(service.disassociate_alert, alert_uuid, body, auth, True)
