import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from aceapi_v2.alerts.service import load_observable
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import require_permission
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

# register_integration_router() authenticates every route; each one still needs its own
# permission gate
router = APIRouter()


class ExampleActionResult(BaseModel):
    alert_uuid: str
    observable: str


@router.post("/alerts/{alert_uuid}/observables/{observable_uuid}/example", response_model=ExampleActionResult)
async def example_observable_action(
    alert_uuid: str,
    observable_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> ExampleActionResult:
    """The example observable action: describes the observable it was clicked on."""
    # loading an alert reads its files and the database through the synchronous session, so it
    # runs in a worker thread
    observable = await run_db_in_thread(load_observable, alert_uuid, observable_uuid)
    logger.info("AUDIT: user %s ran the example action on observable %s in alert %s",
                auth.auth_name, observable, alert_uuid)
    return ExampleActionResult(alert_uuid=alert_uuid, observable=str(observable))
