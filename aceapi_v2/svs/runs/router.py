"""SVS test runs router for ACE API v2 (docs/SVS_RUNS.md, *Registering a run*; docs/SVS_API.md).

The launcher's lifecycle calls: register a run, start it, report how the test executed, cancel it.
Every call needs svs:run_register [ART-2]. A registration against a host that is not a test host is
refused with 403 and alerts (docs/SVS_RUNS.md, *Refused registrations*).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.svs.runs import service
from aceapi_v2.svs.runs.schemas import RunExecutedRequest, RunLifecycle, RunRegistrationRequest
from aceapi_v2.sync import run_db_in_thread
from saq.svs.refusals import Caller

router = APIRouter(dependencies=[Security(get_current_auth)])

RegisterAuth = Annotated[ApiAuthResult, Depends(require_permission("svs", "run_register"))]


def _caller(auth: ApiAuthResult, request: Request) -> Caller:
    return Caller(name=auth.auth_name, user_id=auth.auth_user_id, key_id=auth.key_id,
                  address=request.client.host if request.client is not None else None)


@router.post("/", response_model=RunLifecycle, status_code=201)
async def register_run(body: RunRegistrationRequest, auth: RegisterAuth, request: Request) -> RunLifecycle:
    """Register a run in state created and get its marker. 422 for a test that is not in the
    catalog, a target whose platform the test doesn't support, or an extra that is too large; 403
    when a target is not a test host or not a user the host lists, which also alerts."""
    return await run_db_in_thread(service.register, body, _caller(auth, request))


@router.post("/{run_id}/start", response_model=RunLifecycle)
async def start_run(run_id: str, auth: RegisterAuth, request: Request) -> RunLifecycle:
    """created -> started: the windows start now. 409 in any other state."""
    return await run_db_in_thread(service.start, run_id, _caller(auth, request))


@router.post("/{run_id}/executed", response_model=RunLifecycle)
async def run_executed(run_id: str, body: RunExecutedRequest, auth: RegisterAuth, request: Request) -> RunLifecycle:
    """Report how the test executed on a started run. A non-zero exit code or an error moves it to
    error. 409 in any other state."""
    return await run_db_in_thread(service.executed, run_id, body, _caller(auth, request))


@router.post("/{run_id}/cancel", response_model=RunLifecycle)
async def cancel_run(run_id: str, auth: RegisterAuth, request: Request) -> RunLifecycle:
    """created or started -> canceled. A canceled run keeps attributing until its attribution window
    ends; one canceled before it started is closed at once. 409 in any other state."""
    return await run_db_in_thread(service.cancel, run_id, _caller(auth, request))
