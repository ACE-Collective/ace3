"""SVS test runs service for ACE API v2 (docs/SVS_RUNS.md, *Registering a run*; docs/SVS_API.md).

Synchronous; the router runs each function through run_db_in_thread. saq.svs.runs owns the runs
and their lifecycle; this maps its errors to HTTP.
"""

from fastapi import HTTPException

from aceapi_v2.svs.runs.schemas import RunExecutedRequest, RunLifecycle, RunRegistrationRequest, RunTarget
from saq.database.model import SVSRun
from saq.svs import runs
from saq.svs.refusals import Caller


def _lifecycle(run: SVSRun) -> RunLifecycle:
    return RunLifecycle(
        run_id=run.uuid, marker=run.marker, state=run.state, test_guid=run.test_guid,
        targets=[RunTarget(hostname=t.hostname, username=t.username, host=t.host, fqdn=t.fqdn, user=t.user)
                 for t in run.targets],
        observation_seconds=run.observation_seconds, attribution_seconds=run.attribution_seconds,
        created_at=run.created_at, started_at=run.started_at, observation_ends_at=run.observation_ends_at,
        attribution_ends_at=run.attribution_ends_at, error_reason=run.error_reason, close_reason=run.close_reason)


def _call(fn, *args, **kwargs) -> RunLifecycle:
    try:
        return _lifecycle(fn(*args, **kwargs))
    except runs.UnknownRun as e:
        raise HTTPException(status_code=404, detail=str(e))
    except runs.RunStateConflict as e:
        raise HTTPException(status_code=409, detail={"message": str(e), "state": e.state})


def register(body: RunRegistrationRequest, caller: Caller) -> RunLifecycle:
    registration = runs.Registration(
        test_guid=body.test_guid,
        targets=[runs.TargetSpec(hostname=t.hostname, username=t.username) for t in body.targets],
        launcher=body.launcher, batch_id=body.batch_id, extra=body.extra)
    try:
        return _lifecycle(runs.register(registration, caller))
    except runs.InvalidRegistration as e:
        raise HTTPException(status_code=422, detail=str(e))
    except runs.RegistrationRefused as e:
        raise HTTPException(status_code=403, detail={"message": "registration refused", "reasons": e.reasons})


def start(run_id: str, caller: Caller) -> RunLifecycle:
    return _call(runs.start, run_id, caller)


def executed(run_id: str, body: RunExecutedRequest, caller: Caller) -> RunLifecycle:
    return _call(runs.executed, run_id, caller, body.exit_code, body.error)


def cancel(run_id: str, caller: Caller) -> RunLifecycle:
    return _call(runs.cancel, run_id, caller)
