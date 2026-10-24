"""Hunt validation router (ACE API v2).

POST /api/v2/hunt/validate: the validate-hunt CLI checks, and optionally runs, a hunt package
against this node (aceapi_v2/hunt/service.py). It answers in the shape the CLI reads rather than
FastAPI's: 200 {"valid": true, ...} and 400 {"valid": false, "error": ...}. Needs hunt:write.
"""

import json
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, Request, Security
from fastapi.responses import Response

from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.hunt.audit import ValidationOutcome, audit_fields, failure_audit_fields, write_audit_record
from aceapi_v2.hunt.schemas import HuntValidationRequest, HuntValidationResult
from aceapi_v2.hunt.service import validate_hunt as run_validation
from aceapi_v2.sync import run_db_in_thread
from saq.json_encoding import _JSONEncoder

router = APIRouter(dependencies=[Security(get_current_auth)])


def _json(body: dict, status: int) -> Response:
    # sorted keys and ACE's encoder for datetimes and the like, which FastAPI's JSONResponse lacks
    return Response(json.dumps(body, cls=_JSONEncoder, sort_keys=True), status_code=status,
                    media_type="application/json")


def _client_ip(request: Request) -> Optional[str]:
    # nginx sets both; X-Real-IP is the direct client, X-Forwarded-For may carry a chain
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host if request.client else None


def _audit(auth: ApiAuthResult, request: Request, event: str, fields: dict[str, Any]) -> None:
    write_audit_record(event, auth, _client_ip(request), **fields)


@router.post(
    "/validate",
    response_model=HuntValidationResult,
    responses={400: {"model": HuntValidationResult, "description": "the hunt is not valid, or its run failed"}},
    openapi_extra={"requestBody": {"required": True, "content": {
        "application/json": {"schema": HuntValidationRequest.model_json_schema()}}}},
)
async def validate_hunt(
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(require_permission("hunt", "write"))],
) -> Response:
    """Check a hunt package the way the hunter loads it and, with execution_arguments, run it,
    optionally analyzing its results or creating alerts, which belong to the caller. The answer
    carries every log line the run wrote."""
    outcome = ValidationOutcome()
    content_type = request.headers.get("content-type", "")
    if content_type.split(";")[0].strip().lower() != "application/json":
        outcome.body, outcome.status = {"valid": False, "error": "request body must be JSON"}, 415
        _audit(auth, request, *audit_fields(outcome))
        return _json(outcome.body, outcome.status)

    try:
        body = await request.json()
    except ValueError:
        outcome.body, outcome.status = {"valid": False, "error": "request body must be JSON"}, 400
        _audit(auth, request, *audit_fields(outcome))
        return _json(outcome.body, outcome.status)

    # run_db_in_thread, not run_in_threadpool: loading the hunter queries through get_db(), whose
    # session belongs to the pool thread and outlives the request unless it is removed. One left
    # holding a dropped connection fails every later request that thread serves.
    try:
        await run_db_in_thread(run_validation, outcome, body, auth.auth_user_id)
    except Exception as e:
        _audit(auth, request, *failure_audit_fields(outcome, e))
        raise

    _audit(auth, request, *audit_fields(outcome))
    return _json(outcome.body, outcome.status)
