"""Query execution flow for the AI investigation API.

Everything below the endpoint runs in a worker thread: the backends' clients are blocking, and the
rate limiter's redis calls are synchronous. Limiter acquire, execute, and release share the
thread's try/finally, so a timeout cancellation of the awaiting coroutine cannot leak a
concurrency slot (and the limiter's reaper is the second net).
"""

import asyncio
import logging
from datetime import timezone

from fastapi import HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_ai.audit import audit_event
from aceapi_ai.query.schemas import (
    AIQueryRequestBody,
    AIQueryResponse,
    BackendDescriptor,
)
from aceapi_ai.ratelimit import RateLimitExceeded, RateLimitUnavailable, rate_limiter
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.auth.utils import API_AUTH_TYPE_USER
from saq.ai_query.interface import (
    AIBackendError,
    AIQueryBackend,
    AIQueryRejected,
    AIQueryRequest,
)
from saq.permissions.logic import key_scope_allows, user_has_permission_async

# added to the query's own timeout budget before the awaiting coroutine gives up on the worker
# thread; the thread itself cannot be cancelled and finishes (and releases its slot) on its own
TIMEOUT_GRACE_SECONDS = 30


def _audit_query_fields(backend: AIQueryBackend, body: AIQueryRequestBody) -> dict:
    return {
        "backend": backend.name,
        "query": body.query,
        "window_start": body.start_time,
        "window_end": body.end_time,
        "limit": body.limit,
        "timeout_seconds": body.timeout_seconds,
    }


async def execute_query(
    backend: AIQueryBackend,
    body: AIQueryRequestBody,
    auth: ApiAuthResult,
    request: Request,
) -> AIQueryResponse:
    limits = backend.config.limits

    def reject(detail: str):
        audit_event("query_rejected", auth, request, **_audit_query_fields(backend, body), detail=detail)
        raise HTTPException(status_code=400, detail=detail)

    extras_class = backend.get_extras_class()
    if body.extras and extras_class is None:
        reject(f"backend {backend.name} accepts no extras")

    if extras_class is not None and body.extras:
        try:
            extras_class.model_validate(body.extras)
        except ValidationError as e:
            reject(f"invalid extras: {e.errors(include_url=False)}")

    if body.timeout_seconds is not None and body.timeout_seconds > limits.max_query_timeout:
        reject(f"timeout_seconds exceeds the maximum of {limits.max_query_timeout}")

    effective_timeout = body.timeout_seconds if body.timeout_seconds is not None else limits.default_query_timeout

    ai_request = AIQueryRequest(
        query=body.query,
        start_time=body.start_time.astimezone(timezone.utc),
        end_time=body.end_time.astimezone(timezone.utc),
        limit=body.limit,
        timeout_seconds=effective_timeout,
        extras=body.extras,
    )

    try:
        backend.validate_request(ai_request)
    except AIQueryRejected as e:
        reject(e.reason)

    def run():
        # concurrency slot first: a request refused for concurrency must not consume a
        # rate/budget token, or clients retrying on the short concurrency Retry-After would
        # burn through the minute window and escalate a transient collision into a longer wait
        with rate_limiter.concurrency_slot(backend.name, limits):
            rate_limiter.check_request(backend.name, limits)
            return backend.execute(ai_request)

    try:
        result = await asyncio.wait_for(asyncio.to_thread(run), effective_timeout + TIMEOUT_GRACE_SECONDS)
    except TimeoutError:
        audit_event("query_error", auth, request, **_audit_query_fields(backend, body),
                    status=504, detail="query timed out")
        raise HTTPException(status_code=504, detail="query timed out")
    except RateLimitExceeded as e:
        audit_event("rate_limited", auth, request, **_audit_query_fields(backend, body),
                    kind=e.kind, detail=e.detail)
        raise HTTPException(status_code=429, detail=e.detail,
                            headers={"Retry-After": str(e.retry_after_seconds)})
    except RateLimitUnavailable:
        audit_event("query_error", auth, request, **_audit_query_fields(backend, body),
                    status=503, detail="rate limiter unavailable")
        raise HTTPException(status_code=503, detail="rate limiter unavailable, refusing query")
    except AIQueryRejected as e:
        reject(e.reason)
    except AIBackendError as e:
        audit_event("query_error", auth, request, **_audit_query_fields(backend, body),
                    status=e.status_code, detail=e.reason)
        raise HTTPException(status_code=e.status_code, detail=e.reason)

    audit_event("query", auth, request, **_audit_query_fields(backend, body),
                row_count=result.row_count, truncated=result.truncated,
                duration_ms=result.duration_ms, status=200)

    return AIQueryResponse(
        backend=backend.name,
        rows=result.rows,
        row_count=result.row_count,
        truncated=result.truncated,
        truncation_reason=result.truncation_reason,
        window_start=result.window_start,
        window_end=result.window_end,
        duration_ms=result.duration_ms,
        meta=result.meta,
    )


async def describe_backends(
    registry: dict[str, AIQueryBackend],
    auth: ApiAuthResult,
    session: AsyncSession,
) -> list[BackendDescriptor]:
    descriptors = []
    for name in sorted(registry):
        backend = registry[name]

        # the same user-permissions ∩ key-scope evaluation require_permission applies, precomputed
        # so the agent can see which backends its key reaches
        authorized = True
        if auth.auth_type == API_AUTH_TYPE_USER:
            authorized = await user_has_permission_async(session, auth.auth_user_id, "ai", name)
        if authorized and auth.key_scope is not None:
            authorized = key_scope_allows(auth.key_scope, "ai", name)

        try:
            described = backend.describe()
        except Exception:
            logging.exception("ai query backend %s describe() failed", name)
            described = backend.base_describe()

        descriptors.append(BackendDescriptor(name=name, authorized=authorized, describe=described))

    return descriptors
