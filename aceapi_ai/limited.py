"""Runs one unit of AI API work under a limiter bucket, with the same discipline as the query lane.

Mirrors aceapi_ai/query/service.py: the concurrency slot is taken first (a concurrency refusal
must not burn a rate token), then the per-minute/hourly check, then the work -- all inside one
worker thread so the slot is held for exactly the duration of the work. Search and export each
have their own bucket (their own limits and counters).
"""

import asyncio
from collections.abc import Callable
from typing import TypeVar

from fastapi import HTTPException, Request

from aceapi_ai.audit import audit_event
from aceapi_ai.ratelimit import RateLimitExceeded, RateLimitUnavailable, rate_limiter
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.sync import run_db_in_thread
from saq.configuration.schema import AIQueryBackendLimits

TIMEOUT_GRACE_SECONDS = 5

T = TypeVar("T")


async def run_limited(
    limit_name: str,
    limits: AIQueryBackendLimits,
    noun: str,
    event: str,
    auth: ApiAuthResult,
    request: Request,
    fn: Callable[[], T],
    **audit_fields,
) -> T:
    """Runs fn in a worker thread inside the limit_name bucket. A timeout, a refusal or an
    unavailable limiter is audited as `event` and raised as 504, 429 or 503; `noun` names the
    work in the error detail. Anything fn raises propagates unchanged."""

    def run() -> T:
        with rate_limiter.concurrency_slot(limit_name, limits):
            rate_limiter.check_request(limit_name, limits)
            return fn()

    try:
        return await asyncio.wait_for(run_db_in_thread(run), limits.max_query_timeout + TIMEOUT_GRACE_SECONDS)
    except TimeoutError:
        audit_event(f"{event}_error", auth, request, **audit_fields, status=504, detail=f"{noun} timed out")
        raise HTTPException(status_code=504, detail=f"{noun} timed out")
    except RateLimitExceeded as e:
        audit_event("rate_limited", auth, request, **audit_fields, kind=e.kind, detail=e.detail)
        raise HTTPException(status_code=429, detail=e.detail, headers={"Retry-After": str(e.retry_after_seconds)})
    except RateLimitUnavailable:
        audit_event(f"{event}_error", auth, request, **audit_fields, status=503, detail="rate limiter unavailable")
        raise HTTPException(status_code=503, detail=f"rate limiter unavailable, refusing {noun}")
