"""Runs a search for the AI API under the same limiter and audit discipline as the query lane.

Mirrors aceapi_ai/query/service.py: the concurrency slot is taken first (a concurrency refusal
must not burn a rate token), then the per-minute/hourly check, then the work -- all inside one
worker thread so the slot is held for exactly the duration of the search.
"""

import asyncio
import logging
from collections.abc import Callable
from typing import TypeVar

from fastapi import HTTPException, Request

from aceapi_ai.audit import audit_event
from aceapi_ai.ratelimit import RateLimitExceeded, RateLimitUnavailable, rate_limiter
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.search import service as v2_service
from aceapi_v2.search.schemas import AlertSearchRequest, AlertSearchResponse, SimilarAlertsRequest
from saq.configuration.config import get_config
from saq.database.pool import remove_all_sessions

logger = logging.getLogger(__name__)

# the limiter keys its counters by backend name; search is its own bucket
SEARCH_LIMIT_NAME = "search"
TIMEOUT_GRACE_SECONDS = 5

T = TypeVar("T")


async def _run_limited(event: str, auth: ApiAuthResult, request: Request, fn: Callable[[], T], **audit_fields) -> T:
    limits = get_config().ai_api.search_limits

    def run() -> T:
        try:
            with rate_limiter.concurrency_slot(SEARCH_LIMIT_NAME, limits):
                rate_limiter.check_request(SEARCH_LIMIT_NAME, limits)
                return fn()
        finally:
            remove_all_sessions()

    try:
        return await asyncio.wait_for(asyncio.to_thread(run), limits.max_query_timeout + TIMEOUT_GRACE_SECONDS)
    except TimeoutError:
        audit_event(f"{event}_error", auth, request, **audit_fields, status=504, detail="search timed out")
        raise HTTPException(status_code=504, detail="search timed out")
    except RateLimitExceeded as e:
        audit_event("rate_limited", auth, request, **audit_fields, kind=e.kind, detail=e.detail)
        raise HTTPException(status_code=429, detail=e.detail, headers={"Retry-After": str(e.retry_after_seconds)})
    except RateLimitUnavailable:
        audit_event(f"{event}_error", auth, request, **audit_fields, status=503, detail="rate limiter unavailable")
        raise HTTPException(status_code=503, detail="rate limiter unavailable, refusing search")


async def search_alerts(body: AlertSearchRequest, auth: ApiAuthResult, request: Request) -> AlertSearchResponse:
    fields = dict(query=body.query, filters=body.filters.model_dump(mode="json"), limit=body.limit, offset=body.offset, lanes=list(body.lanes))
    response = await _run_limited("search", auth, request, lambda: v2_service.search_alerts_sync(body), **fields)
    audit_event("search", auth, request, **fields, result_count=len(response.results), total=response.total,
                result_uuids=[r.alert.uuid for r in response.results], status=200)
    return response


async def similar_alerts(body: SimilarAlertsRequest, auth: ApiAuthResult, request: Request) -> AlertSearchResponse:
    fields = dict(alert_uuid=body.alert_uuid, filters=body.filters.model_dump(mode="json"), limit=body.limit, offset=body.offset)
    response = await _run_limited("similar", auth, request, lambda: v2_service.similar_alerts_sync(body), **fields)
    audit_event("similar", auth, request, **fields, result_count=len(response.results), total=response.total,
                result_uuids=[r.alert.uuid for r in response.results], status=200)
    return response
