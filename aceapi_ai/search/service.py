"""Runs a search for the AI API under the same limiter and audit discipline as the query lane
(aceapi_ai/limited.py), in its own bucket."""

import logging
from collections.abc import Callable
from typing import TypeVar

from fastapi import Request

from aceapi_ai.audit import audit_event
from aceapi_ai.limited import run_limited
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.search import service as v2_service
from aceapi_v2.search.schemas import AlertSearchRequest, AlertSearchResponse, SimilarAlertsRequest
from saq.configuration.config import get_config

logger = logging.getLogger(__name__)

# the limiter keys its counters by backend name; search is its own bucket
SEARCH_LIMIT_NAME = "search"

T = TypeVar("T")


async def _run_limited(event: str, auth: ApiAuthResult, request: Request, fn: Callable[[], T], **audit_fields) -> T:
    limits = get_config().ai_api.search_limits
    return await run_limited(SEARCH_LIMIT_NAME, limits, "search", event, auth, request, fn, **audit_fields)


async def search_alerts(body: AlertSearchRequest, auth: ApiAuthResult, request: Request) -> AlertSearchResponse:
    fields = dict(query=body.query, filters=body.filters.model_dump(mode="json"), limit=body.limit, offset=body.offset,
                  lanes=list(body.lanes), include_test_alerts=body.include_test_alerts)
    response = await _run_limited("search", auth, request, lambda: v2_service.search_alerts_sync(body), **fields)
    audit_event("search", auth, request, **fields, result_count=len(response.results), total=response.total,
                excluded_test_alerts=response.excluded_test_alerts,
                result_uuids=[r.alert.uuid for r in response.results], status=200)
    return response


async def similar_alerts(body: SimilarAlertsRequest, auth: ApiAuthResult, request: Request) -> AlertSearchResponse:
    fields = dict(alert_uuid=body.alert_uuid, filters=body.filters.model_dump(mode="json"), limit=body.limit,
                  offset=body.offset, include_test_alerts=body.include_test_alerts)
    response = await _run_limited("similar", auth, request, lambda: v2_service.similar_alerts_sync(body), **fields)
    audit_event("similar", auth, request, **fields, result_count=len(response.results), total=response.total,
                excluded_test_alerts=response.excluded_test_alerts,
                result_uuids=[r.alert.uuid for r in response.results], status=200)
    return response
