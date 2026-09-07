"""Alert search for the AI investigation API: the RAG surface for agentic triage.

Reuses the aceapi_v2 search service but sits behind its own ai:search permission (so an AI key
never needs alert:read on the main app), records every query in the audit trail, and is rate
limited like the query backends (ai_api.search_limits).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from aceapi_ai.dependencies import get_current_auth
from aceapi_ai.search import service
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import require_permission
from aceapi_v2.search.schemas import AlertSearchRequest, AlertSearchResponse, SimilarAlertsRequest

router = APIRouter()

_require_ai_search = require_permission("ai", "search", auth_dependency=get_current_auth)


@router.post("/alerts", response_model=AlertSearchResponse)
async def search_alerts(
    body: AlertSearchRequest,
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(_require_ai_search)],
) -> AlertSearchResponse:
    """Search past alerts by free text, indicator, tag or uuid.

    Exact indicator/tag/uuid matches come first (tier "exact", newest first); semantic matches over
    the alerts' text follow. Each result carries the alert's disposition so the caller can answer
    "has this been seen before and what did the analyst decide".
    """
    return await service.search_alerts(body, auth, request)


@router.post("/similar", response_model=AlertSearchResponse)
async def similar_alerts(
    body: SimilarAlertsRequest,
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(_require_ai_search)],
) -> AlertSearchResponse:
    """Alerts most similar to the given alert, with their dispositions."""
    return await service.similar_alerts(body, auth, request)
