"""Alert search routes (docs/SEARCH.md)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.search import service
from aceapi_v2.search.schemas import AlertSearchRequest, AlertSearchResponse, SimilarAlertsRequest
from aceapi_v2.sync import run_db_in_thread

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.post("/alerts", response_model=AlertSearchResponse)
async def search_alerts(
    body: AlertSearchRequest,
    _: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> AlertSearchResponse:
    """Search alerts by free text, indicator, tag or uuid.

    Exact matches (an observable value, file hash, tag or alert uuid found verbatim) are returned
    first, newest first, with tier "exact"; semantic matches over the alert's text follow. The
    ranking happens before pagination, so page one always holds the best matches.
    """
    return await run_db_in_thread(service.search_alerts_sync, body)


@router.post("/similar", response_model=AlertSearchResponse)
async def similar_alerts(
    body: SimilarAlertsRequest,
    _: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> AlertSearchResponse:
    """Alerts most similar to the given alert, with their dispositions -- "have we seen this before?"."""
    return await run_db_in_thread(service.similar_alerts_sync, body)
