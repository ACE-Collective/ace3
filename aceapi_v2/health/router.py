"""Health check router for ACE API v2."""

from fastapi import APIRouter

from aceapi_v2.health.schemas import HealthResponse

router = APIRouter()


@router.get("/ping", response_model=HealthResponse)
async def ping() -> HealthResponse:
    """Health check endpoint that verifies API is running."""
    return HealthResponse(result="pong")
