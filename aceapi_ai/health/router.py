"""Health check router for the AI investigation API."""

from fastapi import APIRouter

from aceapi_v2.health.schemas import HealthResponse

router = APIRouter()


@router.get("/ping", response_model=HealthResponse)
async def ping() -> HealthResponse:
    """Health check endpoint that verifies the API is running."""
    return HealthResponse(result="pong")
