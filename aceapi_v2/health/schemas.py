"""Health check schemas for ACE API v2."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Response model for health check endpoint."""

    result: str
