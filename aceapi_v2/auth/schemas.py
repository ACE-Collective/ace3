"""Authentication schemas for ACE API v2."""

from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel


class Token(BaseModel):
    """Response model for token endpoints."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """Request model for token refresh endpoint."""

    refresh_token: str


class TokenData(BaseModel):
    """Decoded token data."""

    username: Optional[str] = None
    user_id: Optional[int] = None
    token_type: Optional[str] = None  # "access" or "refresh"


@dataclass
class ApiAuthResult:
    """Result of API authentication (API key or JWT)."""

    auth_type: Optional[str] = None
    auth_name: Optional[str] = None
    auth_user_id: Optional[int] = None
