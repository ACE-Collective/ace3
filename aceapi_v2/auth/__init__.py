"""Authentication module for ACE API v2.

Re-exports common auth components for convenient imports:
    from aceapi_v2.auth import Token, create_access_token, verify_token
"""

from aceapi_v2.auth.schemas import ApiAuthResult, RefreshRequest, Token, TokenData
from aceapi_v2.auth.utils import (
    API_AUTH_TYPE_CONFIG,
    API_AUTH_TYPE_USER,
    API_HEADER_NAME,
    create_access_token,
    create_refresh_token,
    verify_api_key,
    verify_flask_session,
    verify_token,
)

__all__ = [
    "ApiAuthResult",
    "RefreshRequest",
    "Token",
    "TokenData",
    "API_AUTH_TYPE_CONFIG",
    "API_AUTH_TYPE_USER",
    "API_HEADER_NAME",
    "create_access_token",
    "create_refresh_token",
    "verify_api_key",
    "verify_flask_session",
    "verify_token",
]
