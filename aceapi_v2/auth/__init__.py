"""Authentication module for ACE API v2.

Re-exports common auth components for convenient imports:
    from aceapi_v2.auth import ApiAuthResult, verify_api_key
"""

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.auth.utils import (
    API_AUTH_TYPE_CONFIG,
    API_AUTH_TYPE_USER,
    API_HEADER_NAME,
    verify_api_key,
    verify_flask_session,
)

__all__ = [
    "ApiAuthResult",
    "API_AUTH_TYPE_CONFIG",
    "API_AUTH_TYPE_USER",
    "API_HEADER_NAME",
    "verify_api_key",
    "verify_flask_session",
]
