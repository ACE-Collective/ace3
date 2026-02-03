"""FastAPI dependencies for authentication and authorization.

Supports dual authentication:
- API Key (x-ace-auth header) - for M2M / service authentication
- JWT Bearer Token (OAuth2 password flow) - for user GUI authentication
"""

import hashlib
import logging
from typing import Annotated, Callable, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth import (
    API_AUTH_TYPE_USER,
    API_HEADER_NAME,
    ApiAuthResult,
    verify_api_key,
    verify_flask_session,
    verify_token,
)
from aceapi_v2.database import get_async_session
from saq.permissions.logic import user_has_permission

# Security schemes - both will appear in Swagger UI "Authorize" dialog
api_key_header = APIKeyHeader(
    name=API_HEADER_NAME,
    scheme_name="API Key",
    description="API key for machine-to-machine authentication",
    auto_error=False,
)
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v2/auth/token",
    scheme_name="JWT Token",
    description="Username/password login for users",
    auto_error=False,
)


async def get_current_auth(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    api_key: Annotated[Optional[str], Security(api_key_header)] = None,
    token: Annotated[Optional[str], Security(oauth2_scheme)] = None,
) -> ApiAuthResult:
    """Combined auth dependency - accepts API key, JWT token, or Flask session cookie.

    Tries API key first, then JWT token, then Flask session cookie.

    Returns:
        ApiAuthResult with authentication details

    Raises:
        HTTPException: 401 if no authentication method succeeds
    """
    # Try API key first (M2M authentication)
    if api_key:
        result = await verify_api_key(api_key, session)
        if result:
            return result

    # Try JWT token (user authentication)
    if token:
        token_data = verify_token(token, expected_type="access")
        if token_data:
            return ApiAuthResult(
                auth_type=API_AUTH_TYPE_USER,
                auth_name=token_data.username,
                auth_user_id=token_data.user_id,
            )

    # Try Flask session cookie
    # TODO: temporary, remove when Flask GUI is retired)
    flask_cookie = request.cookies.get("session")
    if flask_cookie:
        # TEMPORARY DEBUG: log session cookie for comparison with Flask app (remove after debugging)
        cookie_hash = hashlib.sha256(flask_cookie.encode("utf-8", errors="replace")).hexdigest()[:16]
        raw_cookie_header_len = len(request.headers.get("cookie", ""))
        logging.info(
            "[DEBUG SESSION COOKIE] API v2 received session cookie: len=%d hash=%s Cookie_header_len=%d value=%s",
            len(flask_cookie),
            cookie_hash,
            raw_cookie_header_len,
            flask_cookie,
        )
        result = await verify_flask_session(flask_cookie, session)
        if result:
            return result
        logging.info(
            "[DEBUG SESSION COOKIE] API v2 session cookie present but verification failed (see verify_flask_session logs)"
        )
    else:
        logging.info(
            "[DEBUG SESSION COOKIE] API v2 received no session cookie; Cookie header present=%s",
            "cookie" in [h.lower() for h in request.headers.keys()],
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_permission(major: str, minor: str) -> Callable:
    """Factory function that creates a dependency requiring a specific permission.

    Args:
        major: The major permission category (e.g., "analysis")
        minor: The minor permission (e.g., "read")

    Returns:
        A FastAPI dependency function that validates the permission.
    """

    async def permission_dependency(
        auth: Annotated[ApiAuthResult, Security(get_current_auth)],
    ) -> ApiAuthResult:
        if auth.auth_type == API_AUTH_TYPE_USER:
            if not user_has_permission(auth.auth_user_id, major, minor):
                logging.warning(
                    f"user {auth.auth_user_id} does not have permission {major}.{minor}"
                )
                raise HTTPException(status_code=403, detail="Permission denied")

        return auth

    return permission_dependency
