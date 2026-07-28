"""FastAPI dependencies for authentication and authorization.

Supports dual authentication:
- API Key (x-ace-auth header) - for M2M / service authentication
- JWT Bearer Token (OAuth2 password flow) - for user GUI authentication
"""

import logging
from typing import Annotated, Callable, Optional
from urllib.parse import urlsplit

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
from saq.permissions.logic import user_has_permission_async

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


# Methods that cannot change state, and so cannot be a CSRF target.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _request_hostname(request: Request) -> Optional[str]:
    """The hostname this request was addressed to, port stripped, honouring the reverse proxy."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    host = host.split(",")[0].strip()  # x-forwarded-host may be a list
    if not host:
        return None
    return urlsplit(f"//{host}").hostname


def _reject_cross_site_cookie_write(request: Request) -> None:
    """Reject state-changing requests authenticated by the Flask session cookie unless they are
    same-origin.

    Cookie authentication is the only CSRF-exposed path here: an attacker's page cannot make a
    browser attach an `x-ace-auth` header or a bearer token, but it *can* make it send cookies.

    Both signals used below are set by the browser and cannot be forged by page JavaScript:
      * `Sec-Fetch-Site` is sent by modern browsers and states the request's site relationship.
      * `Origin` is sent on every cross-origin request and on same-origin state-changing requests.

    A cookie-authenticated write carrying neither signal is not a browser request we recognize, and
    cookie auth exists solely for the Flask GUI, so it is refused. Non-browser clients should use an
    API key or a bearer token, neither of which reaches this check.
    """
    if request.method.upper() in SAFE_METHODS:
        return

    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        # "none" means a user-initiated navigation (typing a URL, a bookmark); not cross-site.
        if fetch_site in ("same-origin", "none"):
            return
        logging.warning("rejected cross-site cookie-authenticated %s (sec-fetch-site=%s)", request.method, fetch_site)
        raise HTTPException(status_code=403, detail="cross-site request rejected")

    origin = request.headers.get("origin")
    if origin:
        host = _request_hostname(request)
        # Compare hostnames, not netlocs: the reverse proxy forwards `Host: $host`, which drops the
        # port, so an Origin of "https://ace.example.com:8443" would never equal a Host of
        # "ace.example.com". Browsers reach this branch only when Sec-Fetch-Site is absent.
        if host and urlsplit(origin).hostname == host:
            return
        logging.warning("rejected cross-origin cookie-authenticated %s (origin=%s host=%s)", request.method, origin, host)
        raise HTTPException(status_code=403, detail="cross-site request rejected")

    logging.warning("rejected cookie-authenticated %s with no Origin or Sec-Fetch-Site header", request.method)
    raise HTTPException(status_code=403, detail="cross-site request rejected")


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
        result = await verify_flask_session(flask_cookie, session)
        if result:
            # cookies ride along automatically, so this is the only CSRF-exposed auth path
            _reject_cross_site_cookie_write(request)
            return result

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
        session: Annotated[AsyncSession, Depends(get_async_session)],
    ) -> ApiAuthResult:
        if auth.auth_type == API_AUTH_TYPE_USER:
            if not await user_has_permission_async(session, auth.auth_user_id, major, minor):
                logging.warning(
                    f"user {auth.auth_user_id} does not have permission {major}.{minor}"
                )
                raise HTTPException(status_code=403, detail="Permission denied")

        return auth

    return permission_dependency
