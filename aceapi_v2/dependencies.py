"""FastAPI dependencies for authentication and authorization.

Supports dual authentication:
- API Key (x-ace-auth header) - for M2M / service / agent authentication
- Flask session cookie - for the browser GUI (temporary, until the Flask GUI is retired)
"""

import logging
from collections.abc import Callable
from typing import Annotated, Optional
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth import (
    API_AUTH_TYPE_CONFIG,
    API_AUTH_TYPE_USER,
    API_HEADER_NAME,
    ApiAuthResult,
    verify_api_key,
    verify_flask_session,
)
from aceapi_v2.database import get_async_session
from saq.permissions.logic import key_scope_allows, user_has_permission_async

# Security scheme - appears in the Swagger UI "Authorize" dialog
api_key_header = APIKeyHeader(
    name=API_HEADER_NAME,
    scheme_name="API Key",
    description="API key for machine-to-machine authentication",
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
) -> ApiAuthResult:
    """Combined auth dependency - accepts an API key or a Flask session cookie.

    Tries the API key first, then the Flask session cookie.

    Returns:
        ApiAuthResult with authentication details

    Raises:
        HTTPException: 401 if no authentication method succeeds
    """
    # Try API key first (M2M / agent authentication)
    if api_key:
        result = await verify_api_key(api_key, session)
        if result:
            return result

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


def require_permission(major: str, minor: str, auth_dependency: Callable | None = None) -> Callable:
    """Factory function that creates a dependency requiring a specific permission.

    Args:
        major: The major permission category (e.g., "analysis")
        minor: The minor permission (e.g., "read")
        auth_dependency: The authentication dependency supplying the ApiAuthResult; defaults to
            this app's combined API-key/session get_current_auth. Other apps (aceapi_ai) pass
            their own so the same enforcement logic runs behind a different auth surface.

    Returns:
        A FastAPI dependency function that validates the permission.
    """
    if auth_dependency is None:
        auth_dependency = get_current_auth

    async def permission_dependency(
        auth: Annotated[ApiAuthResult, Security(auth_dependency)],
        session: Annotated[AsyncSession, Depends(get_async_session)],
    ) -> ApiAuthResult:
        # Effective permission is the intersection of the user's permissions and the key's scope.
        # user_has_permission_async is unchanged, so group/user DENY is fully preserved; the key
        # scope is a pure AND-narrowing on top. Config keys have no user to intersect with, so
        # their scope decides alone (a None scope is the deprecated legacy bypass).
        if auth.auth_type == API_AUTH_TYPE_USER:
            if not await user_has_permission_async(session, auth.auth_user_id, major, minor):
                logging.warning(
                    f"user {auth.auth_user_id} does not have permission {major}.{minor}"
                )
                raise HTTPException(status_code=403, detail="Permission denied")

        if auth.auth_type in (API_AUTH_TYPE_USER, API_AUTH_TYPE_CONFIG):
            if auth.key_scope is not None and not key_scope_allows(auth.key_scope, major, minor):
                logging.warning(
                    f"api key '{auth.auth_name}' ({auth.auth_type}) scope does not permit {major}.{minor}"
                )
                raise HTTPException(status_code=403, detail="Permission denied")

        return auth

    return permission_dependency
