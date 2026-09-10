"""User preference router for ACE API v2, mounted at /users/me/preferences.

Every route acts on the CALLER's own preferences: the user id comes from the auth result,
never from the request, so there is no id to tamper with. No permission beyond being
authenticated as a user is required -- a preference is per-user GUI state whose entire
content is something the analyst could already click into the page.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Security
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_self_service
from aceapi_v2.user_preferences import service
from aceapi_v2.user_preferences.schemas import PreferenceRead, PreferencesRead
from aceapi_v2.user_preferences.service import UnknownPreferenceKey

router = APIRouter(dependencies=[Security(get_current_auth)])

# Every route here is self-service: no permission grant, but the credential must be a user
# credential that carries no narrowing scope. See require_self_service().
_require_self = require_self_service()


def _require_user(auth: ApiAuthResult) -> int:
    if auth.auth_user_id is None:
        raise HTTPException(status_code=401, detail="User authentication required")
    return auth.auth_user_id


def _unknown_key(key: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"Unknown preference {key!r}")


@router.get("", response_model=PreferencesRead)
async def get_preferences(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(_require_self)],
) -> PreferencesRead:
    """Every registered preference for the caller, defaults filled in."""
    return await service.get_preferences(session, _require_user(auth))


@router.get("/{key}", response_model=PreferenceRead)
async def get_preference(
    key: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(_require_self)],
) -> PreferenceRead:
    try:
        return await service.get_preference(session, _require_user(auth), key)
    except UnknownPreferenceKey:
        raise _unknown_key(key)


@router.put("/{key}", response_model=PreferenceRead)
async def set_preference(
    key: str,
    body: dict[str, Any],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(_require_self)],
) -> PreferenceRead:
    """Replace the caller's value for one preference. The body is the value itself, in the
    shape the key's schema declares; it is normalized before it is stored and the response
    carries the normalized form."""
    try:
        return await service.set_preference(session, _require_user(auth), key, body)
    except UnknownPreferenceKey:
        raise _unknown_key(key)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors(include_url=False))


@router.delete("/{key}", response_model=PreferenceRead)
async def reset_preference(
    key: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(_require_self)],
) -> PreferenceRead:
    """Forget the caller's stored value so the default applies again; returns the default."""
    try:
        return await service.reset_preference(session, _require_user(auth), key)
    except UnknownPreferenceKey:
        raise _unknown_key(key)
