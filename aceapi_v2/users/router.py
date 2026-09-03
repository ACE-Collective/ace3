"""Users / roles / permissions management router (ACE API v2)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.users import service
from aceapi_v2.users.schemas import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyRead,
    ApiKeyUpdate,
    CatalogEntryRead,
    GroupCreate,
    GroupDelete,
    GroupRead,
    ManagementView,
    PermissionGrant,
    PermissionInput,
    PermissionRevoke,
    UserCreate,
    UserDetail,
    UserRead,
    UserUpdate,
)

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/management-view", response_model=ManagementView)
async def management_view(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "read"))],
    include_disabled: bool = True,
) -> ManagementView:
    return await service.get_management_view(session, include_disabled=include_disabled)


@router.get("/details", response_model=dict[int, UserDetail])
async def user_details(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "read"))],
    user_ids: Annotated[list[int], Query()],
) -> dict[int, UserDetail]:
    return await service.get_users_details(session, user_ids)


@router.get("/catalog", response_model=list[CatalogEntryRead])
async def permission_catalog(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "read"))],
) -> list[CatalogEntryRead]:
    return await service.list_permission_catalog(session)


@router.post("/", response_model=UserRead, status_code=201)
async def create_user(
    body: UserCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> UserRead:
    try:
        user = await service.create_user(
            session,
            username=body.username,
            email=body.email,
            display_name=body.display_name,
            password=body.password,
            queue=body.queue,
            timezone=body.timezone,
            permissions=body.permissions,
            groups=body.groups,
            created_by=auth.auth_user_id,
        )
    except service.InvalidUserError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return service._user_read(user)


@router.patch("/", status_code=200)
async def update_users(
    body: dict[int, UserUpdate],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> dict:
    try:
        await service.update_users(session, body, actor_id=auth.auth_user_id)
    except service.UserNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"success": "Users updated successfully"}


@router.post("/groups", response_model=GroupRead, status_code=201)
async def create_group(
    body: GroupCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> GroupRead:
    try:
        group = await service.create_auth_group(session, body.name)
    except service.InvalidGroupError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return GroupRead(id=group.id, name=group.name)


@router.post("/groups/delete", status_code=200)
async def delete_groups(
    body: GroupDelete,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> dict:
    await service.delete_auth_groups(session, body.groups)
    return {"success": "permission groups deleted"}


@router.post("/permissions", status_code=200)
async def add_permission(
    body: PermissionGrant,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> dict:
    try:
        await service.grant_permission(
            session,
            perm=PermissionInput(major=body.major, minor=body.minor, effect=body.effect),
            user_ids=body.users,
            group_ids=body.groups,
            actor_id=auth.auth_user_id,
        )
    except service.InvalidPermissionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"success": "Permission added successfully"}


@router.get("/me/apikeys", response_model=list[ApiKeyRead])
async def list_my_api_keys(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Security(get_current_auth)],
) -> list[ApiKeyRead]:
    """List the *caller's own* API keys (metadata + scope only; no secret). The user id comes from
    the auth result, not the request, so there is no id to tamper with. Read-only: minting and
    revoking keys require ``user:write`` and go through the admin endpoints below."""
    if auth.auth_user_id is None:
        raise HTTPException(status_code=404, detail="not authenticated as a user")

    keys = await service.list_user_api_keys(session, auth.auth_user_id)
    return [service._api_key_read(k) for k in keys]


@router.get("/{user_id}/apikeys", response_model=list[ApiKeyRead])
async def list_user_api_keys(
    user_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "read"))],
) -> list[ApiKeyRead]:
    keys = await service.list_user_api_keys(session, user_id)
    return [service._api_key_read(k) for k in keys]


@router.post("/{user_id}/apikeys", response_model=ApiKeyCreated, status_code=201)
async def create_api_key(
    user_id: int,
    body: ApiKeyCreate,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> ApiKeyCreated:
    """Mint a new API key for a user. The plaintext is returned exactly once and is never
    recoverable afterward. Exactly one of ``inherit`` or a non-empty ``scope`` must be provided."""
    try:
        key, api_key = await service.create_user_api_key(
            session,
            user_id,
            name=body.name,
            inherit=body.inherit,
            scope=body.scope,
            created_by=auth.auth_user_id,
        )
    except service.UserNotFoundForApiKeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except service.InvalidPermissionError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # a credential must not be cached by the browser or any intermediary
    response.headers["Cache-Control"] = "no-store"
    return ApiKeyCreated(key_id=key.id, user_id=user_id, api_key=api_key)


@router.put("/apikeys/{key_id}", response_model=ApiKeyRead)
async def update_api_key(
    key_id: int,
    body: ApiKeyUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> ApiKeyRead:
    """Rename a key and replace its scope. The secret is unchanged, so a key already in use picks
    up the new permissions without being reissued. Same exactly-one-of rule as creation."""
    try:
        key = await service.update_user_api_key(
            session, key_id, name=body.name, inherit=body.inherit, scope=body.scope
        )
    except service.InvalidPermissionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if key is None:
        raise HTTPException(status_code=404, detail=f"API key {key_id} not found")
    return service._api_key_read(key)


@router.delete("/apikeys/{key_id}", status_code=200)
async def revoke_api_key(
    key_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> dict:
    revoked = await service.revoke_user_api_key(session, key_id)
    return {"revoked": revoked}


@router.post("/permissions/delete", status_code=200)
async def delete_permission(
    body: PermissionRevoke,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("user", "write"))],
) -> dict:
    await service.revoke_permissions(
        session, user_permission_ids=body.users, group_permission_ids=body.groups
    )
    return {"success": "Permission deleted successfully"}
