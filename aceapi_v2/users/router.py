"""Users / roles / permissions management router (ACE API v2)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.users import service
from aceapi_v2.users.schemas import (
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
    group = await service.create_auth_group(session, body.name)
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
    await service.grant_permission(
        session,
        perm=PermissionInput(major=body.major, minor=body.minor, effect=body.effect),
        user_ids=body.users,
        group_ids=body.groups,
        actor_id=auth.auth_user_id,
    )
    return {"success": "Permission added successfully"}


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
