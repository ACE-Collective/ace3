"""Common router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.common import service
from aceapi_v2.common.schemas import (
    CompanyRead,
    NamedDescriptionRead,
    PingResponse,
    SupportedApiVersionResponse,
)
from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.schemas.base import ListResponse

router = APIRouter(dependencies=[Security(get_current_auth)])


# ping and supported_api_version are liveness/version negotiation: any authenticated principal may
# call them, and they carry no sensitive data. They are on the route-coverage test's public
# allowlist. The valid_* reference-data endpoints require system:read so a scoped key (e.g. ai:read)
# cannot browse them.
@router.get("/ping", response_model=PingResponse)
async def ping() -> PingResponse:
    return PingResponse(result="pong")


@router.get("/supported_api_version", response_model=SupportedApiVersionResponse)
async def supported_api_version() -> SupportedApiVersionResponse:
    return SupportedApiVersionResponse(result=1)


@router.get("/valid_companies", response_model=ListResponse[CompanyRead])
async def valid_companies(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("system", "read"))],
) -> ListResponse[CompanyRead]:
    rows = await service.get_valid_companies(session)
    return ListResponse(data=[CompanyRead.model_validate(r) for r in rows])


@router.get("/valid_observables", response_model=ListResponse[NamedDescriptionRead])
async def valid_observables(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("system", "read"))],
) -> ListResponse[NamedDescriptionRead]:
    items = await service.get_valid_observables(session)
    return ListResponse(data=[NamedDescriptionRead(**i) for i in items])


@router.get("/valid_directives", response_model=ListResponse[NamedDescriptionRead])
async def valid_directives(
    _: Annotated[ApiAuthResult, Depends(require_permission("system", "read"))],
) -> ListResponse[NamedDescriptionRead]:
    items = await service.get_valid_directives()
    return ListResponse(data=[NamedDescriptionRead(**i) for i in items])
