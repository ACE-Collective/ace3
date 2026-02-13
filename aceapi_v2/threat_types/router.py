"""Threat type router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.cache import TTLCache
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth
from aceapi_v2.schemas import ListResponse
from aceapi_v2.threat_types import service
from aceapi_v2.threat_types.schemas import ThreatTypeCreate, ThreatTypeRead, ThreatTypeUpdate

router = APIRouter(dependencies=[Security(get_current_auth)])

_cache = TTLCache()


@router.get("/", response_model=ListResponse[ThreatTypeRead])
async def list_threat_types(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ListResponse[ThreatTypeRead]:
    cached = _cache.get("threat_types")
    if cached is not None:
        _cache.set_cache_headers(response)
        return cached

    types = await service.get_threat_types(session)
    data = ListResponse(data=[ThreatTypeRead(id=t.id, name=t.name) for t in types])
    _cache.set("threat_types", data)
    _cache.set_cache_headers(response)
    return data


@router.post("/", response_model=ThreatTypeRead, status_code=201)
async def create_threat_type(
    body: ThreatTypeCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ThreatTypeRead:
    threat_type = await service.create_threat_type(session, body.name)
    _cache.clear()
    return ThreatTypeRead(id=threat_type.id, name=threat_type.name)


@router.get("/{threat_type_id}", response_model=ThreatTypeRead)
async def get_threat_type(
    threat_type_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ThreatTypeRead:
    threat_type = await service.get_threat_type(session, threat_type_id)
    if threat_type is None:
        raise HTTPException(status_code=404, detail="Threat type not found")
    return ThreatTypeRead(id=threat_type.id, name=threat_type.name)


@router.patch("/{threat_type_id}", response_model=ThreatTypeRead)
async def update_threat_type(
    threat_type_id: int,
    body: ThreatTypeUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ThreatTypeRead:
    threat_type = await service.update_threat_type(session, threat_type_id, name=body.name)
    if threat_type is None:
        raise HTTPException(status_code=404, detail="Threat type not found")
    _cache.clear()
    return ThreatTypeRead(id=threat_type.id, name=threat_type.name)


@router.delete("/{threat_type_id}", status_code=204)
async def delete_threat_type(
    threat_type_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    deleted = await service.delete_threat_type(session, threat_type_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Threat type not found")
    _cache.clear()
