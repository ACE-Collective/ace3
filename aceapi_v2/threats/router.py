"""Threat (malware-threat mapping) router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth
from aceapi_v2.schemas import ListResponse
from aceapi_v2.threats import service
from aceapi_v2.threats.schemas import ThreatCreate, ThreatRead

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/", response_model=ListResponse[ThreatRead])
async def list_threats(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    malware_id: int | None = None,
) -> ListResponse[ThreatRead]:
    threats = await service.get_threats(session, malware_id=malware_id)
    data = ListResponse(
        data=[
            ThreatRead(
                malware_id=t.malware_id,
                threat_type_id=t.threat_type_id,
                threat_type_name=t.threat_type.name,
            )
            for t in threats
        ]
    )
    return data


@router.post("/", response_model=ThreatRead, status_code=201)
async def create_threat(
    body: ThreatCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ThreatRead:
    threat = await service.create_threat(session, body.malware_id, body.threat_type_id)
    return ThreatRead(
        malware_id=threat.malware_id,
        threat_type_id=threat.threat_type_id,
        threat_type_name=threat.threat_type.name,
    )


@router.delete("/", status_code=204)
async def delete_threat(
    malware_id: int,
    threat_type_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    deleted = await service.delete_threat(session, malware_id, threat_type_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Threat mapping not found")
