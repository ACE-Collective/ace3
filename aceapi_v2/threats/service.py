"""Threat (malware-threat mapping) service for ACE API v2."""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from saq.database.model import Malware, Threat, ThreatType

logger = logging.getLogger(__name__)


async def get_threats(session: AsyncSession, malware_id: int | None = None) -> list[Threat]:
    stmt = (
        select(Threat)
        .join(Malware, Threat.malware_id == Malware.id)
        .join(ThreatType)
        .options(selectinload(Threat.threat_type))
        .order_by(Malware.name)
    )
    if malware_id is not None:
        stmt = stmt.where(Threat.malware_id == malware_id)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def create_threat(session: AsyncSession, malware_id: int, threat_type_id: int) -> Threat:
    threat = Threat(malware_id=malware_id, threat_type_id=threat_type_id)
    session.add(threat)
    await session.flush()
    # Load the relationship for the response
    await session.refresh(threat, attribute_names=["threat_type"])
    return threat


async def delete_threat(session: AsyncSession, malware_id: int, threat_type_id: int) -> bool:
    result = await session.execute(
        select(Threat).where(Threat.malware_id == malware_id, Threat.threat_type_id == threat_type_id)
    )
    threat = result.scalar_one_or_none()
    if threat is None:
        return False
    await session.delete(threat)
    await session.flush()
    return True
