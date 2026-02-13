"""Threat type service for ACE API v2."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import ThreatType


async def get_threat_types(session: AsyncSession) -> list[ThreatType]:
    result = await session.execute(select(ThreatType).order_by(ThreatType.name))
    return list(result.scalars().all())


async def get_threat_type(session: AsyncSession, threat_type_id: int) -> ThreatType | None:
    result = await session.execute(select(ThreatType).where(ThreatType.id == threat_type_id))
    return result.scalar_one_or_none()


async def create_threat_type(session: AsyncSession, name: str) -> ThreatType:
    threat_type = ThreatType(name=name)
    session.add(threat_type)
    await session.flush()
    return threat_type


async def update_threat_type(session: AsyncSession, threat_type_id: int, name: str | None = None) -> ThreatType | None:
    threat_type = await get_threat_type(session, threat_type_id)
    if threat_type is None:
        return None
    if name is not None:
        threat_type.name = name
    await session.flush()
    return threat_type


async def delete_threat_type(session: AsyncSession, threat_type_id: int) -> bool:
    threat_type = await get_threat_type(session, threat_type_id)
    if threat_type is None:
        return False
    await session.delete(threat_type)
    await session.flush()
    return True
