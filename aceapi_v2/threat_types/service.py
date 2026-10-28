"""Threat type service for ACE API v2."""

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Threat, ThreatType


class ThreatTypeConflict(Exception):
    """The name is taken, or malware still uses the threat type."""


async def get_threat_types(session: AsyncSession) -> list[ThreatType]:
    result = await session.execute(select(ThreatType).order_by(ThreatType.name))
    return list(result.scalars().all())


async def get_threat_type(session: AsyncSession, threat_type_id: int) -> ThreatType | None:
    result = await session.execute(select(ThreatType).where(ThreatType.id == threat_type_id))
    return result.scalar_one_or_none()


async def _flush_name(session: AsyncSession, name: str) -> None:
    # the unique index on name decides, so that two requests for the same name cannot both win
    try:
        await session.flush()
    except IntegrityError as e:
        await session.rollback()
        raise ThreatTypeConflict(f"a threat type named {name!r} already exists") from e


async def create_threat_type(session: AsyncSession, name: str) -> ThreatType:
    threat_type = ThreatType(name=name)
    session.add(threat_type)
    await _flush_name(session, name)
    return threat_type


async def update_threat_type(session: AsyncSession, threat_type_id: int, name: str | None = None) -> ThreatType | None:
    threat_type = await get_threat_type(session, threat_type_id)
    if threat_type is None:
        return None
    if name is not None:
        threat_type.name = name
        await _flush_name(session, name)
    return threat_type


async def delete_threat_type(session: AsyncSession, threat_type_id: int) -> bool:
    threat_type = await get_threat_type(session, threat_type_id)
    if threat_type is None:
        return False

    # malware_threat_mapping's foreign key has no ON DELETE, so the delete would fail on it
    used_by = (await session.execute(
        select(func.count()).select_from(Threat).where(Threat.threat_type_id == threat_type_id))).scalar_one()
    if used_by:
        raise ThreatTypeConflict(f"threat type {threat_type.name!r} is used by {used_by} malware")

    await session.delete(threat_type)
    await session.flush()
    return True
