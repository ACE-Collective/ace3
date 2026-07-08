"""Tests for the aceapi_v2 observable-detection settings service."""

import hashlib

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Observable, User
from aceapi_v2.detection import service

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


async def _make_observable(session: AsyncSession, otype: str, value: str, **kwargs) -> Observable:
    obs = Observable(type=otype, sha256=_sha256(value), value=value.encode("utf8"), **kwargs)
    session.add(obs)
    await session.flush()
    return obs


class TestListDetectionObservables:
    @pytest.mark.asyncio
    async def test_filter_for_detection(self, session: AsyncSession):
        await _make_observable(session, "ipv4", "10.0.0.1", for_detection=True)
        await _make_observable(session, "ipv4", "10.0.0.2", for_detection=False)
        await session.flush()

        enabled = await service.list_detection_observables(session, for_detection=True)
        values = {o.value for o in enabled}
        assert "10.0.0.1" in values
        assert "10.0.0.2" not in values

    @pytest.mark.asyncio
    async def test_search(self, session: AsyncSession):
        await _make_observable(session, "fqdn", "evil.example.com", for_detection=True)
        await _make_observable(session, "fqdn", "good.example.org", for_detection=True)
        await session.flush()

        results = await service.list_detection_observables(session, search="evil")
        values = {o.value for o in results}
        assert "evil.example.com" in values
        assert "good.example.org" not in values

    @pytest.mark.asyncio
    async def test_enabled_by_display_name(self, session: AsyncSession):
        user = User(username="det_enabler", email="det_enabler@e.com", display_name="Det Enabler", password="pw")
        session.add(user)
        await session.flush()
        await _make_observable(session, "ipv4", "10.9.9.9", for_detection=True, enabled_by=user.id)
        await session.flush()

        results = await service.list_detection_observables(session, search="10.9.9.9")
        assert results[0].enabled_by == "Det Enabler"


class TestSetForDetection:
    @pytest.mark.asyncio
    async def test_enable(self, session: AsyncSession):
        user = User(username="det_u1", email="det_u1@e.com", display_name="U1", password="pw")
        session.add(user)
        obs = await _make_observable(session, "ipv4", "1.1.1.1", for_detection=False)
        await session.flush()

        result = await service.set_observable_for_detection(session, obs.id, True, user.id, "because reasons")
        assert result.for_detection is True
        assert result.detection_context == "because reasons"
        assert result.enabled_by == "U1"

    @pytest.mark.asyncio
    async def test_disable(self, session: AsyncSession):
        obs = await _make_observable(session, "ipv4", "2.2.2.2", for_detection=True)
        await session.flush()
        result = await service.set_observable_for_detection(session, obs.id, False, 1, None)
        assert result.for_detection is False

    @pytest.mark.asyncio
    async def test_unknown_id(self, session: AsyncSession):
        assert await service.set_observable_for_detection(session, 999999, True, 1, None) is None


class TestSetExpiration:
    @pytest.mark.asyncio
    async def test_set_and_clear(self, session: AsyncSession):
        from datetime import datetime
        obs = await _make_observable(session, "ipv4", "3.3.3.3", for_detection=True)
        await session.flush()

        when = datetime(2030, 1, 1, 12, 0, 0)
        result = await service.set_observable_expiration(session, obs.id, when)
        assert result.expires_on == when

        cleared = await service.set_observable_expiration(session, obs.id, None)
        assert cleared.expires_on is None

    @pytest.mark.asyncio
    async def test_unknown_id(self, session: AsyncSession):
        assert await service.set_observable_expiration(session, 999999, None) is None
