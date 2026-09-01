"""Tests for aceapi_v2 observables service."""

import hashlib

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import aceapi_v2.observables.service as observables_service
from aceapi_v2.observables.schemas import LookupPair
from aceapi_v2.observables.service import (
    get_interesting_observables_by_hashes,
    lookup_observables,
    observable_is_interesting,
    set_observable_interesting,
)
from saq.database.model import Observable

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


class TestObservableIsInteresting:
    """Test the observable_is_interesting service function."""

    @pytest.mark.asyncio
    async def test_returns_false_when_not_exists(self, session: AsyncSession):
        result = await observable_is_interesting(session, "ipv4", _sha256("10.0.0.1"))
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_when_not_interesting(self, session: AsyncSession):
        obs = Observable(
            type="ipv4",
            sha256=_sha256("192.168.1.1"),
            value=b"192.168.1.1",
            is_interesting=False,
        )
        session.add(obs)
        await session.commit()

        result = await observable_is_interesting(
            session, "ipv4", _sha256("192.168.1.1")
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_true_when_interesting(self, session: AsyncSession):
        obs = Observable(
            type="ipv4",
            sha256=_sha256("192.168.1.1"),
            value=b"192.168.1.1",
            is_interesting=True,
        )
        session.add(obs)
        await session.commit()

        result = await observable_is_interesting(
            session, "ipv4", _sha256("192.168.1.1")
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_matches_on_type_and_sha256(self, session: AsyncSession):
        """Same sha256 but different type should not match."""
        obs = Observable(
            type="ipv4",
            sha256=_sha256("test"),
            value=b"test",
            is_interesting=True,
        )
        session.add(obs)
        await session.commit()

        result = await observable_is_interesting(session, "domain", _sha256("test"))
        assert result is False


class TestSetObservableInteresting:
    """Test the set_observable_interesting service function."""

    @pytest.mark.asyncio
    async def test_creates_new_observable_when_marking(self, session: AsyncSession):
        await set_observable_interesting(session, "ipv4", "1.2.3.4", True)

        result = await session.execute(
            select(Observable).where(
                Observable.type == "ipv4",
                Observable.sha256 == _sha256("1.2.3.4"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True
        assert db_obs.value == b"1.2.3.4"

    @pytest.mark.asyncio
    async def test_does_not_create_when_unmarking_nonexistent(
        self, session: AsyncSession
    ):
        await set_observable_interesting(session, "ipv4", "10.0.0.1", False)

        result = await session.execute(
            select(Observable).where(
                Observable.type == "ipv4",
                Observable.sha256 == _sha256("10.0.0.1"),
            )
        )
        assert result.scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_updates_existing_observable(self, session: AsyncSession):
        obs = Observable(
            type="domain",
            sha256=_sha256("evil.com"),
            value=b"evil.com",
            is_interesting=False,
        )
        session.add(obs)
        await session.commit()

        await set_observable_interesting(session, "domain", "evil.com", True)

        result = await session.execute(
            select(Observable).where(
                Observable.type == "domain",
                Observable.sha256 == _sha256("evil.com"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True


class TestGetInterestingObservablesByHashes:
    """Test the get_interesting_observables_by_hashes service function."""

    @pytest.mark.asyncio
    async def test_returns_empty_for_empty_input(self, session: AsyncSession):
        result = await get_interesting_observables_by_hashes(session, [])
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_only_interesting_observables(self, session: AsyncSession):
        obs1 = Observable(
            type="ipv4",
            sha256=_sha256("1.1.1.1"),
            value=b"1.1.1.1",
            is_interesting=True,
        )
        obs2 = Observable(
            type="ipv4",
            sha256=_sha256("2.2.2.2"),
            value=b"2.2.2.2",
            is_interesting=False,
        )
        obs3 = Observable(
            type="domain",
            sha256=_sha256("evil.com"),
            value=b"evil.com",
            is_interesting=True,
        )
        session.add_all([obs1, obs2, obs3])
        await session.commit()

        result = await get_interesting_observables_by_hashes(
            session,
            [_sha256("1.1.1.1"), _sha256("2.2.2.2"), _sha256("evil.com")],
        )
        assert len(result) == 2
        result_types = {(o.type, o.value) for o in result}
        assert ("ipv4", b"1.1.1.1") in result_types
        assert ("domain", b"evil.com") in result_types

    @pytest.mark.asyncio
    async def test_ignores_hashes_not_in_db(self, session: AsyncSession):
        obs = Observable(
            type="ipv4",
            sha256=_sha256("1.1.1.1"),
            value=b"1.1.1.1",
            is_interesting=True,
        )
        session.add(obs)
        await session.commit()

        result = await get_interesting_observables_by_hashes(
            session,
            [_sha256("1.1.1.1"), _sha256("nonexistent")],
        )
        assert len(result) == 1
        assert result[0].type == "ipv4"


class TestLookupObservables:
    """Service-level tests for lookup_observables (chunking and stitching)."""

    @pytest.mark.asyncio
    async def test_chunking_merges_all_chunks(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ):
        """Every observable resolves even when the batch spans multiple IN chunks."""
        monkeypatch.setattr(observables_service, "CHUNK_SIZE", 2)

        values = [f"10.20.30.{i}" for i in range(5)]
        for value in values:
            session.add(Observable(type="ipv4", sha256=_sha256(value), value=value.encode("utf8")))
        await session.commit()

        response = await observables_service.lookup_observables(
            session,
            pairs=[LookupPair(type="ipv4", value=v) for v in values],
            recent_alert_limit=5,
            exclude_alert_uuids=[],
            since=None,
        )
        assert len(response.results) == 5
        assert all(r.found for r in response.results)

    @pytest.mark.asyncio
    async def test_type_matching_is_casefolded(self, session: AsyncSession):
        """A stored row whose type differs only in case still stitches back to the request pair
        (observables.type compares case-insensitively in MySQL)."""
        session.add(Observable(type="IPv4", sha256=_sha256("10.40.50.60"), value=b"10.40.50.60"))
        await session.commit()

        response = await lookup_observables(
            session,
            pairs=[LookupPair(type="ipv4", value="10.40.50.60")],
            recent_alert_limit=5,
            exclude_alert_uuids=[],
            since=None,
        )
        (result,) = response.results
        assert result.found is True
