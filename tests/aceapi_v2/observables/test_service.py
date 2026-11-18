"""Tests for aceapi_v2 observables service."""

import hashlib

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import aceapi_v2.observables.service as observables_service
from aceapi_v2.observables.schemas import LookupPair
from aceapi_v2.observables.service import (
    get_interesting_observables_by_hashes,
    lookup_observables,
)
from saq.database.model import Observable

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


class TestGetInterestingObservablesByHashes:
    """Test the get_interesting_observables_by_hashes service function."""

    @pytest.mark.asyncio
    async def test_returns_empty_for_empty_input(self, session: AsyncSession):
        # an empty list asks for nothing, not for every interesting observable
        session.add(Observable(type="ipv4", sha256=_sha256("1.1.1.1"), value=b"1.1.1.1", is_interesting=True))
        await session.commit()

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
            type="fqdn",
            sha256=_sha256("evil.com"),
            value=b"evil.com",
            is_interesting=True,
        )
        # interesting, but not asked for
        obs4 = Observable(
            type="ipv4",
            sha256=_sha256("4.4.4.4"),
            value=b"4.4.4.4",
            is_interesting=True,
        )
        session.add_all([obs1, obs2, obs3, obs4])
        await session.commit()

        result = await get_interesting_observables_by_hashes(
            session,
            [_sha256("1.1.1.1"), _sha256("2.2.2.2"), _sha256("evil.com"), _sha256("nonexistent")],
        )
        assert len(result) == 2
        result_types = {(o.type, o.value) for o in result}
        assert ("ipv4", b"1.1.1.1") in result_types
        assert ("fqdn", b"evil.com") in result_types


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
