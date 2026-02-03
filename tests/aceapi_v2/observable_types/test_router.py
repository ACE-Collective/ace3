"""Tests for aceapi_v2 observable types router."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.observable_types.router import _cache
from saq.database.model import Observable

pytestmark = pytest.mark.integration


class TestObservableTypes:
    """Test the observable types endpoint."""

    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        """Clear the observable types cache before each test."""
        _cache.clear()
        yield
        _cache.clear()

    @pytest.mark.asyncio
    async def test_list_observable_types_requires_auth(
        self, unauth_client: AsyncClient
    ):
        """Test that the endpoint requires authentication."""
        response = await unauth_client.get("/observable-types/")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_list_observable_types_empty(self, client: AsyncClient):
        """Test listing observable types returns proper structure."""
        response = await client.get("/observable-types/")
        assert response.status_code == 200
        data = response.json()
        # Should have the wrapped response format
        assert "data" in data
        assert isinstance(data["data"], list)

    @pytest.mark.asyncio
    async def test_list_observable_types_returns_unique_types(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Test that endpoint returns unique observable types."""
        # Create test observables with different types
        observables = [
            Observable(type="ipv4", sha256=b"a" * 32, value=b"192.168.1.1"),
            Observable(type="ipv4", sha256=b"b" * 32, value=b"192.168.1.2"),
            Observable(type="domain", sha256=b"c" * 32, value=b"example.com"),
            Observable(type="url", sha256=b"d" * 32, value=b"https://example.com"),
            Observable(type="domain", sha256=b"e" * 32, value=b"test.com"),
        ]
        for obs in observables:
            session.add(obs)
        await session.commit()

        response = await client.get("/observable-types/")
        assert response.status_code == 200

        data = response.json()
        assert "data" in data
        types = data["data"]
        assert isinstance(types, list)

        # Extract type names from response objects
        type_names = [t["name"] for t in types]

        # Should contain our types (uniquely)
        assert "ipv4" in type_names
        assert "domain" in type_names
        assert "url" in type_names

        # Should be sorted alphabetically
        assert type_names == sorted(type_names)

    @pytest.mark.asyncio
    async def test_list_observable_types_sorted(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Test that observable types are returned in sorted order."""
        # Create observables with types that would be unsorted if not ordered
        observables = [
            Observable(type="zebra_type", sha256=b"z" * 32, value=b"z"),
            Observable(type="alpha_type", sha256=b"a" * 32, value=b"a"),
            Observable(type="middle_type", sha256=b"m" * 32, value=b"m"),
        ]
        for obs in observables:
            session.add(obs)
        await session.commit()

        response = await client.get("/observable-types/")
        assert response.status_code == 200

        data = response.json()
        type_names = [t["name"] for t in data["data"]]
        assert type_names == sorted(type_names)

    @pytest.mark.asyncio
    async def test_list_observable_types_response_format(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Test that response follows the expected schema."""
        # Create a test observable
        observable = Observable(type="test_type", sha256=b"t" * 32, value=b"test")
        session.add(observable)
        await session.commit()

        response = await client.get("/observable-types/")
        assert response.status_code == 200

        data = response.json()
        # Verify response structure
        assert "data" in data
        assert isinstance(data["data"], list)

        # Find our test type and verify its structure
        test_types = [t for t in data["data"] if t["name"] == "test_type"]
        assert len(test_types) == 1
        assert test_types[0] == {"name": "test_type"}
