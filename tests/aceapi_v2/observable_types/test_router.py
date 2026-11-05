"""Tests for aceapi_v2 observable types router."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.observable_types.router import _cache
from saq.database.model import Observable
from saq.observables.type_hierarchy import get_all_valid_types

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
    async def test_list_observable_types_matches_registry(self, client: AsyncClient):
        """The endpoint returns exactly the configured valid types, sorted."""
        response = await client.get("/observable-types/")
        assert response.status_code == 200

        data = response.json()
        type_names = [t["name"] for t in data["data"]]

        # The configured observable_types.yaml (plus Python-registered classes)
        # is the single source of truth.
        assert type_names == sorted(get_all_valid_types())
        # Sanity check: a well-known registry type is present.
        assert "ipv4" in type_names

    @pytest.mark.asyncio
    async def test_db_only_types_are_excluded(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Observable types that exist only in the database are NOT returned.

        The YAML registry is the single source of truth, so stale/legacy types
        in old observable rows must not leak into the response.
        """
        db_only_type = "zebra_type_not_in_yaml"
        assert db_only_type not in get_all_valid_types()

        session.add(
            Observable(type=db_only_type, sha256=b"z" * 32, value=b"z")
        )
        await session.commit()

        response = await client.get("/observable-types/")
        assert response.status_code == 200

        type_names = [t["name"] for t in response.json()["data"]]
        assert db_only_type not in type_names

    @pytest.mark.asyncio
    async def test_list_observable_types_response_format(self, client: AsyncClient):
        """Test that response follows the expected schema."""
        response = await client.get("/observable-types/")
        assert response.status_code == 200

        data = response.json()
        # Verify response structure
        assert "data" in data
        assert isinstance(data["data"], list)

        # A known-valid registry type has the expected object shape.
        ipv4_types = [t for t in data["data"] if t["name"] == "ipv4"]
        assert len(ipv4_types) == 1
        assert ipv4_types[0] == {"name": "ipv4"}
