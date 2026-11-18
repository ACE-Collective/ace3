"""Tests for aceapi_v2 common router."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.constants import DIRECTIVE_DESCRIPTIONS, VALID_DIRECTIVES
from saq.database.model import Company
from saq.observables.type_hierarchy import get_all_valid_types, get_type_hierarchy

pytestmark = pytest.mark.integration


class TestPing:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        # the credential is required once, for the whole router, so one route checks it for all
        response = await unauth_client.get("/common/ping")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_ok(self, client: AsyncClient):
        response = await client.get("/common/ping")
        assert response.status_code == 200
        assert response.json() == {"result": "pong"}


class TestSupportedApiVersion:
    @pytest.mark.asyncio
    async def test_ok(self, client: AsyncClient):
        response = await client.get("/common/supported_api_version")
        assert response.status_code == 200
        assert response.json() == {"result": 1}


class TestValidCompanies:
    @pytest.mark.asyncio
    async def test_returns_inserted(
        self, session: AsyncSession, client: AsyncClient
    ):
        session.add(Company(name="zzz-test-company"))
        session.add(Company(name="aaa-test-company"))
        await session.commit()

        response = await client.get("/common/valid_companies")
        assert response.status_code == 200

        data = response.json()
        assert "data" in data
        names = [c["name"] for c in data["data"]]
        assert "aaa-test-company" in names
        assert "zzz-test-company" in names
        # sorted alphabetically
        assert names == sorted(names)
        # each item has id + name
        for company in data["data"]:
            assert set(company.keys()) == {"id", "name"}
            assert isinstance(company["id"], int)


class TestValidObservables:
    @pytest.mark.asyncio
    async def test_excludes_deprecated_and_has_descriptions(
        self, client: AsyncClient
    ):
        response = await client.get("/common/valid_observables")
        assert response.status_code == 200

        data = response.json()
        assert "data" in data
        names = [o["name"] for o in data["data"]]

        # no deprecated types are returned
        hierarchy = get_type_hierarchy()
        for t in get_all_valid_types():
            if hierarchy.is_deprecated(t):
                assert t not in names

        # every item has name + description
        for item in data["data"]:
            assert set(item.keys()) == {"name", "description"}
            assert isinstance(item["name"], str)
            assert isinstance(item["description"], str)

        # items that have a configured description expose it
        for item in data["data"]:
            configured = hierarchy.description_for(item["name"])
            if configured is not None:
                assert item["description"] == configured


class TestValidDirectives:
    @pytest.mark.asyncio
    async def test_ok(self, client: AsyncClient):
        response = await client.get("/common/valid_directives")
        assert response.status_code == 200

        data = response.json()
        assert "data" in data
        names = [d["name"] for d in data["data"]]

        # every directive with a description is represented
        for directive in VALID_DIRECTIVES:
            if directive in DIRECTIVE_DESCRIPTIONS:
                assert directive in names

        # every returned item carries the mapped description
        for item in data["data"]:
            assert item["name"] in VALID_DIRECTIVES
            assert item["description"] == DIRECTIVE_DESCRIPTIONS[item["name"]]
