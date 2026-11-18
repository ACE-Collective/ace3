"""Tests for the aceapi_v2 threat types router."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Malware, Threat, ThreatType

pytestmark = pytest.mark.integration

BASE = "/threat-types"


async def _create(client: AsyncClient, name: str) -> dict:
    response = await client.post(f"{BASE}/", json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()


class TestAuth:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get(f"{BASE}/")).status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path,body", [
        ("GET", "/", None),
        ("POST", "/", {"name": "rat"}),
        ("GET", "/1", None),
        ("PATCH", "/1", {"name": "rat"}),
        ("DELETE", "/1", None),
    ])
    async def test_requires_permission(self, noperm_client: AsyncClient, method, path, body):
        response = await noperm_client.request(method, f"{BASE}{path}", json=body)
        assert response.status_code == 403


class TestCrud:
    @pytest.mark.asyncio
    async def test_list_is_sorted_by_name_and_sees_every_change(self, client: AsyncClient):
        rat = await _create(client, "rat")
        await _create(client, "botnet")
        # the list is cached: a create, a rename and a delete each have to invalidate it
        assert [t["name"] for t in (await client.get(f"{BASE}/")).json()["data"]] == ["botnet", "rat"]

        botnet = (await client.get(f"{BASE}/")).json()["data"][0]
        assert (await client.patch(f"{BASE}/{botnet['id']}", json={"name": "wiper"})).status_code == 200
        assert [t["name"] for t in (await client.get(f"{BASE}/")).json()["data"]] == ["rat", "wiper"]

        assert (await client.delete(f"{BASE}/{rat['id']}")).status_code == 204
        response = await client.get(f"{BASE}/")
        assert [t["name"] for t in response.json()["data"]] == ["wiper"]
        assert response.headers["Cache-Control"] == "private, max-age=300"

    @pytest.mark.asyncio
    async def test_get_one(self, client: AsyncClient):
        rat = await _create(client, "rat")

        assert (await client.get(f"{BASE}/{rat['id']}")).json() == rat

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,body", [("GET", None), ("PATCH", {"name": "rat"}), ("DELETE", None)])
    async def test_an_unknown_id_is_404(self, client: AsyncClient, method, body):
        response = await client.request(method, f"{BASE}/999999", json=body)
        assert response.status_code == 404
        assert response.json()["detail"] == "Threat type not found"

    @pytest.mark.asyncio
    async def test_a_patch_without_a_name_changes_nothing(self, client: AsyncClient):
        rat = await _create(client, "rat")

        response = await client.patch(f"{BASE}/{rat['id']}", json={})

        assert response.status_code == 200
        assert response.json() == rat


class TestConflicts:
    @pytest.mark.asyncio
    async def test_a_name_that_exists_is_409(self, client: AsyncClient):
        await _create(client, "rat")

        response = await client.post(f"{BASE}/", json={"name": "rat"})

        assert response.status_code == 409
        assert response.json()["detail"] == "a threat type named 'rat' already exists"

    @pytest.mark.asyncio
    async def test_renaming_to_a_name_that_exists_is_409(self, client: AsyncClient):
        await _create(client, "rat")
        botnet = await _create(client, "botnet")

        response = await client.patch(f"{BASE}/{botnet['id']}", json={"name": "rat"})

        assert response.status_code == 409
        assert response.json()["detail"] == "a threat type named 'rat' already exists"
        assert (await client.get(f"{BASE}/{botnet['id']}")).json()["name"] == "botnet"

    @pytest.mark.asyncio
    async def test_a_threat_type_that_malware_uses_cannot_be_deleted(self, client: AsyncClient, session: AsyncSession):
        rat = ThreatType(name="rat")
        malware = Malware(name="example malware")
        session.add_all([rat, malware])
        await session.flush()
        session.add(Threat(malware_id=malware.id, threat_type_id=rat.id))
        await session.flush()

        response = await client.delete(f"{BASE}/{rat.id}")

        assert response.status_code == 409
        assert response.json()["detail"] == "threat type 'rat' is used by 1 malware"
        assert (await client.get(f"{BASE}/{rat.id}")).status_code == 200
