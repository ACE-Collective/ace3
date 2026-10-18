"""GET/POST/PUT/DELETE /api/v2/svs/test-hosts (docs/SVS_API.md, *Test hosts*)."""

import csv
import io
import json

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.svs import hosts
from tests.aceapi_v2.conftest import api_key_client, make_api_key

pytestmark = pytest.mark.integration

WIN10 = {"hostname": "WIN10-01.corp.example", "usernames": ["CORP\\svc_art"], "ips": ["10.0.0.5"],
         "platform": "windows", "notes": "lab 3"}


@pytest.mark.asyncio
async def test_create_read_update_delete(client: AsyncClient, test_user):
    response = await client.post("/svs/test-hosts/", json=WIN10)
    assert response.status_code == 201, response.text
    host = response.json()
    assert (host["hostname"], host["fqdn"], host["usernames"], host["ips"], host["platform"]) == (
        "win10-01", "win10-01.corp.example", ["svc_art"], ["10.0.0.5"], "windows")
    assert host["created_by"] == test_user.username

    assert (await client.get(f"/svs/test-hosts/{host['id']}")).json() == host

    response = await client.put(f"/svs/test-hosts/{host['id']}", json={"hostname": "win10-01", "usernames": []})
    assert response.status_code == 200, response.text
    assert response.json()["usernames"] == [] and response.json()["fqdn"] is None

    assert (await client.delete(f"/svs/test-hosts/{host['id']}")).status_code == 204
    assert (await client.get(f"/svs/test-hosts/{host['id']}")).status_code == 404
    assert (await client.delete(f"/svs/test-hosts/{host['id']}")).status_code == 404


@pytest.mark.asyncio
async def test_a_change_from_a_stale_form_is_refused(client: AsyncClient, test_user):
    """docs/SVS_API.md, *Conflicting writes*"""
    host = (await client.post("/svs/test-hosts/", json=WIN10)).json()
    seen = {"If-Match": host["updated_at"]}
    path = f"/svs/test-hosts/{host['id']}"

    first = await client.put(path, json={**WIN10, "notes": "lab 4"}, headers=seen)
    assert first.status_code == 200, first.text
    second = await client.put(path, json={**WIN10, "usernames": []}, headers=seen)
    assert second.status_code == 412
    assert second.json()["detail"]["current"]["notes"] == "lab 4"
    assert (await client.get(path)).json()["usernames"] == ["svc_art"]

    assert (await client.put(path, json={**WIN10, "usernames": []},
                             headers={"If-Match": first.json()["updated_at"]})).status_code == 200


@pytest.mark.asyncio
async def test_errors(client: AsyncClient):
    assert (await client.post("/svs/test-hosts/", json=WIN10)).status_code == 201
    assert (await client.post("/svs/test-hosts/", json={"hostname": "win10-01"})).status_code == 409
    response = await client.post("/svs/test-hosts/", json={"hostname": "win10-02", "platform": "iaas"})
    assert response.status_code == 422 and "is not one of windows, linux, macos" in response.json()["detail"]
    assert (await client.post("/svs/test-hosts/", json={"hostname": ""})).status_code == 422
    assert (await client.put("/svs/test-hosts/99999", json={"hostname": "x"})).status_code == 404


@pytest.mark.asyncio
async def test_the_listing_pages_by_hostname(client: AsyncClient):
    for name in ("c-host", "a-host", "b-host"):
        hosts.create_host(hosts.build_spec(name), None)

    first = (await client.get("/svs/test-hosts/", params={"limit": 2})).json()
    assert [row["hostname"] for row in first["data"]] == ["a-host", "b-host"]
    second = (await client.get("/svs/test-hosts/", params={"limit": 2, "cursor": first["next_cursor"]})).json()
    assert [row["hostname"] for row in second["data"]] == ["c-host"] and second["next_cursor"] is None

    assert (await client.get("/svs/test-hosts/", params={"cursor": "garbage"})).status_code == 400
    future = (await client.get("/svs/test-hosts/", params={"changed_since": "2099-01-01T00:00:00Z"})).json()
    assert future["data"] == []


@pytest.mark.asyncio
async def test_exports(client: AsyncClient):
    hosts.create_host(hosts.build_spec("win10-01", usernames=["a", "b"], ips=["10.0.0.5"]), None)

    lines = (await client.get("/svs/test-hosts/export/ndjson")).text.splitlines()
    assert [json.loads(line)["hostname"] for line in lines] == ["win10-01"]

    records = list(csv.DictReader(io.StringIO((await client.get("/svs/test-hosts/export/csv")).text)))
    assert records[0]["usernames"] == "a,b" and records[0]["ips"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_reading_needs_run_read_and_writing_needs_admin(_override_db_session, session: AsyncSession, test_user):
    host = hosts.create_host(hosts.build_spec("win10-01"), None)

    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(reader) as client:
        assert (await client.get("/svs/test-hosts/")).status_code == 200
        assert (await client.get(f"/svs/test-hosts/{host.id}")).status_code == 200
        assert (await client.post("/svs/test-hosts/", json={"hostname": "x"})).status_code == 403
        assert (await client.put(f"/svs/test-hosts/{host.id}", json={"hostname": "x"})).status_code == 403
        assert (await client.delete(f"/svs/test-hosts/{host.id}")).status_code == 403

    admin = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "admin")])
    async with api_key_client(admin) as client:
        assert (await client.post("/svs/test-hosts/", json={"hostname": "x"})).status_code == 201
        assert (await client.get("/svs/test-hosts/")).status_code == 403


@pytest.mark.asyncio
async def test_no_permission(noperm_client: AsyncClient):
    assert (await noperm_client.get("/svs/test-hosts/")).status_code == 403
