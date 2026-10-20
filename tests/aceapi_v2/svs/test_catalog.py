"""GET /api/v2/svs/tests, the Atomic Red Team test catalog (docs/SVS_API.md, *Tests*)."""

import csv
import io
import json
from datetime import datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import SVSCatalogTest, SVSRun
from saq.database.pool import get_db
from saq.svs.catalog import content_hash
from tests.aceapi_v2.conftest import api_key_client, make_api_key

pytestmark = pytest.mark.integration

RUN_UUID = "dddddddd-4444-4444-8444-444444444444"


def _test(guid: str, technique: str, name: str, *, platforms=("windows",), executor="powershell", removed=False,
          repository="atomic-red-team") -> None:
    entry = {"name": name, "auto_generated_guid": guid, "supported_platforms": list(platforms),
             "executor": {"name": executor, "command": "whoami"}}
    db = get_db()
    db.add(SVSCatalogTest(
        guid=guid, repository=repository, technique=technique, technique_name=f"{technique} name", name=name,
        description=f"{name} does a thing", platforms=json.dumps(list(platforms)), executor=executor,
        test=json.dumps(entry), content_hash=content_hash(entry), commit="a" * 40,
        path=f"atomics/{technique}/{technique}.yaml", first_seen_at=datetime.now(),
        removed_at=datetime.now() if removed else None))
    db.commit()


def _guid(n: int) -> str:
    return f"{n:08x}-0000-4000-8000-000000000000"


@pytest.fixture
def catalog():
    _test(_guid(1), "T1059.001", "PowerShell download")
    _test(_guid(2), "T1059", "Command interpreter", platforms=("linux", "macos"), executor="sh")
    _test(_guid(3), "T1003", "Dump credentials")
    _test(_guid(4), "T1059.003", "Batch file", executor="command_prompt", removed=True, repository="custom")
    _test(_guid(5), "T10590", "Not a sub-technique of T1059")


async def _guids(client: AsyncClient, *filters: str) -> list[str]:
    response = await client.get("/svs/tests/", params={"f": list(filters)})
    assert response.status_code == 200, response.text
    return [row["guid"] for row in response.json()["data"]]


@pytest.mark.asyncio
async def test_ordered_by_technique_then_name(client: AsyncClient, catalog):
    assert await _guids(client) == [_guid(3), _guid(2), _guid(1), _guid(4), _guid(5)]


@pytest.mark.asyncio
@pytest.mark.parametrize("filters, expected", [
    # a technique also finds its sub-techniques, and nothing that only shares its prefix
    (["technique:T1059"], [2, 1, 4]),
    (["technique:t1059.001"], [1]),
    (["!technique:T1059"], [3, 5]),
    (["platform:linux"], [2]),
    (["executor:sh,command_prompt"], [2, 4]),
    (["name:download"], [1]),
    (["repository:custom"], [4]),
    (["removed:true"], [4]),
    (["removed:false", "technique:T1059"], [2, 1]),
])
async def test_filters(client: AsyncClient, catalog, filters, expected):
    assert await _guids(client, *filters) == [_guid(n) for n in expected]


@pytest.mark.asyncio
async def test_a_bad_filter_is_422(client: AsyncClient, catalog):
    assert (await client.get("/svs/tests/", params={"f": "technique:mimikatz"})).status_code == 422
    assert (await client.get("/svs/tests/", params={"f": "nonsense:x"})).status_code == 422


@pytest.mark.asyncio
async def test_pages(client: AsyncClient, catalog):
    first = (await client.get("/svs/tests/", params={"limit": 2})).json()
    second = (await client.get("/svs/tests/", params={"limit": 2, "cursor": first["next_cursor"]})).json()
    third = (await client.get("/svs/tests/", params={"limit": 2, "cursor": second["next_cursor"]})).json()
    assert [row["guid"] for page in (first, second, third) for row in page["data"]] == [
        _guid(3), _guid(2), _guid(1), _guid(4), _guid(5)]
    assert third["next_cursor"] is None


@pytest.mark.asyncio
async def test_detail(client: AsyncClient, catalog):
    response = await client.get(f"/svs/tests/{_guid(1).upper()}")
    assert response.status_code == 200, response.text
    detail = response.json()
    assert detail["name"] == "PowerShell download" and detail["technique"] == "T1059.001"
    assert detail["description"] == "PowerShell download does a thing"
    assert detail["test"]["executor"]["command"] == "whoami"
    assert detail["platforms"] == ["windows"] and detail["removed_at"] is None

    assert (await client.get("/svs/tests/not-a-guid")).status_code == 400
    assert (await client.get(f"/svs/tests/{_guid(99)}")).status_code == 404


@pytest.mark.asyncio
async def test_each_tests_state_and_runs(client: AsyncClient, catalog):
    """The state and history columns (saq.svs.test_state, tested there in full)."""
    db = get_db()
    db.add(SVSRun(uuid=RUN_UUID, test_guid=_guid(1), test_content_hash="0" * 64, catalog_commit="a" * 40,
                  platform="windows", state="ended", marker="svs-" + "a" * 26, launcher="art", extra="{}", created_at=datetime.now(),
                  observation_seconds=3600, attribution_seconds=3600))
    db.commit()

    rows = {row["guid"]: row for row in (await client.get("/svs/tests/")).json()["data"]}
    ran = rows[_guid(1)]
    assert (ran["test_state"], ran["run_count"], ran["last_run_id"], ran["recent_runs"]) == (
        "awaiting_review", 1, RUN_UUID, 1)
    assert (rows[_guid(3)]["test_state"], rows[_guid(3)]["run_count"]) == ("never_run", 0)
    detail = (await client.get(f"/svs/tests/{_guid(1)}")).json()
    assert detail["test_state"] == "awaiting_review"
    assert [(row["platform"], row["test_state"]) for row in detail["platform_states"]] == [("windows", "awaiting_review")]
    # one state per supported platform, never_run where it has no run or decision
    detail = (await client.get(f"/svs/tests/{_guid(2)}")).json()
    assert [(row["platform"], row["test_state"]) for row in detail["platform_states"]] == [
        ("linux", "never_run"), ("macos", "never_run")]
    # the list carries the roll-up only
    assert "platform_states" not in ran
    records = list(csv.DictReader(io.StringIO((await client.get("/svs/tests/export/csv")).text)))
    assert {record["test_state"] for record in records} == {"awaiting_review", "never_run"}


@pytest.mark.asyncio
async def test_exports(client: AsyncClient, catalog):
    lines = (await client.get("/svs/tests/export/ndjson", params={"f": "technique:T1059"})).text.splitlines()
    assert [json.loads(line)["guid"] for line in lines] == [_guid(2), _guid(1), _guid(4)]

    records = list(csv.DictReader(io.StringIO((await client.get("/svs/tests/export/csv")).text)))
    assert len(records) == 5
    assert next(r for r in records if r["guid"] == _guid(2))["platforms"] == "linux,macos"


@pytest.mark.asyncio
async def test_permissions(_override_db_session, session: AsyncSession, test_user, catalog, noperm_client):
    key = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(key) as client:
        assert (await client.get("/svs/tests/")).status_code == 200
        assert (await client.get(f"/svs/tests/{_guid(1)}")).status_code == 200
    assert (await noperm_client.get("/svs/tests/")).status_code == 403
