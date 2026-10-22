"""A test's expectations, ignores and settings through the API (docs/SVS_API.md, *Expectations*,
*Ignores*, *Test settings*): /svs/expectations, /svs/ignores and /svs/tests/{guid}/..."""

import csv
import io
import json

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.svs.expectations import service as expectations_service
from aceapi_v2.svs.expectations.schemas import ExpectationRequest
from saq.database.model import SVSRunResultState
from saq.database.pool import get_db
from saq.svs import results
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run

# several runs on one test host are fixtures here; the host's claim is tested in test_runs.py
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("overlapping_runs")]

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
OTHER_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
SIGNATURE = "22222222-bbbb-4bbb-8bbb-222222222222"
NOISE = "33333333-cccc-4ccc-8ccc-333333333333"
MULTI_GUID = "eeeeeeee-5555-4555-8555-555555555555"


@pytest.fixture(autouse=True)
def setup(no_hunts, yara_dir):
    add_catalog_test(GUID)
    add_catalog_test(OTHER_GUID)
    add_test_host("win10-01")


def _stale(run_id: int) -> bool:
    db = get_db()
    db.expire_all()
    state = db.get(SVSRunResultState, run_id)
    return state is not None and state.stale


class TestConflictingDecisions:
    """Two reviewers deciding the same candidate, and a stale reason (docs/SVS_API.md, *Conflicting
    writes*)."""

    @pytest.mark.asyncio
    async def test_a_candidate_decided_twice(self, client: AsyncClient, test_user):
        path = f"/svs/tests/{GUID}/expectations/windows/{SIGNATURE}"
        undecided = {"If-None-Match": "*"}
        first = await client.put(path, json={"state": "expected"}, headers=undecided)
        assert first.status_code == 200, first.text
        second = await client.put(path, json={"state": "rejected"}, headers=undecided)
        assert second.status_code == 412
        assert second.json()["detail"]["current"]["state"] == "expected"

        # a change from the decision as last read
        seen = {"If-Match": first.json()["updated_at"]}
        changed = await client.put(path, json={"state": "rejected"}, headers=seen)
        assert changed.status_code == 200 and changed.json()["state"] == "rejected"
        assert (await client.put(path, json={"state": "expected"}, headers=seen)).status_code == 412
        # removed since it was read
        assert (await client.delete(path)).status_code == 204
        stale = await client.put(path, json={"state": "expected"}, headers={"If-Match": changed.json()["updated_at"]})
        assert stale.status_code == 412 and stale.json()["detail"]["current"] is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", [f"/svs/tests/{GUID}/ignores/{NOISE}", f"/svs/ignores/global/{NOISE}"])
    async def test_an_ignore_added_twice_and_a_stale_reason(self, client: AsyncClient, test_user, path):
        first = await client.put(path, json={"reason": "launcher noise"}, headers={"If-None-Match": "*"})
        assert first.status_code == 200, first.text
        assert (await client.put(path, json={"reason": "x"}, headers={"If-None-Match": "*"})).status_code == 412

        seen = {"If-Match": first.json()["updated_at"]}
        assert (await client.put(path, json={"reason": "winrm"}, headers=seen)).status_code == 200
        stale = await client.put(path, json={"reason": "stale"}, headers=seen)
        assert stale.status_code == 412 and stale.json()["detail"]["current"]["reason"] == "winrm"


class TestExpectations:
    @pytest.mark.asyncio
    async def test_decide_list_and_remove(self, client: AsyncClient, test_user):
        run = started_run(GUID)
        results.compute_result(run.id)

        response = await client.put(f"/svs/tests/{GUID}/expectations/windows/{SIGNATURE}",
                                    json={"state": "expected", "reason": "the macro", "run_id": run.uuid})
        assert response.status_code == 200, response.text
        expectation = response.json()
        assert (expectation["state"], expectation["reason"], expectation["decided_from_run_id"],
                expectation["decided_by"]) == ("expected", "the macro", run.uuid, test_user.username)
        assert _stale(run.id)

        await client.put(f"/svs/tests/{OTHER_GUID}/expectations/windows/{NOISE}", json={"state": "rejected"})
        rows = (await client.get("/svs/expectations/")).json()["data"]
        assert [(row["test_guid"], row["state"]) for row in rows] == [(GUID, "expected"), (OTHER_GUID, "rejected")]
        rows = (await client.get("/svs/expectations/", params={"test": GUID, "state": "expected"})).json()["data"]
        assert [row["signature_uuid"] for row in rows] == [SIGNATURE]
        assert (await client.get("/svs/expectations/", params={"state": "candidate"})).status_code == 422

        assert (await client.delete(f"/svs/tests/{GUID}/expectations/windows/{SIGNATURE}")).status_code == 204
        assert (await client.delete(f"/svs/tests/{GUID}/expectations/windows/{SIGNATURE}")).status_code == 404

    @pytest.mark.asyncio
    async def test_errors(self, client: AsyncClient):
        other_run = started_run(OTHER_GUID)
        unknown = "cccccccc-0000-4000-8000-000000000000"
        assert (await client.put(f"/svs/tests/{unknown}/expectations/windows/{SIGNATURE}",
                                 json={"state": "expected"})).status_code == 404
        assert (await client.put(f"/svs/tests/{GUID}/expectations/windows/not-a-uuid",
                                 json={"state": "expected"})).status_code == 422
        assert (await client.put(f"/svs/tests/{GUID}/expectations/windows/{SIGNATURE}",
                                 json={"state": "candidate"})).status_code == 422
        response = await client.put(f"/svs/tests/{GUID}/expectations/windows/{SIGNATURE}",
                                    json={"state": "expected", "run_id": other_run.uuid})
        assert response.status_code == 422 and "is not a run of test" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_paging_changed_since_and_exports(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(expectations_service, "CHANGED_SINCE_SETTLE_SECONDS", 0)
        for signature in (SIGNATURE, NOISE):
            await client.put(f"/svs/tests/{GUID}/expectations/windows/{signature}", json={"state": "expected"})

        first = (await client.get("/svs/expectations/", params={"limit": 1})).json()
        second = (await client.get("/svs/expectations/", params={"limit": 1, "cursor": first["next_cursor"]})).json()
        assert [first["data"][0]["signature_uuid"], second["data"][0]["signature_uuid"]] == [SIGNATURE, NOISE]
        assert second["next_cursor"] is None

        changed = (await client.get("/svs/expectations/", params={"changed_since": "2000-01-01T00:00:00Z",
                                                                   "limit": 1})).json()
        assert len(changed["data"]) == 1 and changed["next_cursor"]
        assert (await client.get("/svs/expectations/", params={"cursor": "garbage"})).status_code == 400

        lines = (await client.get("/svs/expectations/export/ndjson")).text.splitlines()
        assert len([json.loads(line) for line in lines]) == 2
        records = list(csv.DictReader(io.StringIO((await client.get("/svs/expectations/export/csv")).text)))
        assert {record["signature_uuid"] for record in records} == {SIGNATURE, NOISE}

    @pytest.mark.asyncio
    async def test_per_platform(self, client: AsyncClient):
        add_catalog_test(MULTI_GUID, platforms=("linux", "macos"))
        add_test_host("lin-01", platform="linux")
        add_test_host("mac-01", platform="macos")
        linux, macos = started_run(MULTI_GUID, "lin-01"), started_run(MULTI_GUID, "mac-01")
        for run in (linux, macos):
            results.compute_result(run.id)

        response = await client.put(f"/svs/tests/{MULTI_GUID}/expectations/linux/{SIGNATURE}",
                                    json={"state": "expected", "run_id": macos.uuid})
        assert response.status_code == 422 and "is on macos" in response.json()["detail"]
        response = await client.put(f"/svs/tests/{MULTI_GUID}/expectations/windows/{SIGNATURE}",
                                    json={"state": "expected"})
        assert response.status_code == 422 and "is not one of" in response.json()["detail"]

        response = await client.put(f"/svs/tests/{MULTI_GUID}/expectations/linux/{SIGNATURE}",
                                    json={"state": "expected"})
        assert response.status_code == 200 and response.json()["platform"] == "linux"
        # only the platform's runs are judged by it
        assert _stale(linux.id) and not _stale(macos.id)
        assert results.compute_result(linux.id).counts == {"missing": 1}
        assert results.compute_result(macos.id).counts == {}

        # the same signature is decided apart on each platform
        await client.put(f"/svs/tests/{MULTI_GUID}/expectations/macos/{SIGNATURE}", json={"state": "rejected"})
        rows = (await client.get("/svs/expectations/", params={"test": MULTI_GUID})).json()["data"]
        assert [(row["platform"], row["state"]) for row in rows] == [("linux", "expected"), ("macos", "rejected")]
        rows = (await client.get("/svs/expectations/", params={"platform": "macos"})).json()["data"]
        assert [row["state"] for row in rows] == ["rejected"]
        records = list(csv.DictReader(io.StringIO((await client.get("/svs/expectations/export/csv")).text)))
        assert sorted(record["platform"] for record in records) == ["linux", "macos"]

        assert (await client.delete(f"/svs/tests/{MULTI_GUID}/expectations/macos/{SIGNATURE}")).status_code == 204
        assert (await client.delete(f"/svs/tests/{MULTI_GUID}/expectations/macos/{SIGNATURE}")).status_code == 404
        assert [row["platform"] for row in (await client.get("/svs/expectations/")).json()["data"]] == ["linux"]

    def test_a_config_key_is_refused(self):
        with pytest.raises(HTTPException) as e:
            expectations_service.set_expectation(GUID, "windows", SIGNATURE, ExpectationRequest(state="expected"), None, "ci")
        assert e.value.status_code == 422


class TestIgnores:
    @pytest.mark.asyncio
    async def test_a_tests_and_global_ignores(self, client: AsyncClient):
        mine, other = started_run(GUID), started_run(OTHER_GUID)
        for run in (mine, other):
            results.compute_result(run.id)

        response = await client.put(f"/svs/tests/{GUID}/ignores/{NOISE}", json={"reason": "winrm"})
        assert response.status_code == 200, response.text
        assert (response.json()["scope"], response.json()["test_guid"]) == ("test", GUID)
        assert _stale(mine.id) and not _stale(other.id)

        response = await client.put(f"/svs/ignores/global/{SIGNATURE}", json={"reason": "remoting"})
        assert response.status_code == 200 and response.json()["scope"] == "global"
        assert _stale(other.id)

        # a test's ignores include the global ones
        rows = (await client.get("/svs/ignores/", params={"test": GUID})).json()["data"]
        assert {(row["scope"], row["signature_uuid"]) for row in rows} == {("test", NOISE), ("global", SIGNATURE)}
        rows = (await client.get("/svs/ignores/", params={"test": OTHER_GUID})).json()["data"]
        assert [row["signature_uuid"] for row in rows] == [SIGNATURE]
        assert (await client.get("/svs/ignores/", params={"scope": "nope"})).status_code == 422

        assert (await client.delete(f"/svs/tests/{GUID}/ignores/{NOISE}")).status_code == 204
        assert (await client.delete(f"/svs/tests/{GUID}/ignores/{NOISE}")).status_code == 404
        assert (await client.delete(f"/svs/ignores/global/{SIGNATURE}")).status_code == 204
        assert (await client.get("/svs/ignores/")).json()["data"] == []

    @pytest.mark.asyncio
    async def test_exports(self, client: AsyncClient):
        await client.put(f"/svs/ignores/global/{SIGNATURE}", json={})
        assert len((await client.get("/svs/ignores/export/ndjson")).text.splitlines()) == 1
        records = list(csv.DictReader(io.StringIO((await client.get("/svs/ignores/export/csv")).text)))
        assert records[0]["scope"] == "global"


class TestSettings:
    @pytest.mark.asyncio
    async def test_set_read_and_remove(self, client: AsyncClient, test_user):
        assert (await client.get(f"/svs/tests/{GUID}/settings")).status_code == 404

        response = await client.put(f"/svs/tests/{GUID}/settings", json={"observation_minutes": 45})
        assert response.status_code == 200, response.text
        assert (response.json()["observation_minutes"], response.json()["set_by"]) == (45, test_user.username)
        assert (await client.get(f"/svs/tests/{GUID}/settings")).json()["observation_minutes"] == 45

        assert (await client.put(f"/svs/tests/{GUID}/settings", json={"observation_minutes": 0})).status_code == 422

        # a PUT replaces the settings: holds_host alone goes back to the computed window
        response = await client.put(f"/svs/tests/{GUID}/settings", json={"holds_host": True})
        assert response.status_code == 200, response.text
        assert (response.json()["observation_minutes"], response.json()["holds_host"]) == (None, True)
        assert (await client.get(f"/svs/tests/{GUID}/settings")).json()["holds_host"] is True

        assert (await client.delete(f"/svs/tests/{GUID}/settings")).status_code == 204
        assert (await client.delete(f"/svs/tests/{GUID}/settings")).status_code == 404
        unknown = "cccccccc-0000-4000-8000-000000000000"
        assert (await client.get(f"/svs/tests/{unknown}/settings")).status_code == 404


@pytest.mark.asyncio
async def test_permissions(_override_db_session, session: AsyncSession, test_user):
    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(reader) as client:
        assert (await client.get("/svs/expectations/")).status_code == 200
        assert (await client.get("/svs/ignores/")).status_code == 200
        assert (await client.put(f"/svs/tests/{GUID}/expectations/windows/{SIGNATURE}",
                                 json={"state": "expected"})).status_code == 403
        assert (await client.put(f"/svs/tests/{GUID}/ignores/{NOISE}", json={})).status_code == 403
        assert (await client.put(f"/svs/tests/{GUID}/settings", json={"observation_minutes": 30})).status_code == 403
        assert (await client.put(f"/svs/ignores/global/{NOISE}", json={})).status_code == 403

    manager = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_manage")])
    async with api_key_client(manager) as client:
        assert (await client.put(f"/svs/tests/{GUID}/expectations/windows/{SIGNATURE}",
                                 json={"state": "expected"})).status_code == 200
        assert (await client.put(f"/svs/tests/{GUID}/ignores/{NOISE}", json={})).status_code == 200
        assert (await client.put(f"/svs/tests/{GUID}/settings", json={"observation_minutes": 30})).status_code == 200
        # a global ignore changes every test's results
        assert (await client.put(f"/svs/ignores/global/{NOISE}", json={})).status_code == 403
        assert (await client.get("/svs/expectations/")).status_code == 403

    admin = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "admin")])
    async with api_key_client(admin) as client:
        assert (await client.put(f"/svs/ignores/global/{NOISE}", json={})).status_code == 200
        assert (await client.delete(f"/svs/ignores/global/{NOISE}")).status_code == 204
        assert (await client.put(f"/svs/tests/{GUID}/ignores/{NOISE}", json={})).status_code == 403


@pytest.mark.asyncio
async def test_no_permission(noperm_client: AsyncClient):
    assert (await noperm_client.get("/svs/expectations/")).status_code == 403
    assert (await noperm_client.get("/svs/ignores/")).status_code == 403
