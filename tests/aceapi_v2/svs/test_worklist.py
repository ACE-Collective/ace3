"""/api/v2/svs/worklist, the declared-vs-measured worklist (docs/SVS_API.md, *Worklist*)."""

import csv
import io
import json
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.svs.worklist import service
from aceapi_v2.svs.worklist.schemas import ResolutionRequest
from saq.database.model import SVSTechniqueWorklist, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.svs import coverage, expectations, signatures, windows
from saq.svs.attack import load_attack_catalog
from saq.svs.coverage import refresh_coverage
from saq.svs.signatures import SignatureTags
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.svs.conftest import ATTACK_EXTRACT, add_catalog_test

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
SIGNATURE = "22222222-bbbb-4bbb-8bbb-222222222222"
YARA = "33333333-cccc-4ccc-8ccc-333333333333"
OTHER = "44444444-dddd-4ddd-8ddd-444444444444"
T0 = datetime(2026, 10, 17, 12, 0, 0)


@pytest.fixture
def attack_catalog(tmp_path, monkeypatch):
    """The miniature ATT&CK release, wherever the worklist reads one."""
    path = tmp_path / "v99.0.json"
    path.write_text(json.dumps(ATTACK_EXTRACT))
    catalog = load_attack_catalog(path)
    for target in ("aceapi_v2.svs.worklist.service.get_attack_catalog", "saq.gui.filter_entry.get_attack_catalog",
                   "saq.svs.coverage.get_attack_catalog"):
        monkeypatch.setattr(target, lambda: catalog)
    return catalog


@pytest.fixture
def no_settle(monkeypatch):
    monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 0)


def _row(signature_uuid: str, technique: str, status: str, kind: str = "declared", **values) -> None:
    columns = dict(
        signature_uuid=signature_uuid, technique=technique, kind=kind, status=status,
        declared_as=json.dumps([technique] if kind != "undeclared" else []), tag_present=kind != "undeclared",
        signature_counts=True, counts=status in ("open", "kept", "confirmed"), measured=status != "retired",
        measured_techniques=json.dumps(["T1059.001"]), signature_family="hunt",
        signature_name=f"hunt {signature_uuid[:4]}", first_seen_at=T0, status_changed_at=T0)
    columns.update(values)
    with private_transaction() as session:
        session.add(SVSTechniqueWorklist(**columns))


@pytest.fixture
def unittest_user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()


@pytest.fixture
def rows(attack_catalog, unittest_user_id):
    _row(SIGNATURE, "T1059", "confirmed")
    _row(SIGNATURE, "T1547", "open")
    _row(SIGNATURE, "T1059.002", "undeclared", kind="undeclared")
    _row(YARA, "T1547", "remove_pending", signature_family="yara", signature_name="Autostart rule",
         resolution="remove", reason="wrong", reference="https://git.example/pull/3",
         resolved_by_user_id=unittest_user_id, resolved_at=datetime.now() - timedelta(hours=1))
    _row(YARA, "T9999", "unknown", kind="unknown", signature_family="yara", signature_name="Autostart rule")
    _row(OTHER, "T1059.001", "retired", resolution="keep", reason="r", resolved_at=T0)


ORDER = [f"{SIGNATURE}/T1059", f"{SIGNATURE}/T1059.002", f"{SIGNATURE}/T1547", f"{YARA}/T1547", f"{YARA}/T9999",
         f"{OTHER}/T1059.001"]


def _key(row: dict) -> str:
    return f"{row['signature_uuid']}/{row['technique']}"


async def _keys(client: AsyncClient, *filters: str) -> list[str]:
    response = await client.get("/svs/worklist/", params={"f": list(filters)})
    assert response.status_code == 200, response.text
    return [_key(row) for row in response.json()["data"]]


class TestList:
    @pytest.mark.asyncio
    async def test_ordered_by_signature_then_technique(self, client: AsyncClient, rows):
        assert await _keys(client) == ORDER
        (row,) = (await client.get("/svs/worklist/", params={"f": f"signature:{YARA}", "limit": 1})).json()["data"]
        assert (row["technique_name"], row["declared_as"], row["measured_techniques"], row["resolution"],
                row["resolved_by"], row["reference"], row["counts"]) == (
            "Boot or Logon Autostart Execution", ["T1547"], ["T1059.001"], "remove", "unittest",
            "https://git.example/pull/3", False)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("filters, expected", [
        ([f"signature:{SIGNATURE}"], ORDER[:3]),
        (["signature:autostart"], ORDER[3:5]),
        (["family:yara"], ORDER[3:5]),
        # a technique also finds its sub-techniques
        (["technique:T1059"], [ORDER[0], ORDER[1], ORDER[5]]),
        (["!technique:T1059"], [ORDER[2], ORDER[3], ORDER[4]]),
        (["status:open,remove_pending"], [ORDER[2], ORDER[3]]),
        (["kind:undeclared,unknown"], [ORDER[1], ORDER[4]]),
        (["resolution:keep"], [ORDER[5]]),
        (["resolution:none", "kind:declared"], [ORDER[0], ORDER[2]]),
        (["!resolution:none"], [ORDER[3], ORDER[5]]),
        (["resolved_by:unittest"], [ORDER[3]]),
        (["resolved:-1d"], [ORDER[3]]),
    ])
    async def test_filters(self, client: AsyncClient, rows, filters, expected):
        assert await _keys(client, *filters) == expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["status:closed", "kind:manual", "technique:TA0002", "nonsense:x"])
    async def test_a_bad_filter_is_422(self, client: AsyncClient, rows, value):
        assert (await client.get("/svs/worklist/", params={"f": value})).status_code == 422

    @pytest.mark.asyncio
    async def test_pages(self, client: AsyncClient, rows):
        keys, cursor = [], None
        while True:
            params = {"limit": 4} | ({"cursor": cursor} if cursor else {})
            page = (await client.get("/svs/worklist/", params=params)).json()
            keys += [_key(row) for row in page["data"]]
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert keys == ORDER

    @pytest.mark.asyncio
    async def test_changed_since(self, client: AsyncClient, rows, no_settle):
        page = (await client.get("/svs/worklist/", params={"changed_since": "2000-01-01T00:00:00Z", "limit": 4})).json()
        rest = (await client.get("/svs/worklist/", params={"changed_since": "2000-01-01T00:00:00Z",
                                                           "cursor": page["next_cursor"]})).json()
        # in (updated_at, id) order: the order they were written
        assert [_key(row) for row in page["data"] + rest["data"]] == [
            ORDER[0], ORDER[2], ORDER[1], ORDER[3], ORDER[4], ORDER[5]]

        # a cursor of one order doesn't page the other
        assert (await client.get("/svs/worklist/", params={"cursor": page["next_cursor"]})).status_code == 400

    @pytest.mark.asyncio
    async def test_unsettled_rows_wait(self, client: AsyncClient, rows, monkeypatch):
        monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 3600)
        assert (await client.get("/svs/worklist/", params={"changed_since": "2000-01-01T00:00:00"})).json()["data"] == []

    @pytest.mark.asyncio
    async def test_exports(self, client: AsyncClient, rows):
        lines = (await client.get("/svs/worklist/export/ndjson", params={"f": "family:yara"})).text.splitlines()
        assert [json.loads(line)["technique"] for line in lines] == ["T1547", "T9999"]

        response = await client.get("/svs/worklist/export/csv")
        assert response.headers["content-type"].startswith("text/csv")
        records = list(csv.DictReader(io.StringIO(response.text)))
        assert [f"{r['signature_uuid']}/{r['technique']}" for r in records] == ORDER
        assert (records[0]["declared_as"], records[0]["measured_techniques"]) == ("T1059", "T1059.001")

        assert (await client.get("/svs/worklist/export/csv", params={"f": "status:closed"})).status_code == 422


class TestResolutions:
    @pytest.mark.asyncio
    async def test_set_and_clear(self, client: AsyncClient, rows):
        response = await client.put(f"/svs/worklist/{SIGNATURE}/t1547/resolution",
                                    json={"resolution": "keep", "reason": "no test reaches it"})
        assert response.status_code == 200, response.text
        row = response.json()
        assert (row["status"], row["resolution"], row["reason"], row["resolved_by"], row["counts"]) == (
            "kept", "keep", "no test reaches it", "unittest", True)

        response = await client.put(f"/svs/worklist/{SIGNATURE}/T1547/resolution",
                                    json={"resolution": "remove", "reason": "it doesn't",
                                          "reference": "https://git.example/pull/9"})
        assert (response.json()["status"], response.json()["counts"]) == ("remove_pending", False)

        assert (await client.delete(f"/svs/worklist/{SIGNATURE}/T1547/resolution")).status_code == 204
        assert (await client.delete(f"/svs/worklist/{SIGNATURE}/T1547/resolution")).status_code == 404
        assert await _keys(client, "status:open") == [ORDER[2]]

        # a retired row's stale resolution can be cleared
        assert (await client.delete(f"/svs/worklist/{OTHER}/T1059.001/resolution")).status_code == 204

    @pytest.mark.asyncio
    @pytest.mark.parametrize("signature, technique, body, status", [
        (SIGNATURE, "T1059", {"resolution": "keep", "reason": "r"}, 409),
        (SIGNATURE, "T1059.002", {"resolution": "keep", "reason": "r"}, 409),
        (YARA, "T9999", {"resolution": "remove", "reason": "r"}, 409),
        (OTHER, "T1059.001", {"resolution": "keep", "reason": "r"}, 409),
        (SIGNATURE, "T1105", {"resolution": "keep", "reason": "r"}, 404),
        (SIGNATURE, "T1547", {"resolution": "maybe", "reason": "r"}, 422),
        (SIGNATURE, "T1547", {"resolution": "keep", "reason": " "}, 422),
        (SIGNATURE, "T1547", {"resolution": "keep"}, 422),
        (SIGNATURE, "T1547", {"resolution": "remove", "reason": "r", "reference": "javascript:alert(1)"}, 422),
    ])
    async def test_refusals(self, client: AsyncClient, rows, signature, technique, body, status):
        response = await client.put(f"/svs/worklist/{signature}/{technique}/resolution", json=body)
        assert response.status_code == status, response.text

    @pytest.mark.asyncio
    async def test_a_conflict_names_the_status(self, client: AsyncClient, rows):
        response = await client.put(f"/svs/worklist/{SIGNATURE}/T1059/resolution",
                                    json={"resolution": "keep", "reason": "r"})
        assert "is confirmed" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_bulk(self, client: AsyncClient, rows):
        response = await client.post("/svs/worklist/bulk/resolve", json={
            "rows": [{"signature_uuid": SIGNATURE, "technique": "T1547"},
                     {"signature_uuid": YARA, "technique": "T1547"},
                     {"signature_uuid": SIGNATURE, "technique": "T1059"},
                     {"signature_uuid": SIGNATURE, "technique": "T1105"}],
            "resolution": "keep", "reason": "covers what no atomic reaches"})
        assert response.status_code == 200, response.text
        assert response.json() == {
            "done": [{"signature_uuid": SIGNATURE, "technique": "T1547"},
                     {"signature_uuid": YARA, "technique": "T1547"}],
            "conflicts": [{"signature_uuid": SIGNATURE, "technique": "T1059", "status": "confirmed"}],
            "unknown": [{"signature_uuid": SIGNATURE, "technique": "T1105"}]}
        assert await _keys(client, "status:kept") == [ORDER[2], ORDER[3]]

        assert (await client.post("/svs/worklist/bulk/resolve", json={
            "rows": [], "resolution": "keep", "reason": "r"})).status_code == 422
        assert (await client.post("/svs/worklist/bulk/resolve", json={
            "rows": [{"signature_uuid": SIGNATURE, "technique": "T1547"}], "resolution": "keep",
            "reason": ""})).status_code == 422

    def test_a_config_key_is_refused(self, rows):
        with pytest.raises(HTTPException) as e:
            service.set_resolution(SIGNATURE, "T1547", ResolutionRequest(resolution="keep", reason="r"), None, "ci")
        assert e.value.status_code == 422


class TestSignature:
    @pytest.mark.asyncio
    async def test_rows_and_what_is_measured_now(self, client: AsyncClient, attack_catalog, monkeypatch,
                                                 unittest_user_id):
        monkeypatch.setattr(windows, "hunt_info", lambda: {})
        monkeypatch.setattr(coverage, "signature_techniques",
                            lambda: {SIGNATURE: SignatureTags(SIGNATURE, "hunt", "Hunt", True, ("T1547",), ())})
        monkeypatch.setattr(signatures, "_yara_signatures", lambda: {})
        add_catalog_test(GUID, name="PowerShell download")
        expectations.set_expectation(GUID, SIGNATURE, "expected", unittest_user_id, platform="windows")
        refresh_coverage("test")

        detail = (await client.get(f"/svs/worklist/{SIGNATURE}")).json()
        assert (detail["signature_family"], detail["signature_name"]) == ("hunt", "Hunt")
        assert [(row["technique"], row["status"]) for row in detail["rows"]] == [
            ("T1059.001", "undeclared"), ("T1547", "open")]
        assert detail["measured"] == [{
            "technique": "T1059.001", "technique_name": "PowerShell",
            "tests": [{"guid": GUID, "name": "PowerShell download", "platform": "windows"}]}]

        assert (await client.get(f"/svs/worklist/{OTHER}")).status_code == 404


@pytest.mark.asyncio
async def test_permissions(_override_db_session, session: AsyncSession, test_user, rows, noperm_client):
    body = {"resolution": "keep", "reason": "r"}
    bulk = {"rows": [{"signature_uuid": SIGNATURE, "technique": "T1547"}], **body}

    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(reader) as client:
        for path in ("/svs/worklist/", f"/svs/worklist/{SIGNATURE}", "/svs/worklist/export/csv"):
            assert (await client.get(path)).status_code == 200, path
        assert (await client.put(f"/svs/worklist/{SIGNATURE}/T1547/resolution", json=body)).status_code == 403
        assert (await client.delete(f"/svs/worklist/{SIGNATURE}/T1547/resolution")).status_code == 403
        assert (await client.post("/svs/worklist/bulk/resolve", json=bulk)).status_code == 403

    manager = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_manage")])
    async with api_key_client(manager) as client:
        assert (await client.put(f"/svs/worklist/{SIGNATURE}/T1547/resolution", json=body)).status_code == 200
        assert (await client.post("/svs/worklist/bulk/resolve", json=bulk)).status_code == 200
        assert (await client.delete(f"/svs/worklist/{SIGNATURE}/T1547/resolution")).status_code == 204
        assert (await client.get("/svs/worklist/")).status_code == 403

    for path in ("/svs/worklist/", f"/svs/worklist/{SIGNATURE}"):
        assert (await noperm_client.get(path)).status_code == 403, path
