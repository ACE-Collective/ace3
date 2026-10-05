"""GET /api/v2/alerts/{uuid}/detection-points and the verdict writes under it (docs/SVS.md, Part 1)."""

import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select

from aceapi_v2.detection_points import service
from saq.database.model import DetectionPointVerdictHistory
from saq.database.pool import get_db
from tests.saq.helpers import insert_alert_with_detections

pytestmark = pytest.mark.integration

SIG_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SIG_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
MULTI = [{"description": "generic logo rule", "signature_uuid": SIG_A, "fqdn": "one.example.com"},
         {"description": "phish kit", "signature_uuid": SIG_B}]


def _path(alert, suffix: str = "") -> str:
    return f"/alerts/{alert.uuid}/detection-points{suffix}"


async def _rows(client: AsyncClient, alert) -> list[dict]:
    response = await client.get(_path(alert))
    assert response.status_code == 200, response.text
    return response.json()


class TestAccess:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        alert_uuid = str(uuid.uuid4())
        assert (await unauth_client.get(f"/alerts/{alert_uuid}/detection-points")).status_code == 401

    @pytest.mark.asyncio
    async def test_reads_need_alert_read_and_writes_alert_write(self, noperm_client: AsyncClient):
        alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
        content_hash = "0" * 64
        assert (await noperm_client.get(_path(alert))).status_code == 403
        assert (await noperm_client.put(_path(alert, f"/{content_hash}/verdict"),
                                        json={"verdict": "fp"})).status_code == 403
        assert (await noperm_client.delete(_path(alert, f"/{content_hash}/verdict"))).status_code == 403
        assert (await noperm_client.post(_path(alert, "/confirm"))).status_code == 403

    def test_a_key_without_a_user_cannot_set_verdicts(self):
        # config API keys authenticate as nobody, and a verdict records who set it
        alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
        with pytest.raises(HTTPException) as e:
            service.set_detection_verdict(alert.uuid, "0" * 64, "fp", None)
        assert e.value.status_code == 422


class TestList:
    @pytest.mark.asyncio
    async def test_rows(self, client: AsyncClient):
        alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")

        rows = await _rows(client, alert)

        assert sorted(row["description"] for row in rows) == ["generic logo rule", "phish kit"]
        by_description = {row["description"]: row for row in rows}
        on_fqdn = by_description["generic logo rule"]
        assert on_fqdn["alert_uuid"] == alert.uuid
        assert on_fqdn["signature_uuid"] == SIG_A
        assert on_fqdn["node_kind"] == "observable"
        assert on_fqdn["node_type"] == "fqdn"
        assert len(on_fqdn["content_hash"]) == 64
        assert (on_fqdn["verdict"], on_fqdn["verdict_source"], on_fqdn["override"]) == \
            ("tp", "inherited_multi", None)
        assert by_description["phish kit"]["node_kind"] == "root"

    @pytest.mark.asyncio
    async def test_unclassified_alert_has_no_verdicts(self, client: AsyncClient):
        alert = insert_alert_with_detections(MULTI)
        assert {(row["verdict"], row["verdict_source"]) for row in await _rows(client, alert)} == {(None, None)}

    @pytest.mark.asyncio
    async def test_unknown_and_invalid_alert(self, client: AsyncClient):
        assert (await client.get(f"/alerts/{uuid.uuid4()}/detection-points")).status_code == 404
        assert (await client.get("/alerts/not-a-uuid/detection-points")).status_code == 400


class TestVerdicts:
    @pytest.mark.asyncio
    async def test_set_and_clear(self, client: AsyncClient):
        alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
        content_hash = (await _rows(client, alert))[0]["content_hash"]

        response = await client.put(_path(alert, f"/{content_hash}/verdict"), json={"verdict": "fp"})
        assert response.status_code == 200, response.text
        row = response.json()
        assert (row["verdict"], row["verdict_source"], row["override"]) == ("fp", "explicit", "fp")
        assert row["override_user"] == "unittest"

        response = await client.delete(_path(alert, f"/{content_hash}/verdict"))
        assert response.status_code == 200, response.text
        row = response.json()
        assert (row["verdict"], row["verdict_source"], row["override"]) == ("tp", "inherited_multi", None)

        changes = get_db().execute(
            select(DetectionPointVerdictHistory.old_verdict, DetectionPointVerdictHistory.new_verdict)
            .where(DetectionPointVerdictHistory.alert_id == alert.id)
            .order_by(DetectionPointVerdictHistory.id)).all()
        assert [tuple(c) for c in changes] == [(None, "fp"), ("fp", None)]

    @pytest.mark.asyncio
    async def test_fp_alert_refuses_overrides(self, client: AsyncClient):
        alert = insert_alert_with_detections(MULTI, disposition="FALSE_POSITIVE")
        content_hash = (await _rows(client, alert))[0]["content_hash"]

        response = await client.put(_path(alert, f"/{content_hash}/verdict"), json={"verdict": "tp"})
        assert response.status_code == 409
        assert "correct its disposition" in response.json()["detail"]
        assert (await client.post(_path(alert, "/confirm"))).status_code == 409

    @pytest.mark.asyncio
    async def test_bad_requests(self, client: AsyncClient):
        alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
        content_hash = (await _rows(client, alert))[0]["content_hash"]

        assert (await client.put(_path(alert, f"/{'0' * 64}/verdict"), json={"verdict": "fp"})).status_code == 404
        assert (await client.put(_path(alert, "/not-a-hash/verdict"), json={"verdict": "fp"})).status_code == 422
        assert (await client.put(_path(alert, f"/{content_hash}/verdict"), json={"verdict": "maybe"})).status_code == 422
        assert (await client.put(f"/alerts/{uuid.uuid4()}/detection-points/{content_hash}/verdict",
                                 json={"verdict": "fp"})).status_code == 404

    @pytest.mark.asyncio
    async def test_confirm(self, client: AsyncClient):
        alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")

        response = await client.post(_path(alert, "/confirm"))
        assert response.status_code == 200, response.text
        assert response.json() == {"confirmed": 2}
        assert {(row["verdict"], row["verdict_source"]) for row in await _rows(client, alert)} == {("tp", "explicit")}
