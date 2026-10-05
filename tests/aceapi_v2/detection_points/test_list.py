"""GET /api/v2/detection-points and its /export/ndjson and /export/csv streams: every detection with
its verdict, for export and reporting (docs/SVS_API.md)."""

import collections
import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import update

from aceapi_v2.application import app
from aceapi_v2.detection_points import service
from saq.database.model import Alert, DetectionPoint, User
from saq.database.pool import get_db
from saq.detection_verdicts.store import clear_verdict, set_verdict
from saq.signatures.builtin import BUILTIN_SIGNATURE_UUID
from tests.saq.helpers import insert_alert_with_detections

pytestmark = pytest.mark.integration

SIG_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SIG_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
LONG_AGO = datetime(2020, 1, 1, 0, 0, 0)


def _detection(signature_uuid: str, fqdn: str | None = None, description: str = "fired") -> dict:
    return {"description": description, "signature_uuid": signature_uuid, "fqdn": fqdn}


def _set_alert(alert, **values):
    get_db().execute(update(Alert).where(Alert.id == alert.id).values(**values))
    get_db().commit()


def _user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


async def _get(client: AsyncClient, *filters: str, **params) -> list[dict]:
    response = await client.get("/detection-points/", params={"f": list(filters), **params})
    assert response.status_code == 200, response.text
    return response.json()["data"]


async def _all_pages(client: AsyncClient, params: dict, limit: int) -> list[dict]:
    rows = []
    cursor = None
    for _ in range(100):
        page_params = dict(params, limit=limit)
        if cursor:
            page_params["cursor"] = cursor
        response = await client.get("/detection-points/", params=page_params)
        assert response.status_code == 200, response.text
        body = response.json()
        rows.extend(body["data"])
        cursor = body["next_cursor"]
        if cursor is None:
            return rows
    raise AssertionError("pagination did not terminate")


class TestAccess:
    PATHS = ("/detection-points/", "/detection-points/export/ndjson", "/detection-points/export/csv")

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        for path in self.PATHS:
            assert (await unauth_client.get(path)).status_code == 401

    @pytest.mark.asyncio
    async def test_requires_alert_read(self, noperm_client: AsyncClient):
        for path in self.PATHS:
            assert (await noperm_client.get(path)).status_code == 403


class TestRows:
    @pytest.mark.asyncio
    async def test_rows_carry_the_verdict(self, client: AsyncClient):
        alert = insert_alert_with_detections(
            [_detection(SIG_A, "one.example.com"), _detection(SIG_B)], disposition="DELIVERY")

        rows = await _get(client)

        assert {row["alert_uuid"] for row in rows} == {alert.uuid}
        assert {(row["signature_uuid"], row["node_kind"]) for row in rows} == {(SIG_A, "observable"), (SIG_B, "root")}
        assert {(row["verdict"], row["verdict_source"]) for row in rows} == {("tp", "inherited_multi")}

    @pytest.mark.asyncio
    async def test_only_this_nodes_alerts(self, client: AsyncClient):
        visible = insert_alert_with_detections([_detection(SIG_A)])
        elsewhere = insert_alert_with_detections([_detection(SIG_A)])
        _set_alert(elsewhere, location="some-other-node")

        assert [row["alert_uuid"] for row in await _get(client)] == [visible.uuid]


class TestKeysetPaging:
    @pytest.mark.asyncio
    async def test_no_skip_or_repeat_while_detections_arrive(self, client: AsyncClient):
        for index in range(5):
            insert_alert_with_detections([_detection(SIG_A, description=f"d{index}")])

        first = await client.get("/detection-points/", params={"limit": 2})
        body = first.json()
        seen = [row["content_hash"] + row["alert_uuid"] for row in body["data"]]
        insert_alert_with_detections([_detection(SIG_A, description="late")])

        rest = await _all_pages(client, {"cursor": body["next_cursor"]}, 2)
        seen += [row["content_hash"] + row["alert_uuid"] for row in rest]
        assert len(seen) == len(set(seen)) == 6

    @pytest.mark.asyncio
    async def test_bad_cursor_and_limits(self, client: AsyncClient):
        assert (await client.get("/detection-points/", params={"cursor": "garbage"})).status_code == 400
        assert (await client.get("/detection-points/", params={"limit": 0})).status_code == 422
        assert (await client.get("/detection-points/", params={"limit": 1001})).status_code == 422


class TestFilters:
    @pytest.fixture
    def alerts(self):
        """A TP alert with two signatures (one detection marked FP), an FP alert, an open alert
        in another queue, and an old TP alert with a built-in detection."""
        tp = insert_alert_with_detections(
            [_detection(SIG_A, "one.example.com"), _detection(SIG_B)], disposition="DELIVERY")
        fp = insert_alert_with_detections([_detection(SIG_A)], disposition="FALSE_POSITIVE")
        open_ = insert_alert_with_detections([_detection(SIG_B)])
        _set_alert(open_, queue="external")
        old = insert_alert_with_detections([_detection(BUILTIN_SIGNATURE_UUID)], disposition="DELIVERY")
        _set_alert(old, insert_date=datetime.now() - timedelta(days=200))

        noise = get_db().query(DetectionPoint.content_hash).filter(
            DetectionPoint.alert_id == tp.id, DetectionPoint.signature_uuid == SIG_A).scalar()
        set_verdict(tp.id, noise, "fp", _user_id())
        return {"tp": tp, "fp": fp, "open": open_, "old": old}

    @staticmethod
    def _alerts_of(rows: list[dict], alerts: dict) -> list[str]:
        names = {alert.uuid: name for name, alert in alerts.items()}
        return sorted(names[row["alert_uuid"]] + ":" + (row["verdict"] or "none") for row in rows)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("filters, expected", [
        (["signature:" + SIG_A], ["fp:fp", "tp:fp"]),
        (["family:builtin"], ["old:tp"]),
        (["queue:external"], ["open:none"]),
        (["verdict:fp"], ["fp:fp", "tp:fp"]),
        (["verdict:none"], ["open:none"]),
        # an inverse keeps the rows whose value is null
        (["!verdict:tp"], ["fp:fp", "open:none", "tp:fp"]),
        (["source:explicit"], ["tp:fp"]),
        (["source:inherited_multi"], ["tp:tp"]),
        (["has_override:true"], ["tp:fp"]),
        (["alert_date:-90d", "verdict:tp,fp"], ["fp:fp", "tp:fp", "tp:tp"]),
        # repeats of one filter are ORed, different filters ANDed
        (["verdict:tp", "verdict:none"], ["old:tp", "open:none", "tp:tp"]),
        (["signature:" + SIG_B, "verdict:tp"], ["tp:tp"]),
    ])
    async def test_filters(self, client: AsyncClient, alerts, filters, expected):
        assert self._alerts_of(await _get(client, *filters), alerts) == expected

    @pytest.mark.asyncio
    async def test_signature_version(self, client: AsyncClient, alerts):
        rows = await _get(client, f"signature:{BUILTIN_SIGNATURE_UUID}%3Ano-such-version")
        assert rows == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("filter_param", ["nope:x", "verdict:maybe", "source:inherited", "alert_date:soon"])
    async def test_bad_filters_are_422(self, client: AsyncClient, filter_param):
        response = await client.get("/detection-points/", params={"f": filter_param})
        assert response.status_code == 422


class TestChangedSince:
    @pytest.mark.asyncio
    async def test_a_verdict_change_or_a_disposition_change(self, client: AsyncClient):
        a = insert_alert_with_detections([_detection(SIG_A, "one.example.com"), _detection(SIG_B)],
                                         disposition="DELIVERY")
        b = insert_alert_with_detections([_detection(SIG_A)], disposition="DELIVERY")
        for alert in (a, b):
            _set_alert(alert, updated_at=LONG_AGO)
        get_db().execute(update(DetectionPoint).values(insert_date=LONG_AGO))
        get_db().commit()

        since = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        assert await _get(client, changed_since=since) == []

        # setting and clearing a verdict both show up; the cleared verdict leaves only history
        content_hash = (await _get(client))[0]["content_hash"]
        set_verdict(a.id, content_hash, "fp", _user_id())
        clear_verdict(a.id, content_hash, _user_id())
        assert [row["content_hash"] for row in await _get(client, changed_since=since)] == [content_hash]

        # a disposition change re-derives every verdict of the alert
        _set_alert(b, disposition="FALSE_POSITIVE")
        rows = await _get(client, changed_since=since)
        assert {row["alert_uuid"] for row in rows} == {a.uuid, b.uuid}


class TestExport:
    @pytest.mark.asyncio
    async def test_ndjson(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 2)
        alert = insert_alert_with_detections(
            [_detection(SIG_A, f"{n}.example.com") for n in range(3)], disposition="DELIVERY")

        response = await client.get("/detection-points/export/ndjson", params={"f": "verdict:tp"})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/x-ndjson")
        lines = [json.loads(line) for line in response.text.splitlines()]
        assert len(lines) == 3 and {line["alert_uuid"] for line in lines} == {alert.uuid}

    @pytest.mark.asyncio
    async def test_csv(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 2)
        root = insert_alert_with_detections([_detection(SIG_A, f"{n}.example.com") for n in range(3)])

        response = await client.get("/detection-points/export/csv")
        assert response.status_code == 200
        records = list(csv.DictReader(io.StringIO(response.text)))
        assert len(records) == 3
        assert {r["alert_uuid"] for r in records} == {root.uuid}
        assert {r["verdict"] for r in records} == {""}

    @pytest.mark.asyncio
    async def test_a_failure_part_way_ends_with_an_error_line(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 1)
        insert_alert_with_detections([_detection(SIG_A, "one.example.com"), _detection(SIG_B)])

        original = service.fetch_detection_point_page
        calls = []

        def _fail_after_first(*args, **kwargs):
            calls.append(1)
            if len(calls) > 1:
                raise RuntimeError("database went away")
            return original(*args, **kwargs)

        monkeypatch.setattr(service, "fetch_detection_point_page", _fail_after_first)
        response = await client.get("/detection-points/export/ndjson")
        lines = [json.loads(line) for line in response.text.splitlines()]
        assert len(lines) == 2 and "content_hash" in lines[0] and "error" in lines[1]

    def test_each_export_documents_exactly_one_media_type(self):
        paths = app.openapi()["paths"]
        for path, media_type in (("/detection-points/export/ndjson", "application/x-ndjson"),
                                 ("/detection-points/export/csv", "text/csv")):
            assert list(paths[path]["get"]["responses"]["200"]["content"]) == [media_type]


@pytest.mark.asyncio
async def test_worked_example_fp_rate(client: AsyncClient):
    """docs/SVS_API.md, *Per-signature FP rate over 90 days*, run against the API."""
    insert_alert_with_detections([_detection(SIG_A)], disposition="FALSE_POSITIVE")
    insert_alert_with_detections([_detection(SIG_A)], disposition="DELIVERY")
    insert_alert_with_detections([_detection(SIG_A)], disposition="DELIVERY")
    insert_alert_with_detections([_detection(SIG_B)], disposition="DELIVERY")
    insert_alert_with_detections([_detection(SIG_B)])  # open: no verdict, not counted
    old = insert_alert_with_detections([_detection(SIG_B)], disposition="FALSE_POSITIVE")
    _set_alert(old, insert_date=datetime.now() - timedelta(days=120))  # outside the window

    counts = collections.defaultdict(collections.Counter)
    params = {"f": ["alert_date:-90d", "verdict:tp,fp"], "limit": 2}
    while True:
        page = (await client.get("/detection-points/", params=params)).json()
        for row in page["data"]:
            counts[row["signature_uuid"]][row["verdict"]] += 1
        if page["next_cursor"] is None:
            break
        params["cursor"] = page["next_cursor"]

    rates = {sig: round(v["fp"] / (v["tp"] + v["fp"]), 3) for sig, v in counts.items()}
    assert rates == {SIG_A: 0.333, SIG_B: 0.0}
