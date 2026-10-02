"""GET /api/v2/alerts and its /export/ndjson and /export/csv streams: the alert listing for export
and reporting."""

import csv
import io
import json
from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import text

from aceapi_v2.alerts import service
from saq.database.model import Alert, AuthUserPermission, Company, DetectionPoint, Tag, TagMapping, User
from saq.database.pool import get_db
from saq.database.util.alert import touch_alerts
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.integration

LONG_AGO = datetime(2020, 1, 1, 0, 0, 0)


def _set(alert: Alert, **values) -> None:
    """Writes columns directly. An explicit updated_at overrides ON UPDATE CURRENT_TIMESTAMP."""
    db = get_db()
    db.execute(Alert.__table__.update().where(Alert.id == alert.id).values(**values))
    db.commit()


def _updated_at(alert: Alert) -> datetime:
    return get_db().execute(
        text("SELECT updated_at FROM alerts WHERE id = :id"), {"id": alert.id}).scalar_one()


async def _all_pages(client: AsyncClient, params: dict, limit: int) -> list[dict]:
    rows = []
    cursor = None
    for _ in range(100):
        page_params = dict(params, limit=limit)
        if cursor:
            page_params["cursor"] = cursor
        response = await client.get("/alerts/", params=page_params)
        assert response.status_code == 200, response.text
        body = response.json()
        rows.extend(body["data"])
        cursor = body["next_cursor"]
        if cursor is None:
            return rows
    raise AssertionError("pagination did not terminate")


@pytest.fixture
def no_settle(monkeypatch):
    """Lets changed_since return rows changed a moment ago (the settle window is tested on its own)."""
    monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 0)


class TestAccess:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        for path in ("/alerts/", "/alerts/export/ndjson", "/alerts/export/csv"):
            assert (await unauth_client.get(path)).status_code == 401

    @pytest.mark.asyncio
    async def test_requires_alert_read(self, noperm_client: AsyncClient):
        for path in ("/alerts/", "/alerts/export/ndjson", "/alerts/export/csv"):
            assert (await noperm_client.get(path)).status_code == 403


class TestRows:
    @pytest.mark.asyncio
    async def test_the_full_row(self, client: AsyncClient):
        alert = insert_alert()
        db = get_db()
        user = db.query(User).filter(User.username == "unittest").one()
        _set(alert, owner_id=user.id, disposition="DELIVERY", disposition_user_id=user.id,
             disposition_time=datetime(2026, 3, 1, 12, 0, 0), queue="external")

        for name in ("zeta", "alpha"):
            tag = Tag(name=name)
            db.add(tag)
            db.flush()
            db.add(TagMapping(tag_id=tag.id, alert_id=alert.id))
        for index in range(3):
            db.add(DetectionPoint(alert_id=alert.id, description=f"detection {index}",
                                  signature_uuid="6f3a1b2c-1111-2222-3333-444455556666",
                                  signature_version="v1", content_hash=f"{index:064x}"))
        db.commit()

        response = await client.get("/alerts/")
        assert response.status_code == 200
        (row,) = response.json()["data"]
        assert row["uuid"] == alert.uuid
        assert row["queue"] == "external"
        assert row["disposition"] == "DELIVERY"
        assert row["disposition_user"] == "unittest"
        assert row["owner"] == "unittest"
        assert row["disposition_time"].startswith("2026-03-01T12:00:00")
        assert row["tags"] == ["alpha", "zeta"]
        assert row["detection_count"] == 3
        assert row["location"] == alert.location
        assert row["archived"] is False
        assert row["updated_at"]

        expected_company = db.query(Company.name).filter(Company.id == alert.company_id).scalar() \
            if alert.company_id is not None else None
        assert row["company"] == expected_company

    @pytest.mark.asyncio
    async def test_only_this_nodes_alerts(self, client: AsyncClient):
        """Scoped to the alerts this node shows, exactly as the manage page is."""
        visible = insert_alert()
        elsewhere = insert_alert()
        _set(elsewhere, location="some-other-node")

        rows = (await client.get("/alerts/")).json()["data"]
        assert [row["uuid"] for row in rows] == [visible.uuid]


class TestKeysetPaging:
    @pytest.mark.asyncio
    async def test_pages_follow_the_cursor_in_id_order(self, client: AsyncClient):
        alerts = [insert_alert() for _ in range(5)]

        rows = await _all_pages(client, {}, limit=2)
        assert [row["uuid"] for row in rows] == [alert.uuid for alert in alerts]

    @pytest.mark.asyncio
    async def test_no_skip_or_repeat_while_alerts_arrive(self, client: AsyncClient):
        """The reason this is a keyset and not an offset: a row inserted while a client pages
        would shift every later page by one under OFFSET."""
        first = [insert_alert() for _ in range(4)]

        page = (await client.get("/alerts/", params={"limit": 2})).json()
        seen = [row["uuid"] for row in page["data"]]
        late = [insert_alert() for _ in range(2)]

        cursor = page["next_cursor"]
        while cursor:
            page = (await client.get("/alerts/", params={"limit": 2, "cursor": cursor})).json()
            seen.extend(row["uuid"] for row in page["data"])
            cursor = page["next_cursor"]

        assert seen == [alert.uuid for alert in first + late]

    @pytest.mark.asyncio
    async def test_last_page_has_no_cursor(self, client: AsyncClient):
        insert_alert()
        body = (await client.get("/alerts/", params={"limit": 1})).json()
        assert len(body["data"]) == 1
        assert body["next_cursor"] is None

    @pytest.mark.asyncio
    async def test_bad_cursor(self, client: AsyncClient, no_settle):
        insert_alert()
        insert_alert()
        assert (await client.get("/alerts/", params={"cursor": "garbage!"})).status_code == 400

        # a cursor pages the order it came from: id order and changed_since order don't mix
        id_cursor = (await client.get("/alerts/", params={"limit": 1})).json()["next_cursor"]
        response = await client.get("/alerts/", params={
            "cursor": id_cursor, "changed_since": "2000-01-01T00:00:00"})
        assert response.status_code == 400
        assert "changed_since" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_limit_bounds(self, client: AsyncClient):
        assert (await client.get("/alerts/", params={"limit": 0})).status_code == 422
        assert (await client.get("/alerts/", params={"limit": service.LISTING_MAX_PAGE_SIZE + 1})).status_code == 422


class TestFilters:
    @pytest.mark.asyncio
    async def test_share_link_filters(self, client: AsyncClient):
        default = insert_alert()
        external = insert_alert()
        _set(external, queue="external")

        rows = (await client.get("/alerts/", params={"f": "queue:external"})).json()["data"]
        assert [row["uuid"] for row in rows] == [external.uuid]

        rows = (await client.get("/alerts/", params={"f": "!queue:external"})).json()["data"]
        assert [row["uuid"] for row in rows] == [default.uuid]

    @pytest.mark.asyncio
    async def test_filters_are_anded(self, client: AsyncClient):
        match = insert_alert()
        _set(match, queue="external", disposition="DELIVERY")
        other = insert_alert()
        _set(other, queue="external")

        rows = (await client.get("/alerts/", params=[("f", "queue:external"), ("f", "disposition:DELIVERY")])).json()["data"]
        assert [row["uuid"] for row in rows] == [match.uuid]

    @pytest.mark.asyncio
    async def test_repeats_of_one_filter_are_ored_as_on_the_manage_page(self, client: AsyncClient):
        """The manage page merges entries sharing a name and polarity into one entry whose
        values are ORed (resolve_filter_list); one link means one thing in both places."""
        default = insert_alert()
        external = insert_alert()
        _set(external, queue="external")
        insert_alert_elsewhere = insert_alert()
        _set(insert_alert_elsewhere, queue="third")

        rows = (await client.get("/alerts/", params=[("f", "queue:default"), ("f", "queue:external")])).json()["data"]
        assert [row["uuid"] for row in rows] == [default.uuid, external.uuid]

    @pytest.mark.asyncio
    async def test_user_sentinels_resolve_against_the_caller(self, _override_db_session, session):
        """$USER_QUEUE in a runbook link means the caller's own queue, as it does in the GUI."""
        insert_alert()
        external = insert_alert()
        _set(external, queue="external")

        # committed through the sync session, which is the one the listing reads the caller from
        db = get_db()
        user = User(username="queue_owner", email="queue_owner@e.com", display_name="Queue Owner",
                    password="pw", queue="external")
        db.add(user)
        db.flush()
        db.add(AuthUserPermission(user_id=user.id, major="*", minor="*", effect="ALLOW"))
        db.commit()

        key = await make_api_key(session, user.id, inherit=True)
        async with api_key_client(key) as client:
            rows = (await client.get("/alerts/", params={"f": "queue:$USER_QUEUE"})).json()["data"]
        assert [row["uuid"] for row in rows] == [external.uuid]

    @pytest.mark.asyncio
    async def test_relative_dates_resolve_in_the_given_timezone(self, client: AsyncClient):
        recent = insert_alert()
        old = insert_alert()
        _set(old, insert_date=datetime(2020, 1, 1))

        rows = (await client.get("/alerts/", params={"f": "alert_date:-7d", "tz": "America/New_York"})).json()["data"]
        assert [row["uuid"] for row in rows] == [recent.uuid]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("params", [
        {"f": "no_such_filter:x"},           # an unknown slug is an error here, not a warning
        {"f": "queue"},                      # malformed
        {"f": "alert_date:not a date"},      # a value the filter cannot use
        {"tz": "Not/AZone"},
    ])
    async def test_bad_filters_are_422(self, client: AsyncClient, params):
        for path in ("/alerts/", "/alerts/export/ndjson", "/alerts/export/csv"):
            assert (await client.get(path, params=params)).status_code == 422


class TestChangedSince:
    @pytest.mark.asyncio
    async def test_only_rows_changed_since(self, client: AsyncClient, no_settle):
        unchanged = insert_alert()
        changed = insert_alert()
        for alert in (unchanged, changed):
            _set(alert, updated_at=LONG_AGO)

        # any change to the row moves it: here the version rotation every alert write does
        touch_alerts([changed.uuid])
        get_db().commit()

        rows = (await client.get("/alerts/", params={"changed_since": "2021-01-01T00:00:00Z"})).json()["data"]
        assert [row["uuid"] for row in rows] == [changed.uuid]
        assert datetime.fromisoformat(rows[0]["updated_at"]) > LONG_AGO

    @pytest.mark.asyncio
    async def test_ordered_by_updated_at_then_id_across_ties(self, client: AsyncClient, no_settle):
        """Rows sharing an updated_at are ordered by id, and a page boundary inside the tie
        neither skips nor repeats one."""
        alerts = [insert_alert() for _ in range(4)]
        tie = datetime(2026, 5, 1, 12, 0, 0, 123456)
        _set(alerts[0], updated_at=datetime(2026, 5, 2))
        _set(alerts[1], updated_at=tie)
        _set(alerts[2], updated_at=tie)
        _set(alerts[3], updated_at=datetime(2026, 4, 30))

        rows = await _all_pages(client, {"changed_since": "2026-01-01T00:00:00"}, limit=1)
        assert [row["uuid"] for row in rows] == [alerts[3].uuid, alerts[1].uuid, alerts[2].uuid, alerts[0].uuid]

    @pytest.mark.asyncio
    async def test_a_timezone_offset_is_honored(self, client: AsyncClient, no_settle):
        alert = insert_alert()
        _set(alert, updated_at=datetime(2026, 5, 1, 12, 0, 0))

        # 08:30 in New York is 12:30 UTC, after the change
        after = (await client.get("/alerts/", params={"changed_since": "2026-05-01T08:30:00-04:00"})).json()["data"]
        assert after == []
        # 07:30 in New York is 11:30 UTC, before it
        before = (await client.get("/alerts/", params={"changed_since": "2026-05-01T07:30:00-04:00"})).json()["data"]
        assert [row["uuid"] for row in before] == [alert.uuid]

    @pytest.mark.asyncio
    async def test_a_change_inside_the_settle_window_waits(self, client: AsyncClient):
        """A row changed seconds ago is not returned yet: its timestamp could still be undercut
        by a transaction that has not committed (CHANGED_SINCE_SETTLE_SECONDS)."""
        settled = insert_alert()
        fresh = insert_alert()
        _set(settled, updated_at=datetime.now() - timedelta(seconds=service.CHANGED_SINCE_SETTLE_SECONDS * 4))

        rows = (await client.get("/alerts/", params={
            "changed_since": (datetime.now() - timedelta(days=1)).isoformat()})).json()["data"]
        uuids = [row["uuid"] for row in rows]
        assert settled.uuid in uuids
        assert fresh.uuid not in uuids


class TestExport:
    @pytest.mark.asyncio
    async def test_ndjson(self, client: AsyncClient, monkeypatch):
        # small pages so the stream crosses several of them
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 2)
        alerts = [insert_alert() for _ in range(5)]

        response = await client.get("/alerts/export/ndjson")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/x-ndjson")
        assert "alerts.ndjson" in response.headers["content-disposition"]
        lines = [json.loads(line) for line in response.text.splitlines()]
        assert [line["uuid"] for line in lines] == [alert.uuid for alert in alerts]

    @pytest.mark.asyncio
    async def test_csv(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 2)
        alerts = [insert_alert() for _ in range(3)]
        _set(alerts[1], queue="external")

        response = await client.get("/alerts/export/csv")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        records = list(csv.DictReader(io.StringIO(response.text)))
        assert [record["uuid"] for record in records] == [alert.uuid for alert in alerts]
        assert records[1]["queue"] == "external"
        assert set(records[0]) == set(service.ALERT_ROW_CSV_FIELDS)

    @pytest.mark.asyncio
    async def test_filters_apply(self, client: AsyncClient):
        insert_alert()
        external = insert_alert()
        _set(external, queue="external")

        response = await client.get("/alerts/export/ndjson", params={"f": "queue:external"})
        assert [json.loads(line)["uuid"] for line in response.text.splitlines()] == [external.uuid]

        response = await client.get("/alerts/export/csv", params={"f": "queue:external"})
        assert [record["uuid"] for record in csv.DictReader(io.StringIO(response.text))] == [external.uuid]

    @pytest.mark.asyncio
    async def test_a_failure_part_way_ends_with_an_error_line(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 1)
        insert_alert()
        insert_alert()

        original = service.fetch_alert_page
        calls = []

        def _fail_after_first(*args, **kwargs):
            calls.append(1)
            if len(calls) > 1:
                raise RuntimeError("database went away")
            return original(*args, **kwargs)

        monkeypatch.setattr(service, "fetch_alert_page", _fail_after_first)
        response = await client.get("/alerts/export/ndjson")
        assert response.status_code == 200
        lines = [json.loads(line) for line in response.text.splitlines()]
        assert len(lines) == 2
        assert "uuid" in lines[0]
        assert "error" in lines[1]

    @pytest.mark.asyncio
    async def test_a_failure_part_way_truncates_the_csv(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 1)
        first = insert_alert()
        insert_alert()

        original = service.fetch_alert_page
        calls = []

        def _fail_after_first(*args, **kwargs):
            calls.append(1)
            if len(calls) > 1:
                raise RuntimeError("database went away")
            return original(*args, **kwargs)

        monkeypatch.setattr(service, "fetch_alert_page", _fail_after_first)
        response = await client.get("/alerts/export/csv")
        assert response.status_code == 200
        assert [record["uuid"] for record in csv.DictReader(io.StringIO(response.text))] == [first.uuid]

    def test_each_export_documents_exactly_one_media_type(self):
        """One route per format: neither export advertises the other's content type, and the
        old combined /export route is gone."""
        from aceapi_v2.application import app

        paths = app.openapi()["paths"]
        assert "/alerts/export" not in paths
        for path, media_type in (("/alerts/export/ndjson", "application/x-ndjson"),
                                 ("/alerts/export/csv", "text/csv")):
            content = paths[path]["get"]["responses"]["200"]["content"]
            assert list(content) == [media_type]
            assert "format" not in [p["name"] for p in paths[path]["get"]["parameters"]]


class TestUpdatedAtColumn:
    def test_the_column_is_maintained_by_the_server(self):
        """The model drift check does not compare server defaults, so pin the DDL here: without
        ON UPDATE the column would silently stop moving."""
        ddl = get_db().execute(text("SHOW CREATE TABLE alerts")).fetchone()[1]
        line = next(line for line in ddl.splitlines() if "`updated_at`" in line)
        assert "timestamp(6)" in line.lower()
        assert "ON UPDATE CURRENT_TIMESTAMP(6)" in line

    def test_every_write_to_the_row_moves_it(self):
        alert = insert_alert()
        _set(alert, updated_at=LONG_AGO)

        touch_alerts([alert.uuid])
        get_db().commit()
        assert _updated_at(alert) > LONG_AGO
