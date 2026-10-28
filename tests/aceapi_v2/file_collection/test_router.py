"""/api/v2/file-collections: the File Collections page."""

import csv
import io
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.constants import F_FILE_LOCATION
from saq.database.model import FileCollection, FileCollectionHistory, User
from saq.database.pool import get_db
from saq.file_collection.database import queue_file_collection
from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.helpers import audit_actor_of, audit_record

pytestmark = pytest.mark.integration

COLLECTOR = "test_collector"


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _caller_id() -> int:
    return get_db().query(User).filter(User.username == "unittest").one().id


def _queue(value: str, status: FileCollectionStatus = FileCollectionStatus.NEW,
           result: FileCollectorStatus | None = None, alert_uuid: str | None = None, **values) -> int:
    collection_id = queue_file_collection(COLLECTOR, F_FILE_LOCATION, value, alert_uuid or str(uuid.uuid4()),
                                          user_id=_caller_id())
    _set(collection_id, status=status.value, result=result.value if result else None, **values)
    return collection_id


def _set(collection_id: int, **values) -> None:
    db = get_db()
    db.execute(FileCollection.__table__.update().where(FileCollection.id == collection_id).values(**values))
    db.commit()


def _collection(collection_id: int) -> FileCollection | None:
    db = get_db()
    db.expire_all()
    return db.get(FileCollection, collection_id)


def _history(collection_id: int, message: str, when: datetime,
             result: FileCollectorStatus = FileCollectorStatus.HOST_OFFLINE) -> None:
    db = get_db()
    db.add(FileCollectionHistory(file_collection_id=collection_id, result=result.value,
                                 status=FileCollectionStatus.IN_PROGRESS.value, message=message, insert_date=when))
    db.commit()


async def _ids(client: AsyncClient, *f: str) -> list[int]:
    response = await client.get("/file-collections/", params={"f": list(f)})
    assert response.status_code == 200, response.text
    return [row["id"] for row in response.json()["data"]]


class TestAccess:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get("/file-collections/")).status_code == 401
        assert (await unauth_client.post("/file-collections/1/cancel")).status_code == 401

    @pytest.mark.asyncio
    async def test_reading_requires_file_collection_read(self, noperm_client: AsyncClient):
        assert (await noperm_client.get("/file-collections/")).status_code == 403
        assert (await noperm_client.get("/file-collections/export/ndjson")).status_code == 403
        assert (await noperm_client.get("/file-collections/1/history")).status_code == 403

    @pytest.mark.asyncio
    async def test_changes_require_file_collection_write(self, _override_db_session, session: AsyncSession, test_user):
        """file_collection:read used to cover stopping, retrying and deleting requests."""
        collection_id = _queue("host@/evil.exe")
        key = await make_api_key(session, test_user.id, inherit=False, scope=[("file_collection", "read")])

        async with api_key_client(key) as reader:
            assert (await reader.get("/file-collections/")).status_code == 200
            assert (await reader.get(f"/file-collections/{collection_id}/history")).status_code == 200
            assert (await reader.post(f"/file-collections/{collection_id}/cancel")).status_code == 403
            assert (await reader.post(f"/file-collections/{collection_id}/retry")).status_code == 403
            assert (await reader.delete(f"/file-collections/{collection_id}")).status_code == 403

        assert _collection(collection_id).status == FileCollectionStatus.NEW.value


class TestList:
    @pytest.mark.asyncio
    async def test_newest_first_in_pages(self, client: AsyncClient):
        ids = [_queue(f"host@/file-{n}") for n in range(5)]

        first = (await client.get("/file-collections/", params={"limit": 3})).json()
        second = (await client.get("/file-collections/", params={"limit": 3, "cursor": first["next_cursor"]})).json()

        assert [row["id"] for page in (first, second) for row in page["data"]] == ids[::-1]
        assert second["next_cursor"] is None

    @pytest.mark.asyncio
    async def test_row(self, client: AsyncClient):
        alert_uuid = str(uuid.uuid4())
        collection_id = _queue("host@/evil.exe", FileCollectionStatus.IN_PROGRESS, FileCollectorStatus.HOST_OFFLINE,
                               alert_uuid=alert_uuid, retry_count=2, result_message="host is offline")

        (row,) = (await client.get("/file-collections/")).json()["data"]

        assert row.items() >= {
            "id": collection_id, "collector": COLLECTOR, "observable_type": F_FILE_LOCATION,
            "observable_value": "host@/evil.exe", "status": "IN_PROGRESS", "result": "HOST_OFFLINE",
            "result_message": "host is offline", "retry_count": 2, "max_retries": 10, "alert_uuid": alert_uuid,
            "requested_by": "unittest", "collected_file_sha256": None,
        }.items()

    @pytest.mark.asyncio
    async def test_filters(self, client: AsyncClient):
        alert_uuid = str(uuid.uuid4())
        new = _queue("laptop@/evil.exe", alert_uuid=alert_uuid)
        offline = _queue("server@/evil.dll", FileCollectionStatus.IN_PROGRESS, FileCollectorStatus.HOST_OFFLINE)
        done = _queue("server@/fine.txt", FileCollectionStatus.COMPLETED, FileCollectorStatus.SUCCESS)
        old = _queue("server@/old.txt", FileCollectionStatus.COMPLETED, FileCollectorStatus.FAILED,
                     insert_date=_utcnow() - timedelta(days=30))

        assert await _ids(client, "value:evil") == [offline, new]
        assert await _ids(client, f"alert:{alert_uuid.upper()}") == [new]
        assert await _ids(client, "status:new,in_progress") == [offline, new]
        assert await _ids(client, "result:host_offline,failed") == [old, offline]
        # inverted, a filter also keeps the rows that have no value, such as no result yet
        assert await _ids(client, "!result:SUCCESS,FAILED") == [offline, new]
        assert await _ids(client, "created:-7d", "collector:test", "type:file_loc") == [done, offline, new]
        assert await _ids(client, f"id:{done}") == [done]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("params, status", [
        ({"f": "result:LOST"}, 422),
        ({"f": "alert:not-a-uuid"}, 422),
        ({"f": "analyst:me"}, 422),
        ({"cursor": "garbage"}, 400),
    ])
    async def test_bad_requests(self, client: AsyncClient, params, status):
        assert (await client.get("/file-collections/", params=params)).status_code == status

    @pytest.mark.asyncio
    async def test_exports(self, client: AsyncClient):
        first = _queue("host@/one")
        second = _queue("host@/two")

        ndjson = await client.get("/file-collections/export/ndjson")
        csv_response = await client.get("/file-collections/export/csv", params={"f": f"id:{first}"})

        assert [json.loads(line)["id"] for line in ndjson.text.splitlines()] == [second, first]
        (row,) = list(csv.DictReader(io.StringIO(csv_response.text)))
        assert (row["id"], row["observable_value"], row["result"]) == (str(first), "host@/one", "")


class TestHistory:
    @pytest.mark.asyncio
    async def test_newest_first(self, client: AsyncClient):
        collection_id = _queue("host@/evil.exe")
        now = _utcnow().replace(microsecond=0)
        _history(collection_id, "host offline", now - timedelta(minutes=1))
        _history(collection_id, "collected", now, FileCollectorStatus.SUCCESS)

        response = await client.get(f"/file-collections/{collection_id}/history")

        assert [(e["message"], e["result"]) for e in response.json()["data"]] == [
            ("collected", "SUCCESS"), ("host offline", "HOST_OFFLINE")]

    @pytest.mark.asyncio
    async def test_unknown_request(self, client: AsyncClient):
        response = await client.get("/file-collections/999999/history")
        assert response.status_code == 404
        assert response.json()["detail"] == "file collection 999999 not found"


class TestCancel:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [FileCollectionStatus.NEW, FileCollectionStatus.IN_PROGRESS])
    async def test_stops_a_request_that_has_not_completed(self, client: AsyncClient, client_actor, status,
                                                          caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        collection_id = _queue("host@/evil.exe", status)

        response = await client.post(f"/file-collections/{collection_id}/cancel")

        assert response.status_code == 200
        assert response.json() == {"id": collection_id, "status": "COMPLETED", "result": "CANCELLED", "retry_count": 0}
        audit = audit_record(caplog, f"user unittest cancelled file collection {collection_id}")
        assert (*audit_actor_of(audit), audit.file_collection_id) == (*client_actor, collection_id)

    @pytest.mark.asyncio
    async def test_a_completed_request_keeps_its_result(self, client: AsyncClient):
        collection_id = _queue("host@/evil.exe", FileCollectionStatus.COMPLETED, FileCollectorStatus.SUCCESS)

        assert (await client.post(f"/file-collections/{collection_id}/cancel")).status_code == 409
        assert _collection(collection_id).result == FileCollectorStatus.SUCCESS.value

    @pytest.mark.asyncio
    async def test_unknown_request(self, client: AsyncClient):
        assert (await client.post("/file-collections/999999/cancel")).status_code == 404


class TestRetry:
    @pytest.mark.asyncio
    async def test_starts_a_request_over(self, client: AsyncClient, client_actor, caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        collection_id = _queue("host@/evil.exe", FileCollectionStatus.COMPLETED, FileCollectorStatus.HOST_OFFLINE,
                               retry_count=10, result_message="gave up")

        response = await client.post(f"/file-collections/{collection_id}/retry")

        assert response.status_code == 200
        assert response.json() == {"id": collection_id, "status": "NEW", "result": None, "retry_count": 0}
        assert _collection(collection_id).result_message is None
        audit = audit_record(caplog, f"user unittest retried file collection {collection_id}")
        assert (*audit_actor_of(audit), audit.file_collection_id) == (*client_actor, collection_id)

    @pytest.mark.asyncio
    async def test_unknown_request(self, client: AsyncClient):
        assert (await client.post("/file-collections/999999/retry")).status_code == 404


class TestDelete:
    @pytest.mark.asyncio
    async def test_deletes_the_request_and_its_history(self, client: AsyncClient, client_actor,
                                                       caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        collection_id = _queue("host@/evil.exe")
        _history(collection_id, "host offline", _utcnow())

        assert (await client.delete(f"/file-collections/{collection_id}")).status_code == 204
        assert _collection(collection_id) is None
        assert get_db().query(FileCollectionHistory).count() == 0
        audit = audit_record(caplog, f"user unittest deleted file collection {collection_id}")
        assert (*audit_actor_of(audit), audit.file_collection_id) == (*client_actor, collection_id)

    @pytest.mark.asyncio
    async def test_unknown_request(self, client: AsyncClient):
        assert (await client.delete("/file-collections/999999")).status_code == 404
