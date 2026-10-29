import json
import logging
import os
import shutil
import threading
import uuid
from unittest.mock import Mock

import httpx
import pytest
from qdrant_client import models
from qdrant_client.http.exceptions import UnexpectedResponse

from saq.configuration.config import get_config
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.qdrant_client import get_qdrant_client
from saq.search import index
from saq.search.documents import SearchDocument
from saq.search.model import SCHEMA_VERSION
from saq.search.types import KIND_ALERT, KIND_COMMENT
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.unit

ALERT_UUID = "2f1e4d3c-1111-2222-3333-444455556666"


def _alert(**kwargs) -> Alert:
    values = dict(uuid=ALERT_UUID, location="node1", storage_dir="x/y", tool="splunk", tool_instance="prod",
                  alert_type="phish", description="desc", queue="default", disposition="OPEN")
    values.update(kwargs)
    return Alert(**values)


class TestPointId:
    def test_deterministic_and_node_independent(self):
        first = index.point_id(ALERT_UUID, KIND_ALERT, "header", 0)
        assert first == index.point_id(ALERT_UUID, KIND_ALERT, "header", 0)
        assert uuid.UUID(first).version == 5

    def test_varies_with_every_component(self):
        base = index.point_id(ALERT_UUID, KIND_ALERT, "header", 0)
        assert base != index.point_id(ALERT_UUID, KIND_ALERT, "header", 1)
        assert base != index.point_id(ALERT_UUID, KIND_COMMENT, "header", 0)
        assert base != index.point_id(str(uuid.uuid4()), KIND_ALERT, "header", 0)

    def test_non_uuid_root(self):
        assert uuid.UUID(index.point_id("not-a-uuid", KIND_ALERT, "header", 0))


class TestCollection:
    def test_name_binds_prefix_model_and_schema(self, monkeypatch):
        monkeypatch.setattr(get_config().qdrant, "collection_prefix", "ace3-alerts")
        monkeypatch.setattr(get_config().search, "embedding_model", "BAAI/bge-small-en-v1.5")
        assert index.collection_name() == f"ace3-alerts-baai-bge-small-en-v1-5-v{SCHEMA_VERSION}"

    def test_ensure_collection_creates_vectors_and_indexes(self, mock_qdrant, mock_model):
        mock_qdrant.collection_exists.return_value = False
        index.ensure_collection(mock_qdrant, mock_model, name="c")

        kwargs = mock_qdrant.create_collection.call_args.kwargs
        assert kwargs["vectors_config"][index.DENSE].size == 8
        assert kwargs["vectors_config"][index.DENSE].distance == models.Distance.COSINE
        assert kwargs["sparse_vectors_config"][index.SPARSE].modifier == models.Modifier.IDF

        indexed = {c.kwargs["field_name"]: c.kwargs["field_schema"] for c in mock_qdrant.create_payload_index.call_args_list}
        assert indexed[index.FIELD_ROOT_UUID] == models.PayloadSchemaType.KEYWORD
        assert indexed[index.FIELD_TAGS] == models.PayloadSchemaType.KEYWORD
        assert indexed[index.FIELD_INSERT_DATE] == models.PayloadSchemaType.DATETIME

    def test_ensure_collection_only_backfills_missing_indexes(self, mock_qdrant, mock_model):
        mock_qdrant.get_collection.return_value = Mock(payload_schema={name: {} for name in index.KEYWORD_INDEXES + index.DATETIME_INDEXES})
        index.ensure_collection(mock_qdrant, mock_model, name="c")
        mock_qdrant.create_collection.assert_not_called()
        mock_qdrant.create_payload_index.assert_not_called()


@pytest.fixture
def real_collection(qdrant_available):
    """A client for the real qdrant and a collection name no other test uses; the collection is dropped afterwards."""
    name = f"ace3-test-{uuid.uuid4().hex[:8]}"
    yield get_qdrant_client(), name
    # a new client, because the test may have replaced methods on the one it was given
    cleanup = get_qdrant_client()
    if cleanup.collection_exists(collection_name=name):
        cleanup.delete_collection(collection_name=name)


ALL_PAYLOAD_INDEXES = set(index.KEYWORD_INDEXES + index.DATETIME_INDEXES)

# what qdrant answers a read of a collection while another worker's create of it is still running
CREATE_RUNNING = (500, b'{"status":{"error":"Service internal error: 0 of 0 read operations failed"}}')


def fail_first_read(monkeypatch, client, status: int = CREATE_RUNNING[0], content: bytes = CREATE_RUNNING[1]):
    """Makes the client's first get_collection() fail with this reply. Returns the real get_collection."""
    real_get_collection = client.get_collection
    reads = []

    def get_collection(**kwargs):
        reads.append(kwargs)
        if len(reads) == 1:
            raise UnexpectedResponse(status_code=status, reason_phrase="", headers=httpx.Headers(), content=content)
        return real_get_collection(**kwargs)

    monkeypatch.setattr(client, "get_collection", get_collection)
    return real_get_collection


@pytest.mark.integration
class TestEnsureCollectionRace:
    """Every indexer worker runs ensure_collection() when it starts, so with no collection yet
    two of them can both find it missing and both create it. These tests use the real qdrant, so
    the 409 is the one the client raises."""

    def test_losing_the_create_race_still_creates_the_payload_indexes(self, real_collection, mock_model, monkeypatch, caplog):
        client, name = real_collection
        # the winner has created the collection but not yet its payload indexes
        client.create_collection(collection_name=name, vectors_config={index.DENSE: models.VectorParams(size=8, distance=models.Distance.COSINE)})
        # what the loser saw just before the winner's create
        monkeypatch.setattr(client, "collection_exists", lambda **kwargs: False)
        real_get_collection = fail_first_read(monkeypatch, client)

        with caplog.at_level(logging.INFO):
            assert index.ensure_collection(client, mock_model, name=name) == name

        assert set(real_get_collection(collection_name=name).payload_schema) == ALL_PAYLOAD_INDEXES
        events = [record.message for record in caplog.records]
        assert "search_collection_created" not in events
        assert "search_collection_already_exists" in events

    def test_reading_the_schema_during_the_winners_create_still_creates_the_payload_indexes(self, real_collection, mock_model, monkeypatch, caplog):
        client, name = real_collection
        client.create_collection(collection_name=name, vectors_config={index.DENSE: models.VectorParams(size=8, distance=models.Distance.COSINE)})
        # qdrant reports the collection as existing about a millisecond before the winner's
        # create returns, so a worker can find it and then fail to read it
        real_get_collection = fail_first_read(monkeypatch, client)

        with caplog.at_level(logging.INFO):
            assert index.ensure_collection(client, mock_model, name=name) == name

        assert set(real_get_collection(collection_name=name).payload_schema) == ALL_PAYLOAD_INDEXES
        unreadable = [record for record in caplog.records if record.message == "search_collection_schema_unreadable"]
        assert [(record.levelno, record.collection, record.status) for record in unreadable] == [(logging.INFO, name, 500)]

    def test_other_schema_read_failures_still_raise(self, real_collection, mock_model, monkeypatch):
        client, name = real_collection
        client.create_collection(collection_name=name, vectors_config={index.DENSE: models.VectorParams(size=8, distance=models.Distance.COSINE)})
        fail_first_read(monkeypatch, client, status=403, content=b'{"status":{"error":"forbidden"}}')

        with pytest.raises(UnexpectedResponse) as error:
            index.ensure_collection(client, mock_model, name=name)

        assert error.value.status_code == 403

    def test_racing_workers_both_succeed_and_the_indexes_cover_new_points(self, qdrant_available, mock_model):
        """Two workers create the collection at the same moment, with nothing scripted. The loser
        creates its indexes while the winner's create is still running, so the test checks that
        the indexes cover a point written afterwards as well as appearing in the schema."""
        admin = get_qdrant_client()
        point = models.PointStruct(
            id=str(uuid.uuid4()),
            vector={index.DENSE: [0.1] * 8},
            payload={field_name: "x" for field_name in index.KEYWORD_INDEXES} | {field_name: "2026-10-29T00:00:00Z" for field_name in index.DATETIME_INDEXES},
        )
        for _ in range(5):
            name = f"ace3-test-{uuid.uuid4().hex[:8]}"
            start = threading.Barrier(2, timeout=30)
            errors = []

            def worker():
                client = get_qdrant_client()
                start.wait()
                try:
                    index.ensure_collection(client, mock_model, name=name)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=worker) for _ in range(2)]
            try:
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=60)

                assert not any(thread.is_alive() for thread in threads)
                assert errors == []
                admin.upsert(collection_name=name, points=[point], wait=True)
                schema = admin.get_collection(collection_name=name).payload_schema
                assert {field_name: info.points for field_name, info in schema.items()} == {field_name: 1 for field_name in ALL_PAYLOAD_INDEXES}
            finally:
                if admin.collection_exists(collection_name=name):
                    admin.delete_collection(collection_name=name)

    def test_other_create_failures_still_raise(self, real_collection, mock_model):
        client, name = real_collection
        # qdrant rejects a zero-length vector with a 400, not the 409 of an existing collection
        mock_model.get_embedding_dimension.return_value = 0

        with pytest.raises(UnexpectedResponse) as error:
            index.ensure_collection(client, mock_model, name=name)

        assert error.value.status_code == 400
        assert not client.collection_exists(collection_name=name)


class TestBuildPoints:
    def test_payload_and_vectors(self, mock_model, search_config):
        alert = _alert()
        documents = [
            SearchDocument(kind=KIND_ALERT, key="header", title="desc", text="a phishing email about invoices"),
            SearchDocument(kind=KIND_COMMENT, key="12", title="bob", text="confirmed false positive", analysis_uuid=None),
        ]
        points = index.build_points(alert, documents, mock_model)
        assert len(points) == 2
        first = points[0]
        assert first.id == index.point_id(ALERT_UUID, KIND_ALERT, "header", 0)
        assert len(first.vector[index.DENSE]) == 8
        assert isinstance(first.vector[index.SPARSE], models.SparseVector)
        assert first.payload[index.FIELD_ROOT_UUID] == ALERT_UUID
        assert first.payload[index.FIELD_KIND] == KIND_ALERT
        assert first.payload[index.FIELD_TEXT].startswith("desc\n")
        assert first.payload[index.FIELD_DISPOSITION] == "OPEN"
        assert first.payload[index.FIELD_LOCATION] == "node1"
        assert first.payload[index.FIELD_TAGS] == []

    def test_long_document_is_chunked(self, mock_model, search_config):
        text = " ".join(f"w{i}" for i in range(40))
        points = index.build_points(_alert(), [SearchDocument(kind=KIND_ALERT, key="header", text=text)], mock_model)
        assert len(points) == search_config.max_chunks_per_document
        assert [p.payload[index.FIELD_CHUNK] for p in points] == [0, 1, 2, 3]
        assert len({p.id for p in points}) == 4

    def test_no_documents_no_points(self, mock_model, search_config):
        assert index.build_points(_alert(), [], mock_model) == []
        mock_model.encode.assert_not_called()


class TestWritePoints:
    def test_upsert_before_delete_of_stale_points(self, mock_qdrant):
        parent = Mock()
        parent.attach_mock(mock_qdrant.upload_points, "upload_points")
        parent.attach_mock(mock_qdrant.delete, "delete")
        points = [models.PointStruct(id=str(uuid.uuid4()), vector={}, payload={}) for _ in range(2)]

        index.write_points(mock_qdrant, "c", ALERT_UUID, points)

        names = [call[0] for call in parent.mock_calls]
        assert names.index("upload_points") < names.index("delete")
        selector = mock_qdrant.delete.call_args.kwargs["points_selector"]
        assert selector.filter.must[0].match.value == ALERT_UUID
        assert set(selector.filter.must_not[0].has_id) == {p.id for p in points}

    def test_empty_point_set_deletes_everything_for_the_alert(self, mock_qdrant):
        index.write_points(mock_qdrant, "c", ALERT_UUID, [])
        mock_qdrant.upload_points.assert_not_called()
        assert mock_qdrant.delete.call_args.kwargs["points_selector"].filter.must_not is None

    def test_incomplete_delete_raises(self, mock_qdrant):
        mock_qdrant.delete.return_value = Mock(status=models.UpdateStatus.ACKNOWLEDGED)
        with pytest.raises(index.IndexError_):
            index.write_points(mock_qdrant, "c", ALERT_UUID, [])


class TestPayloadUpdates:
    @pytest.mark.integration
    def test_update_alert_payload_uses_set_payload_with_filter(self, mock_qdrant):
        alert = insert_alert()
        alert.disposition = "FALSE_POSITIVE"
        get_db().commit()

        assert index.update_alert_payload(alert.uuid) is True
        kwargs = mock_qdrant.set_payload.call_args.kwargs
        assert kwargs["payload"][index.FIELD_DISPOSITION] == "FALSE_POSITIVE"
        assert set(kwargs["payload"]) == set(index.MUTABLE_FIELDS)
        assert kwargs["points"].must[0].match.value == alert.uuid

    @pytest.mark.integration
    def test_update_missing_alert(self, mock_qdrant):
        assert index.update_alert_payload(str(uuid.uuid4())) is False
        mock_qdrant.set_payload.assert_not_called()

    def test_delete_alert(self, mock_qdrant):
        index.delete_alert(ALERT_UUID)
        selector = mock_qdrant.delete.call_args.kwargs["points_selector"]
        assert selector.filter.must[0].match.value == ALERT_UUID

    def test_delete_alert_without_collection(self, mock_qdrant):
        mock_qdrant.collection_exists.return_value = False
        index.delete_alert(ALERT_UUID)
        mock_qdrant.delete.assert_not_called()


class TestIndexAlert:
    @pytest.mark.integration
    def test_missing_alert_is_skipped(self, mock_qdrant):
        result = index.index_alert(str(uuid.uuid4()))
        assert result.skipped == "alert not found"
        mock_qdrant.upload_points.assert_not_called()

    @pytest.mark.integration
    def test_unloadable_alert_is_skipped(self, mock_qdrant, caplog):
        alert = insert_alert()
        shutil.rmtree(alert.storage_dir)
        with caplog.at_level(logging.WARNING):
            assert index.index_alert(alert.uuid).skipped == "alert storage missing"

        mock_qdrant.upload_points.assert_not_called()
        records = [record for record in caplog.records if record.message == "search_index_alert_storage_missing"]
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING
        assert records[0].alert_uuid == alert.uuid
        assert records[0].storage_dir == alert.storage_dir
        assert records[0].path.endswith(os.path.join(alert.storage_dir, "data.json"))

    @pytest.mark.integration
    def test_corrupt_alert_still_raises(self, mock_qdrant):
        # only missing files are a skip: anything else raises so the indexer requeues it and,
        # if it keeps failing, dead-letters it with an ERROR
        alert = insert_alert()
        with open(os.path.join(alert.storage_dir, "data.json"), "w") as fp:
            fp.write("{not json")

        with pytest.raises(json.JSONDecodeError):
            index.index_alert(alert.uuid)

        mock_qdrant.upload_points.assert_not_called()

    def test_to_utc_iso(self):
        from datetime import datetime, timezone
        assert index.to_utc_iso(datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02T03:04:05Z"
        assert index.to_utc_iso(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)) == "2026-01-02T03:04:05Z"
        assert index.to_utc_iso(None) is None
