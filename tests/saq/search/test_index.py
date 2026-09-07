import uuid
from unittest.mock import Mock

import pytest
from qdrant_client import models

from saq.configuration.config import get_config
from saq.database.model import Alert
from saq.search import index
from saq.search.documents import SearchDocument
from saq.search.model import SCHEMA_VERSION
from saq.search.types import KIND_ALERT, KIND_COMMENT

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
    def test_update_alert_payload_uses_set_payload_with_filter(self, mock_qdrant, monkeypatch):
        alert = _alert(disposition="FALSE_POSITIVE")
        db = Mock()
        db.query.return_value.filter.return_value.one_or_none.return_value = alert
        monkeypatch.setattr("saq.search.index.get_db", lambda: db)

        assert index.update_alert_payload(ALERT_UUID) is True
        kwargs = mock_qdrant.set_payload.call_args.kwargs
        assert kwargs["payload"][index.FIELD_DISPOSITION] == "FALSE_POSITIVE"
        assert set(kwargs["payload"]) == set(index.MUTABLE_FIELDS)
        assert kwargs["points"].must[0].match.value == ALERT_UUID

    def test_update_missing_alert(self, mock_qdrant, monkeypatch):
        db = Mock()
        db.query.return_value.filter.return_value.one_or_none.return_value = None
        monkeypatch.setattr("saq.search.index.get_db", lambda: db)
        assert index.update_alert_payload(ALERT_UUID) is False
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
    def test_missing_alert_is_skipped(self, mock_qdrant, monkeypatch):
        monkeypatch.setattr("saq.search.index.load_alert", lambda _: None)
        result = index.index_alert(ALERT_UUID)
        assert result.skipped
        mock_qdrant.upload_points.assert_not_called()

    def test_unloadable_alert_is_skipped(self, mock_qdrant, monkeypatch):
        alert = Mock()
        type(alert).root_analysis = property(lambda self: (_ for _ in ()).throw(RuntimeError("gone")))
        monkeypatch.setattr("saq.search.index.load_alert", lambda _: alert)
        assert index.index_alert(ALERT_UUID).skipped

    def test_to_utc_iso(self):
        from datetime import datetime, timezone
        assert index.to_utc_iso(datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02T03:04:05Z"
        assert index.to_utc_iso(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)) == "2026-01-02T03:04:05Z"
        assert index.to_utc_iso(None) is None
