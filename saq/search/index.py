"""The qdrant side of the index: collection lifecycle and per-alert writes.

One collection holds every alert. Each point is one chunk of one document (see documents.py)
carrying two named vectors -- `dense` from the embedding model and `sparse` from
saq.search.sparse -- and a payload of the text plus the alert metadata used for filtering.
Mutable metadata (disposition, queue, tags) is refreshed with set_payload; nothing is ever
re-encoded for a disposition change.

The collection name embeds the model slug and a schema version, so a model change (or a
payload layout change) lands in a fresh collection rather than mixing incompatible vectors.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from qdrant_client import QdrantClient, models

from saq.configuration.config import get_config
from saq.database.model import Alert, Comment, load_alert
from saq.database.pool import get_db
from saq.qdrant_client import get_qdrant_client
from saq.search.chunking import chunk_text
from saq.search.documents import SearchDocument, extract_documents
from saq.search.model import (
    SCHEMA_VERSION,
    dense_dimension,
    encode_documents,
    load_model,
    max_chunk_tokens,
    model_slug,
)
from saq.search.sparse import sparse_vector

DENSE = "dense"
SPARSE = "sparse"

# payload fields
FIELD_ROOT_UUID = "root_uuid"
FIELD_KIND = "kind"
FIELD_KEY = "key"
FIELD_CHUNK = "chunk"
FIELD_TEXT = "text"
FIELD_TITLE = "title"
FIELD_ALERT_TYPE = "alert_type"
FIELD_TOOL = "tool"
FIELD_QUEUE = "queue"
FIELD_DISPOSITION = "disposition"
FIELD_INSERT_DATE = "insert_date"
FIELD_LOCATION = "location"
FIELD_TAGS = "tags"
FIELD_ANALYSIS_UUID = "analysis_uuid"
FIELD_OBSERVABLE_UUID = "observable_uuid"

KEYWORD_INDEXES = (FIELD_ROOT_UUID, FIELD_KIND, FIELD_ALERT_TYPE, FIELD_QUEUE, FIELD_DISPOSITION, FIELD_LOCATION, FIELD_TAGS)
DATETIME_INDEXES = (FIELD_INSERT_DATE,)

# the payload fields refreshed by update_alert_payload
MUTABLE_FIELDS = (FIELD_DISPOSITION, FIELD_QUEUE, FIELD_TAGS)


class IndexError_(Exception):
    """Raised when qdrant reports a write did not complete."""


@dataclass
class IndexResult:
    alert_uuid: str
    document_count: int = 0
    point_count: int = 0
    seconds: float = 0.0
    skipped: Optional[str] = None
    documents: list[SearchDocument] = field(default_factory=list)


def collection_name() -> str:
    return f"{get_config().qdrant.collection_prefix}-{model_slug()}-v{SCHEMA_VERSION}"


def point_id(root_uuid: str, kind: str, key: str, chunk: int) -> str:
    """Deterministic point id: the same alert produces the same ids on every node and after moves."""
    try:
        namespace = uuid.UUID(root_uuid)
    except ValueError:
        namespace = uuid.uuid5(uuid.NAMESPACE_URL, root_uuid)

    return str(uuid.uuid5(namespace, f"{kind}:{key}:{chunk}"))


def root_uuid_filter(alert_uuid: str) -> models.Filter:
    return models.Filter(must=[models.FieldCondition(key=FIELD_ROOT_UUID, match=models.MatchValue(value=alert_uuid))])


def to_utc_iso(value: Optional[datetime]) -> Optional[str]:
    """Alert timestamps are naive UTC in the database; qdrant wants RFC 3339."""
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def alert_tags(alert: Alert) -> list[str]:
    names = set()
    for mapping in getattr(alert, "tag_mappings", None) or []:
        tag = getattr(mapping, "tag", None)
        if tag is not None and tag.name:
            names.add(tag.name.casefold())

    return sorted(names)


def alert_metadata_payload(alert: Alert) -> dict:
    """The alert-level payload shared by every point of the alert."""
    return {
        FIELD_ROOT_UUID: alert.uuid,
        FIELD_ALERT_TYPE: alert.alert_type,
        FIELD_TOOL: alert.tool,
        FIELD_QUEUE: alert.queue,
        FIELD_DISPOSITION: alert.disposition,
        FIELD_INSERT_DATE: to_utc_iso(alert.insert_date),
        FIELD_LOCATION: alert.location,
        FIELD_TAGS: alert_tags(alert),
    }


def mutable_payload(alert: Alert) -> dict:
    payload = alert_metadata_payload(alert)
    return {key: payload[key] for key in MUTABLE_FIELDS}


def existing_payload_indexes(client: QdrantClient, name: str) -> set[str]:
    info = client.get_collection(collection_name=name)
    return set((info.payload_schema or {}).keys())


def ensure_collection(client: QdrantClient, model, name: Optional[str] = None) -> str:
    """Creates the collection and its payload indexes if they do not exist. Returns the name."""
    name = name or collection_name()
    if not client.collection_exists(collection_name=name):
        logging.info("search_collection_created", extra={"collection": name})
        client.create_collection(
            collection_name=name,
            vectors_config={DENSE: models.VectorParams(size=dense_dimension(model), distance=models.Distance.COSINE)},
            sparse_vectors_config={SPARSE: models.SparseVectorParams(modifier=models.Modifier.IDF)},
        )

    present = existing_payload_indexes(client, name)
    for field_name in KEYWORD_INDEXES:
        if field_name not in present:
            client.create_payload_index(collection_name=name, field_name=field_name, field_schema=models.PayloadSchemaType.KEYWORD, wait=True)

    for field_name in DATETIME_INDEXES:
        if field_name not in present:
            client.create_payload_index(collection_name=name, field_name=field_name, field_schema=models.PayloadSchemaType.DATETIME, wait=True)

    return name


def build_points(alert: Alert, documents: list[SearchDocument], model) -> list[models.PointStruct]:
    """Chunks and encodes documents into points carrying both named vectors."""
    config = get_config().search
    chunk_tokens = max_chunk_tokens(model)
    overlap = min(config.chunk_overlap, chunk_tokens - 1)
    metadata = alert_metadata_payload(alert)

    entries: list[tuple[SearchDocument, int, str]] = []
    for document in documents:
        chunks = chunk_text(
            document.text,
            model.tokenizer,
            chunk_tokens=chunk_tokens,
            overlap=overlap,
            max_chunks=config.max_chunks_per_document,
            title=document.title if document.embed_title else None,
            log_key=f"{alert.uuid}/{document.kind}/{document.key}",
        )
        for chunk in chunks:
            entries.append((document, chunk.index, chunk.text))

    if not entries:
        return []

    dense_vectors = encode_documents(model, [text for _, _, text in entries])

    points = []
    for (document, chunk_index, text), dense in zip(entries, dense_vectors):
        payload = dict(metadata)
        payload.update({
            FIELD_KIND: document.kind,
            FIELD_KEY: document.key,
            FIELD_CHUNK: chunk_index,
            FIELD_TEXT: text,
            FIELD_TITLE: document.title,
            FIELD_ANALYSIS_UUID: document.analysis_uuid,
            FIELD_OBSERVABLE_UUID: document.observable_uuid,
        })
        points.append(models.PointStruct(
            id=point_id(alert.uuid, document.kind, document.key, chunk_index),
            vector={DENSE: dense, SPARSE: sparse_vector(text)},
            payload=payload,
        ))

    return points


def load_comments(alert_uuid: str) -> list[Comment]:
    return get_db().query(Comment).filter(Comment.uuid == alert_uuid).order_by(Comment.insert_date.asc()).all()


def write_points(client: QdrantClient, name: str, alert_uuid: str, points: list[models.PointStruct]) -> None:
    """Upserts points then removes any older point of the alert that is not in the new set.

    Upsert-before-delete is deliberate: a failure between the two leaves a superset rather
    than an empty index for the alert.
    """
    if points:
        client.upload_points(collection_name=name, points=points, wait=True)

    result = client.delete(
        collection_name=name,
        points_selector=models.FilterSelector(filter=models.Filter(
            must=[models.FieldCondition(key=FIELD_ROOT_UUID, match=models.MatchValue(value=alert_uuid))],
            must_not=[models.HasIdCondition(has_id=[point.id for point in points])] if points else None,
        )),
        wait=True,
    )
    if result.status != models.UpdateStatus.COMPLETED:
        raise IndexError_(f"stale point cleanup for {alert_uuid} returned {result.status}")


def index_loaded_alert(alert: Alert, *, client: Optional[QdrantClient] = None, model=None, comments: Optional[list[Comment]] = None) -> IndexResult:
    """Indexes an Alert whose root analysis is already loaded."""
    start = time.time()
    client = client or get_qdrant_client()
    model = model or load_model()
    name = ensure_collection(client, model)

    root = alert.root_analysis
    comments = load_comments(alert.uuid) if comments is None else comments
    documents = extract_documents(alert, root, comments, max_document_bytes=get_config().search.max_document_bytes)
    points = build_points(alert, documents, model)
    write_points(client, name, alert.uuid, points)

    seconds = time.time() - start
    # DEBUG: the indexer service logs search_index_task_complete with these same counts plus
    # the op, the worker and the queue depth; `ace search index --sync` prints its own summary
    logging.debug(f"indexed alert {alert.uuid} ({len(documents)} documents, {len(points)} points) in {seconds:.2f} seconds")
    return IndexResult(alert_uuid=alert.uuid, document_count=len(documents), point_count=len(points), seconds=seconds, documents=documents)


def index_alert(alert_uuid: str, *, client: Optional[QdrantClient] = None, model=None) -> IndexResult:
    """Loads and indexes one alert. A missing alert (or storage directory) is skipped, not an error."""
    alert = load_alert(alert_uuid)
    if alert is None:
        # DEBUG: surfaced to operators as the `skipped` field on search_index_task_complete
        logging.debug(f"alert {alert_uuid} not found, nothing to index")
        return IndexResult(alert_uuid=alert_uuid, skipped="alert not found")

    try:
        root = alert.root_analysis
    except Exception as e:
        logging.debug(f"unable to load alert {alert_uuid} for indexing: {e}")
        return IndexResult(alert_uuid=alert_uuid, skipped=f"unable to load: {e}")

    if root is None:
        return IndexResult(alert_uuid=alert_uuid, skipped="root analysis unavailable")

    return index_loaded_alert(alert, client=client, model=model)


def update_alert_payload(alert_uuid: str, *, client: Optional[QdrantClient] = None) -> bool:
    """Refreshes disposition/queue/tags on every point of the alert. Returns False when the alert is gone."""
    alert = get_db().query(Alert).filter(Alert.uuid == alert_uuid).one_or_none()
    if alert is None:
        # DEBUG: surfaced to operators as updated=False on search_index_task_complete
        logging.debug(f"alert {alert_uuid} not found, nothing to update")
        return False

    client = client or get_qdrant_client()
    name = collection_name()
    if not client.collection_exists(collection_name=name):
        return False

    client.set_payload(collection_name=name, payload=mutable_payload(alert), points=root_uuid_filter(alert_uuid), wait=True)
    return True


def delete_alert(alert_uuid: str, *, client: Optional[QdrantClient] = None) -> None:
    client = client or get_qdrant_client()
    name = collection_name()
    if not client.collection_exists(collection_name=name):
        return

    client.delete(collection_name=name, points_selector=models.FilterSelector(filter=root_uuid_filter(alert_uuid)), wait=True)


def alert_point_ids(alert_uuid: str, *, client: Optional[QdrantClient] = None, kinds: Optional[tuple[str, ...]] = None, limit: int = 256) -> list[str]:
    """The ids of the alert's points (optionally only some document kinds)."""
    client = client or get_qdrant_client()
    name = collection_name()
    if not client.collection_exists(collection_name=name):
        return []

    must = [models.FieldCondition(key=FIELD_ROOT_UUID, match=models.MatchValue(value=alert_uuid))]
    if kinds:
        must.append(models.FieldCondition(key=FIELD_KIND, match=models.MatchAny(any=list(kinds))))

    records, _ = client.scroll(collection_name=name, scroll_filter=models.Filter(must=must), limit=limit, with_payload=False, with_vectors=False)
    return [str(record.id) for record in records]


def drop_collection(*, client: Optional[QdrantClient] = None) -> bool:
    client = client or get_qdrant_client()
    name = collection_name()
    if not client.collection_exists(collection_name=name):
        return False

    client.delete_collection(collection_name=name)
    return True


def status(*, client: Optional[QdrantClient] = None) -> dict:
    client = client or get_qdrant_client()
    name = collection_name()
    result = {"collection": name, "exists": client.collection_exists(collection_name=name), "model": get_config().search.embedding_model, "schema_version": SCHEMA_VERSION}
    if result["exists"]:
        info = client.get_collection(collection_name=name)
        result["points_count"] = info.points_count
        result["indexed_vectors_count"] = info.indexed_vectors_count
        result["payload_indexes"] = sorted((info.payload_schema or {}).keys())
        result["status"] = str(info.status)

    return result
